// phase4/relay-server.mjs —— VAP Phase 4 跨 NAT 中继（零第三方依赖，node:net）
//
// 跨 NAT 第一步：中继模式。让信封跨越 NAT 边界——客户端经 TCP 注册到中继，
// 中继按 nodeId 查表转发信封。中继**只转发不解密不验签**（信封自带 Ed25519 签名保护）。
//
//   createRelayServer({ port, host, drop, maxFrameBytes, maxFramesPerSec, requireTakeoverAuth })
//     → { start(), stop(), stats(), get port, registry() }
//
// 安全（修复批次 1 · M3）：
//   - 注册白名单：nodeId 必须匹配 NODE_ID_PATTERN，否则拒绝注册；
//   - 顶替认证：同名 nodeId 顶替旧连接须携带与旧注册者一致的 pubKey（requireTakeoverAuth，
//     默认开启）；不匹配 → 拒绝顶替，旧连接不受影响；
//   - 帧限速：单连接每秒帧数超过 maxFramesPerSec 立即断连。
//
// 行协议：4 字节大端长度前缀 + JSON 正文（length-prefixed JSON）。
//   客户端消息：
//     { type:'register', nodeId, pubKey }         注册（或同名顶替旧连接）
//     { type:'relay',    to, envelope }           转发信封到 nodeId=to
//   服务端消息：
//     { type:'relay',    to, envelope }           原样字节转发给接收方
//
// 复用 ../vap-core.mjs 的信封/三闸在接收方（relay-client 与实验装置内完成），
// 本模块只「搬运与转发」，不复制信封构造/验签/军法/诚实边界等任何判定逻辑。

import net from 'node:net';
import http from 'node:http';

export const DEFAULT_MAX_FRAME_BYTES = 1024 * 1024; // 单帧上限 1MB，防内存滥用
export const DEFAULT_MAX_FRAMES_PER_SEC = 1000;     // 单连接每秒最大帧数，超限断连（M3）

// 注册白名单（M3）：nodeId 是转发表的键，也会进日志/度量 → 只允许字母/数字/下划线/连字符。
export const NODE_ID_PATTERN = /^[0-9a-zA-Z_-]{1,64}$/;

function isValidNodeId(nodeId) {
  return typeof nodeId === 'string' && NODE_ID_PATTERN.test(nodeId);
}

// ---------------------------------------------------------------------------
// 行协议：encodeFrame（4 字节大端长度 + JSON 正文）
// ---------------------------------------------------------------------------

export function encodeFrame(message) {
  const payload = Buffer.from(JSON.stringify(message), 'utf8');
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

// createFrameDecoder({ onFrame, onError, maxFrameBytes }) → { push(chunk) }
// 缓冲式解码：处理半包（partial）与粘包（多个帧连读）。onFrame(message, frameBuffer, len)
// 收到一个完整帧即回调；frameBuffer 为 4+len 的原始字节（供「原样字节」转发）。
export function createFrameDecoder({
  onFrame,
  onError,
  maxFrameBytes = DEFAULT_MAX_FRAME_BYTES,
} = {}) {
  let buf = Buffer.alloc(0);

  function push(chunk) {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const len = buf.readUInt32BE(0);
      if (len > maxFrameBytes) {
        const err = new Error(`frame too large: ${len} > ${maxFrameBytes}`);
        if (onError) onError(err);
        return;
      }
      if (buf.length < 4 + len) return; // 半包，等更多字节
      const frame = buf.subarray(0, 4 + len);
      buf = buf.subarray(4 + len);
      let message;
      try {
        message = JSON.parse(frame.subarray(4).toString('utf8'));
      } catch (err) {
        if (onError) onError(err);
        continue; // 单帧坏 JSON 不影响后续帧
      }
      if (onFrame) onFrame(message, frame, len);
    }
  }

  return { push };
}

// ---------------------------------------------------------------------------
// createRelayServer —— 中继服务
// ---------------------------------------------------------------------------

export function createRelayServer({
  port = 0,
  host = '127.0.0.1',
  drop = null,                       // 可选：审查模拟钩子 drop(msg) => true 丢弃（默认 null = 永不丢弃）
  maxFrameBytes = DEFAULT_MAX_FRAME_BYTES,
  maxFramesPerSec = DEFAULT_MAX_FRAMES_PER_SEC,
  requireTakeoverAuth = true,        // M3：同名顶替须携带旧注册者 pubKey（默认开启）
  healthPort = null,                 // M11：旁路 HTTP /health 端口（默认 null = 不启用；仅回环）
} = {}) {
  const clients = new Map();         // nodeId -> { socket, pubKey }
  let server = null;
  let boundPort = null;
  let startedAt = null;

  // 度量（R4 无激励基线的数据源）
  let totalBytes = 0;       // 入站字节（中继收到的全部帧字节）
  let forwardedBytes = 0;   // 出站字节（中继写给目标 socket 的字节）
  let forwarded = 0;        // 转发的 relay 帧数
  let registered = 0;       // 累计注册次数
  let replacements = 0;     // 同名顶替次数（认证通过的顶替）
  let dropped = 0;          // 被 drop 钩子丢弃的帧数
  let rejectedRegistrations = 0; // 注册被拒（nodeId 不合白名单）
  let rejectedTakeovers = 0;     // 顶替被拒（pubKey 与旧注册者不匹配）
  let rateLimited = 0;           // 因帧速率超限被断连的连接数
  let errorCount = 0;            // M11：累计错误（帧过大/坏 JSON/传输错误）

  function stats() {
    return {
      connections: clients.size,
      totalBytes,
      forwardedBytes,
      forwarded,
      registered,
      replacements,
      dropped,
      rejectedRegistrations,
      rejectedTakeovers,
      rateLimited,
      uptimeMs: startedAt ? Date.now() - startedAt : 0,
    };
  }

  // M11：真实健康状态（connections/bytes/errors/uptime）。
  function health() {
    return {
      ok: true,
      connections: clients.size,
      totalBytes,
      forwardedBytes,
      forwarded,
      errors: errorCount,
      uptimeMs: startedAt ? Date.now() - startedAt : 0,
    };
  }

  function registry() {
    return Array.from(clients.keys());
  }

  function handleSocket(socket) {
    // 帧限速（M3）：每连接 1 秒滑动窗口计数，超限立即断连（防单连接刷帧打死中继）。
    let windowStart = Date.now();
    let framesInWindow = 0;

    const decoder = createFrameDecoder({
      maxFrameBytes,
      onFrame: (msg, frame) => {
        totalBytes += frame.length;

        const nowMs = Date.now();
        if (nowMs - windowStart >= 1000) {
          windowStart = nowMs;
          framesInWindow = 0;
        }
        framesInWindow += 1;
        if (framesInWindow > maxFramesPerSec) {
          rateLimited += 1;
          try { socket.destroy(); } catch { /* 尽力 */ }
          return;
        }

        if (!msg || typeof msg !== 'object') return;

        if (msg.type === 'register') {
          const nodeId = msg.nodeId;
          // 白名单（M3）：非法 nodeId 直接拒绝注册（不进转发表）。
          if (!isValidNodeId(nodeId)) {
            rejectedRegistrations += 1;
            return;
          }
          const pubKey = typeof msg.pubKey === 'string' && msg.pubKey.length > 0 ? msg.pubKey : null;
          const prev = clients.get(nodeId);
          if (prev && prev.socket !== socket) {
            // 顶替认证（M3）：新连接必须携带与旧注册者一致的 pubKey，否则拒绝顶替
            // （旧连接保留在表内），杜绝「知道 nodeId 就能抢走别人信封」。
            if (requireTakeoverAuth && (pubKey == null || pubKey !== prev.pubKey)) {
              rejectedTakeovers += 1;
              return;
            }
            replacements += 1;
            try { prev.socket.destroy(); } catch { /* 尽力 */ }
          }
          clients.set(nodeId, { socket, pubKey });
          registered += 1;
          return;
        }

        if (msg.type === 'relay') {
          if (typeof drop === 'function' && drop(msg)) {
            dropped += 1;
            return;
          }
          const to = msg.to;
          if (typeof to !== 'string' || to.length === 0) return;
          const entry = clients.get(to);
          if (!entry || !entry.socket || entry.socket.destroyed) return; // 目标不在线：静默丢弃
          forwarded += 1;
          forwardedBytes += frame.length;
          // 原样字节转发：写回同一 frame（不重新序列化、不验签不解密）。
          entry.socket.write(frame);
          return;
        }

        // 未知类型：忽略
      },
      onError: () => {
        errorCount += 1; // 帧过大 / 坏 JSON（M11 计数）
        try { socket.destroy(); } catch { /* 尽力 */ }
      },
    });

    socket.on('data', (chunk) => decoder.push(chunk));
    socket.on('error', () => { errorCount += 1; /* 传输层错误不抛，close 时清理 */ });
    socket.on('close', () => {
      for (const [nodeId, entry] of clients) {
        if (entry.socket === socket) clients.delete(nodeId);
      }
    });
  }

  function start() {
    if (server) return Promise.resolve(boundPort);
    return new Promise((resolve, reject) => {
      const s = net.createServer(handleSocket);
      s.on('error', reject);
      s.listen(port, host, () => {
        server = s;
        boundPort = s.address().port;
        startedAt = Date.now();
        resolve(boundPort);
      });
    });
  }

  // M11：旁路 HTTP /health（node:http，仅回环默认）。healthPort 为 null 则不启用。
  let healthServer = null;
  let healthBoundPort = null;

  function startHealth() {
    if (healthServer) return Promise.resolve(healthBoundPort);
    if (healthPort == null) return Promise.resolve(null);
    return new Promise((resolve, reject) => {
      const hs = http.createServer((req, res) => {
        if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) {
          const body = JSON.stringify(health());
          res.writeHead(200, {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(body),
          });
          res.end(body);
          return;
        }
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'not found' }));
      });
      hs.on('error', reject);
      hs.listen(healthPort, '127.0.0.1', () => {
        healthServer = hs;
        healthBoundPort = hs.address().port;
        resolve(healthBoundPort);
      });
    });
  }

  function stopHealth() {
    if (!healthServer) return Promise.resolve();
    const hs = healthServer;
    healthServer = null;
    healthBoundPort = null;
    return new Promise((resolve) => hs.close(() => resolve()));
  }

  function stop() {
    const s = server;
    server = null;
    boundPort = null;
    startedAt = null;
    return Promise.all([
      new Promise((resolve) => {
        for (const [, entry] of clients) {
          try { entry.socket.destroy(); } catch { /* 尽力 */ }
        }
        clients.clear();
        if (!s) return resolve();
        s.close(() => resolve());
      }),
      stopHealth(),
    ]).then(() => undefined);
  }

  return {
    start,
    stop,
    stats,
    health,
    startHealth,
    stopHealth,
    registry,
    get port() {
      return boundPort;
    },
    get healthPort() {
      return healthBoundPort;
    },
  };
}
