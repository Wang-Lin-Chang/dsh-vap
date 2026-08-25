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
// 安全（生产级加固批次 · S4/S5）：
//   - S4 顶替活性判定：不再用 socket.writable 位（Node 背压时 writable=false 会误判死连接
//     → 攻击者可无 pubKey 顶替），改用「最后活跃时间超过 relayIdleDeadMs」判定死连接
//     （TCP keepalive 30s 探测兜底）；
//   - S5a 注册必须携带非空 pubKey（杜绝匿名抢占未注册 nodeId）；
//   - S5b 同名顶替一律要求 pubKey 与旧注册者一致（旧连接已死也要求，防「打瘫旧连接再抢名」）；
//   - S5c relay 转发校验 from：消息必须来自注册该 nodeId 的连接（from === 注册名）；
//   - S5d 出站带宽上限：per-destination 与全局字节/秒令牌桶，超限丢弃（防 1MB×1000帧/s 打满目标）。
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
import tls from 'node:tls';

export const DEFAULT_MAX_FRAME_BYTES = 1024 * 1024; // 单帧上限 1MB，防内存滥用
export const DEFAULT_MAX_FRAMES_PER_SEC = 1000;     // 单连接每秒最大帧数，超限断连（M3）
export const DEFAULT_IDLE_DEAD_MS = 90_000;         // S4：连接最后活跃超过此时长判死（TCP keepalive 30s 兜底）
export const DEFAULT_BYTES_PER_SEC_PER_DEST = 512 * 1024; // S5d：单目的端出站带宽上限 512KB/s
export const DEFAULT_BYTES_PER_SEC_GLOBAL = 5 * 1024 * 1024; // S5d：全局出站带宽上限 5MB/s

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
  requireTakeoverAuth = true,        // M3/S5b：同名顶替须携带旧注册者 pubKey（默认开启）
  relayIdleDeadMs = DEFAULT_IDLE_DEAD_MS,          // S4：活性判定窗口
  relayBytesPerSecPerDest = DEFAULT_BYTES_PER_SEC_PER_DEST, // S5d：单目的端带宽上限
  relayBytesPerSecGlobal = DEFAULT_BYTES_PER_SEC_GLOBAL,    // S5d：全局带宽上限
  tlsOptions = null,                 // S6：{ cert, key }（PEM 文件路径或内容）——设置则走 TLS
  healthPort = null,                 // M11：旁路 HTTP /health 端口（默认 null = 不启用；仅回环）
  verbose = false,                   // 诊断日志：register/takeover/relay/close 事件（默认关）
} = {}) {
  const clients = new Map();         // nodeId -> { socket, pubKey, act }
  // S5b 墓碑（复验轮发现）：nodeId 的 pubKey 绑定记忆。首注册记录 pubKey，此后无论
  // 旧连接活还是死，同名注册都必须携带一致 pubKey——封死「先打瘫旧连接 → close 清表
  // → 再首注册抢名」的绕过路径。close 只从 clients 删活跃条目，不删本表。
  const knownPubKeys = new Map();    // nodeId -> pubKey
  const destBuckets = new Map();     // S5d：nodeId -> { tokens, last } 每目的端字节令牌桶
  const globalBucket = { tokens: relayBytesPerSecGlobal, last: Date.now() }; // S5d：全局出站桶
  // 诊断日志写 stderr（不污染 stdout 的就绪信号/度量输出）。
  const log = verbose
    ? (...a) => process.stderr.write(`[relay] ${new Date().toISOString()} ${a.join(' ')}\n`)
    : () => {};
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
  let rejectedRegistrations = 0; // 注册被拒（nodeId 不合白名单 / 无 pubKey）
  let rejectedTakeovers = 0;     // 顶替被拒（pubKey 与旧注册者不匹配）
  let rateLimited = 0;           // 因帧速率超限被断连的连接数
  let relayFromMismatch = 0;     // S5c：relay 消息 from 与注册名不符被拒的帧数
  let relayRateLimited = 0;      // S5d：因出站带宽上限被丢弃的帧数
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
      relayFromMismatch,
      relayRateLimited,
      uptimeMs: startedAt ? Date.now() - startedAt : 0,
    };
  }

  // S5d：字节令牌桶（rate=cap：按配置速率匀速补充，桶容量=每秒上限）
  function takeBytes(bucket, perSecCap, n) {
    const now = Date.now();
    bucket.tokens = Math.min(perSecCap, bucket.tokens + ((now - bucket.last) / 1000) * perSecCap);
    bucket.last = now;
    if (bucket.tokens < n) return false;
    bucket.tokens -= n;
    return true;
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
    // 死连接检测（relay 单向故障根因修复）：开 TCP keepalive，30s 起探测 NAT 半开连接。
    // 半开的死 socket 经 close 事件从转发表清理，避免「对端消息持续写入死 socket」的单向转发。
    try { socket.setKeepAlive(true, 30000); } catch { /* 尽力 */ }

    // S4/S5c：连接级状态。act 是共享活性对象（条目内同一引用），任何 data 都刷新活跃时间；
    // registeredId 在注册成功后记录，relay 消息必须 from===registeredId。
    let registeredId = null;
    const act = { t: Date.now() };

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
            if (verbose) log('register REJECT invalid nodeId=', JSON.stringify(nodeId));
            return;
          }
          // S5a：注册必须携带非空 pubKey（匿名注册 = 可抢占任意未注册 nodeId）。
          const pubKey = typeof msg.pubKey === 'string' && msg.pubKey.length > 0 ? msg.pubKey : null;
          if (pubKey == null) {
            rejectedRegistrations += 1;
            if (verbose) log('register REJECT no pubKey nodeId=', nodeId);
            return;
          }
          const prev = clients.get(nodeId);
          if (prev && prev.socket !== socket) {
            // 顶替认证（M3 + S4/S5b）：一律要求新连接携带与旧注册者一致的 pubKey——
            // 旧连接已死（destroyed/半关闭/超时无活跃）也要求，防「先打瘫旧连接再抢名」。
            const prevDead = prev.socket.destroyed
              || prev.socket.writableEnded
              || prev.socket.readableEnded
              || Date.now() - prev.act.t > relayIdleDeadMs;
            if (requireTakeoverAuth && prev.pubKey && pubKey !== prev.pubKey) {
              rejectedTakeovers += 1;
              if (verbose) log('register REJECT takeover nodeId=', nodeId, 'pubKey mismatch prevDead=', prevDead);
              return;
            }
            replacements += 1;
            if (verbose) log('register takeover nodeId=', nodeId, 'prevDead=', prevDead);
            try { prev.socket.destroy(); } catch { /* 尽力 */ }
          } else {
            // S5b 墓碑：无活跃连接时的注册也要对照 pubKey 记忆（防「打瘫旧连接后首注册抢名」）。
            const remembered = knownPubKeys.get(nodeId);
            if (requireTakeoverAuth && remembered && remembered !== pubKey) {
              rejectedTakeovers += 1;
              if (verbose) log('register REJECT key-memory nodeId=', nodeId, 'pubKey mismatch (previous holder exists)');
              return;
            }
          }
          clients.set(nodeId, { socket, pubKey, act });
          knownPubKeys.set(nodeId, pubKey); // S5b：绑定记忆（首注册 + 每次合法注册刷新）
          registeredId = nodeId;
          registered += 1;
          if (verbose) log('register ok nodeId=', nodeId, 'clients=', clients.size);
          return;
        }

        if (msg.type === 'relay') {
          // S5c：转发必须来自注册该 nodeId 的连接（未注册连接或伪造 from 一律拒绝）。
          if (registeredId === null || msg.from !== registeredId) {
            relayFromMismatch += 1;
            if (verbose) log('relay REJECT from-mismatch registeredId=', registeredId, 'msg.from=', msg.from);
            return;
          }
          if (typeof drop === 'function' && drop(msg)) {
            dropped += 1;
            return;
          }
          const to = msg.to;
          if (typeof to !== 'string' || to.length === 0) return;
          const entry = clients.get(to);
          if (!entry || !entry.socket || entry.socket.destroyed) {
            if (verbose) log('relay DROP to=', to, 'not-online (单向故障可疑点)');
            return; // 目标不在线：静默丢弃
          }
          // S5d：出站带宽上限（全局 + 单目的端），超限丢弃。
          if (!takeBytes(globalBucket, relayBytesPerSecGlobal, frame.length)) {
            relayRateLimited += 1;
            return;
          }
          let db = destBuckets.get(to);
          if (!db) {
            db = { tokens: relayBytesPerSecPerDest, last: Date.now() };
            destBuckets.set(to, db);
          }
          if (!takeBytes(db, relayBytesPerSecPerDest, frame.length)) {
            relayRateLimited += 1;
            return;
          }
          forwarded += 1;
          forwardedBytes += frame.length;
          // 原样字节转发：写回同一 frame（不重新序列化、不验签不解密）。
          entry.socket.write(frame);
          if (verbose) log('relay fwd to=', to, 'bytes=', frame.length, 'from=', msg.from || '?');
          return;
        }

        // 未知类型：忽略
      },
      onError: () => {
        errorCount += 1; // 帧过大 / 坏 JSON（M11 计数）
        try { socket.destroy(); } catch { /* 尽力 */ }
      },
    });

    socket.on('data', (chunk) => {
      act.t = Date.now(); // S4：刷新连接活跃时间
      decoder.push(chunk);
    });
    socket.on('error', () => { errorCount += 1; /* 传输层错误不抛，close 时清理 */ });
    socket.on('close', () => {
      for (const [nodeId, entry] of clients) {
        if (entry.socket === socket) {
          clients.delete(nodeId);
          destBuckets.delete(nodeId); // S5d：清理离线的目的端桶
          if (verbose) log('close remove nodeId=', nodeId, 'clients=', clients.size);
        }
      }
    });
  }

  function start() {
    if (server) return Promise.resolve(boundPort);
    return new Promise((resolve, reject) => {
      // S6：tlsOptions 提供 cert/key 时用 node:tls 创建服务器（中继传输层加密）。
      const s = tlsOptions ? tls.createServer(tlsOptions, handleSocket) : net.createServer(handleSocket);
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
