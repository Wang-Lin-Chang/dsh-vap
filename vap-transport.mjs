// vap-transport.mjs —— VAP 中环 v0：可插拔传输
//
// 把传输从「本地文件系统」抽象为可插拔后端：FileTransport（v0 行为）与
// HttpGateway/HttpClient（node:http，真本地回环）。零第三方依赖，仅 node: 内置模块。
//
// 复用 vap-core 的信封/验签/验证门（createVapNode/createBrain/verify/canonicalJson）：
// 本模块不复制信封构造或判定逻辑，只负责「文件即消息」与「HTTP 搬运」。
// 契约依据：同目录 brief-ring.md、vap-spec.md、vap-core.mjs。

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

import { claimNonce, verifyEnvelopeSignature, NONCE_PATTERN } from './vap-core.mjs';
import { silentLogger } from './logger.mjs';
import { loadConfig } from './config.mjs';

// 请求体大小上限（默认 1MB，超出返回 413）
export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

// ---------------------------------------------------------------------------
// 入站白名单（修复批次 1：F1 / M1）
//   ENVELOPE_ID_PATTERN  严格形状：evt- + 16 位小写十六进制（node.send 的生成格式）；
//   SAFE_NAME_PATTERN    宽松形状：仅字母/数字/点/下划线/连字符，且不含 '..'。
// 严格模式（默认）用前者；strictEnvelopeId:false 的兼容模式用后者 ——
// 两种模式都杜绝路径穿越（'../'、'/'、'\' 一律进不来），差别只是是否允许自定义 id。
// ---------------------------------------------------------------------------

export const ENVELOPE_ID_PATTERN = /^evt-[0-9a-f]{16}$/;
const SAFE_NAME_PATTERN = /^[0-9A-Za-z._-]{1,128}$/;

function isStrictEnvelopeId(id) {
  return typeof id === 'string' && ENVELOPE_ID_PATTERN.test(id);
}

function isSafeEnvelopeId(id) {
  return typeof id === 'string' && SAFE_NAME_PATTERN.test(id) && !id.includes('..');
}

// 监听地址可能是通配地址（0.0.0.0 / ::），URL 里不能直接用 → 映射到回环；
// IPv6 字面量在 URL 里需要方括号。
function hostForUrl(host) {
  if (typeof host !== 'string' || host.length === 0) return '127.0.0.1';
  if (host === '0.0.0.0' || host === '::' || host === '*') return '127.0.0.1';
  if (host.includes(':')) return `[${host}]`;
  return host;
}

// ---------------------------------------------------------------------------
// 传输层自身的文件工具。原子写（tmp+rename）与 vap-core 内部同名工具等价，
// 但它是传输层的文件 IO 而非信封/验证门逻辑，故在此独立实现（不复制信封逻辑）。
// ---------------------------------------------------------------------------

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function atomicWrite(filePath, content) {
  ensureDir(path.dirname(filePath));
  const tmp = `${filePath}.tmp-${crypto.randomBytes(6).toString('hex')}`;
  fs.writeFileSync(tmp, content, 'utf8');
  try {
    fs.renameSync(tmp, filePath);
  } catch (err) {
    // 某些平台上 rename 覆盖已存在文件可能失败：移除目标后重试一次。
    if (err && (err.code === 'EEXIST' || err.code === 'EPERM' || err.code === 'ENOTEMPTY')) {
      try { fs.unlinkSync(filePath); } catch { /* 目标本就不存在 */ }
      fs.renameSync(tmp, filePath);
    } else {
      try { fs.unlinkSync(tmp); } catch { /* 尽力清理 */ }
      throw err;
    }
  }
}

function listFiles(dir) {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

function readJsonFile(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 组网辅助：relayed 去重标记（防环）+ relay-log 落盘 + 尽力转发
// ---------------------------------------------------------------------------

// 转发前认领 relayed 标记：root/relayed/<envelopeId>（envelopeId 本身即 evt-<hex>，
// 与 outbox/inbox-http 的 evt-<id>.json 命名一致）；O_EXCL 原子创建，与租约同义。
// 首次返回 true（本网关尚未转发过该 envelopeId），已存在返回 false（不重复转发）。
function claimRelayed(root, envelopeId) {
  const dir = path.join(root, 'relayed');
  ensureDir(dir);
  let fd;
  try {
    fd = fs.openSync(path.join(dir, envelopeId), 'wx');
  } catch (err) {
    if (err && err.code === 'EEXIST') return false;
    throw err;
  }
  fs.closeSync(fd);
  return true;
}

function countRelayed(root) {
  return listFiles(path.join(root, 'relayed')).length;
}

// relay-log.jsonl：peers 转发失败记一行（异步尽力，不影响入站成功）。
function appendRelayLog(root, entry) {
  const file = path.join(root, 'relay-log.jsonl');
  ensureDir(path.dirname(file));
  fs.appendFileSync(file, `${JSON.stringify(entry)}\n`, 'utf8');
}

// 尽力转发到单个 peer：POST /envelopes，带 x-vap-relay: 1（一跳转发语义标记）。
function forwardToPeer(peerUrl, envelope) {
  return new Promise((resolve) => {
    const base = peerUrl.replace(/\/+$/, '');
    let url;
    try {
      url = new URL('/envelopes', `${base}/`);
    } catch {
      resolve({ ok: false, error: `invalid peer url: ${peerUrl}` });
      return;
    }
    const payload = JSON.stringify(envelope);
    const req = http.request(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-vap-relay': '1',
      },
    }, (res) => {
      res.resume();
      res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode }));
    });
    req.on('error', (err) => resolve({ ok: false, error: String((err && err.message) || err) }));
    req.on('timeout', () => req.destroy(new Error('peer forward timeout')));
    req.setTimeout(2000);
    req.write(payload);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// createFileTransport —— 现 v0 行为：信封写 root/outbox/、从 root/outbox/ 读。
// 统一为 Transport 形状 { send, read, markDelivered, countUndelivered }。
// ---------------------------------------------------------------------------

export function createFileTransport({ root } = {}) {
  if (!root) throw new Error('createFileTransport: root is required');
  const outbox = path.join(root, 'outbox');
  ensureDir(outbox);

  // 把已构造的信封原子写入 outbox/evt-<id>.json（信封构造复用 vap-core 的 createVapNode.send）。
  function send(envelope) {
    if (!envelope || typeof envelope !== 'object' || !envelope.id) {
      throw new Error('createFileTransport.send: envelope.id is required');
    }
    atomicWrite(path.join(outbox, `${envelope.id}.json`), `${JSON.stringify(envelope, null, 2)}\n`);
    return envelope;
  }

  // 投递后标记：outbox/evt-<id>.delivered（网关 GET 投递后调用）。
  function markDelivered(envelopeId) {
    atomicWrite(path.join(outbox, `${envelopeId}.delivered`), `${Date.now()}\n`);
  }

  // 读未投递信封：排除 .delivered 标记与 .verdict/.delivered 等非 .json 文件；
  // after 为游标（envelopeId，不含 .json），仅返回文件名字典序严格大于游标的信封。
  function read(options = {}) {
    const after = options && options.after;
    const files = listFiles(outbox)
      .filter((name) => /^evt-.*\.json$/.test(name))
      .sort();
    const envelopes = [];
    for (const file of files) {
      const envelopeId = file.replace(/\.json$/, '');
      if (fs.existsSync(path.join(outbox, `${envelopeId}.delivered`))) continue;
      if (after && file <= `${after}.json`) continue;
      const envelope = readJsonFile(path.join(outbox, file));
      if (envelope) envelopes.push(envelope);
    }
    return envelopes;
  }

  function countUndelivered() {
    return read().length;
  }

  return { root, outbox, send, read, markDelivered, countUndelivered };
}

// ---------------------------------------------------------------------------
// createHttpGateway —— HTTP 网关（node:http）。
//   POST /envelopes           接收远端信封 → 原子写 root/inbox-http/evt-<id>.json → 202
//   GET  /envelopes?after=<id> 出站：返回 outbox 未投递信封数组，投递后标 .delivered
//   GET  /health               { ok, envelopesIn, envelopesOut }
// 启动/关闭：start()（返回实际端口，port=0 自动分配）、stop()。
// 网关只搬运不裁决：军法闸/诚实边界闸仍由接收方复用 vap-core 的 verify/createBrain；
// 网关只做「身份闸的签名前置校验」（M7，requireInboundSignature），拒绝搬运无效签名。
//
// 参数（修复批次 1 新增）：
//   host                     监听地址，默认 '127.0.0.1'（安全默认：仅回环）。
//                            跨机部署显式传 '0.0.0.0' 或具体网卡地址（F2）。
//   strictEnvelopeId         true（默认）= envelope.id 必须匹配 evt-<16 hex>（M1）；
//                            false = 兼容模式，仍禁止路径穿越字符但允许自定义 id。
//   requireInboundSignature  true（默认）= 入站信封先验 Ed25519 签名，失败 403（M7）；
//                            false = 旧「只搬运」语义（伪造件交由下游三道闸裁决）。
//
// 参数（生产级加固批次 · S7/S8）：
//   gatewayToken             null（默认）= 未配置时 GET /envelopes 仅允许回环（127.0.0.1/::1）；
//                            配置后出站投递必须携带 Authorization: Bearer <token>
//                            （timing-safe 比较）。POST 入站仍走验签准入，不强制 token。
//   inboundRatePerSec        10（默认）= POST /envelopes 每来源 IP 令牌桶速率；
//   inboundRateBurst         30（默认）= 桶容量（突发上限）；
//   maxInboxFiles            10000（默认）= inbox-http 落盘文件数上限，超限 503。
// ---------------------------------------------------------------------------

export function createHttpGateway({
  port = 0,
  host = '127.0.0.1',
  root,
  laws,
  peers = [],
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  strictEnvelopeId = true,
  requireInboundSignature = true,
  log = null,
  logger = null,
  config = null,
  gatewayToken = null,
  inboundRatePerSec = 10,
  inboundRateBurst = 30,
  maxInboxFiles = 10000,
} = {}) {
  // M8：config（loadConfig 合并结果）可覆盖 host/port 默认值；显式参数仍优先。
  const cfg = config && typeof config === 'object' ? config : null;
  if (cfg) {
    if (host === '127.0.0.1' && typeof cfg.gatewayHost === 'string' && cfg.gatewayHost) host = cfg.gatewayHost;
    if (port === 0 && Number.isInteger(cfg.gatewayPort) && cfg.gatewayPort >= 0) port = cfg.gatewayPort;
  }
  if (!root) throw new Error('createHttpGateway: root is required');
  // M9：接结构化 logger（无 file 时静默 console.error 至少 error 级）。
  const logr = logger || silentLogger();
  const legacyLog = typeof log === 'function' ? log : null;
  function emitLog(level, message) {
    if (level === 'error') recordError(new Error(message));
    if (legacyLog) legacyLog(message);
    else if (level === 'error') logr.error(message, { component: 'gateway' });
    else logr.info(message, { component: 'gateway' });
  }
  const fileTransport = createFileTransport({ root });
  const inboxHttp = path.join(root, 'inbox-http');
  ensureDir(inboxHttp);
  ensureDir(path.join(root, 'relayed'));

  const peersList = (Array.isArray(peers) ? peers : [])
    .filter((u) => typeof u === 'string' && u.length > 0);

  // 提供了 laws 且工作区缺 laws.json 时落一份，供下游 verify 使用同一规则（规则是数据）。
  if (laws && !fs.existsSync(path.join(root, 'laws.json'))) {
    atomicWrite(path.join(root, 'laws.json'), `${JSON.stringify(laws, null, 2)}\n`);
  }

  let server = null;
  let boundPort = null;
  let errorCount = 0;      // M11：累计错误次数
  let lastError = null;    // M11：最近一次错误
  let authRejected = 0;    // S7：GET /envelopes 认证失败次数
  let rateRejected = 0;    // S8：POST 入站限速拒绝次数
  let quotaRejected = 0;   // S8：inbox 配额拒绝次数
  const ipBuckets = new Map(); // S8：来源 IP -> { tokens, last }

  // S7：出站投递认证。gatewayToken 未配置时仅回环可读 outbox（防公网部署被拉空队列）；
  // 配置后必须 Bearer token（timing-safe 比较）。
  const tokenBuf = typeof gatewayToken === 'string' && gatewayToken.length > 0 ? Buffer.from(gatewayToken) : null;

  function isLoopbackRemote(req) {
    const a = String(req.socket.remoteAddress || '');
    return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
  }

  function outboundAuthOk(req) {
    if (!tokenBuf) return isLoopbackRemote(req);
    const h = req.headers && req.headers.authorization;
    const m = typeof h === 'string' && /^Bearer (.+)$/.exec(h);
    if (!m) return false;
    const a = Buffer.from(m[1]);
    return a.length === tokenBuf.length && crypto.timingSafeEqual(a, tokenBuf);
  }

  // S8：POST 入站 per-IP 令牌桶（防自签洪泛无限落盘 + 向 peers 放大）。
  function postAllow(ip) {
    const now = Date.now();
    let e = ipBuckets.get(ip);
    if (!e) {
      e = { tokens: inboundRateBurst, last: now };
      ipBuckets.set(ip, e);
    }
    e.tokens = Math.min(inboundRateBurst, e.tokens + ((now - e.last) / 1000) * inboundRatePerSec);
    e.last = now;
    if (e.tokens < 1) return false;
    e.tokens -= 1;
    return true;
  }

  function recordError(err) {
    errorCount += 1;
    lastError = String((err && err.message) || err);
  }

  // M11：ok = 目录可写探测成功（真实状态，而非恒真）。
  function probeWritable(dir) {
    try {
      const probe = path.join(dir, `.probe-${crypto.randomBytes(4).toString('hex')}`);
      fs.writeFileSync(probe, 'ok', 'utf8');
      fs.unlinkSync(probe);
      return true;
    } catch {
      return false;
    }
  }

  function countInbound() {
    return listFiles(inboxHttp).filter((name) => /^evt-.*\.json$/.test(name)).length;
  }

  function health(options = {}) {
    const detail = options && options.detail === true;
    // S8：顺带清理 5 分钟无活动的限速桶（防 Map 无限增长）。
    const now = Date.now();
    for (const [ip, e] of ipBuckets) if (now - e.last > 300000) ipBuckets.delete(ip);
    const ok = probeWritable(inboxHttp) && probeWritable(fileTransport.outbox);
    const base = {
      ok,
      envelopesIn: countInbound(),
      envelopesOut: fileTransport.countUndelivered(),
      peers: peersList.length,
      relayed: countRelayed(root),
    };
    if (!detail) return base;
    // M11 + S7/S8：真实状态（error 计数 / lastError / 积压数 / 安全拒绝计数）。
    return {
      ...base,
      errors: errorCount,
      lastError,
      inboxBacklog: base.envelopesIn,
      outboxBacklog: base.envelopesOut,
      writable: ok,
      authRejected,
      rateRejected,
      quotaRejected,
    };
  }

  // 异步尽力转发到全部 peers：转发失败只记 relay-log 一行，不影响入站成功。
  function forwardToPeers(envelope) {
    for (const peerUrl of peersList) {
      forwardToPeer(peerUrl, envelope).then((res) => {
        if (!res.ok) {
          appendRelayLog(root, {
            ts: new Date().toISOString(),
            envelopeId: envelope && envelope.id,
            peer: peerUrl,
            ok: false,
            error: res.error || `HTTP ${res.status}`,
          });
        }
      });
    }
  }

  function respond(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
    });
    res.end(body);
  }

  // 边读边计数请求体，超过 limit 立即终止并报告（不缓存超大请求体）。
  function readRequestBody(req, limit, onDone) {
    let size = 0;
    const chunks = [];
    let settled = false;
    const contentLength = Number.parseInt(req.headers['content-length'] || '0', 10) || 0;
    if (contentLength > limit) {
      settled = true;
      req.resume();
      onDone({ tooLarge: true });
      return;
    }
    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > limit) {
        settled = true;
        req.resume();
        onDone({ tooLarge: true });
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      onDone({ text: Buffer.concat(chunks).toString('utf8') });
    });
    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      onDone({ error: err });
    });
  }

  function handle(req, res) {
    let url;
    try {
      url = new URL(req.url, `http://${hostForUrl(host)}`);
    } catch {
      respond(res, 400, { ok: false, error: 'invalid request url' });
      return;
    }
    const route = url.pathname;
    const method = req.method;

    if (method === 'GET' && route === '/health') {
      respond(res, 200, health());
      return;
    }

    if (method === 'GET' && route === '/envelopes') {
      // S7：出站投递认证——未配置 token 时仅回环；配置后必须 Bearer token。
      if (!outboundAuthOk(req)) {
        authRejected += 1;
        emitLog('error', 'GET /envelopes status=403 unauthorized');
        respond(res, 403, { ok: false, error: 'unauthorized' });
        return;
      }
      const after = url.searchParams.get('after') || undefined;
      const envelopes = fileTransport.read({ after });
      for (const env of envelopes) fileTransport.markDelivered(env.id);
      emitLog('info', `GET /envelopes status=200 delivered=${envelopes.length}`);
      respond(res, 200, envelopes);
      return;
    }

    if (method === 'POST' && route === '/envelopes') {
      // S8：入站限速（per-IP 令牌桶）——防自签洪泛无限落盘与向 peers 放大。
      const remoteIp = String(req.socket.remoteAddress || '');
      if (!postAllow(remoteIp)) {
        rateRejected += 1;
        emitLog('error', `POST /envelopes status=429 rate-limited ip=${remoteIp}`);
        respond(res, 429, { ok: false, error: 'rate limited' });
        return;
      }
      // S8：inbox 落盘配额——文件数超限即 503（不无限增长）。
      if (countInbound() >= maxInboxFiles) {
        quotaRejected += 1;
        emitLog('error', 'POST /envelopes status=503 inbox-quota');
        respond(res, 503, { ok: false, error: 'inbox quota exceeded' });
        return;
      }
      const isRelay = req.headers['x-vap-relay'] === '1';
      readRequestBody(req, maxBodyBytes, (result) => {
        if (result.tooLarge) {
          emitLog('error', 'POST /envelopes status=413 too-large');
          respond(res, 413, { ok: false, error: 'request body exceeds limit' });
          return;
        }
        if (result.error) {
          emitLog('error', `POST /envelopes status=400 body-read-failed ${String(result.error)}`);
          respond(res, 400, { ok: false, error: 'request body read failed' });
          return;
        }
        let envelope;
        try {
          envelope = JSON.parse(result.text);
        } catch {
          emitLog('error', 'POST /envelopes status=400 invalid-json');
          respond(res, 400, { ok: false, error: 'invalid JSON body' });
          return;
        }
        if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) || !envelope.id) {
          emitLog('error', 'POST /envelopes status=400 missing-envelope-id');
          respond(res, 400, { ok: false, error: 'envelope.id is required' });
          return;
        }
        // 防重放：入站信封必须带 nonce，缺失 → 400；形状非法 → 400；nonce 已见 → 409。
        if (typeof envelope.nonce !== 'string' || envelope.nonce.length === 0) {
          emitLog('error', 'POST /envelopes status=400 missing-nonce');
          respond(res, 400, { ok: false, error: 'missing nonce' });
          return;
        }
        // 安全（F1）：nonce 参与 seen-nonces 文件名拼接 → 先过白名单，绝不把
        // '../../x' 之类交给文件系统（单个远程请求即可写任意路径 = DoS）。
        if (!NONCE_PATTERN.test(envelope.nonce)) {
          emitLog('error', 'POST /envelopes status=400 bad-nonce');
          respond(res, 400, { ok: false, error: 'bad nonce' });
          return;
        }
        // 安全（M1）：envelope.id 参与 inbox-http/<id>.json 文件名拼接 → 白名单。
        const idOk = strictEnvelopeId ? isStrictEnvelopeId(envelope.id) : isSafeEnvelopeId(envelope.id);
        if (!idOk) {
          emitLog('error', 'POST /envelopes status=400 bad-envelope-id');
          respond(res, 400, { ok: false, error: 'bad envelope id' });
          return;
        }
        // 对端认证最小化（M7）：验签前置。网关不跑军法/诚实边界（仍由下游裁决），
        // 只拒绝搬运「签名无效/无签名」的信封。
        if (requireInboundSignature && !verifyEnvelopeSignature(envelope)) {
          emitLog('error', `POST /envelopes status=403 bad-signature id=${envelope.id}`);
          respond(res, 403, { ok: false, error: 'signature verification failed' });
          return;
        }
        let claimed;
        try {
          claimed = claimNonce(root, envelope.nonce);
        } catch (err) {
          // 认领 nonce 时的任何异常（含文件系统异常）都不许把网关打崩。
          recordError(err);
          emitLog('error', `POST /envelopes status=400 nonce-claim-failed ${String((err && err.message) || err)}`);
          respond(res, 400, { ok: false, error: 'bad nonce' });
          return;
        }
        if (!claimed) {
          emitLog('info', `POST /envelopes status=409 replay id=${envelope.id}`);
          respond(res, 409, { ok: false, error: 'replay rejected' });
          return;
        }
        try {
          atomicWrite(path.join(inboxHttp, `${envelope.id}.json`), `${JSON.stringify(envelope, null, 2)}\n`);
        } catch (err) {
          recordError(err);
          emitLog('error', `POST /envelopes status=500 store-failed ${String((err && err.message) || err)}`);
          respond(res, 500, { ok: false, error: 'failed to store envelope' });
          return;
        }
        // 组网转发：envelopeId 去重防环（relayed 标记），异步尽力转发、失败记 relay-log。
        // 带 x-vap-relay: 1 的入站信封同样受 relayed 标记约束（一跳内不重复转发）。
        if (peersList.length > 0 && claimRelayed(root, envelope.id)) {
          forwardToPeers(envelope);
        }
        emitLog('info', `POST /envelopes status=202 id=${envelope.id} relay=${isRelay ? 1 : 0}`);
        respond(res, 202, { ok: true, envelopeId: envelope.id });
      });
      return;
    }

    respond(res, 404, { ok: false, error: 'not found' });
  }

  function start() {
    if (server) return Promise.resolve(boundPort);
    return new Promise((resolve, reject) => {
      const s = http.createServer(handle);
      s.on('error', reject);
      // F2：监听地址来自 host 参数（默认回环）；跨机部署显式传 '0.0.0.0'/网卡地址。
      s.listen(port, host, () => {
        server = s;
        boundPort = s.address().port;
        resolve(boundPort);
      });
    });
  }

  function stop() {
    if (!server) return Promise.resolve();
    const s = server;
    server = null;
    boundPort = null;
    return new Promise((resolve, reject) => {
      s.close((err) => (err ? reject(err) : resolve()));
    });
  }

  return {
    start,
    stop,
    health,
    get port() {
      return boundPort;
    },
    // F2：实际监听地址与可拨号 base URL（通配地址映射为回环，供本机客户端使用）。
    host,
    get baseUrl() {
      return boundPort == null ? null : `http://${hostForUrl(host)}:${boundPort}`;
    },
    root,
    fileTransport,
    inboxHttp,
    logger: logr,
  };
}

// ---------------------------------------------------------------------------
// createHttpClient —— 远端节点客户端（node:http）。
//   post(envelope)  POST /envelopes → { status, ok, envelopeId? , error? }
//   poll({ after }) GET  /envelopes → 信封数组（未投递）
// ---------------------------------------------------------------------------

export function createHttpClient({ baseUrl } = {}) {
  if (!baseUrl) throw new Error('createHttpClient: baseUrl is required');
  const base = baseUrl.replace(/\/+$/, '');

  function request(method, pathname, body) {
    return new Promise((resolve, reject) => {
      const url = new URL(pathname, `${base}/`);
      const headers = { accept: 'application/json' };
      let payload = null;
      if (body !== undefined && body !== null) {
        payload = JSON.stringify(body);
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(payload);
      }
      const req = http.request(url, { method, headers }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let data = null;
          try { data = text ? JSON.parse(text) : null; } catch { data = null; }
          resolve({ status: res.statusCode, data, text });
        });
      });
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  async function post(envelope) {
    const { status, data } = await request('POST', '/envelopes', envelope);
    if (status === 202) {
      return { status, ok: true, envelopeId: data && data.envelopeId };
    }
    return { status, ok: false, error: (data && data.error) || `HTTP ${status}` };
  }

  async function poll(options = {}) {
    const after = options.after ? `?after=${encodeURIComponent(options.after)}` : '';
    const { status, data } = await request('GET', `/envelopes${after}`);
    if (status === 200) return Array.isArray(data) ? data : [];
    const error = (data && data.error) || `HTTP ${status}`;
    throw new Error(`createHttpClient.poll: ${error}`);
  }

  return { baseUrl, post, poll };
}
