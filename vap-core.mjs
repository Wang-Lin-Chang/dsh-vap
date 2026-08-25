// vap-core.mjs —— VAP v0 插件核心
//
// 信任域内的可验证智能体交互协议实现。零第三方依赖，仅使用 node: 内置模块。
// 契约依据：同目录 vap-spec.md（§1-§7）与 brief.md。
//
// 说明：Ed25519 签名只证明"消息出自持有私钥的节点"，不防节点签自己的谎言；
// 谎言的裁决交给验证门（三道闸）与后续交叉复核，见 spec §0 诚实边界。

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { saveKey, loadKey } from './key-store.mjs';

// ---------------------------------------------------------------------------
// 常量与默认军法（规则是数据：升级 = 改 laws.json，不改代码）
// ---------------------------------------------------------------------------

const DEFAULT_LAWS = Object.freeze({
  rules: Object.freeze([
    Object.freeze({ id: 'SIG_REQUIRED',   check: 'sig 验签通过',                     severity: 'reject' }),
    Object.freeze({ id: 'BOUNDARY_VALID', check: 'boundary ∈ {L2a,L1,L0}',           severity: 'reject' }),
    Object.freeze({ id: 'SUMMARY_BOUND',  check: 'report.summary 字符数 ≤ 100',      severity: 'reject' }),
    Object.freeze({ id: 'EVIDENCE_L2A',   check: 'boundary=L2a ⇒ evidence.devices 非空', severity: 'reject' }),
    Object.freeze({ id: 'FROM_KNOWN',     check: 'from.nodeId 在登记册或首封自注册',   severity: 'warn' }),
  ]),
});

export const constants = Object.freeze({
  SUMMARY_BOUND: 100,
  LEASE_TIMEOUT_MS: 30000,
  LEASE_TIMEOUT_SEC: 30,
  DEFAULT_LAWS,
});

const BOUNDARIES = new Set(['L2a', 'L1', 'L0']);

// 安全白名单（修复批次 1）：
//   NONCE_PATTERN   nonce 只允许 16 位小写十六进制（node.send 的生成格式），
//                   任何含 '/'、'\'、'..' 或超长的取值都不得参与路径拼接；
//   TASK_ID_PATTERN taskId 只允许字母/数字/下划线/连字符（1-64），杜绝 inbox 锁路径穿越。
// S9（生产级加固）：nonce 放宽为 16~32 位十六进制——旧信封（16 hex）兼容，
// 新生成用 32 hex（128 位随机，生日界 2^64）。
export const NONCE_PATTERN = /^[0-9a-f]{16,32}$/;
export const TASK_ID_PATTERN = /^[0-9a-zA-Z_-]{1,64}$/;

export function isValidNonce(nonce) {
  return typeof nonce === 'string' && NONCE_PATTERN.test(nonce);
}

export function isValidTaskId(taskId) {
  return typeof taskId === 'string' && TASK_ID_PATTERN.test(taskId);
}

// ---------------------------------------------------------------------------
// canonicalJson —— 规范化 JSON：键按字典序递归排序、无空白
// ---------------------------------------------------------------------------

// S11（生产级加固，fuzz 实证升格 P0）：深度/节点预算 + 循环引用检测。
// 深层嵌套（~5000 层对象）此前触发未捕获 RangeError 栈溢出 → 进程崩溃；
// 循环引用此前无限递归。现在超限抛可控 TypeError/RangeError，由调用方 catch 后拒件。
export const MAX_CANONICAL_DEPTH = 64;      // 嵌套深度上限（正常信封 < 10 层）
export const MAX_CANONICAL_NODES = 100000;  // 总节点数预算（防超宽对象 DoS）

function sortObjectDeep(value, depth = 0, seen = null, counter = { n: 0 }) {
  counter.n += 1;
  if (counter.n > MAX_CANONICAL_NODES) {
    throw new RangeError(`canonicalJson: node budget exceeded (${MAX_CANONICAL_NODES})`);
  }
  if (Array.isArray(value)) {
    if (depth >= MAX_CANONICAL_DEPTH) {
      throw new RangeError(`canonicalJson: depth limit ${MAX_CANONICAL_DEPTH} exceeded`);
    }
    return value.map((v) => sortObjectDeep(v, depth + 1, seen, counter));
  }
  if (value && typeof value === 'object') {
    if (depth >= MAX_CANONICAL_DEPTH) {
      throw new RangeError(`canonicalJson: depth limit ${MAX_CANONICAL_DEPTH} exceeded`);
    }
    const pathSet = seen || new Set();
    if (pathSet.has(value)) {
      throw new TypeError('canonicalJson: circular reference');
    }
    pathSet.add(value);
    try {
      const out = {};
      for (const key of Object.keys(value).sort()) {
        out[key] = sortObjectDeep(value[key], depth + 1, pathSet, counter);
      }
      return out;
    } finally {
      pathSet.delete(value);
    }
  }
  return value;
}

export function canonicalJson(obj) {
  return JSON.stringify(sortObjectDeep(obj));
}

// ---------------------------------------------------------------------------
// Ed25519 信封：签名对象 = canonical JSON of
//   { v, id, ts, from.nodeId, from.pubKey, to, claim, evidence, boundary, report, nonce }
// （不含 sig 自身；from 展平为带点的键，见 spec §1 签名规范与 brief 纪律 4）
// nonce 纳入签名对象：签名绑定 nonce，防重放不能靠「签名后追加字段」蒙混。
// ---------------------------------------------------------------------------

function signPayload(envelope) {
  return {
    v: envelope.v,
    id: envelope.id,
    ts: envelope.ts,
    'from.nodeId': envelope.from ? envelope.from.nodeId : undefined,
    'from.pubKey': envelope.from ? envelope.from.pubKey : undefined,
    to: envelope.to,
    claim: envelope.claim,
    evidence: envelope.evidence,
    boundary: envelope.boundary,
    report: envelope.report,
    nonce: envelope.nonce,
  };
}

function coerceKeyObject(key, kind) {
  if (key && typeof key === 'object' && typeof key.export === 'function') {
    return key; // 已经是 KeyObject
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    const buf = Buffer.from(key);
    return kind === 'public'
      ? crypto.createPublicKey({ key: buf, format: 'der', type: 'spki' })
      : crypto.createPrivateKey({ key: buf, format: 'der', type: 'pkcs8' });
  }
  if (typeof key === 'string') {
    const text = key.trim();
    if (text.startsWith('-----BEGIN')) {
      return kind === 'public' ? crypto.createPublicKey(text) : crypto.createPrivateKey(text);
    }
    const buf = Buffer.from(text, 'base64');
    return kind === 'public'
      ? crypto.createPublicKey({ key: buf, format: 'der', type: 'spki' })
      : crypto.createPrivateKey({ key: buf, format: 'der', type: 'pkcs8' });
  }
  throw new Error(`cannot coerce ${kind} key`);
}

function publicKeyToBase64(publicKey) {
  return coerceKeyObject(publicKey, 'public')
    .export({ type: 'spki', format: 'der' })
    .toString('base64');
}

function signPayloadBytes(payload, privateKey) {
  return crypto.sign(null, Buffer.from(canonicalJson(payload), 'utf8'), privateKey);
}

// 导出（M7）：HTTP 网关做「验签前置」时复用同一份验签逻辑（网关只验身份闸的签名，
// 不跑军法/诚实边界 —— 保持「网关只搬运不裁决军法」语义）。
export function verifyEnvelopeSignature(envelope) {
  try {
    const pubKey = envelope.from && envelope.from.pubKey;
    if (!pubKey) return false;
    const sig = envelope.sig;
    if (!sig) return false;
    const payload = signPayload(envelope);
    const data = Buffer.from(canonicalJson(payload), 'utf8');
    const key = coerceKeyObject(pubKey, 'public');
    return crypto.verify(null, data, key, Buffer.from(sig, 'base64'));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 文件系统辅助：原子写（tmp + rename）、O_EXCL 租约、目录、JSON 读取
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
    //
    // M21 诚实边界：这条回退分支是「先删目标再 rename」，在 Windows 上并非原子——
    // unlink 与 rename 之间存在窗口，并发读者可能短暂看到目标文件缺失；且该分支
    // 没有写侧互斥（多进程同写同一路径仍可能交错）。v0 信任域内单写者场景够用，
    // 多写者并发语义是已知缺口（见 spec §6 / writeRegistryEntry 的 TODO(M4-并发)）。
    if (err && (err.code === 'EEXIST' || err.code === 'EPERM' || err.code === 'ENOTEMPTY')) {
      try { fs.unlinkSync(filePath); } catch { /* 目标本就不存在 */ }
      fs.renameSync(tmp, filePath);
    } else {
      try { fs.unlinkSync(tmp); } catch { /* 尽力清理 */ }
      throw err;
    }
  }
}

function readJsonIfExists(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function listFiles(dir) {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // M22 跨平台语义：process.kill(pid, 0) 发「空信号」探测进程存在性——
    //   ESRCH = 无此进程（已死）；EPERM = 存在但无权限（活）。
    // 已知局限（诚实标注）：① Windows 上 kill(pid,0) 语义弱化，可能对已死进程
    //   也抛 EPERM/ESRCH 之外的结果；② PID 复用——旧进程死后其 PID 被新进程
    //   复用，本函数会误判为「仍存活」。收养判定因此叠加 startSec/mtime 双证据
    //   一起看（三证据齐备才收养），不单信 PID 探测。见 adoptIn 的 evidence。
    return err && err.code === 'EPERM';
  }
}

function charCount(str) {
  return typeof str === 'string' ? Array.from(str).length : 0;
}

// ---------------------------------------------------------------------------
// seen-nonces —— 防重放 nonce 查重（一次性认领：O_EXCL 创建空标记文件，存在即重放）
// 说明：nonce 查重是「create-if-absent」语义，与租约同为一次性认领；用 O_EXCL
// 原子创建（而非 tmp+rename 覆盖写）保证「存在即重放」无竞态、可持久化。
// ---------------------------------------------------------------------------

export function nonceSeen(root, nonce) {
  if (!isValidNonce(nonce)) return false; // 非法 nonce 一律不碰文件系统
  return fs.existsSync(path.join(root, 'seen-nonces', nonce));
}

// 原子认领 nonce：首次调用返回 true（落一个空标记文件 root/seen-nonces/<nonce>），
// 已见过（标记文件已存在）返回 false（重放）。持久化在文件系统，跨进程可见。
// 安全（F1）：nonce 必须匹配 NONCE_PATTERN，否则直接 return false —— 不做任何路径
// 拼接、不建目录、不开文件。否则 nonce='../../x' 之类可让单个远程请求写任意路径（DoS）。
export function claimNonce(root, nonce) {
  if (!isValidNonce(nonce)) return false;
  const dir = path.join(root, 'seen-nonces');
  ensureDir(dir);
  let fd;
  try {
    fd = fs.openSync(path.join(dir, nonce), 'wx'); // O_EXCL：仅当不存在时创建
  } catch (err) {
    if (err && err.code === 'EEXIST') return false;
    throw err;
  }
  fs.closeSync(fd);
  pruneSeenNonces(dir); // S9：低频过期清理（防目录无限增长）
  return true;
}

// S9（生产级加固）：seen-nonces 过期清理。每 N 次认领扫描一次，删除
// 超过 SEEN_NONCE_TTL_MS（默认 30 天）未触达的标记文件——防重放窗口即 TTL。
const SEEN_NONCE_TTL_MS = 30 * 24 * 3600 * 1000;
let nonceClaimCounter = 0;
function pruneSeenNonces(dir) {
  nonceClaimCounter += 1;
  if (nonceClaimCounter % 100 !== 0) return;
  const cutoff = Date.now() - SEEN_NONCE_TTL_MS;
  try {
    for (const name of fs.readdirSync(dir)) {
      const p = path.join(dir, name);
      try {
        if (fs.statSync(p).mtimeMs < cutoff) fs.unlinkSync(p);
      } catch { /* 单文件异常不影响清理 */ }
    }
  } catch { /* 目录不可读时跳过本轮 */ }
}

// ---------------------------------------------------------------------------
// 军法规则判定器（按 rule.id 分发；severity 由规则数据决定，见 §3）
// ---------------------------------------------------------------------------

const LAW_CHECKERS = {
  SIG_REQUIRED(envelope, ctx) {
    if (ctx.sigValid) return { ok: true, note: 'signature verified' };
    return { ok: false, note: 'signature verification failed' };
  },
  BOUNDARY_VALID(envelope) {
    const b = envelope.boundary;
    if (BOUNDARIES.has(b)) return { ok: true, note: `boundary ${b} valid` };
    return { ok: false, note: `invalid boundary '${b}'` };
  },
  SUMMARY_BOUND(envelope, ctx) {
    const len = charCount(envelope.report && envelope.report.summary);
    const limit = typeof ctx.summaryBound === 'number' ? ctx.summaryBound : constants.SUMMARY_BOUND;
    if (len <= limit) return { ok: true, note: `summary length ${len} ≤ ${limit}` };
    return { ok: false, note: `summary length ${len} exceeds ${limit}` };
  },
  EVIDENCE_L2A(envelope) {
    if (envelope.boundary !== 'L2a') return { ok: true, note: 'boundary not L2a' };
    const devices = envelope.evidence && envelope.evidence.devices;
    if (Array.isArray(devices) && devices.length > 0) {
      return { ok: true, note: `evidence.devices count ${devices.length}` };
    }
    return { ok: false, note: 'L2a requires non-empty evidence.devices (suggest L0)' };
  },
  FROM_KNOWN(envelope, ctx) {
    const nodeId = envelope.from && envelope.from.nodeId;
    if (ctx.registry.has(nodeId)) return { ok: true, note: 'node known' };
    return { ok: false, note: `unknown node '${nodeId}' (self-register on first envelope)` };
  },
};

// ---------------------------------------------------------------------------
// makeLaws —— 默认军法 + overrides 合并（规则是数据，可升级）
// ---------------------------------------------------------------------------

export function makeLaws(overrides) {
  const laws = { rules: DEFAULT_LAWS.rules.map((rule) => ({ ...rule })) };
  const extraRules = overrides && overrides.rules;
  if (Array.isArray(extraRules)) {
    for (const override of extraRules) {
      const idx = laws.rules.findIndex((rule) => rule.id === override.id);
      if (idx >= 0) {
        laws.rules[idx] = { ...laws.rules[idx], ...override };
      } else {
        laws.rules.push({ ...override });
      }
    }
  }
  return laws;
}

// ---------------------------------------------------------------------------
// 验证上下文与三道闸
// ---------------------------------------------------------------------------

function buildCtx(root) {
  const registry = new Set();
  const reg = readJsonIfExists(path.join(root, 'registry.json'));
  if (reg && typeof reg === 'object' && !Array.isArray(reg)) {
    for (const nodeId of Object.keys(reg)) registry.add(nodeId);
  }
  let laws = readJsonIfExists(path.join(root, 'laws.json'));
  if (!laws || !Array.isArray(laws.rules)) {
    laws = makeLaws();
  }
  return { registry, laws, summaryBound: constants.SUMMARY_BOUND };
}

function runGates(envelope, ctx) {
  const sigValid = verifyEnvelopeSignature(envelope);

  // ① 身份闸：Ed25519 验签
  const identity = {
    pass: sigValid,
    reason: sigValid ? null : 'signature verification failed',
  };

  // SIG_REQUIRED 军法规则复用身份闸的验签结果（避免重复验签，且保证一致）。
  const effectiveCtx = { ...ctx, sigValid };

  // ② 军法闸：规则是数据，逐条判定
  const ruleResults = effectiveCtx.laws.rules.map((rule) => {
    const checker = LAW_CHECKERS[rule.id];
    if (!checker) {
      return { id: rule.id, ok: true, severity: 'warn', note: `no checker for rule '${rule.id}'` };
    }
    const result = checker(envelope, effectiveCtx);
    return {
      id: rule.id,
      ok: result.ok,
      severity: rule.severity || 'warn',
      note: result.note || rule.check,
    };
  });
  const lawRejects = ruleResults.filter((r) => !r.ok && r.severity === 'reject');
  const laws = {
    pass: lawRejects.length === 0,
    rules: ruleResults,
    reasons: ruleResults.filter((r) => !r.ok).map((r) => `${r.id}: ${r.note}`),
  };

  // ③ 诚实边界闸：boundary=L2a 的 claim 必须带 evidence.devices 非空
  let boundary;
  if (envelope.boundary !== 'L2a') {
    boundary = { pass: true, reason: null, suggest: null };
  } else {
    const devices = envelope.evidence && envelope.evidence.devices;
    const ok = Array.isArray(devices) && devices.length > 0;
    boundary = {
      pass: ok,
      reason: ok ? null : 'boundary L2a requires non-empty evidence.devices',
      suggest: ok ? null : 'L0',
    };
  }

  const pass = identity.pass && laws.pass && boundary.pass;
  return { pass, gates: { identity, laws, boundary } };
}

function collectReasons(result) {
  const reasons = [];
  if (!result.gates.identity.pass) reasons.push(`identity: ${result.gates.identity.reason}`);
  for (const rule of result.gates.laws.rules) {
    if (!rule.ok) reasons.push(`law:${rule.id}: ${rule.note}`);
  }
  if (!result.gates.boundary.pass) reasons.push(`boundary: ${result.gates.boundary.reason}`);
  return reasons;
}

// ---------------------------------------------------------------------------
// 登记册：把 { nodeId, pubKey } 写入 registry.json（nodeId → pubKey 映射）
// ---------------------------------------------------------------------------

function readRegistryMap(root) {
  const reg = readJsonIfExists(path.join(root, 'registry.json'));
  if (reg && typeof reg === 'object' && !Array.isArray(reg)) return reg;
  return {};
}

function writeRegistryEntry(root, nodeId, pubKey) {
  // 并发（M4）：先读 → 合并 → 单次 atomicWrite（tmp+rename）。同进程内串行安全。
  // TODO(M4-并发)：多进程同时登记仍可能后写覆盖先写（读-改-写非原子）；
  // 批次 2 的写侧互斥（O_EXCL 锁文件或单写者进程）落地后本注释一并移除。
  const reg = readRegistryMap(root);
  reg[nodeId] = pubKey;
  atomicWrite(path.join(root, 'registry.json'), `${JSON.stringify(reg, null, 2)}\n`);
}

// ---------------------------------------------------------------------------
// 租约（O_EXCL）与收养（三证据）
// ---------------------------------------------------------------------------

function lockPathFor(root, taskId) {
  // 安全（M5）：taskId 参与文件名拼接，必须先过白名单，否则 '../x' 可越出 inbox。
  if (!isValidTaskId(taskId)) throw new Error(`invalid taskId '${taskId}' (expected ${TASK_ID_PATTERN})`);
  return path.join(root, 'inbox', `task-${taskId}.lock`);
}

function acquireLease(root, taskId, nodeId) {
  const lockPath = lockPathFor(root, taskId);
  ensureDir(path.dirname(lockPath));
  let fd;
  try {
    fd = fs.openSync(lockPath, 'wx'); // O_EXCL：仅当锁不存在时创建
  } catch (err) {
    if (err && err.code === 'EEXIST') return null;
    throw err;
  }
  const startSec = Math.floor(Date.now() / 1000);
  fs.writeSync(fd, `${nodeId}:${process.pid}:${startSec}`, null, 'utf8');
  fs.closeSync(fd);
  return { lockPath, startSec };
}

function adoptIn(root, nowFn) {
  const deadLetter = path.join(root, 'dead-letter');
  const inbox = path.join(root, 'inbox');
  const lockFiles = listFiles(deadLetter)
    .filter((name) => /^task-.*\.lock$/.test(name))
    .sort();
  const adopted = [];
  for (const lockFile of lockFiles) {
    const taskId = lockFile.replace(/^task-/, '').replace(/\.lock$/, '');
    if (!isValidTaskId(taskId)) continue; // 安全（M5）：畸形 taskId 不参与重派路径拼接
    const lockPath = path.join(deadLetter, lockFile);
    const content = fs.readFileSync(lockPath, 'utf8').trim();
    const match = /^([^:]+):(\d+):(\d+)$/.exec(content);
    if (!match) continue; // 畸形租约，跳过
    const nodeId = match[1];
    const pid = Number.parseInt(match[2], 10);
    const startSec = Number.parseInt(match[3], 10);

    const nowMs = nowFn().getTime();
    const nowSec = Math.floor(nowMs / 1000);
    let mtimeMs = nowMs;
    try {
      mtimeMs = fs.statSync(lockPath).mtimeMs;
    } catch { /* 现场已被清理 */ }

    const pidDead = !isPidAlive(pid);
    const startSecExpired = nowSec - startSec > constants.LEASE_TIMEOUT_SEC;
    const mtimeExpired = nowMs - mtimeMs > constants.LEASE_TIMEOUT_MS;
    const evidence = { pidDead, startSecExpired, mtimeExpired };

    // 三证据齐备才收养：pid 死 + startSec 比对（内容超时）+ 租约超时（mtime）
    if (!(pidDead && startSecExpired && mtimeExpired)) continue;

    const taskFile = path.join(deadLetter, `task-${taskId}.json`);
    let task = null;
    try {
      task = JSON.parse(fs.readFileSync(taskFile, 'utf8'));
    } catch { /* 任务文件缺失则重派空任务 */ }

    atomicWrite(path.join(inbox, `task-${taskId}.json`), `${JSON.stringify(task == null ? {} : task, null, 2)}\n`);
    try { fs.unlinkSync(lockPath); } catch { /* 清理尽力 */ }
    try { fs.unlinkSync(taskFile); } catch { /* 清理尽力 */ }

    adopted.push({ taskId, nodeId, pid, startSec, evidence, task });
  }
  return adopted;
}

// ---------------------------------------------------------------------------
// createVapNode —— 节点
// ---------------------------------------------------------------------------

export function createVapNode({ nodeId, root, keyPair, now, persistKeys = false } = {}) {
  if (!nodeId) throw new Error('createVapNode: nodeId is required');
  if (!root) throw new Error('createVapNode: root is required');
  const nowFn = typeof now === 'function' ? now : () => new Date();

  let publicKey;
  let privateKey;
  let persisted = false;
  if (keyPair && keyPair.publicKey && keyPair.privateKey) {
    publicKey = coerceKeyObject(keyPair.publicKey, 'public');
    privateKey = coerceKeyObject(keyPair.privateKey, 'private');
  } else if (persistKeys) {
    // F3：无注入 keyPair 且开启 persistKeys → 先 loadKey；加载成功用持久身份，
    // 否则生成新钥并落盘。
    const loaded = loadKey(root, nodeId);
    if (loaded) {
      privateKey = loaded;
      publicKey = crypto.createPublicKey(loaded);
    } else {
      const generated = crypto.generateKeyPairSync('ed25519');
      publicKey = generated.publicKey;
      privateKey = generated.privateKey;
      saveKey(root, nodeId, privateKey);
    }
    persisted = true;
  } else {
    const generated = crypto.generateKeyPairSync('ed25519');
    publicKey = generated.publicKey;
    privateKey = generated.privateKey;
  }
  if (persistKeys) {
    // 注入 keyPair 的路径也要落盘（用户显式给了钥也保证持久化，重启仍是同一身份）。
    saveKey(root, nodeId, privateKey);
  }
  const pubKey = publicKeyToBase64(publicKey);

  const node = {
    nodeId,
    root,
    publicKey,
    privateKey,
    pubKey,
  };

  node.register = function register() {
    writeRegistryEntry(node.root, node.nodeId, node.pubKey);
    return { nodeId: node.nodeId, pubKey: node.pubKey };
  };

  node.send = function send({ to, claim, evidence, boundary, report } = {}) {
    const envelope = {
      v: 1,
      id: `evt-${crypto.randomBytes(8).toString('hex')}`,
      nonce: crypto.randomBytes(16).toString('hex'), // S9：128 位随机 nonce（32 hex）
      ts: nowFn().toISOString(),
      from: { nodeId: node.nodeId, pubKey: node.pubKey },
      to: to || 'brain',
      sig: '',
      claim: claim || { type: 'report', body: {} },
      evidence: evidence || { devices: [], bills: {}, digest: '' },
      boundary: boundary || 'L2a',
      report: report || { summary: '', keyNumbers: [], request: '' },
    };
    envelope.sig = signPayloadBytes(signPayload(envelope), privateKey).toString('base64');
    atomicWrite(path.join(node.root, 'outbox', `${envelope.id}.json`), `${JSON.stringify(envelope, null, 2)}\n`);
    return envelope;
  };

  // M18 五函数契约：report 是 send 的命名别名——把已构造的信封写 outbox，
  // 落盘步骤与 send 完全一致（同一原子写、同一 evt-<id>.json 命名）。
  node.report = function report(envelope) {
    if (!envelope || typeof envelope !== 'object' || !envelope.id) {
      throw new Error('report: envelope.id is required');
    }
    atomicWrite(path.join(node.root, 'outbox', `${envelope.id}.json`), `${JSON.stringify(envelope, null, 2)}\n`);
    return envelope;
  };

  // M18 五函数契约：doWork 桩实现——创建 root/agents/<nodeId>/ 目录并记录一条
  // JSONL work 条目（工作产物存本节点、不上报，spec §2）。真实执行器是下一阶段题。
  node.doWork = function doWork(task, workDir) {
    const agentDir = workDir || path.join(node.root, 'agents', node.nodeId);
    ensureDir(agentDir);
    const entry = {
      nodeId: node.nodeId,
      ts: nowFn().toISOString(),
      task: task == null ? null : task,
    };
    fs.appendFileSync(path.join(agentDir, 'work.jsonl'), `${JSON.stringify(entry)}\n`, 'utf8');
    return entry;
  };

  // M18 五函数契约：respondExpand 桩实现——从 root/expand-resps/ 读字段响应，无则
  // 返回 null。TODO(瞬态区语义)：expand-resps 是瞬态交换区、不入快照；写入端尚未
  // 实现，本桩只占「读侧」契约位（spec §2 标注为桩）。
  node.respondExpand = function respondExpand(taskId, field) {
    if (typeof taskId !== 'string' || taskId.length === 0) return null;
    const data = readJsonIfExists(path.join(node.root, 'expand-resps', `${taskId}.json`));
    if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
    if (field == null) return data;
    return data[field] !== undefined ? data[field] : null;
  };

  node.verify = function verify(envelope) {
    const ctx = buildCtx(node.root);
    const result = runGates(envelope, ctx);
    return { pass: result.pass, gates: result.gates };
  };

  node.claimTask = function claimTask() {
    const inbox = path.join(node.root, 'inbox');
    const taskFiles = listFiles(inbox)
      .filter((name) => /^task-.*\.json$/.test(name))
      .sort();
    for (const file of taskFiles) {
      const taskId = file.replace(/^task-/, '').replace(/\.json$/, '');
      if (!isValidTaskId(taskId)) continue; // 安全（M5）：畸形 taskId 不认领
      const lease = acquireLease(node.root, taskId, node.nodeId);
      if (!lease) continue; // 已被他人持有
      let task;
      try {
        task = JSON.parse(fs.readFileSync(path.join(inbox, file), 'utf8'));
      } catch {
        task = {};
      }
      return { ...task, taskId, startSec: lease.startSec };
    }
    return null;
  };

  node.heartbeat = function heartbeat(task) {
    if (!task || !task.taskId) throw new Error('heartbeat: task.taskId is required');
    if (!isValidTaskId(task.taskId)) throw new Error(`heartbeat: invalid taskId '${task.taskId}'`);
    const lockPath = lockPathFor(node.root, task.taskId);
    const startSec = Math.floor(nowFn().getTime() / 1000);
    const content = `${node.nodeId}:${process.pid}:${startSec}`;
    fs.writeFileSync(lockPath, content, 'utf8');
    const when = nowFn();
    fs.utimesSync(lockPath, when, when);
    return { taskId: task.taskId, nodeId: node.nodeId, pid: process.pid, startSec };
  };

  node.complete = function complete(task, result) {
    if (!task || !task.taskId) throw new Error('complete: task.taskId is required');
    if (!isValidTaskId(task.taskId)) throw new Error(`complete: invalid taskId '${task.taskId}'`);
    const storedTask = { ...task };
    delete storedTask.taskId;
    delete storedTask.startSec;
    const record = {
      taskId: task.taskId,
      nodeId: node.nodeId,
      ts: nowFn().toISOString(),
      exit: 'EXIT',
      task: storedTask,
      result,
    };
    atomicWrite(path.join(node.root, 'done', `${task.taskId}.json`), `${JSON.stringify(record, null, 2)}\n`);
    try { fs.unlinkSync(lockPathFor(node.root, task.taskId)); } catch { /* 锁可能已不在 */ }
    try { fs.unlinkSync(path.join(node.root, 'inbox', `task-${task.taskId}.json`)); } catch { /* 尽力清理 */ }
    return record;
  };

  node.adopt = function adopt() {
    return adoptIn(node.root, nowFn);
  };

  return node;
}

// ---------------------------------------------------------------------------
// createBrain —— 脑进程
// ---------------------------------------------------------------------------

export function createBrain({ root, now } = {}) {
  if (!root) throw new Error('createBrain: root is required');
  const nowFn = typeof now === 'function' ? now : () => new Date();

  const brain = { root };

  brain.consume = function consume() {
    const outbox = path.join(brain.root, 'outbox');
    const envelopeFiles = listFiles(outbox)
      .filter((name) => /^evt-.*\.json$/.test(name))
      .sort();
    const verdicts = [];
    for (const file of envelopeFiles) {
      const envelopePath = path.join(outbox, file);
      let envelope;
      try {
        envelope = JSON.parse(fs.readFileSync(envelopePath, 'utf8'));
      } catch {
        continue; // 读不出来的信封不裁决
      }
      const envelopeId = envelope.id || file.replace(/\.json$/, '');
      const verdictPath = path.join(outbox, `${envelopeId}.verdict`);
      if (fs.existsSync(verdictPath)) continue; // 已裁决过，幂等跳过

      // 防重放（传输/裁决层内建）：信封带 nonce 则查重（seen-nonces），
      // 重复 → verdict pass=false + reason 'replay rejected' 且不入账；
      // 无 nonce 按 v0 行为放行（向后兼容旧信封，验证门三道闸与 laws.json 不变）。
      let replayRejected = false;
      if (typeof envelope.nonce === 'string' && envelope.nonce.length > 0) {
        if (!claimNonce(brain.root, envelope.nonce)) {
          replayRejected = true;
        }
      }

      const ctx = buildCtx(brain.root);
      let result;
      if (replayRejected) {
        result = {
          pass: false,
          gates: {
            identity: { pass: true, reason: null },
            laws: { pass: true, rules: [], reasons: [] },
            boundary: { pass: true, reason: null, suggest: null },
          },
        };
      } else {
        result = runGates(envelope, ctx);
        // 首封自注册（M4）：**仅裁决通过（pass）才登记**。
        // 修复前：任何信封（含验签失败/军法拒绝的伪造件）都会被写进 registry.json，
        // 攻击者可用一封必被拒的信封污染登记册（FROM_KNOWN 从此对其恒真）。
        const from = envelope.from;
        if (result.pass && from && from.nodeId && from.pubKey) {
          writeRegistryEntry(brain.root, from.nodeId, from.pubKey);
        }
      }

      const verdict = {
        envelopeId,
        ts: nowFn().toISOString(),
        pass: result.pass,
        gates: result.gates,
        reasons: replayRejected ? ['replay rejected'] : collectReasons(result),
      };
      atomicWrite(verdictPath, `${JSON.stringify(verdict, null, 2)}\n`);
      if (result.pass) {
        atomicWrite(path.join(brain.root, 'done', `${envelopeId}.json`), `${JSON.stringify(envelope, null, 2)}\n`);
      }
      verdicts.push(verdict);
    }
    return verdicts;
  };

  brain.adopt = function adopt() {
    return adoptIn(brain.root, nowFn);
  };

  return brain;
}
