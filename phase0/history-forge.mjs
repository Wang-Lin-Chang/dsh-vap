// history-forge.mjs —— VAP Phase 0 行为历史稀缺性装置
//
// 只验证一个假设：伪造 1000 个裸公钥零成本；伪造 1 个"有可验证历史"的公钥不可行
// （除非真干活）——历史成本杠杆存在。
//
// 零第三方依赖：仅 node:crypto（sha256、Ed25519）。设计依据：phase0/DESIGN.md。
//
// 凭证三要素：
//   work:    { seed, difficulty }       可验证任务（sha256 链，difficulty 次迭代）
//   solution: hex                         唯一正确解（单向，无法跳过计算）
//   auditors: [ { id, sig } × n ]         多路独立审计签名（各持独立密钥，互不认识）
//
// 签名绑定 work+solution：签名对象 = canonicalJson({ work:{seed,difficulty}, solution })，
// 因此篡改 seed / difficulty / solution 任一字段都会使验签失败。

import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// 基础原语：sha256 hex / canonicalJson（键按字典序递归排序、无空白）
// ---------------------------------------------------------------------------

function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function sortObjectDeep(value) {
  if (Array.isArray(value)) {
    return value.map(sortObjectDeep);
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = sortObjectDeep(value[key]);
    }
    return out;
  }
  return value;
}

export function canonicalJson(obj) {
  return JSON.stringify(sortObjectDeep(obj));
}

// ---------------------------------------------------------------------------
// 任务：可验证 sha256 链
//   h0 = sha256(seed)
//   h_{i+1} = sha256(h_i || ':' || i)，i = 0 .. difficulty-1
//   solution = 最终哈希（hex）
// 单向：无法跳过 difficulty 次迭代直接得到解；确定性：任何人重算得到同一解。
// ---------------------------------------------------------------------------

function normalizeTask(task) {
  if (!task || typeof task !== 'object') {
    throw new Error('normalizeTask: task must be an object');
  }
  if (typeof task.seed !== 'string' || task.seed.length === 0) {
    throw new Error('normalizeTask: seed must be a non-empty string');
  }
  const difficulty = Number(task.difficulty);
  if (!Number.isInteger(difficulty) || difficulty < 0) {
    throw new Error('normalizeTask: difficulty must be a non-negative integer');
  }
  return { seed: task.seed, difficulty };
}

export function makeTask(seed, difficulty) {
  return normalizeTask({ seed, difficulty });
}

export function solveTask(task) {
  const { seed, difficulty } = normalizeTask(task);
  let prev = sha256hex(seed);
  for (let i = 0; i < difficulty; i++) {
    prev = sha256hex(`${prev}:${i}`);
  }
  return prev;
}

// 重放验证：O(difficulty) 重算并与给定 solution 比对。
export function verifySolution(task, solution) {
  try {
    if (typeof solution !== 'string' || !/^[0-9a-f]{64}$/.test(solution)) return false;
    return solveTask(task) === solution;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 审计者：n 个独立 Ed25519 密钥对（互不共享）
// ---------------------------------------------------------------------------

function publicKeyToBase64(publicKey) {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}

export function createAuditors(n) {
  const count = Number(n);
  if (!Number.isInteger(count) || count < 1) {
    throw new Error('createAuditors: n must be a positive integer');
  }
  const auditors = [];
  for (let i = 0; i < count; i++) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    auditors.push({
      id: `aud-${crypto.randomBytes(8).toString('hex')}`,
      publicKey: publicKeyToBase64(publicKey),
      privateKey,
    });
  }
  return auditors;
}

// 从审计者数组导出 { id -> 公钥(base64) }，供 verifyCredential 使用。
export function auditorPublicKeys(auditors) {
  if (!Array.isArray(auditors)) throw new Error('auditorPublicKeys: auditors must be an array');
  const map = {};
  for (const aud of auditors) map[aud.id] = aud.publicKey;
  return map;
}

// ---------------------------------------------------------------------------
// 凭证铸造：每个审计者独立重算 solution，通过后才对 work+solution 签名
// ---------------------------------------------------------------------------

// 签名对象 = canonical JSON of { work:{seed,difficulty}, solution }（绑定 work+solution）。
function credentialMessage(work, solution) {
  return canonicalJson({ work: { seed: work.seed, difficulty: work.difficulty }, solution });
}

function signMessage(message, privateKey) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('base64');
}

export function forgeCredential({ task, solution, auditors } = {}) {
  const work = normalizeTask(task);
  if (typeof solution !== 'string' || !/^[0-9a-f]{64}$/.test(solution)) {
    throw new Error('forgeCredential: solution must be a 64-char hex string');
  }
  if (!Array.isArray(auditors) || auditors.length === 0) {
    throw new Error('forgeCredential: auditors must be a non-empty array');
  }
  const message = credentialMessage(work, solution);
  const signed = [];
  for (const aud of auditors) {
    if (!aud || typeof aud.id !== 'string' || !aud.privateKey) {
      throw new Error('forgeCredential: malformed auditor (missing id or privateKey)');
    }
    // 每个审计者独立重算验证，通过才签（不信自报的 solution）。
    const recomputed = solveTask(work);
    if (recomputed !== solution) {
      throw new Error(
        `forgeCredential: auditor '${aud.id}' recomputed a different solution and refuses to sign`,
      );
    }
    signed.push({ id: aud.id, sig: signMessage(message, aud.privateKey) });
  }
  return {
    work,
    solution,
    auditors: signed,
    ts: new Date().toISOString(),
    forgedBy: null,
  };
}

// ---------------------------------------------------------------------------
// 凭证验证：① 重算 solution ② 逐路验签 ③ 审计者互异，全部通过才 true
// ---------------------------------------------------------------------------

function coercePublicKey(key) {
  if (key && typeof key === 'object' && typeof key.export === 'function') {
    return key; // 已是 KeyObject
  }
  if (typeof key === 'string') {
    return crypto.createPublicKey({ key: Buffer.from(key.trim(), 'base64'), format: 'der', type: 'spki' });
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return crypto.createPublicKey({ key: Buffer.from(key), format: 'der', type: 'spki' });
  }
  throw new Error('coercePublicKey: unsupported key value');
}

// 接受 Map | 普通对象 {id->key} | 审计者数组 [{id, publicKey}]。
function normalizeAuditorKeys(auditorKeys) {
  const map = new Map();
  if (auditorKeys instanceof Map) {
    for (const [id, key] of auditorKeys) map.set(id, coercePublicKey(key));
    return map;
  }
  if (Array.isArray(auditorKeys)) {
    for (const aud of auditorKeys) {
      if (aud && aud.id && (aud.publicKey || aud.pubKey)) {
        map.set(aud.id, coercePublicKey(aud.publicKey || aud.pubKey));
      }
    }
    return map;
  }
  if (auditorKeys && typeof auditorKeys === 'object') {
    for (const [id, key] of Object.entries(auditorKeys)) map.set(id, coercePublicKey(key));
  }
  return map;
}

// 详细判定：返回 { pass, reasons }，便于实验记录拒绝原因。
export function verifyCredentialDetailed(cred, auditorKeys) {
  const reasons = [];
  if (!cred || !cred.work || typeof cred.work !== 'object') {
    return { pass: false, reasons: ['malformed credential (missing work)'] };
  }

  // ① 重算 solution（不信凭证自带的 solution）。
  let solutionOk = false;
  try {
    solutionOk = verifySolution(cred.work, cred.solution);
  } catch {
    solutionOk = false;
  }
  if (!solutionOk) {
    reasons.push('solution recomputation mismatch (work not actually performed)');
  }

  // ③ 审计者互异。
  const auditors = Array.isArray(cred.auditors) ? cred.auditors : [];
  const ids = auditors.map((a) => (a && typeof a.id === 'string' ? a.id : null));
  const distinct = ids.length > 0 && new Set(ids).size === ids.length && ids.every((id) => id !== null);
  if (!distinct) {
    reasons.push('auditors not distinct (duplicate or missing auditor id)');
  }

  // ② 逐路验签（绑定 work+solution）。
  const keys = normalizeAuditorKeys(auditorKeys);
  const message = solutionOk ? credentialMessage({ seed: cred.work.seed, difficulty: cred.work.difficulty }, cred.solution) : null;
  for (const a of auditors) {
    const id = a && a.id;
    const pubKey = keys.get(id);
    if (!pubKey) {
      reasons.push(`auditor '${id}' public key not found`);
      continue;
    }
    let sigOk = false;
    if (message != null && typeof a.sig === 'string') {
      try {
        sigOk = crypto.verify(null, Buffer.from(message, 'utf8'), pubKey, Buffer.from(a.sig, 'base64'));
      } catch {
        sigOk = false;
      }
    }
    if (!sigOk) {
      reasons.push(`auditor '${id}' signature invalid (not bound to work+solution)`);
    }
  }

  return { pass: reasons.length === 0, reasons };
}

export function verifyCredential(cred, auditorKeys) {
  return verifyCredentialDetailed(cred, auditorKeys).pass;
}

// ---------------------------------------------------------------------------
// 伪造变体（装置内，用于实验对照；真实攻击者不会自我标注 forgedBy）
// ---------------------------------------------------------------------------

export function forgeFake({ kind } = {}) {
  // 自包含：现场铸造一个真实凭证作为底材，再按 kind 破坏其中一环。
  const seed = `forgefake-${crypto.randomBytes(8).toString('hex')}`;
  const task = makeTask(seed, 3);
  const solution = solveTask(task);
  const auditors = createAuditors(3);
  const real = forgeCredential({ task, solution, auditors });
  const keys = auditorPublicKeys(auditors);

  let credential;
  switch (kind) {
    case 'randomSolution': {
      // 跳过工作、编造 solution：重算必不匹配（签名也因绑定 solution 而失效）。
      credential = {
        work: { ...task },
        solution: crypto.randomBytes(32).toString('hex'),
        auditors: real.auditors.map((a) => ({ ...a })),
        ts: real.ts,
        forgedBy: { kind: 'randomSolution', note: 'solution fabricated without doing work' },
      };
      break;
    }
    case 'fakeSig': {
      // solution 正确但审计签名为随机字节（无审计者私钥）：验签必失败。
      credential = {
        work: { ...task },
        solution,
        auditors: real.auditors.map((a) => ({
          id: a.id,
          sig: crypto.randomBytes(64).toString('base64'),
        })),
        ts: real.ts,
        forgedBy: { kind: 'fakeSig', note: 'signatures fabricated without auditor private keys' },
      };
      break;
    }
    case 'duplicateAuditor': {
      // solution 与签名都真实，但同一审计者被复用 3 次：互异性检查必失败。
      const first = { ...real.auditors[0] };
      credential = {
        work: { ...task },
        solution,
        auditors: [first, first, first],
        ts: real.ts,
        forgedBy: { kind: 'duplicateAuditor', note: 'single auditor reused three times' },
      };
      break;
    }
    default:
      throw new Error(
        `forgeFake: unknown kind '${kind}' (expected randomSolution | fakeSig | duplicateAuditor)`,
      );
  }
  return { credential, auditorKeys: keys };
}
