// bootstrap-forge.mjs —— VAP Phase 0.5 自举装置（审计者信任引导）
//
// 解决 Phase 0 留下的缺口：审计者从哪来？若审计者身份免费，攻击者自造审计者给自己发
// 凭证（自我背书），历史稀缺性崩塌。
//
// 假设：审计者资格链（资格 = 持有更早代际凭证）+ 审计留痕（放水可追责）使自我背书
//       不可行、放水可追责。
// 唯一不可消除的中心化假设：创世锚（诚实标注）。
//
// 复用 phase0/history-forge.mjs 原语：makeTask / solveTask / verifySolution /
// createAuditors / canonicalJson（相对路径 import，不复制代码）。
// 零第三方依赖：仅 node:crypto / node:fs / node:path。
//
// 凭证结构 = phase0 结构 + { generation, holder, prior }：
//   work:     { seed, difficulty }        可验证任务（sha256 链）
//   solution: hex                          唯一正确解
//   auditors: [ { id, sig } × n ]          审计签名（绑定 generation+holder+work+solution）
//   generation: int                        代际（0 由创世锚签，k 由持 gen-(k-1) 者签）
//   holder:    string                      持有者 id
//   prior:     [ { auditorId, credentialId, credential } ] | null  资格证明引用（含全量凭证）
//   credentialId: string                   派生字段（= 核心内容哈希），用于留痕与追责
//   ts / forgedBy                          时间戳与伪造路径留痕
//
// 签名对象 = canonicalJson({ generation, holder, work:{seed,difficulty}, solution })，
// 因此篡改 generation / holder / seed / difficulty / solution 任一字段验签必失败。

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {
  makeTask,
  solveTask,
  verifySolution,
  createAuditors,
  canonicalJson,
} from '../phase0/history-forge.mjs';
import { defaultTrailDir } from '../config.mjs';

// M13：TRAIL_DIR 默认 os.tmpdir()/vap-trails（绝不默认源码树 __dirname）。
const TRAIL_DIR = defaultTrailDir();

// ---------------------------------------------------------------------------
// 局部基础原语（history-forge.mjs 未导出的极小助手）
// ---------------------------------------------------------------------------

function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

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

function signMessage(message, privateKey) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('base64');
}

function verifySig(message, publicKey, sigB64) {
  try {
    if (typeof sigB64 !== 'string') return false;
    return crypto.verify(
      null,
      Buffer.from(message, 'utf8'),
      coercePublicKey(publicKey),
      Buffer.from(sigB64, 'base64'),
    );
  } catch {
    return false;
  }
}

// 签名对象 = 绑定 generation + holder + work + solution。
function credentialMessage({ generation, holder, work, solution }) {
  return canonicalJson({
    generation: Number(generation),
    holder,
    work: { seed: work.seed, difficulty: work.difficulty },
    solution,
  });
}

// 凭证唯一 id = 核心内容（代际+持有者+任务+解）的 sha256 前 24 位。
export function credentialIdOf(cred) {
  const core = canonicalJson({
    generation: Number(cred.generation),
    holder: cred.holder,
    work: { seed: cred.work.seed, difficulty: cred.work.difficulty },
    solution: cred.solution,
  });
  return `cred-${sha256hex(core).slice(0, 24)}`;
}

// ctx 辅助读取（Map 或普通对象均可）。
function ctxKey(ctx, id) {
  if (!ctx) return null;
  if (ctx.keys instanceof Map) return ctx.keys.get(id) || null;
  if (ctx.keys && typeof ctx.keys === 'object') return ctx.keys[id] || null;
  return null;
}

function ctxCredential(ctx, id) {
  if (!ctx) return null;
  if (ctx.credentials instanceof Map) return ctx.credentials.get(id) || null;
  if (ctx.credentials && typeof ctx.credentials === 'object') return ctx.credentials[id] || null;
  return null;
}

// ---------------------------------------------------------------------------
// 创世锚（Genesis Anchor）
// ---------------------------------------------------------------------------

// 1 个预设审计者：密钥在装置内生成（复用 createAuditors(1)），id 固定为 genesis-anchor。
// 这是自举的信任种子，是唯一中心化假设（诚实标注）。
export function createGenesisAnchor() {
  const [aud] = createAuditors(1);
  return {
    id: 'genesis-anchor',
    role: 'genesis',
    publicKey: aud.publicKey,
    privateKey: aud.privateKey,
  };
}

// 生成一个普通节点（可作为持有者，日后也能当审计者）。复用 createAuditors(1)。
export function createNode() {
  const [node] = createAuditors(1);
  return node;
}

// ---------------------------------------------------------------------------
// 资格证明解析：审计者自身的 gen-(generation-1) 凭证
// ---------------------------------------------------------------------------

function resolvePriorCredential(auditor, priorCredential) {
  if (auditor && auditor.priorCredential) return auditor.priorCredential;
  if (!priorCredential) return null;
  if (Array.isArray(priorCredential)) {
    return priorCredential.find((c) => c && c.holder === auditor.id) || null;
  }
  if (priorCredential instanceof Map) {
    return priorCredential.get(auditor.id) || null;
  }
  if (priorCredential && typeof priorCredential === 'object') {
    if (priorCredential.holder === auditor.id) return priorCredential;
    if (priorCredential[auditor.id]) return priorCredential[auditor.id];
  }
  return null;
}

function buildPrior(auditors, generation, priorCredential) {
  if (generation === 0) return null;
  const prior = [];
  for (const a of auditors) {
    const qc = resolvePriorCredential(a, priorCredential);
    if (qc) {
      prior.push({
        auditorId: a.id,
        credentialId: qc.credentialId || credentialIdOf(qc),
        credential: qc,
      });
    }
  }
  return prior;
}

// ---------------------------------------------------------------------------
// 签发凭证
// ---------------------------------------------------------------------------

// 返回 { ok, credential?, reasons }：
//   ok=true  → 资格判定通过，credential 已由各审计者签名；
//   ok=false → 拒绝（自我背书 / 资格不足 / 跨代伪造 / 验签或重放失败），reasons 给出原因。
//
// 资格判定：
//   generation=0：auditors 必须含创世锚（只有创世锚有 gen-0 签发资格）；
//   generation≥1：每个审计者必须出示自己持有的 gen-(generation-1) 凭证，验签 + 重放
//                 验证通过才算有资格（ctx 提供时做全链验证回验到创世锚）。
//   自引用禁止：审计者 id == 持有者 id → 拒绝（自我背书）。
export function issueCredential({ task, holder, auditors, generation, priorCredential, ctx } = {}) {
  const reasons = [];

  const gen = Number(generation);
  if (!Number.isInteger(gen) || gen < 0) {
    return { ok: false, reasons: ['generation must be a non-negative integer'] };
  }
  if (typeof holder !== 'string' || holder.length === 0) {
    return { ok: false, reasons: ['holder must be a non-empty string'] };
  }
  if (!Array.isArray(auditors) || auditors.length === 0) {
    return { ok: false, reasons: ['auditors must be a non-empty array'] };
  }

  let work;
  try {
    work = makeTask(task.seed, task.difficulty);
  } catch (e) {
    return { ok: false, reasons: [`malformed task: ${e && e.message ? e.message : e}`] };
  }

  // 自引用禁止：审计者 id 与持有者 id 相同 → 自我背书。
  const selfEndorsed = auditors.filter((a) => a && a.id === holder);
  if (selfEndorsed.length > 0) {
    reasons.push(`self-endorsement forbidden: auditor '${selfEndorsed[0].id}' equals holder`);
    return { ok: false, reasons };
  }

  // 签发者独立重算 solution（不信任何自报的解）。
  const solution = solveTask(work);
  const message = credentialMessage({ generation: gen, holder, work, solution });

  // 资格判定。
  if (gen === 0) {
    const genesisId = ctx && ctx.genesis && typeof ctx.genesis.id === 'string' ? ctx.genesis.id : 'genesis-anchor';
    const hasGenesis = auditors.some((a) => a && (a.role === 'genesis' || a.id === genesisId));
    if (!hasGenesis) {
      reasons.push('generation 0 requires the genesis anchor among auditors');
    }
    for (const a of auditors) {
      const isGenesis = a && (a.role === 'genesis' || a.id === genesisId);
      if (!isGenesis) {
        reasons.push(`auditor '${a && a.id}' lacks qualification for generation 0 (only the genesis anchor may issue gen-0)`);
      }
    }
  } else {
    for (const a of auditors) {
      if (!a || typeof a.id !== 'string' || !a.privateKey) {
        reasons.push('malformed auditor (missing id or privateKey)');
        continue;
      }
      const qc = resolvePriorCredential(a, priorCredential);
      if (!qc) {
        reasons.push(`auditor '${a.id}' presents no gen-${gen - 1} credential (qualification missing)`);
        continue;
      }
      if (Number(qc.generation) !== gen - 1) {
        reasons.push(`auditor '${a.id}' credential generation ${qc.generation} != required ${gen - 1} (cross-generation forgery)`);
        continue;
      }
      if (qc.holder !== a.id) {
        reasons.push(`auditor '${a.id}' presents a credential held by '${qc.holder}' (not their own)`);
        continue;
      }
      // 重放验证：凭证解必须真干过活。
      if (!verifySolution(qc.work, qc.solution)) {
        reasons.push(`auditor '${a.id}' qualification credential fails replay (solution fabricated)`);
        continue;
      }
      // 验签 + 全链验证（ctx 提供时回验到创世锚）。
      if (ctx) {
        const chainRes = verifyCredentialChain(qc, ctx);
        if (!chainRes.pass) {
          const first = chainRes.reasons[0] || 'unknown';
          reasons.push(`auditor '${a.id}' qualification chain invalid: ${first}`);
        }
      }
    }
  }

  if (reasons.length > 0) {
    return { ok: false, reasons };
  }

  // 通过资格判定 → 各审计者签名（绑定 generation+holder+work+solution）。
  const signed = auditors.map((a) => ({ id: a.id, sig: signMessage(message, a.privateKey) }));

  const credential = {
    work,
    solution,
    auditors: signed,
    generation: gen,
    holder,
    prior: buildPrior(auditors, gen, priorCredential),
    ts: new Date().toISOString(),
    forgedBy: null,
  };
  credential.credentialId = credentialIdOf(credential);
  return { ok: true, credential };
}

// ---------------------------------------------------------------------------
// 代际链验证：沿资格链逐代回验到创世锚
// ---------------------------------------------------------------------------

// verifyCredentialChain(cred, ctx) → { pass, reasons, chain }
//   ctx = { genesis: { id, publicKey }, keys: Map<id, publicKey>, credentials: Map<id, credential> }
//   - 重算 solution（不信自报）；
//   - 审计者互异；自引用禁止（审计者 == 持有者 → 拒）；
//   - generation=0：审计者必须是创世锚，逐路验签（对创世锚公钥）；
//   - generation≥1：每个审计者资格凭证 = prior 中该审计者持有的 gen-(gen-1) 凭证，
//     递归验证其自身链，再用 ctx.keys 中的公钥验签本凭证；
//   - chain 为 DFS 前序，末端即创世锚根。
export function verifyCredentialChain(cred, ctx) {
  const reasons = [];
  const chain = [];

  function walk(c, depth) {
    if (!c || typeof c !== 'object' || !c.work) {
      reasons.push('malformed credential (missing work)');
      return false;
    }

    const gen = Number(c.generation);
    const credId = c.credentialId || credentialIdOf(c);
    const node = { credentialId: credId, generation: gen, holder: c.holder, depth, auditorIds: [] };
    chain.push(node); // DFS 前序，根凭证在前、创世锚在后

    // ① 重算 solution。
    let solutionOk = false;
    try {
      solutionOk = verifySolution(c.work, c.solution);
    } catch {
      solutionOk = false;
    }
    if (!solutionOk) {
      reasons.push(`[${credId}] solution recomputation mismatch (work not actually performed)`);
      return false;
    }

    // ② 审计者互异。
    const auditors = Array.isArray(c.auditors) ? c.auditors : [];
    const ids = auditors.map((a) => (a && typeof a.id === 'string' ? a.id : null));
    const distinct = ids.length > 0 && new Set(ids).size === ids.length && ids.every((x) => x !== null);
    if (!distinct) {
      reasons.push(`[${credId}] auditors not distinct (duplicate or missing auditor id)`);
      return false;
    }
    node.auditorIds = ids;

    // ③ 自引用禁止。
    for (const id of ids) {
      if (id === c.holder) {
        reasons.push(`[${credId}] self-endorsement: auditor '${id}' equals holder`);
        return false;
      }
    }

    const message = credentialMessage({ generation: gen, holder: c.holder, work: c.work, solution: c.solution });

    // ④ 代际资格判定 + 验签。
    if (gen === 0) {
      if (!ctx || !ctx.genesis || typeof ctx.genesis.id !== 'string') {
        reasons.push(`[${credId}] generation 0 requires ctx.genesis`);
        return false;
      }
      const genesisId = ctx.genesis.id;
      for (const a of auditors) {
        if (a.id !== genesisId) {
          reasons.push(`[${credId}] gen-0 auditor '${a.id}' is not the genesis anchor`);
          return false;
        }
        if (!verifySig(message, ctx.genesis.publicKey, a.sig)) {
          reasons.push(`[${credId}] genesis signature invalid for auditor '${a.id}'`);
          return false;
        }
      }
      node.root = 'genesis-anchor';
      return true;
    }

    // gen ≥ 1：每个审计者必须出示 gen-(gen-1) 凭证。
    const prior = Array.isArray(c.prior) ? c.prior : [];
    for (const a of auditors) {
      const priorEntry = prior.find((p) => p && p.auditorId === a.id);
      const qc = priorEntry
        ? (priorEntry.credential || ctxCredential(ctx, priorEntry.credentialId))
        : null;
      if (!qc) {
        reasons.push(`[${credId}] auditor '${a.id}' has no gen-${gen - 1} qualification credential`);
        return false;
      }
      if (Number(qc.generation) !== gen - 1) {
        reasons.push(`[${credId}] auditor '${a.id}' qualification generation ${qc.generation} != ${gen - 1}`);
        return false;
      }
      if (qc.holder !== a.id) {
        reasons.push(`[${credId}] auditor '${a.id}' qualification credential held by '${qc.holder}'`);
        return false;
      }

      // 验签本凭证（审计者公钥来自 ctx.keys）。
      const pubKey = ctxKey(ctx, a.id);
      if (!pubKey) {
        reasons.push(`[${credId}] auditor '${a.id}' public key not found in ctx.keys`);
        return false;
      }
      if (!verifySig(message, pubKey, a.sig)) {
        reasons.push(`[${credId}] auditor '${a.id}' signature invalid (not bound to generation+holder+work+solution)`);
        return false;
      }

      // 递归验证资格凭证自身链（回验到创世锚）。
      if (!walk(qc, depth + 1)) {
        reasons.push(`[${credId}] auditor '${a.id}' qualification chain invalid`);
        return false;
      }
    }
    return true;
  }

  const pass = walk(cred, 0);
  return { pass, reasons: Array.from(new Set(reasons)), chain };
}

// ---------------------------------------------------------------------------
// 审计留痕（Audit Trail）
// ---------------------------------------------------------------------------

// 每次签名追加一行 { auditorId, credentialId, generation, ts } 到 trail-<auditorId>.jsonl。
export function signAuditTrail(auditor, cred, trailDir = TRAIL_DIR) {
  if (!auditor || typeof auditor.id !== 'string') {
    throw new Error('signAuditTrail: auditor must have an id');
  }
  const credentialId = cred.credentialId || credentialIdOf(cred);
  const line = {
    auditorId: auditor.id,
    credentialId,
    generation: Number(cred.generation),
    ts: new Date().toISOString(),
  };
  fs.mkdirSync(trailDir, { recursive: true });
  const file = path.join(trailDir, `trail-${auditor.id}.jsonl`);
  fs.appendFileSync(file, JSON.stringify(line) + '\n', 'utf8');
  return { file, line };
}

function readTrail(trailPath) {
  if (!fs.existsSync(trailPath)) return [];
  const text = fs.readFileSync(trailPath, 'utf8');
  return text
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

// 确定性伪随机数（mulberry32），保证抽查结果可复现。
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function deterministicSample(arr, k, seed) {
  if (k <= 0) return [];
  if (k >= arr.length) return arr.slice();
  const rand = mulberry32(seed);
  const idx = arr.map((_, i) => i);
  for (let i = idx.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    const tmp = idx[i];
    idx[i] = idx[j];
    idx[j] = tmp;
  }
  return idx.slice(0, k).map((i) => arr[i]);
}

// ---------------------------------------------------------------------------
// 独立复核抽查（Audit Quality Check）
// ---------------------------------------------------------------------------

// 抽查 trail 中的凭证：对每一条抽样调用 verifyFn(entry)（应返回 { pass, reasons } 或布尔），
// 返回 { total, checked, passed, failed, failRate, evidence, sampledCredentialIds }。
// 放水证据 = 失败凭证（credentialId）+ 签名者 id（auditorId）+ 失败原因。
export function auditQuality(trailPath, verifyFn, { sampleRatio = 1, seed = 0x5eed } = {}) {
  const entries = readTrail(trailPath);
  const total = entries.length;
  const ratio = typeof sampleRatio === 'number' ? sampleRatio : 1;
  const sampleSize = Math.min(total, Math.max(0, Math.round(total * ratio)));
  const sample = deterministicSample(entries, sampleSize, seed);

  const evidence = [];
  let passed = 0;
  for (const entry of sample) {
    let res;
    try {
      res = verifyFn(entry);
    } catch (e) {
      res = { pass: false, reasons: [String((e && e.message) || e)] };
    }
    const pass = res === true || (res && res.pass === true);
    if (pass) {
      passed += 1;
    } else {
      evidence.push({
        auditorId: entry.auditorId,
        credentialId: entry.credentialId,
        generation: entry.generation,
        reasons: res && Array.isArray(res.reasons) ? res.reasons : ['verification failed'],
      });
    }
  }

  const checked = sample.length;
  const failed = checked - passed;
  const failRate = checked === 0 ? 0 : failed / checked;
  return {
    total,
    checked,
    passed,
    failed,
    failRate,
    evidence,
    sampledCredentialIds: sample.map((e) => e.credentialId),
  };
}

// ---------------------------------------------------------------------------
// 放水变体（装置内，用于 D/E 实验对照）
// ---------------------------------------------------------------------------

// 模拟合格审计者故意放水：不对 solution 重算即签名，签一个重放验证必失败的伪造凭证。
// 签名本身用真私钥（验签能过），但 solution 是错的 → verifyCredentialChain 在重放闸拦截。
export function forgeLaxSign(qualifiedAuditor, fakeCred) {
  if (!qualifiedAuditor || typeof qualifiedAuditor.id !== 'string' || !qualifiedAuditor.privateKey) {
    throw new Error('forgeLaxSign: qualifiedAuditor must have id and privateKey');
  }
  if (!fakeCred || !fakeCred.work || typeof fakeCred.solution !== 'string') {
    throw new Error('forgeLaxSign: fakeCred must have work and solution');
  }
  const message = credentialMessage({
    generation: Number(fakeCred.generation),
    holder: fakeCred.holder,
    work: fakeCred.work,
    solution: fakeCred.solution,
  });
  const sig = signMessage(message, qualifiedAuditor.privateKey);
  const auditors = (Array.isArray(fakeCred.auditors) ? fakeCred.auditors : [])
    .filter((a) => a && a.id !== qualifiedAuditor.id);
  auditors.push({ id: qualifiedAuditor.id, sig });

  const out = {
    ...fakeCred,
    auditors,
    forgedBy: { kind: 'laxSign', auditorId: qualifiedAuditor.id, note: 'qualified auditor signed without recomputing solution (放水)' },
  };
  out.credentialId = out.credentialId || credentialIdOf(out);
  return out;
}
