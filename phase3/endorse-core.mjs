// endorse-core.mjs —— VAP Phase 3 分布式 2/3 背书（信任聚合）
//
// 把单点门限签名升级为真正的分布式多节点背书（Quorum Certificate, QC）。
// 复用（零改动，仅相对路径 import）：
//   - ../vap-core.mjs                 信封 / 三道闸 / canonicalJson
//   - ../phase0.5/bootstrap-forge.mjs 凭证资格链（verifyCredentialChain）
//
// 三件套（见 phase3/DESIGN.md §一）：
//   Envelope（vap-core 既有）→ 过三闸（验证门先行）
//   Endorsement = { nodeId, pubKey, sig }   # sig = Ed25519(私钥, canonicalJson(envelope))
//   QuorumCertificate(QC) = {
//     envelope,
//     endorsements: [ Endorsement × m ],
//     rosterSize,          # 背书者总数 n
//     threshold: ceil(2n/3)
//   }
//
// 零第三方依赖：仅 node:crypto 与相对路径 import。

import crypto from 'node:crypto';

import { canonicalJson } from '../vap-core.mjs';
import { verifyCredentialChain } from '../phase0.5/bootstrap-forge.mjs';

// ---------------------------------------------------------------------------
// 常量与门槛
// ---------------------------------------------------------------------------

// 2/3 门槛：ceil(2n/3)。n 为 roster 背书者总数。
export function quorumThreshold(n) {
  return Math.ceil((2 * Number(n)) / 3);
}

// ---------------------------------------------------------------------------
// 密钥规范化（复用 vap-core 的 Ed25519 语义，此处为局部助手，不改 vap-core）
// ---------------------------------------------------------------------------

function coercePublicKey(key) {
  if (key && typeof key === 'object' && typeof key.export === 'function') {
    return key; // 已是 KeyObject
  }
  if (typeof key === 'string') {
    const text = key.trim();
    if (text.startsWith('-----BEGIN')) return crypto.createPublicKey(text);
    return crypto.createPublicKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'spki' });
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return crypto.createPublicKey({ key: Buffer.from(key), format: 'der', type: 'spki' });
  }
  throw new Error('endorse-core: unsupported public key value');
}

function coercePrivateKey(key) {
  if (key && typeof key === 'object' && typeof key.export === 'function') {
    return key; // 已是 KeyObject
  }
  if (typeof key === 'string') {
    const text = key.trim();
    if (text.startsWith('-----BEGIN')) return crypto.createPrivateKey(text);
    return crypto.createPrivateKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'pkcs8' });
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return crypto.createPrivateKey({ key: Buffer.from(key), format: 'der', type: 'pkcs8' });
  }
  throw new Error('endorse-core: unsupported private key value');
}

function publicKeyToBase64(publicKey) {
  return coercePublicKey(publicKey).export({ type: 'spki', format: 'der' }).toString('base64');
}

function normalizePubKeyB64(key) {
  if (key == null) return null;
  return typeof key === 'string' ? key : publicKeyToBase64(key);
}

// ---------------------------------------------------------------------------
// 签名 / 验签（背书签名对象 = canonicalJson(envelope)，与 vap-core 的信封三闸验签独立）
// ---------------------------------------------------------------------------

function signEnvelope(envelope, privateKey) {
  return crypto
    .sign(null, Buffer.from(canonicalJson(envelope), 'utf8'), coercePrivateKey(privateKey))
    .toString('base64');
}

function verifySigOverMessage(message, publicKey, sigB64) {
  try {
    if (typeof sigB64 !== 'string' || sigB64.length === 0) return false;
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

function verifyEndorsement(envelope, publicKey, sigB64) {
  return verifySigOverMessage(canonicalJson(envelope), publicKey, sigB64);
}

// ---------------------------------------------------------------------------
// roster 规范化：Map | 普通对象 | 数组 → Map<nodeId, { pubKey, credential }>
// ---------------------------------------------------------------------------

function normalizeEntry(entry) {
  if (entry == null) return { pubKey: null, credential: null };
  const isBareKey =
    typeof entry === 'string' ||
    Buffer.isBuffer(entry) ||
    entry instanceof Uint8Array ||
    (typeof entry === 'object' && typeof entry.export === 'function');
  if (isBareKey) return { pubKey: entry, credential: null };
  return {
    pubKey: entry.pubKey != null ? entry.pubKey : entry.publicKey != null ? entry.publicKey : null,
    credential: entry.credential != null ? entry.credential : null,
  };
}

function resolveRoster(roster) {
  const map = new Map();
  const ingest = (id, entry) => {
    if (id == null || id === '') return;
    map.set(id, normalizeEntry(entry));
  };
  if (roster instanceof Map) {
    for (const [id, entry] of roster) ingest(id, entry);
    return map;
  }
  if (Array.isArray(roster)) {
    for (const r of roster) {
      if (r && r.nodeId != null) ingest(r.nodeId, { pubKey: r.pubKey != null ? r.pubKey : r.publicKey, credential: r.credential });
    }
    return map;
  }
  if (roster && typeof roster === 'object') {
    for (const [id, entry] of Object.entries(roster)) ingest(id, entry);
    return map;
  }
  return map;
}

function resolveCredential(credentialCtx, entry, nodeId) {
  if (entry && entry.credential) return entry.credential;
  if (!credentialCtx || !credentialCtx.credentials) return null;
  const creds = credentialCtx.credentials;
  if (creds instanceof Map) return creds.get(nodeId) || null;
  if (typeof creds === 'object') return creds[nodeId] || null;
  return null;
}

// ---------------------------------------------------------------------------
// endorse —— 外部有效性谓词 + 资格门 + Ed25519 背书签名
// ---------------------------------------------------------------------------

// endorse(envelope, endorser, gateVerify?) → Endorsement { nodeId, pubKey, sig }
//   endorser = { nodeId, pubKey, privateKey, credential? }
//   gateVerify = vap-core 的 verify（真实三道闸）。缺省时回退 endorser.gateVerify / endorser.verify。
// 返回：
//   - 成功 → { nodeId, pubKey, sig }
//   - 信封不过三闸 → { refused: true, reason, gateResult }（外部有效性谓词拒签并留痕）
//   - 无资格凭证 → 抛错（endorser 必须持有资格凭证）
export function endorse(envelope, endorser, gateVerify) {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('endorse: envelope must be an object');
  }
  if (!endorser || typeof endorser.nodeId !== 'string' || endorser.nodeId.length === 0) {
    throw new Error('endorse: endorser must have a non-empty nodeId');
  }
  const endorserPubKey = endorser.pubKey != null ? endorser.pubKey : endorser.publicKey;
  if (endorserPubKey == null || endorser.privateKey == null) {
    throw new Error('endorse: endorser must have pubKey and privateKey');
  }

  // 外部有效性谓词：不过三闸的信封拒绝背书（验证门先行，不信自报）。
  const gv = gateVerify || endorser.gateVerify || endorser.verify;
  if (typeof gv !== 'function') {
    throw new Error('endorse: gateVerify (vap-core verify) is required for the external validity predicate');
  }
  let gateResult;
  try {
    gateResult = gv(envelope);
  } catch (err) {
    gateResult = { pass: false, error: String((err && err.message) || err) };
  }
  if (!gateResult || gateResult.pass !== true) {
    const reason = gateResult && gateResult.error
      ? `external validity gate error: ${gateResult.error}`
      : 'envelope fails three gates (external validity predicate refused)';
    return { refused: true, reason, gateResult: gateResult || null };
  }

  // 资格门：背书者必须持有资格凭证（无资格抛错）。
  if (!endorser.credential) {
    throw new Error(`endorse: endorser '${endorser.nodeId}' lacks qualification credential (unqualified)`);
  }

  const pubKey = normalizePubKeyB64(endorserPubKey);
  const sig = signEnvelope(envelope, endorser.privateKey);
  return { nodeId: endorser.nodeId, pubKey, sig };
}

// ---------------------------------------------------------------------------
// collectQC —— 聚合：去重（按 nodeId 保留首个）+ 逐签验签 + 数量达标
// ---------------------------------------------------------------------------

// collectQC({ envelope, endorsements, roster, threshold? }) →
//   { ok: true, qc, ignored, required, kept }          # 达标 → QC
//   { ok: false, qc: null, reasons, ignored, required, kept }  # 不足 → 诚实失败
export function collectQC({ envelope, endorsements, roster, threshold } = {}) {
  if (!envelope || typeof envelope !== 'object') {
    return { ok: false, qc: null, reasons: ['collectQC: envelope must be an object'], ignored: [], required: null, kept: 0 };
  }
  if (!Array.isArray(endorsements)) {
    return { ok: false, qc: null, reasons: ['collectQC: endorsements must be an array'], ignored: [], required: null, kept: 0 };
  }
  const rosterMap = resolveRoster(roster);
  const n = rosterMap.size;
  const required = threshold != null ? Number(threshold) : quorumThreshold(n);

  const ignored = [];
  const seen = new Set();
  const kept = [];

  for (const e of endorsements) {
    if (!e || typeof e.nodeId !== 'string') {
      ignored.push('collectQC: malformed endorsement (missing nodeId) ignored');
      continue;
    }
    if (seen.has(e.nodeId)) {
      ignored.push(`collectQC: duplicate endorser '${e.nodeId}' ignored (kept first)`);
      continue;
    }
    const entry = rosterMap.get(e.nodeId);
    if (!entry || entry.pubKey == null) {
      ignored.push(`collectQC: endorser '${e.nodeId}' not in roster, ignored`);
      continue;
    }
    if (!verifyEndorsement(envelope, entry.pubKey, e.sig)) {
      ignored.push(`collectQC: endorser '${e.nodeId}' signature invalid, ignored`);
      continue;
    }
    seen.add(e.nodeId);
    kept.push({ nodeId: e.nodeId, pubKey: normalizePubKeyB64(entry.pubKey), sig: e.sig });
  }

  if (kept.length < required) {
    return {
      ok: false,
      qc: null,
      reasons: [`collectQC: effective endorsements ${kept.length} < threshold ${required} (no 2/3 quorum)`],
      ignored,
      required,
      kept: kept.length,
    };
  }

  const qc = {
    envelope,
    endorsements: kept,
    rosterSize: n,
    threshold: required,
  };
  return { ok: true, qc, ignored, required, kept: kept.length };
}

// ---------------------------------------------------------------------------
// verifyQC —— 全量验证：逐签验签 + 互异 + 数量达标 + 三闸重放 + 资格链回验
// ---------------------------------------------------------------------------

// verifyQC(qc, rosterKeys, gateVerify, credentialCtx?) → { pass, reasons, detail }
//   ① 每个背书签名有效（对 roster 权威公钥验签，防密钥替换）
//   ② 签名者互异
//   ③ 有效背书数 ≥ ceil(2n/3)（n 按 roster 重新推算，不信 QC 自报的 threshold）
//   ④ 信封过三闸（gateVerify 注入 vap-core 的 verify，真实调用，不 mock）
//   ⑤ 资格链验证（每个背书者的资格凭证沿代际链回验到创世锚）
export function verifyQC(qc, rosterKeys, gateVerify, credentialCtx) {
  const reasons = [];
  const detail = { required: null, effective: 0, sigInvalid: [], duplicate: [], unqualified: [], gatePass: null };

  if (!qc || !qc.envelope || typeof qc.envelope !== 'object') {
    return { pass: false, reasons: ['verifyQC: malformed QC (missing envelope)'], detail };
  }
  if (!Array.isArray(qc.endorsements)) {
    return { pass: false, reasons: ['verifyQC: malformed QC (missing endorsements array)'], detail };
  }
  if (typeof gateVerify !== 'function') {
    return { pass: false, reasons: ['verifyQC: gateVerify must be a function (vap-core verify)'], detail };
  }

  const rosterMap = resolveRoster(rosterKeys);
  const n = rosterMap.size;
  const required = quorumThreshold(n);
  detail.required = required;

  if (qc.rosterSize != null && Number(qc.rosterSize) !== n) {
    reasons.push(`verifyQC: QC rosterSize ${qc.rosterSize} != roster ${n}`);
  }
  if (qc.threshold != null && Number(qc.threshold) !== required) {
    reasons.push(`verifyQC: QC threshold ${qc.threshold} != ceil(2n/3)=${required}`);
  }

  const seen = new Set();
  let effective = 0;

  for (const e of qc.endorsements) {
    const id = e && e.nodeId;
    if (typeof id !== 'string' || id.length === 0 || typeof e.pubKey !== 'string' || typeof e.sig !== 'string') {
      reasons.push('verifyQC: malformed endorsement (missing nodeId/pubKey/sig)');
      continue;
    }
    const entry = rosterMap.get(id);
    if (!entry || entry.pubKey == null) {
      detail.unqualified.push(id);
      reasons.push(`verifyQC: endorser '${id}' not in qualified roster (no qualification)`);
      continue;
    }
    // ① 逐签验签（对 roster 权威公钥）。
    if (!verifyEndorsement(qc.envelope, entry.pubKey, e.sig)) {
      detail.sigInvalid.push(id);
      reasons.push(`verifyQC: endorsement '${id}' signature invalid`);
      continue;
    }
    // ② 签名者互异。
    if (seen.has(id)) {
      detail.duplicate.push(id);
      reasons.push(`verifyQC: duplicate endorser '${id}'`);
      continue;
    }
    seen.add(id);

    // ⑤ 资格链验证（背书者资格凭证回验）。
    const cred = resolveCredential(credentialCtx, entry, id);
    if (!cred) {
      detail.unqualified.push(id);
      reasons.push(`verifyQC: endorser '${id}' has no qualification credential`);
      continue;
    }
    let chainRes;
    try {
      chainRes = verifyCredentialChain(cred, credentialCtx);
    } catch (err) {
      chainRes = { pass: false, reasons: [String((err && err.message) || err)] };
    }
    if (!chainRes || chainRes.pass !== true) {
      detail.unqualified.push(id);
      const first = (chainRes && chainRes.reasons && chainRes.reasons[0]) || 'unknown';
      reasons.push(`verifyQC: endorser '${id}' qualification chain invalid: ${first}`);
      continue;
    }
    effective += 1;
  }

  // ③ 数量达标。
  if (effective < required) {
    reasons.push(`verifyQC: effective endorsements ${effective} < threshold ${required} (no 2/3 quorum)`);
  }

  // ④ 信封过三闸（真实调用 vap-core verify）。
  let gateResult;
  try {
    gateResult = gateVerify(qc.envelope);
  } catch (err) {
    gateResult = { pass: false, gates: null, error: String((err && err.message) || err) };
  }
  const gatePass = !!(gateResult && gateResult.pass === true);
  detail.gatePass = gatePass;
  if (!gatePass) {
    reasons.push('verifyQC: envelope fails three gates (replayed, not trusted)');
  }

  detail.effective = effective;
  return { pass: reasons.length === 0, reasons, detail };
}

// ---------------------------------------------------------------------------
// detectDoubleSign —— 双签冲突证据（同一 nodeId 对同一 envelopeId 的不同内容签名）
// ---------------------------------------------------------------------------

// detectDoubleSign(signatures) → [ evidence ]
//   signatures: [ { nodeId, pubKey, envelopeId, content, sig } × k ]
//     content 为 canonical 字符串或对象（对象会被 canonicalJson 规范化）。
//   evidence = { nodeId, envelopeId, pubKey, sigA, sigB, contentA, contentB }
//     contentA ≠ contentB，且两签名均对 pubKey 验签通过 → 任何第三方可验。
export function detectDoubleSign(signatures) {
  if (!Array.isArray(signatures)) return [];

  const normalized = [];
  for (const s of signatures) {
    if (!s || typeof s.nodeId !== 'string' || s.nodeId.length === 0) continue;
    if (s.pubKey == null || typeof s.sig !== 'string') continue;
    const content = typeof s.content === 'string' ? s.content : canonicalJson(s.content);
    normalized.push({
      nodeId: s.nodeId,
      pubKey: s.pubKey,
      envelopeId: s.envelopeId,
      content,
      sig: s.sig,
    });
  }

  // 按 (nodeId, envelopeId) 分组。
  const groups = new Map();
  for (const s of normalized) {
    const key = `${s.nodeId}\u0000${s.envelopeId == null ? '' : String(s.envelopeId)}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(s);
  }

  const evidence = [];
  for (const group of groups.values()) {
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        const a = group[i];
        const b = group[j];
        if (a.content === b.content) continue; // 同内容 = 同签名，非冲突
        const aOk = verifySigOverMessage(a.content, a.pubKey, a.sig);
        const bOk = verifySigOverMessage(b.content, b.pubKey, b.sig);
        if (aOk && bOk) {
          evidence.push({
            nodeId: a.nodeId,
            envelopeId: a.envelopeId,
            pubKey: normalizePubKeyB64(a.pubKey),
            sigA: a.sig,
            sigB: b.sig,
            contentA: a.content,
            contentB: b.content,
          });
        }
      }
    }
  }
  return evidence;
}

// verifyDoubleSignEvidence(evidence) → bool（第三方用公钥即可验冲突，无需信任任何声称）
export function verifyDoubleSignEvidence(evidence) {
  if (!evidence || typeof evidence !== 'object') return false;
  const contentA = typeof evidence.contentA === 'string' ? evidence.contentA : canonicalJson(evidence.contentA);
  const contentB = typeof evidence.contentB === 'string' ? evidence.contentB : canonicalJson(evidence.contentB);
  if (contentA === contentB) return false;
  if (!verifySigOverMessage(contentA, evidence.pubKey, evidence.sigA)) return false;
  if (!verifySigOverMessage(contentB, evidence.pubKey, evidence.sigB)) return false;
  return true;
}

// verifyDoubleSignEvidenceBound(evidence, expectedPubKey) → bool（F6 嫁祸防线）
//
// 在 verifyDoubleSignEvidence 之上再加一条：**证据签名所用公钥必须等于期望公钥**
// （调用方给出的、被指控者在 roster/登记册里的注册公钥）。
// 少了这一条，攻击者可以拿自己（或任何第三方）的密钥造一份"真实可验"的双签证据，
// 再把 evidence.nodeId 写成无辜者 → 无辜者被除名（嫁祸）。
// 比较前把两边都规范化为 spki DER base64：KeyObject / PEM / base64 三种写法等价。
export function verifyDoubleSignEvidenceBound(evidence, expectedPubKey) {
  if (!verifyDoubleSignEvidence(evidence)) return false;
  if (expectedPubKey == null) return false;
  let expected;
  let actual;
  try {
    expected = publicKeyToBase64(expectedPubKey);
    actual = publicKeyToBase64(evidence.pubKey);
  } catch {
    // 任一侧不是可解析的公钥：退回严格字符串比较（不放行任何不等的情况）。
    const e = normalizePubKeyB64(expectedPubKey);
    const a = normalizePubKeyB64(evidence.pubKey);
    return typeof e === 'string' && typeof a === 'string' && e === a;
  }
  return expected === actual;
}
