// vap-to-membership.mjs —— VAP Phase 6 动态成员 + 军法上链（VAP-TO 扩展）
//
// 零第三方依赖，仅 node: 内置模块与相对路径 import。
// 复用（零改动，只 import）：
//   - ../phase5/vap-to.mjs           锁步 QC 链共识内核（createNode / leaderOf / hashBlock / GENESIS_HASH）
//   - ../vap-core.mjs                canonicalJson / makeLaws
//   - ../phase3/endorse-core.mjs     collectQC / detectDoubleSign / verifyDoubleSignEvidence / quorumThreshold
//   - ../phase0.5/bootstrap-forge.mjs verifyCredentialChain / credentialIdOf
//
// 设计依据：phase6/DESIGN.md。
//   ① 成员变更走窄车道（type=membership），提交于高度 h → h+2 生效（roster 切换、f 重算）；
//   ② equivocation 双签证据 = 密码学铁证：slash 交易上链 → 作恶者签名从提交高度起立即不计入，
//     roster 表变更延迟 2 块；
//   ③ 军法（laws）作为投票前谓词：不满足的信封提案 0 票（诚实节点拒投），不进 QC；
//   ④ 复用零改动：phase5/vap-core/phase3/phase0.5 均只 import，不改源码；
//     动态 roster / 军法谓词 / h+2 调度在本模块内、对 createNode 返回实例做扩展（不改文件）。

import crypto from 'node:crypto';

import { createNode, leaderOf, hashBlock, GENESIS_HASH } from '../phase5/vap-to.mjs';
import { canonicalJson, makeLaws } from '../vap-core.mjs';
import { saveKey, loadKey } from '../key-store.mjs';
import {
  collectQC,
  detectDoubleSign,
  verifyDoubleSignEvidence,
  verifyDoubleSignEvidenceBound,
  quorumThreshold,
} from '../phase3/endorse-core.mjs';
import { verifyCredentialChain, credentialIdOf } from '../phase0.5/bootstrap-forge.mjs';

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

// no-equivocation：作恶者（或背书者）已被 equivocation 除名 → 投票前拒。
export const NO_EQUIVOCATION_RULE = Object.freeze({
  id: 'NO_EQUIVOCATION',
  check: 'from.nodeId 与背书者不在 equivocation 除名集',
  severity: 'reject',
});

const BOUNDARIES = new Set(['L2a', 'L1', 'L0']);
const SUMMARY_BOUND = 100;

// ---------------------------------------------------------------------------
// 局部密码学助手（phase5 内的同名助手为闭包，未导出；此处按同语义重实现，不改复用模块）
// ---------------------------------------------------------------------------

function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function coercePublicKey(key) {
  if (key && typeof key === 'object' && typeof key.export === 'function') return key;
  if (typeof key === 'string') {
    const text = key.trim();
    if (text.startsWith('-----BEGIN')) return crypto.createPublicKey(text);
    return crypto.createPublicKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'spki' });
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return crypto.createPublicKey({ key: Buffer.from(key), format: 'der', type: 'spki' });
  }
  throw new Error('vap-to-membership: unsupported public key value');
}

function coercePrivateKey(key) {
  if (key && typeof key === 'object' && typeof key.export === 'function') return key;
  if (typeof key === 'string') {
    const text = key.trim();
    if (text.startsWith('-----BEGIN')) return crypto.createPrivateKey(text);
    return crypto.createPrivateKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'pkcs8' });
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return crypto.createPrivateKey({ key: Buffer.from(key), format: 'der', type: 'pkcs8' });
  }
  throw new Error('vap-to-membership: unsupported private key value');
}

function signString(message, privateKey) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), coercePrivateKey(privateKey)).toString('base64');
}

function verifyString(message, publicKey, sigB64) {
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

function charCount(str) {
  return typeof str === 'string' ? Array.from(str).length : 0;
}

// 区块签名/哈希对象（与 phase5 blockContent 同构）。
function blockContent(proposal) {
  return {
    view: proposal.view,
    leader: proposal.leader,
    parentHash: proposal.parentHash,
    txs: proposal.txs || [],
  };
}

// ---------------------------------------------------------------------------
// 信封军法谓词（本地重实现 vap-core 的可判定规则，作为共识级投票前检查）
// ---------------------------------------------------------------------------

// 与 vap-core signPayload 一致：from 展平为带点键，nonce 纳入，不含 sig。
function envelopeSignPayload(env) {
  return {
    v: env.v,
    id: env.id,
    ts: env.ts,
    'from.nodeId': env.from ? env.from.nodeId : undefined,
    'from.pubKey': env.from ? env.from.pubKey : undefined,
    to: env.to,
    claim: env.claim,
    evidence: env.evidence,
    boundary: env.boundary,
    report: env.report,
    nonce: env.nonce,
  };
}

function verifyEnvelopeSig(env) {
  try {
    const pubKey = env.from && env.from.pubKey;
    const sig = env.sig;
    if (!pubKey || !sig) return false;
    return crypto.verify(
      null,
      Buffer.from(canonicalJson(envelopeSignPayload(env)), 'utf8'),
      coercePublicKey(pubKey),
      Buffer.from(sig, 'base64'),
    );
  } catch {
    return false;
  }
}

function defaultLaws() {
  const laws = makeLaws(); // 5 条默认可判定规则（规则是数据）
  laws.rules = laws.rules.concat([{ ...NO_EQUIVOCATION_RULE }]);
  return laws;
}

// ---------------------------------------------------------------------------
// createMembershipNode —— 动态成员 + 军法上链节点（扩展 phase5 createNode）
// ---------------------------------------------------------------------------

// createMembershipNode({ nodeId, keyPair, n, f, peers, now, randomBytes, ledgerDir, laws, credentialCtx, persistKeys, autoRestore })
//   参数同 phase5 createNode，另加：
//   - laws          : 军法规则对象 { rules: [...] }；缺省用 defaultLaws()（5 条默认 + no-equivocation）
//   - credentialCtx : { genesis:{id,publicKey}, keys:Map, credentials:Map }，用于 join 资格凭证回验
//   - persistKeys   : true = 私钥落盘（load→use→save，F3）；rotateKey 生效时新钥落盘（原子切换）
//   - autoRestore   : true = 启动即恢复（回放账本重建成员状态，M12）
export function createMembershipNode({
  nodeId,
  keyPair,
  n,
  f,
  peers,
  now,
  randomBytes,
  ledgerDir,
  laws,
  credentialCtx,
  persistKeys = false,
  autoRestore = false,
} = {}) {
  const node = createNode({ nodeId, keyPair, n, f, peers, now, randomBytes, ledgerDir, persistKeys });

  node.laws = laws && Array.isArray(laws.rules) ? laws : defaultLaws();
  node.credentialCtx = credentialCtx || null;
  node.persistKeys = !!persistKeys;

  // ---- 成员扩展状态 ----
  node.membershipNonces = new Set();   // 已提交 membership 交易的 from:nonce
  node.pendingChanges = [];            // 已提交、待 h+2 生效的 roster 变更
  node.membershipLog = [];             // 成员变更审计留痕（scheduled/expelled-immediate/applied）
  node.rotateStash = null;             // 本节点密钥轮换的新私钥暂存（h+2 换钥用）

  // ---- 动态 roster 助手（闭包） ----

  function recomputeQuorum() {
    node.n = node.roster.length;
    node.f = Math.floor((node.n - 1) / 3);
    // TLC 实测修正：与 phase5 同——n>3f+1 时 2f+1 诚实票下界过低（同视图双 QC 反例），
    // 门槛 = max(2f+1, ⌈2n/3⌉)。
    node.threshold = Math.max(2 * node.f + 1, Math.ceil((2 * node.n) / 3));
  }

  function joinSubjectOf(tx) {
    let derivedId;
    try {
      // F7：credential 结构可能缺 work/solution 等字段，credentialIdOf 会抛 TypeError；
      // 判定链路不许因一笔畸形交易崩掉（异常 → 视为无 credentialId，后续照常判拒）。
      derivedId = tx.credential ? (tx.credential.credentialId || credentialIdOf(tx.credential)) : undefined;
    } catch {
      derivedId = undefined;
    }
    const credentialId = tx.credentialId || derivedId;
    return { op: 'join', nodeId: tx.nodeId, pubKey: tx.pubKey, credentialId };
  }

  function checkJoinContent(tx) {
    const reasons = [];
    const cred = tx.credential;
    if (!cred) {
      reasons.push('join: missing credential');
      return { pass: false, reasons };
    }
    // F7：凭证必须是带 work 的对象（缺 .work 会让 verifyCredentialChain/credentialIdOf 抛
    // TypeError → 全节点崩）。结构不合 → 直接判拒，绝不进入密码学验证链路。
    if (typeof cred !== 'object' || Array.isArray(cred) || !cred.work || typeof cred.work !== 'object') {
      reasons.push('join: malformed credential (missing work)');
      return { pass: false, reasons };
    }
    if (node.credentialCtx) {
      let res;
      try {
        res = verifyCredentialChain(cred, node.credentialCtx);
      } catch (err) {
        res = { pass: false, reasons: [String((err && err.message) || err)] };
      }
      if (!res.pass) reasons.push(`join: credential chain invalid: ${(res.reasons && res.reasons[0]) || 'unknown'}`);
    } else {
      reasons.push('join: no credential context to verify');
    }
    if (cred.holder !== tx.nodeId) reasons.push(`join: credential holder '${cred.holder}' != nodeId '${tx.nodeId}'`);
    if (tx.credentialId && cred.credentialId && tx.credentialId !== cred.credentialId) {
      reasons.push('join: credentialId mismatch');
    }
    const subject = joinSubjectOf(tx);
    if (!verifyString(canonicalJson(subject), tx.pubKey, tx.selfSig)) {
      reasons.push('join: selfSig invalid (pubKey ownership not proven)');
    }
    if (node.peerMap.has(tx.nodeId)) reasons.push(`join: node '${tx.nodeId}' already in roster`);
    for (const [id, pk] of node.peerMap) {
      if (pk === tx.pubKey) { reasons.push(`join: pubKey already used by '${id}'`); break; }
    }
    return { pass: reasons.length === 0, reasons };
  }

  function applyRosterChange(change) {
    const tx = change.tx;
    if (tx.op === 'join') {
      if (!node.peerMap.has(tx.nodeId)) {
        node.roster.push({ nodeId: tx.nodeId, pubKey: tx.pubKey });
        node.roster.sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
        node.peerMap.set(tx.nodeId, tx.pubKey);
      }
    } else if (tx.op === 'slash' || tx.op === 'expel') {
      if (node.peerMap.has(tx.nodeId)) {
        node.roster = node.roster.filter((r) => r.nodeId !== tx.nodeId);
        node.peerMap.delete(tx.nodeId);
      }
    } else if (tx.op === 'rotate') {
      if (node.peerMap.has(tx.nodeId)) {
        // M2 兜底：非法新钥不该走到这里（checkMembershipTx 已拦），但历史账本回放
        // 可能带入旧的非法交易 → 解析失败就跳过这次轮换，不许抛异常炸掉生效流程。
        let coercedNew = null;
        if (node.nodeId === tx.nodeId) {
          try {
            coercedNew = coercePublicKey(tx.newPubKey);
          } catch (err) {
            node.membershipLog.push({
              kind: 'rejected',
              op: 'rotate',
              nodeId: tx.nodeId,
              reason: `invalid newPubKey: ${String((err && err.message) || err)}`,
            });
            return;
          }
        }
        node.peerMap.set(tx.nodeId, tx.newPubKey);
        const entry = node.roster.find((r) => r.nodeId === tx.nodeId);
        if (entry) entry.pubKey = tx.newPubKey;
        if (node.nodeId === tx.nodeId) {
          node.pubKey = tx.newPubKey;
          node.publicKey = coercedNew;
          if (node.rotateStash && node.rotateStash.nonce === tx.nonce && node.rotateStash.newPrivateKey) {
            node.privateKey = coercePrivateKey(node.rotateStash.newPrivateKey);
            // F3：轮换生效即把新私钥落盘（原子切换持久身份）。
            if (node.persistKeys) {
              saveKey(node.ledgerRoot, node.nodeId, node.privateKey);
            }
          }
        }
      }
    }
    recomputeQuorum();
    node.membershipLog.push({
      kind: 'applied',
      op: tx.op,
      nodeId: tx.nodeId,
      rosterSize: node.n,
      f: node.f,
      threshold: node.threshold,
    });
  }

  function scheduleMembership(tx, height) {
    const record = { op: tx.op, tx, submitHeight: height, activateHeight: height + 2, applied: false };
    node.pendingChanges.push(record);
    node.membershipLog.push({
      kind: 'scheduled',
      op: tx.op,
      submitHeight: height,
      activateHeight: height + 2,
      nodeId: tx.nodeId,
    });
    return record;
  }

  // ---- 军法谓词（可判定规则，投票前检查） ----

  // checkLaws(subject)：对信封形态 subject 逐条判定 laws.rules；reject 级失败进 reasons。
  // F7 异常边界：畸形 subject 不得把判定链路打崩 → 异常一律判拒。
  node.checkLaws = function checkLaws(subject) {
    try {
      return checkLawsInner(subject);
    } catch (err) {
      return {
        pass: false,
        reasons: [`laws check failed: ${String((err && err.message) || err)}`],
        rules: [],
      };
    }
  };

  function checkLawsInner(subject) {
    const rules = [];
    const reasons = [];
    if (!subject || typeof subject !== 'object' || Array.isArray(subject)) {
      return { pass: false, reasons: ['laws: subject must be an object'], rules };
    }
    for (const rule of node.laws.rules || []) {
      let ok = true;
      let note = rule.check || '';
      switch (rule.id) {
        case 'SIG_REQUIRED':
          ok = verifyEnvelopeSig(subject);
          note = ok ? 'signature verified' : 'signature verification failed';
          break;
        case 'BOUNDARY_VALID':
          ok = BOUNDARIES.has(subject.boundary);
          note = ok ? `boundary ${subject.boundary} valid` : `invalid boundary '${subject.boundary}'`;
          break;
        case 'SUMMARY_BOUND': {
          const len = charCount(subject.report && subject.report.summary);
          ok = len <= SUMMARY_BOUND;
          note = ok ? `summary length ${len} <= ${SUMMARY_BOUND}` : `summary length ${len} exceeds ${SUMMARY_BOUND}`;
          break;
        }
        case 'EVIDENCE_L2A': {
          if (subject.boundary !== 'L2a') {
            ok = true;
            note = 'boundary not L2a';
          } else {
            const devices = subject.evidence && subject.evidence.devices;
            ok = Array.isArray(devices) && devices.length > 0;
            note = ok ? `evidence.devices count ${devices ? devices.length : 0}` : 'L2a requires non-empty evidence.devices';
          }
          break;
        }
        case 'FROM_KNOWN': {
          const id = subject.from && subject.from.nodeId;
          ok = !!id && node.peerMap.has(id);
          note = ok ? 'node known' : `unknown node '${id}'`;
          break;
        }
        case 'NO_EQUIVOCATION': {
          const id = subject.from && subject.from.nodeId;
          ok = !id || !node.expelled.has(id);
          note = ok ? 'not equivocated' : `'${id}' equivocated`;
          break;
        }
        default:
          note = `no checker for rule '${rule.id}'`;
          break;
      }
      const severity = rule.severity || 'warn';
      rules.push({ id: rule.id, ok, severity, note });
      if (!ok && severity === 'reject') reasons.push(`${rule.id}: ${note}`);
    }
    return { pass: reasons.length === 0, reasons, rules };
  }

  // checkMembershipTx(tx)：membership 窄车道交易的投票前谓词（no-equivocation + op 专属）。
  // F7 异常边界：任何未预料的异常都不许把判定链路（→ vote → 全节点）打崩 —— 一律判拒。
  node.checkMembershipTx = function checkMembershipTx(tx) {
    try {
      return checkMembershipTxInner(tx);
    } catch (err) {
      return {
        pass: false,
        reasons: [`membership tx check failed: ${String((err && err.message) || err)}`],
      };
    }
  };

  function checkMembershipTxInner(tx) {
    const reasons = [];
    if (!tx || typeof tx !== 'object' || Array.isArray(tx)) {
      return { pass: false, reasons: ['membership tx must be an object'] };
    }
    if (tx.from && node.expelled.has(tx.from)) reasons.push(`NO_EQUIVOCATION: submitter '${tx.from}' equivocated`);
    if (tx.nodeId && node.expelled.has(tx.nodeId)) reasons.push(`NO_EQUIVOCATION: subject '${tx.nodeId}' equivocated`);
    // F7 类型守卫：endorsements 若存在必须是数组。修复前 `for (const e of tx.endorsements || [])`
    // 对数字/对象直接抛 TypeError（"is not iterable"）→ 一笔畸形交易崩掉全部诚实节点。
    if (tx.endorsements != null && !Array.isArray(tx.endorsements)) {
      reasons.push('endorsements: must be an array');
    } else {
      for (const e of Array.isArray(tx.endorsements) ? tx.endorsements : []) {
        if (e && e.nodeId && node.expelled.has(e.nodeId)) reasons.push(`NO_EQUIVOCATION: endorser '${e.nodeId}' equivocated`);
      }
    }

    switch (tx.op) {
      case 'join': {
        if (!Array.isArray(tx.endorsements)) {
          reasons.push('join: endorsements must be an array');
          return { pass: false, reasons };
        }
        const content = checkJoinContent(tx);
        reasons.push(...content.reasons);
        const rosterMap = node.activeRoster();
        const required = quorumThreshold(rosterMap.size);
        const res = collectQC({
          envelope: joinSubjectOf(tx),
          endorsements: tx.endorsements,
          roster: rosterMap,
          threshold: required,
        });
        if (!res.ok) reasons.push(`join: endorsements ${res.kept} < ${res.required} (no 2/3 quorum)`);
        break;
      }
      case 'rotate': {
        const current = node.peerMap.get(tx.nodeId);
        if (!current) {
          reasons.push(`rotate: node '${tx.nodeId}' not in roster`);
        } else if (current !== tx.oldPubKey) {
          reasons.push(`rotate: oldPubKey does not match current roster key for '${tx.nodeId}'`);
        } else {
          const subject = { op: 'rotate', nodeId: tx.nodeId, oldPubKey: tx.oldPubKey, newPubKey: tx.newPubKey };
          if (!verifyString(canonicalJson(subject), tx.oldPubKey, tx.sig)) {
            reasons.push('rotate: old-key signature invalid');
          }
        }
        // M2：新钥必须是可解析的 Ed25519 公钥。修复前非法 newPubKey 一路上链，
        // 到 h+2 生效时 applyRosterChange 里 coercePublicKey 抛错 → 节点崩/roster 破。
        try {
          coercePublicKey(tx.newPubKey);
        } catch (err) {
          reasons.push(`rotate: newPubKey is not a usable public key (${String((err && err.message) || err)})`);
        }
        if (tx.newPubKey === tx.oldPubKey) reasons.push('rotate: newPubKey equals oldPubKey');
        for (const [id, pk] of node.peerMap) {
          if (id !== tx.nodeId && pk === tx.newPubKey) { reasons.push(`rotate: newPubKey collides with '${id}'`); break; }
        }
        break;
      }
      case 'slash': {
        if (!tx.evidence) {
          reasons.push('slash: missing evidence');
        } else {
          // F6 嫁祸防线：证据签名公钥必须等于被指控者在 roster 里的注册公钥。
          // 只验「证据自身可验」不够 —— 攻击者可用自己的钥造真双签证据，
          // 再把 evidence.nodeId 写成无辜者，把无辜者除名。
          const registered = node.peerMap.get(tx.nodeId);
          if (!registered) {
            reasons.push(`slash: node '${tx.nodeId}' not in roster (no registered pubKey to bind evidence)`);
          } else if (!verifyDoubleSignEvidenceBound(tx.evidence, registered)) {
            if (!verifyDoubleSignEvidence(tx.evidence)) {
              reasons.push('slash: evidence not verifiable');
            } else {
              reasons.push('slash: evidence.pubKey does not match the roster key of the accused node');
            }
          }
          if (tx.evidence.nodeId !== tx.nodeId) reasons.push('slash: evidence.nodeId != tx.nodeId');
        }
        break;
      }
      case 'expel': {
        const current = node.peerMap.get(tx.nodeId);
        if (!current) {
          reasons.push(`expel: node '${tx.nodeId}' not in roster`);
        } else {
          const subject = { op: 'expel', nodeId: tx.nodeId };
          if (!verifyString(canonicalJson(subject), current, tx.sig)) reasons.push('expel: self-signature invalid');
        }
        break;
      }
      case 'report': {
        if (!tx.envelope) {
          reasons.push('report: missing envelope');
        } else {
          const lr = node.checkLaws(tx.envelope);
          reasons.push(...lr.reasons);
        }
        break;
      }
      default:
        reasons.push(`unknown membership op '${tx.op}'`);
    }
    return { pass: reasons.length === 0, reasons };
  }

  // ---- 成员变更 API ----

  // proposeJoin({ nodeId, pubKey, credential, privateKey? })：资格凭证回验 → 打包 join 交易。
  //   privateKey 为申请加入节点的私钥（可选）：提供则产 selfSig（证明 pubKey 归属）。
  node.proposeJoin = function proposeJoin({ nodeId: jId, pubKey, credential, privateKey: jPriv } = {}) {
    if (!jId || typeof jId !== 'string') return { ok: false, reason: 'proposeJoin: nodeId required' };
    if (!pubKey || typeof pubKey !== 'string') return { ok: false, reason: 'proposeJoin: pubKey required' };
    if (!credential) return { ok: false, reason: 'proposeJoin: credential required' };
    if (node.credentialCtx) {
      let res;
      try {
        res = verifyCredentialChain(credential, node.credentialCtx);
      } catch (err) {
        res = { pass: false, reasons: [String((err && err.message) || err)] };
      }
      if (!res.pass) {
        return { ok: false, reason: `proposeJoin: credential chain invalid: ${(res.reasons && res.reasons[0]) || 'unknown'}` };
      }
    }
    const credentialId = credential.credentialId || credentialIdOf(credential);
    const subject = joinSubjectOf({ nodeId: jId, pubKey, credential, credentialId });
    const selfSig = jPriv ? signString(canonicalJson(subject), jPriv) : '';
    const tx = {
      type: 'membership',
      op: 'join',
      nodeId: jId,
      pubKey,
      credential,
      credentialId,
      selfSig,
      endorsements: [],
      from: node.nodeId,
      nonce: `join:${jId}:${credentialId}`,
    };
    return { ok: true, tx, subject };
  };

  // endorseJoin(tx)：现有成员对 join 交易背书（先回验资格凭证 + selfSig + 未重复）。
  node.endorseJoin = function endorseJoin(tx) {
    if (!tx || tx.type !== 'membership' || tx.op !== 'join') {
      return { refused: true, reason: 'endorseJoin: not a join tx' };
    }
    const content = checkJoinContent(tx);
    if (!content.pass) return { refused: true, reason: `endorseJoin: ${content.reasons.join('; ')}` };
    const subject = joinSubjectOf(tx);
    const sig = signString(canonicalJson(subject), node.privateKey);
    return { ok: true, endorsement: { nodeId: node.nodeId, pubKey: node.pubKey, sig } };
  };

  // rotateKey({ oldPubKey, newPubKey, newPrivateKey? })：旧钥签变更交易 → h+2 新钥生效。
  // 返回 { ok, tx }（不自动提交；由调用方把 tx 提交给当前 leader，见 submitTx）。
  node.rotateKey = function rotateKey({ oldPubKey, newPubKey, newPrivateKey } = {}) {
    if (!oldPubKey || !newPubKey) return { ok: false, reason: 'rotateKey: oldPubKey and newPubKey required' };
    if (oldPubKey !== node.pubKey) return { ok: false, reason: 'rotateKey: oldPubKey must match current pubKey' };
    // M2：轮换发起侧就校验新钥可解析（不给共识层递非法钥）。
    try {
      coercePublicKey(newPubKey);
    } catch (err) {
      return { ok: false, reason: `rotateKey: newPubKey is not a usable public key (${String((err && err.message) || err)})` };
    }
    if (typeof newPubKey !== 'string') return { ok: false, reason: 'rotateKey: newPubKey must be a base64/PEM string' };
    const subject = { op: 'rotate', nodeId: node.nodeId, oldPubKey, newPubKey };
    const sig = signString(canonicalJson(subject), node.privateKey);
    const tx = {
      type: 'membership',
      op: 'rotate',
      nodeId: node.nodeId,
      oldPubKey,
      newPubKey,
      sig,
      from: node.nodeId,
      nonce: `rotate:${node.nodeId}:${sha256hex(newPubKey).slice(0, 24)}`,
    };
    if (newPrivateKey) {
      node.rotateStash = { nonce: tx.nonce, newPrivateKey, newPubKey };
    }
    return { ok: true, tx };
  };

  // detectEquivocation(proposals)：仅产证据（不立即除名；除名走 slash 上链）。
  node.detectEquivocation = function detectEquivocation(proposals) {
    if (!Array.isArray(proposals)) return [];
    const sigs = proposals.map((p) => ({
      nodeId: p && p.leader,
      pubKey: p && node.peerMap.get(p.leader),
      envelopeId: p ? String(p.view) : undefined,
      content: p ? blockContent(p) : undefined,
      sig: p && p.sig,
    }));
    return detectDoubleSign(sigs);
  };

  // expelByEquivocation(evidence)：验证双签证据 → 打包 slash 交易（不自动提交；由调用方提交给 leader）。
  // 真正的"签名立即不计入"发生在 slash 交易提交（commitBlock）那一刻，roster 掉表在 h+2。
  // F6：举报时就把证据绑定到被指控者的 roster 注册公钥 —— 举报者也不能拿别人的钥嫁祸。
  node.expelByEquivocation = function expelByEquivocation(evidence) {
    if (!evidence || !verifyDoubleSignEvidence(evidence)) {
      return { ok: false, reason: 'expelByEquivocation: evidence not verifiable' };
    }
    const registered = node.peerMap.get(evidence.nodeId);
    if (!registered) {
      return { ok: false, reason: `expelByEquivocation: '${evidence.nodeId}' not in roster` };
    }
    if (!verifyDoubleSignEvidenceBound(evidence, registered)) {
      return { ok: false, reason: 'expelByEquivocation: evidence.pubKey does not match the roster key of the accused node' };
    }
    const tx = {
      type: 'membership',
      op: 'slash',
      nodeId: evidence.nodeId,
      evidence,
      from: node.nodeId,
      nonce: `slash:${evidence.nodeId}:${sha256hex(canonicalJson(evidence)).slice(0, 24)}`,
    };
    return { ok: true, tx };
  };

  // wrapEnvelope(envelope)：把信封包成窄车道交易（op=report），接受军法投票前谓词裁决。
  // 返回 { ok, tx }（不自动提交；由调用方把 tx 提交给 leader，见 submitTx）。
  node.wrapEnvelope = function wrapEnvelope(envelope) {
    if (!envelope || typeof envelope !== 'object') return { ok: false, reason: 'wrapEnvelope: envelope required' };
    const tx = {
      type: 'membership',
      op: 'report',
      envelope,
      from: envelope.from && envelope.from.nodeId,
      nonce: `report:${envelope.id || crypto.randomBytes(8).toString('hex')}`,
    };
    return { ok: true, tx };
  };

  // ---- h+2 调度 ----

  // applyMembership(ledger, tx)：提交后调度 h+2 生效（roster 切换、f 重算）。
  //   ledger 可传高度数字或 { committedHeight }；缺省用本节点当前已提交高度。
  node.applyMembership = function applyMembership(ledger, tx) {
    let height;
    if (typeof ledger === 'number') height = ledger;
    else if (ledger && typeof ledger.committedHeight === 'number') height = ledger.committedHeight;
    else height = node.committedHeight;
    return scheduleMembership(tx, height);
  };

  // applyDueChanges()：把到达激活高度的 pendingChanges 落到 roster（并重算 f / threshold）。
  node.applyDueChanges = function applyDueChanges() {
    const applied = [];
    for (const change of node.pendingChanges) {
      if (change.applied) continue;
      if (node.committedHeight >= change.activateHeight) {
        applyRosterChange(change);
        change.applied = true;
        applied.push(change);
      }
    }
    return applied;
  };

  // ---- 实例级扩展（不改 phase5 文件；仅替换返回实例上的方法） ----

  // submitTx：窄车道扩展为 type=commit（沿用 phase5）+ type=membership。
  const baseSubmitTx = node.submitTx;
  node.submitTx = function submitTx(tx) {
    if (!tx || typeof tx !== 'object') return { ok: false, reason: 'submitTx: tx must be an object' };
    if (tx.type === 'commit') return baseSubmitTx(tx);
    if (tx.type === 'membership') {
      if (typeof tx.from !== 'string' || typeof tx.nonce !== 'string') {
        return { ok: false, reason: 'submitTx: membership tx needs from + nonce' };
      }
      const key = `${tx.from}:${tx.nonce}`;
      if (node.membershipNonces.has(key)) return { ok: false, reason: `submitTx: membership nonce '${key}' already committed` };
      const alreadyPending = node.pendingTxs.some(
        (t) => t.type === 'membership' && `${t.from}:${t.nonce}` === key,
      );
      if (alreadyPending) return { ok: false, reason: `submitTx: membership nonce '${key}' already pending` };
      node.pendingTxs.push(tx);
      return { ok: true, tx };
    }
    return { ok: false, reason: 'submitTx: default-lane tx is not total-ordered (use nonce dedup)' };
  };

  // safetyRule：在 phase5 安全规则之上，扩展窄车道 type=membership + 军法投票前谓词。
  // F7 异常边界：判定链路（safetyRule → vote）整体包异常兜底 —— 任何未预料异常
  // 都返回 pass:false（拒投），绝不把异常抛给调用者（一笔畸形交易崩全网）。
  node.safetyRule = function safetyRule(proposal) {
    try {
      return safetyRuleInner(proposal);
    } catch (err) {
      return { pass: false, reason: `safety: internal error ${String((err && err.message) || err)}` };
    }
  };

  function safetyRuleInner(proposal) {
    if (!proposal || typeof proposal !== 'object') return { pass: false, reason: 'safety: malformed proposal' };
    const v = Number(proposal.view);
    if (!Number.isInteger(v) || v < 0) return { pass: false, reason: 'safety: invalid view' };
    if (proposal.leader !== node.leaderOf(v)) return { pass: false, reason: `safety: leader mismatch at view ${v}` };
    if (node.expelled.has(proposal.leader)) return { pass: false, reason: `safety: leader ${proposal.leader} expelled` };

    const contentStr = canonicalJson(blockContent(proposal));
    const leaderPub = node.peerMap.get(proposal.leader);
    if (!leaderPub || !verifyString(contentStr, leaderPub, proposal.sig)) {
      return { pass: false, reason: 'safety: invalid leader signature' };
    }
    if (proposal.blockHash !== hashBlock(proposal)) return { pass: false, reason: 'safety: blockHash mismatch' };
    if (v < node.view) return { pass: false, reason: `safety: stale view ${v} < ${node.view}` };
    if (node.votedViews.has(v)) return { pass: false, reason: `safety: already voted in view ${v}` };

    // 携带的 highestQC（justify）有效且不低则先采纳（防安全倒退）。
    if (proposal.justify != null) {
      if (proposal.justify.blockHash !== proposal.parentHash) {
        return { pass: false, reason: 'safety: carried QC (justify) does not match parentHash' };
      }
      if (!node.verifyQC(proposal.justify)) return { pass: false, reason: 'safety: invalid carried QC (justify)' };
      if (!node.highestQC || Number(proposal.justify.view) >= Number(node.highestQC.view)) {
        node.highestQC = proposal.justify;
        node.qcByView.set(proposal.justify.view, proposal.justify);
        node.qcByBlockHash.set(proposal.justify.blockHash, proposal.justify);
      }
    }

    const baseline = node.highestQC
      ? node.highestQC.blockHash
      : node.lastCommittedHash !== GENESIS_HASH
        ? node.lastCommittedHash
        : GENESIS_HASH;
    if (proposal.parentHash !== baseline) {
      return { pass: false, reason: `safety: parentHash does not extend local highest QC (${baseline})` };
    }

    // P2（lock-on-vote）：提案必须扩展当前 lock（lock 为 null=创世则跳过；与 phase5 同步）。
    if (node.lock != null && !node.isDescendant(proposal.parentHash, node.lock.blockHash)) {
      return {
        pass: false,
        reason: `safety: proposal does not extend lock (${node.lock.blockHash})`,
      };
    }

    // 窄车道交易逐笔校验：commit 走 nonce 双花；membership 走 nonce + 军法/op 谓词。
    const txs = proposal.txs;
    if (!Array.isArray(txs)) return { pass: false, reason: 'safety: proposal.txs must be an array' };
    const seen = new Set();
    for (const tx of txs) {
      if (!tx || typeof tx !== 'object') return { pass: false, reason: 'safety: malformed tx' };
      if (tx.type === 'commit') {
        if (typeof tx.from !== 'string' || typeof tx.nonce !== 'string') {
          return { pass: false, reason: 'safety: commit tx needs from + nonce' };
        }
        const key = `${tx.from}:${tx.nonce}`;
        if (node.seenNonces.has(key)) return { pass: false, reason: `double-spend: nonce '${key}' already committed` };
        if (seen.has(key)) return { pass: false, reason: `double-spend: nonce '${key}' duplicated within proposal` };
        seen.add(key);
      } else if (tx.type === 'membership') {
        if (typeof tx.from !== 'string' || typeof tx.nonce !== 'string') {
          return { pass: false, reason: 'safety: membership tx needs from + nonce' };
        }
        const key = `${tx.from}:${tx.nonce}`;
        if (node.membershipNonces.has(key)) return { pass: false, reason: `double-spend: membership nonce '${key}' already committed` };
        if (seen.has(key)) return { pass: false, reason: `double-spend: membership nonce '${key}' duplicated within proposal` };
        seen.add(key);
        const law = node.checkMembershipTx(tx);
        if (!law.pass) return { pass: false, reason: `laws: ${law.reasons.join('; ')}` };
      } else {
        return { pass: false, reason: 'safety: default-lane tx (non-commit/non-membership) must not be total-ordered' };
      }
    }
    return { pass: true, reason: null };
  }

  // 密钥轮换后本节点须用新钥签名。phase5 的 propose/vote/signProposal 内部用构造期闭包私钥
  // （不可替换），故在实例层用 node.privateKey（可替换属性）重实现这三个签名入口。
  function sortTxsLocal(txs) {
    const arr = Array.isArray(txs) ? txs.slice() : [];
    arr.sort((a, b) => {
      const ca = canonicalJson(a);
      const cb = canonicalJson(b);
      if (ca < cb) return -1;
      if (ca > cb) return 1;
      return 0;
    });
    return arr;
  }

  function packTxsLocal() {
    const txs = sortTxsLocal(node.pendingTxs);
    node.pendingTxs = [];
    node.pendingNonces.clear();
    return txs;
  }

  node.signProposal = function signProposal({ view, leader, parentHash, txs } = {}) {
    const proposal = { view, leader, parentHash, txs: sortTxsLocal(txs || []), justify: null, sig: '' };
    proposal.blockHash = hashBlock(proposal);
    proposal.sig = signString(canonicalJson(blockContent(proposal)), node.privateKey);
    return proposal;
  };

  node.propose = function propose(view) {
    const v = Number(view);
    if (!Number.isInteger(v) || v < 0) return { refused: true, reason: `propose: invalid view ${view}` };
    if (node.leaderOf(v) !== node.nodeId) {
      return { refused: true, reason: `propose: node ${node.nodeId} is not leader of view ${v}` };
    }
    if (v < node.view) return { refused: true, reason: `propose: view ${v} < current view ${node.view}` };
    const baseline = node.highestQC
      ? node.highestQC.blockHash
      : node.lastCommittedHash !== GENESIS_HASH
        ? node.lastCommittedHash
        : GENESIS_HASH;
    const proposal = {
      view: v,
      leader: node.nodeId,
      parentHash: baseline,
      txs: packTxsLocal(),
      justify: node.highestQC && node.highestQC.restored ? null : node.highestQC,
      sig: '',
    };
    proposal.blockHash = hashBlock(proposal);
    proposal.sig = signString(canonicalJson(blockContent(proposal)), node.privateKey);
    node.blocks.set(proposal.blockHash, proposal);
    node.activeProposal = proposal;
    node.view = Math.max(node.view, v);
    node.touch();
    return { proposal };
  };

  node.vote = function vote(proposal) {
    const check = node.safetyRule(proposal);
    if (!check.pass) return { voted: false, reason: check.reason };
    try {
      const v = Number(proposal.view);
      node.blocks.set(proposal.blockHash, proposal);
      node.activeProposal = proposal;
      node.votedViews.add(v);
      node.view = Math.max(node.view, v);
      node.touch();

      // P2（lock-on-vote）：投票成功即把 lock 推进到所投区块的父块（与 phase5 同步）。
      if (proposal.parentHash === GENESIS_HASH) {
        node.lock = null; // 创世提案：父块即创世，lock 保持/置创世（null 等价）。
      } else {
        let parentView = null;
        if (proposal.justify != null) {
          parentView = proposal.justify.view;
        } else {
          const parentBlk = node.blocks.get(proposal.parentHash);
          if (parentBlk) parentView = parentBlk.view;
        }
        node.lock = { blockHash: proposal.parentHash, view: parentView };
      }

      const voteTarget = { view: proposal.view, blockHash: proposal.blockHash, parentHash: proposal.parentHash };
      const sig = signString(canonicalJson(voteTarget), node.privateKey);
      return { voted: true, vote: { nodeId: node.nodeId, pubKey: node.pubKey, sig } };
    } catch (err) {
      // F7 异常边界：签名/状态更新阶段的异常也不许外抛 —— 不投票即最安全。
      return { voted: false, reason: `vote: internal error ${String((err && err.message) || err)}` };
    }
  };

  // commitBlock：提交时处理 membership 交易（登记 nonce + 调度 h+2 + slash/expel 立即除名 + 到期生效）。
  const baseCommitBlock = node.commitBlock;
  node.commitBlock = function commitBlock(blk) {
    const height = node.committedHeight;
    baseCommitBlock(blk);
    for (const tx of blk.txs || []) {
      if (tx && tx.type === 'membership') {
        node.membershipNonces.add(`${tx.from}:${tx.nonce}`);
        scheduleMembership(tx, height);
        if (tx.op === 'slash' || tx.op === 'expel') {
          node.expelled.add(tx.nodeId); // 作恶者签名从提交高度起立即不计入
          node.membershipLog.push({ kind: 'expelled-immediate', op: tx.op, height, nodeId: tx.nodeId });
        }
      }
    }
    node.applyDueChanges();
  };

  // ---- M12：成员状态回放 restore（重写 phase5 restore，补成员状态重建） ----

  const baseRestore = node.restore;

  // 回放账本重建成员状态：仅用已提交区块内的 membership 交易，不猜。
  // 自节点私钥不回放重建 —— persistKeys 已在 createNode 阶段 load 落盘新钥；
  // 此处只重建 peerMap/roster（成员关系）与 nonce/expelled/pendingChanges。
  // baseRestore 已把账本前缀重建成 node.committed（按提交顺序，索引 = height），
  // 故直接从 node.committed 回放，避免二次读盘且与已校验前缀严格一致。
  function replayMembership() {
    node.committed.forEach((blk, height) => {
      for (const tx of blk.txs || []) {
        if (!tx || tx.type !== 'membership') continue;
        if (typeof tx.from === 'string' && typeof tx.nonce === 'string') {
          node.membershipNonces.add(`${tx.from}:${tx.nonce}`);
        }
        // pendingChanges 按 activateHeight 重建（submitHeight = height）。
        const change = { op: tx.op, tx, submitHeight: height, activateHeight: height + 2, applied: false };
        node.pendingChanges.push(change);
        if (tx.op === 'slash' || tx.op === 'expel') {
          node.expelled.add(tx.nodeId);
          node.membershipLog.push({ kind: 'expelled-immediate', op: tx.op, height, nodeId: tx.nodeId });
        }
      }
    });
    // 逐条按 activateHeight 应用到期变更（重算 roster / n / f / threshold）。
    for (const change of node.pendingChanges.slice().sort((a, b) => a.activateHeight - b.activateHeight)) {
      if (change.activateHeight > node.committedHeight) continue;
      applyReplayRosterChange(change);
      change.applied = true;
    }
    node.pendingChanges = node.pendingChanges.filter((c) => !c.applied);
  }

  function applyReplayRosterChange(change) {
    const tx = change.tx;
    if (tx.op === 'join') {
      if (!node.peerMap.has(tx.nodeId)) {
        node.roster.push({ nodeId: tx.nodeId, pubKey: tx.pubKey });
        node.roster.sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
        node.peerMap.set(tx.nodeId, tx.pubKey);
      }
    } else if (tx.op === 'slash' || tx.op === 'expel') {
      if (node.peerMap.has(tx.nodeId)) {
        node.roster = node.roster.filter((r) => r.nodeId !== tx.nodeId);
        node.peerMap.delete(tx.nodeId);
      }
    } else if (tx.op === 'rotate') {
      if (node.peerMap.has(tx.nodeId)) {
        node.peerMap.set(tx.nodeId, tx.newPubKey);
        const entry = node.roster.find((r) => r.nodeId === tx.nodeId);
        if (entry) entry.pubKey = tx.newPubKey;
      }
    }
    recomputeQuorum();
    node.membershipLog.push({
      kind: 'applied',
      op: tx.op,
      nodeId: tx.nodeId,
      rosterSize: node.n,
      f: node.f,
      threshold: node.threshold,
    });
  }

  node.restore = function restore() {
    const base = baseRestore();
    // 重置成员扩展状态后回放重建（不可恢复的未提交成员交易丢弃）。
    node.membershipNonces = new Set();
    node.expelled = new Set();
    node.pendingChanges = [];
    node.membershipLog = [];
    node.rotateStash = null;
    // 诚实声明：重启后 lock 从已提交前缀重建，锁不持久化（与 PROOFS.md A4 边界一致）。
    // baseRestore 已重置为 null，此处显式声明意图（置 null 等价锁创世）。
    node.lock = null;
    replayMembership();
    node.touch();
    return { ...base, membershipReplayed: true, rosterSize: node.roster.length, expelled: [...node.expelled] };
  };

  // health()：成员共识节点真实状态（M11）。与 phase5 health 同构（expelled 为计数）。
  node.health = function health() {
    return {
      nodeId: node.nodeId,
      height: node.committedHeight,
      view: node.view,
      committed: node.committed.length,
      rosterSize: node.roster.length,
      f: node.f,
      threshold: node.threshold,
      qcCount: node.qcByBlockHash.size,
      expelled: node.expelled.size,
    };
  };

  // M12：autoRestore = true → 启动即恢复（回放账本重建成员状态）。
  if (autoRestore) node.restore();

  return node;
}
