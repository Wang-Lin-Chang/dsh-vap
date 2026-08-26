// experiments/phase3-experiment.mjs —— VAP Phase 3 实测装置（E1-E6 六组实验）
//
// 运行：node phase3/experiments/phase3-experiment.mjs（在 dsh-vap/ 下）
// 输出：结构化 JSON（stdout + phase3/experiments/phase3-results.json）
//
// E1 正常背书    ：4 节点 roster，3 个有资格节点签名 → QC 成立
// E2 拜占庭拒签  ：1 节点拒签（f=1）→ 剩余 3 签 ≥ ceil(8/3)=3 → QC 仍成立
// E3 伪造背书    ：伪造签名混入 → verifyQC 拒绝
// E4 双签检测    ：1 节点对冲突内容双签 → 冲突证据留痕且第三方可验
// E5 资格不足    ：无 gen 凭证节点签名 → 不计入、QC 不足时诚实失败
// E6 外部有效性  ：不诚实信封（伪签名）→ 有资格背书者全部拒签 → 拿不到 2/3
//
// 复用（零改动）：vap-core（信封/三闸/canonicalJson）、phase0.5（凭证资格链）、phase0（任务）。
// gateVerify 注入 vap-core 的真实 verify（三闸真实重放，不 mock）。
// 零第三方依赖：仅 node:crypto / node:fs / node:os / node:path 与相对路径 import。

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createVapNode, canonicalJson } from '../../vap-core.mjs';
import { createGenesisAnchor, issueCredential } from '../../phase0.5/bootstrap-forge.mjs';
import { makeTask } from '../../phase0/history-forge.mjs';
import {
  endorse,
  collectQC,
  verifyQC,
  detectDoubleSign,
  verifyDoubleSignEvidence,
  quorumThreshold,
} from '../endorse-core.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// 装置搭建助手
// ---------------------------------------------------------------------------

function makeKeypair(id) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId: id,
    pubKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey,
  };
}

function clone(o) {
  return JSON.parse(JSON.stringify(o));
}

// 镜像 vap-core §1 签名对象（signPayload），仅用于装置内构造「同 id 不同内容」的
// 冲突信封夹具；不修改 vap-core。夹具正确性由 gateVerify(envB).pass 自验。
function signVapEnvelopePayload(envelope, privateKey) {
  const payload = {
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
  return crypto.sign(null, Buffer.from(canonicalJson(payload), 'utf8'), privateKey).toString('base64');
}

// 环境搭建：创世锚 + 4 个持 gen-0 凭证的合格背书者 + vap-core 信封与三闸。
function buildWorld() {
  const genesis = createGenesisAnchor();
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-phase3-'));
  const sender = createVapNode({ nodeId: 'origin', root: tmpRoot });
  const gateVerify = (env) => sender.verify(env);

  const envelope = sender.send({
    to: 'brain',
    claim: { type: 'report', body: { n: 1 } },
    evidence: { devices: ['dev-1'], bills: {}, digest: 'sha256:abc' },
    boundary: 'L0',
    report: { summary: 'phase3 quorum envelope', keyNumbers: [], request: '' },
  });

  const nodes = ['n1', 'n2', 'n3', 'n4'].map((id) => {
    const n = makeKeypair(id);
    const res = issueCredential({
      task: makeTask(`phase3-${id}`, 2),
      holder: id,
      auditors: [genesis],
      generation: 0,
    });
    if (!res.ok) throw new Error(`issueCredential ${id}: ${res.reasons.join('; ')}`);
    n.credential = res.credential;
    return n;
  });

  const roster = new Map(nodes.map((n) => [n.nodeId, n.pubKey]));
  const credentialCtx = {
    genesis: { id: genesis.id, publicKey: genesis.publicKey },
    keys: new Map(nodes.map((n) => [n.nodeId, n.pubKey])),
    credentials: new Map(nodes.map((n) => [n.nodeId, n.credential])),
  };

  return { genesis, tmpRoot, sender, gateVerify, envelope, nodes, roster, credentialCtx };
}

// ---------------------------------------------------------------------------
// E1 正常背书：3 个有资格节点签名 → QC 成立
// ---------------------------------------------------------------------------

function experimentE1(w) {
  const { envelope, nodes, roster, gateVerify, credentialCtx } = w;
  const endorsements = nodes.slice(0, 3).map((n) => endorse(envelope, n, gateVerify));
  const collect = collectQC({ envelope, endorsements, roster });
  const verify = collect.ok
    ? verifyQC(collect.qc, roster, gateVerify, credentialCtx)
    : { pass: false, reasons: collect.reasons };
  return {
    label: 'normal endorsement',
    rosterSize: 4,
    threshold: quorumThreshold(4),
    endorsementsCollected: endorsements.length,
    collectQCOk: collect.ok,
    verifyQCPass: verify.pass,
    verifyQCReasons: verify.reasons,
    qcHolds: collect.ok && verify.pass,
  };
}

// ---------------------------------------------------------------------------
// E2 拜占庭拒签：1 节点拒签（f=1）→ 剩余 3 签 ≥3 → QC 仍成立
// ---------------------------------------------------------------------------

function experimentE2(w) {
  const { envelope, nodes, roster, gateVerify, credentialCtx } = w;
  const f = Math.floor((4 - 1) / 3); // 1
  // n4 拜占庭拒签（崩溃/拒签：不产生背书）；诚实节点 n1..n3 背书。
  const honest = nodes.slice(0, 3);
  const endorsements = honest.map((n) => endorse(envelope, n, gateVerify));
  const collect = collectQC({ envelope, endorsements, roster });
  const verify = collect.ok
    ? verifyQC(collect.qc, roster, gateVerify, credentialCtx)
    : { pass: false, reasons: collect.reasons };
  const quorumHeldDespiteRefusal = collect.ok && verify.pass && endorsements.length === 3;
  return {
    label: 'byzantine refusal fault tolerance',
    f,
    refusals: [{ nodeId: 'n4', kind: 'withhold' }],
    honestEndorsements: endorsements.length,
    threshold: quorumThreshold(4),
    collectQCOk: collect.ok,
    verifyQCPass: verify.pass,
    verifyQCReasons: verify.reasons,
    quorumHeldDespiteRefusal,
  };
}

// ---------------------------------------------------------------------------
// E3 伪造背书：伪造签名混入 → verifyQC 拒绝
// ---------------------------------------------------------------------------

function experimentE3(w) {
  const { envelope, nodes, roster, gateVerify, credentialCtx } = w;
  const real = nodes.slice(0, 3).map((n) => endorse(envelope, n, gateVerify));
  const forged = { nodeId: 'n4', pubKey: nodes[3].pubKey, sig: crypto.randomBytes(64).toString('base64') };
  // (a) 聚合层：collectQC 丢弃伪造签名（3 真签名仍达标）。
  const collect = collectQC({ envelope, endorsements: [...real, forged], roster });
  // (b) 验证层：把伪造签名塞进 QC → verifyQC 拒绝。
  const forgedQC = { envelope, endorsements: [...real, forged], rosterSize: 4, threshold: 3 };
  const verify = verifyQC(forgedQC, roster, gateVerify, credentialCtx);
  const forgedRejected =
    collect.ok &&
    collect.qc.endorsements.length === 3 &&
    verify.pass === false &&
    verify.reasons.some((r) => r.includes('signature invalid'));
  return {
    label: 'forged endorsement rejection',
    collectQCOk: collect.ok,
    collectKept: collect.kept,
    collectIgnored: collect.ignored,
    verifyQCPassOnForgedQC: verify.pass,
    verifyQCReasons: verify.reasons,
    forgedRejected,
  };
}

// ---------------------------------------------------------------------------
// E4 双签检测：1 节点对冲突内容双签 → 冲突证据留痕且第三方可验
// ---------------------------------------------------------------------------

function experimentE4(w) {
  const { envelope, nodes, sender, gateVerify } = w;
  const n3 = nodes[2];
  const envA = envelope;
  const envB = clone(envelope);
  envB.claim = { type: 'report', body: { conflicting: true } };
  envB.sig = signVapEnvelopePayload(envB, sender.privateKey);
  // 夹具自验：两信封都过三闸（否则 endorse 会拒签，无法形成双签）。
  if (!gateVerify(envA).pass || !gateVerify(envB).pass) {
    throw new Error('E4 fixture: both envelopes must pass three gates');
  }
  const endA = endorse(envA, n3, gateVerify);
  const endB = endorse(envB, n3, gateVerify);
  const evidence = detectDoubleSign([
    { nodeId: n3.nodeId, pubKey: n3.pubKey, envelopeId: envA.id, content: canonicalJson(envA), sig: endA.sig },
    { nodeId: n3.nodeId, pubKey: n3.pubKey, envelopeId: envB.id, content: canonicalJson(envB), sig: endB.sig },
  ]);
  const evidenceVerifiable = evidence.length === 1 && verifyDoubleSignEvidence(evidence[0]);
  return {
    label: 'double-sign detection',
    envelopeId: envA.id,
    doubleSigner: n3.nodeId,
    evidenceCount: evidence.length,
    evidence: evidence.map((e) => ({
      nodeId: e.nodeId,
      envelopeId: e.envelopeId,
      contentA: e.contentA,
      contentB: e.contentB,
      sigA: e.sigA,
      sigB: e.sigB,
    })),
    evidenceVerifiable,
  };
}

// ---------------------------------------------------------------------------
// E5 资格不足：无 gen 凭证节点签名 → 不计入、QC 不足时诚实失败
// ---------------------------------------------------------------------------

function experimentE5(w) {
  const { envelope, nodes, roster, gateVerify, credentialCtx } = w;
  const outsider = makeKeypair('n5'); // 无 gen 凭证
  // (a) 诚实路径：endorse 直接拒绝无资格者。
  let endorseThrew = false;
  let endorseError = null;
  try {
    endorse(envelope, outsider, gateVerify);
  } catch (err) {
    endorseThrew = true;
    endorseError = String((err && err.message) || err);
  }
  // (b) 不诚实路径：无资格者绕过 endorse 手工签名塞进 QC → verifyQC 不计入、QC 诚实失败。
  const rawSig = crypto.sign(null, Buffer.from(canonicalJson(envelope), 'utf8'), outsider.privateKey).toString('base64');
  const raw = { nodeId: 'n5', pubKey: outsider.pubKey, sig: rawSig };
  const e1 = endorse(envelope, nodes[0], gateVerify);
  const e2 = endorse(envelope, nodes[1], gateVerify);
  const qc = { envelope, endorsements: [e1, e2, raw], rosterSize: 4, threshold: 3 };
  const verify = verifyQC(qc, roster, gateVerify, credentialCtx);
  const unqualifiedNotCounted =
    endorseThrew &&
    verify.pass === false &&
    verify.reasons.some((r) => r.includes("'n5'")) &&
    verify.detail.effective === 2;
  return {
    label: 'unqualified endorser not counted',
    outsiderId: outsider.nodeId,
    endorseThrew,
    endorseError,
    verifyQCPass: verify.pass,
    verifyQCReasons: verify.reasons,
    effectiveEndorsements: verify.detail.effective,
    unqualifiedNotCounted,
  };
}

// ---------------------------------------------------------------------------
// E6 外部有效性：不诚实信封（伪签名）→ 有资格背书者全部拒签 → 拿不到 2/3
// ---------------------------------------------------------------------------

function experimentE6(w) {
  const { envelope, nodes, roster, gateVerify, credentialCtx } = w;
  const dishonest = clone(envelope);
  dishonest.sig = crypto.randomBytes(64).toString('base64'); // 伪签名
  // 有资格背书者全部拒签（外部有效性谓词：不过三闸不背书）。
  const attempts = nodes.map((n) => {
    const r = endorse(dishonest, n, gateVerify);
    return { nodeId: n.nodeId, refused: !!r.refused, reason: r.reason || null };
  });
  const allRefused = attempts.every((a) => a.refused);
  // 聚合层：零有效背书 → 拿不到 2/3。
  const collect = collectQC({ envelope: dishonest, endorsements: [], roster });
  // 加固：即便有不诚实背书者绕过 endorse 手工签名，verifyQC ④ 也会拒绝（三闸重放）。
  const dishonestRaw = nodes.map((n) => ({
    nodeId: n.nodeId,
    pubKey: n.pubKey,
    sig: crypto.sign(null, Buffer.from(canonicalJson(dishonest), 'utf8'), n.privateKey).toString('base64'),
  }));
  const qc = { envelope: dishonest, endorsements: dishonestRaw, rosterSize: 4, threshold: 3 };
  const verify = verifyQC(qc, roster, gateVerify, credentialCtx);
  const noQuorum =
    allRefused &&
    collect.ok === false &&
    verify.pass === false &&
    verify.reasons.some((r) => r.includes('fails three gates'));
  return {
    label: 'dishonest envelope cannot reach 2/3',
    endorserAttempts: attempts,
    allRefused,
    collectQCOk: collect.ok,
    verifyQCPass: verify.pass,
    verifyQCReasons: verify.reasons,
    noQuorum,
  };
}

// ---------------------------------------------------------------------------
// 结论汇总（对照 DESIGN §六 验收标准 + §七 诚实边界）
// ---------------------------------------------------------------------------

function buildConclusion(E1, E2, E3, E4, E5, E6) {
  const a1 = E1.qcHolds;
  const a2 = E2.quorumHeldDespiteRefusal;
  const a3 = E3.forgedRejected;
  const a4 = E4.evidenceVerifiable;
  const a5 = E5.unqualifiedNotCounted;
  const a6 = E6.noQuorum;
  const allPass = a1 && a2 && a3 && a4 && a5 && a6;
  return {
    E1_qcHolds: a1,
    E2_faultTolerance: a2,
    E3_forgedRejected: a3,
    E4_evidenceVerifiable: a4,
    E5_unqualifiedNotCounted: a5,
    E6_noQuorumOnDishonest: a6,
    allPass,
    verdict: allPass
      ? '分布式 2/3 背书成立：正常 QC 达成、f=1 拒签容错、伪造背书拒绝、双签证据第三方可验、无资格不计入、不诚实信封拿不到 2/3'
      : '背书装置未达标：见 E1-E6 各项失败原因',
    honestBoundaries: [
      'roster 是静态的（装置内预设 4 节点）——动态成员是 Phase 6 的题',
      '背书者资格链 gen-k 深度与 roster 的对应关系装置内固定（k=0 起），公网参数未定',
      '网络层（P2P 洪泛背书请求）以内存调用模拟——真实 UDP 洪泛背书是 Phase 4 的题',
      'QC 不产总序（两个 QC 可并存分叉）——共识是 Phase 5 的题，本阶段只有认可没有排序',
      '>2n/3 恶意时系统无法区分（诚实标注：不是防，是数学边界）',
    ],
  };
}

// ---------------------------------------------------------------------------
// 运行 + 输出
// ---------------------------------------------------------------------------

const w = buildWorld();

const E1 = experimentE1(w);
const E2 = experimentE2(w);
const E3 = experimentE3(w);
const E4 = experimentE4(w);
const E5 = experimentE5(w);
const E6 = experimentE6(w);
const endorseConclusion = buildConclusion(E1, E2, E3, E4, E5, E6);

const summary = {
  experiment: 'phase3-endorse',
  generatedAt: new Date().toISOString(),
  zeroDependency: true,
  reusedModules: [
    '../vap-core.mjs',
    '../phase0.5/bootstrap-forge.mjs',
    '../phase0/history-forge.mjs',
  ],
  rosterSize: 4,
  threshold: quorumThreshold(4),
  byzantineToleranceF: Math.floor((4 - 1) / 3),
  genesis: { id: w.genesis.id },
  E1,
  E2,
  E3,
  E4,
  E5,
  E6,
  endorseConclusion,
};

const json = JSON.stringify(summary, null, 2);
process.stdout.write(json + '\n');

fs.mkdirSync(__dirname, { recursive: true });
fs.writeFileSync(path.join(__dirname, 'phase3-results.json'), json + '\n', 'utf8');

// 硬性验收自检。
const ok = endorseConclusion.allPass;
if (!ok) {
  process.stderr.write('PHASE3 EXPERIMENT FAILED: acceptance criteria not met.\n');
  process.exitCode = 1;
} else {
  process.stderr.write(
    `PHASE3 OK: E1=${E1.qcHolds} E2=${E2.quorumHeldDespiteRefusal} ` +
    `E3=${E3.forgedRejected} E4=${E4.evidenceVerifiable} ` +
    `E5=${E5.unqualifiedNotCounted} E6=${E6.noQuorum}\n`,
  );
}
