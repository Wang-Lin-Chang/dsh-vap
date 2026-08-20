// experiments/phase05-experiment.mjs —— VAP Phase 0.5 实测装置（A-E 五组实验）
//
// 运行：node phase0.5/experiments/phase05-experiment.mjs（在 dsh-vap/ 下）
// 输出：结构化 JSON（stdout + phase0.5/experiments/phase05-results.json）
//
// A 合法代际链：创世锚签 gen-0 → gen-0 持有者审计 gen-1 → gen-1 持有者审计 gen-2（+ 延伸 gen-3）
// B 自我背书攻击：自造审计者无凭证 / 审计者==持有者 → 100% 拒
// C 跨代伪造攻击：编造解 / 伪造签名 / 跳代签高职凭证 → 100% 拒
// D 放水攻击与追责：合格审计者故意签伪造凭证 → 验证门抓出 + trail 留痕可追责
// E 独立复核抽查：100 凭证混入放水件，抽查 20%，度量检出率与误伤率
//
// 零第三方依赖：仅 node:crypto / node:fs / node:path 与相对路径 import。

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createGenesisAnchor,
  createNode,
  issueCredential,
  verifyCredentialChain,
  signAuditTrail,
  auditQuality,
  forgeLaxSign,
} from '../bootstrap-forge.mjs';
import { makeTask, solveTask } from '../../phase0/history-forge.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PHASE05_DIR = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 装置搭建助手
// ---------------------------------------------------------------------------

function setupCtx() {
  const genesis = createGenesisAnchor();
  const ctx = {
    genesis: { id: genesis.id, publicKey: genesis.publicKey },
    keys: new Map([[genesis.id, genesis.publicKey]]),
    credentials: new Map(),
  };
  return { genesis, ctx };
}

function registerNode(ctx, node) {
  ctx.keys.set(node.id, node.publicKey);
  return node;
}

function registerCredential(ctx, cred) {
  ctx.credentials.set(cred.credentialId, cred);
  return cred;
}

function verifyFnFor(ctx) {
  return (entry) => {
    const cred = ctx.credentials.get(entry.credentialId);
    if (!cred) return { pass: false, reasons: ['credential not found in registry'] };
    return verifyCredentialChain(cred, ctx);
  };
}

function cleanDir(dir) {
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

// 造一个持有合法 gen-0 凭证的合格审计者（可用于签 gen-1）。
function makeQualifiedAuditor(ctx, genesis, seed) {
  const node = registerNode(ctx, createNode());
  const res = issueCredential({
    task: makeTask(seed, 2),
    holder: node.id,
    auditors: [genesis],
    generation: 0,
    priorCredential: null,
    ctx,
  });
  if (!res.ok) throw new Error(`makeQualifiedAuditor failed: ${res.reasons.join('; ')}`);
  registerCredential(ctx, res.credential);
  return { node, gen0: res.credential };
}

// ---------------------------------------------------------------------------
// A 合法代际链：gen-0 → gen-1 → gen-2（+ 延伸 gen-3）
// ---------------------------------------------------------------------------

function experimentA() {
  const { genesis, ctx } = setupCtx();
  const n0 = registerNode(ctx, createNode());
  const n1 = registerNode(ctx, createNode());
  const n2 = registerNode(ctx, createNode());
  const n3 = registerNode(ctx, createNode());

  const steps = [];

  const r0 = issueCredential({
    task: makeTask('a-gen0-seed', 2),
    holder: n0.id,
    auditors: [genesis],
    generation: 0,
    priorCredential: null,
    ctx,
  });
  if (!r0.ok) throw new Error(`A gen-0: ${r0.reasons.join('; ')}`);
  registerCredential(ctx, r0.credential);
  steps.push({ generation: 0, holder: n0.id, auditorIds: [genesis.id], credentialId: r0.credential.credentialId });

  const r1 = issueCredential({
    task: makeTask('a-gen1-seed', 2),
    holder: n1.id,
    auditors: [{ ...n0, priorCredential: r0.credential }],
    generation: 1,
    priorCredential: r0.credential,
    ctx,
  });
  if (!r1.ok) throw new Error(`A gen-1: ${r1.reasons.join('; ')}`);
  registerCredential(ctx, r1.credential);
  steps.push({ generation: 1, holder: n1.id, auditorIds: [n0.id], credentialId: r1.credential.credentialId });

  const r2 = issueCredential({
    task: makeTask('a-gen2-seed', 2),
    holder: n2.id,
    auditors: [{ ...n1, priorCredential: r1.credential }],
    generation: 2,
    priorCredential: r1.credential,
    ctx,
  });
  if (!r2.ok) throw new Error(`A gen-2: ${r2.reasons.join('; ')}`);
  registerCredential(ctx, r2.credential);
  steps.push({ generation: 2, holder: n2.id, auditorIds: [n1.id], credentialId: r2.credential.credentialId });

  // 延伸 gen-3（DESIGN §三.4：装置内测到 gen-3）。
  const r3 = issueCredential({
    task: makeTask('a-gen3-seed', 2),
    holder: n3.id,
    auditors: [{ ...n2, priorCredential: r2.credential }],
    generation: 3,
    priorCredential: r2.credential,
    ctx,
  });
  if (!r3.ok) throw new Error(`A gen-3: ${r3.reasons.join('; ')}`);
  registerCredential(ctx, r3.credential);
  steps.push({ generation: 3, holder: n3.id, auditorIds: [n2.id], credentialId: r3.credential.credentialId });

  const verifications = [r0.credential, r1.credential, r2.credential, r3.credential].map((cred) => {
    const res = verifyCredentialChain(cred, ctx);
    const rootNode = res.chain[res.chain.length - 1];
    return {
      generation: cred.generation,
      credentialId: cred.credentialId,
      pass: res.pass,
      reasons: res.reasons,
      rootReached: res.pass && !!rootNode && rootNode.root === 'genesis-anchor',
      chainDepth: res.chain.length,
      chainGenerations: res.chain.map((c) => c.generation),
    };
  });

  const allPass = verifications.every((v) => v.pass && v.rootReached);
  return {
    label: 'legitimate generational chain',
    steps,
    verifications,
    allPass,
    rootReached: allPass,
    chainExtendedToGen3: r3.ok,
  };
}

// ---------------------------------------------------------------------------
// B 自我背书攻击：自造审计者无凭证 / 审计者 == 持有者
// ---------------------------------------------------------------------------

function experimentB() {
  const { ctx } = setupCtx();
  const N = 100;

  // B1：自造 3 个"审计者"（无任何凭证）给攻击者签 gen-1 → 资格不足。
  let a1 = 0;
  let r1 = 0;
  const s1 = [];
  for (let i = 0; i < N; i++) {
    const holder = createNode();
    const auditors = [createNode(), createNode(), createNode()];
    const res = issueCredential({
      task: makeTask(`b1-seed-${i}`, 2),
      holder: holder.id,
      auditors,
      generation: 1,
      priorCredential: null,
      ctx,
    });
    a1 += 1;
    if (!res.ok) {
      r1 += 1;
      if (s1.length < 2) s1.push(res.reasons);
    } else {
      throw new Error('B1: unexpected acceptance');
    }
  }

  // B2：自引用禁止——审计者 == 持有者（自我背书）。
  let a2 = 0;
  let r2 = 0;
  const s2 = [];
  for (let i = 0; i < N; i++) {
    const attacker = createNode();
    const auditors = [attacker, createNode(), createNode()];
    const res = issueCredential({
      task: makeTask(`b2-seed-${i}`, 2),
      holder: attacker.id,
      auditors,
      generation: 1,
      priorCredential: null,
      ctx,
    });
    a2 += 1;
    if (!res.ok) {
      r2 += 1;
      if (s2.length < 2) s2.push(res.reasons);
    } else {
      throw new Error('B2: unexpected acceptance');
    }
  }

  return {
    label: 'self-endorsement attack',
    selfMadeNoQualification: { attempted: a1, rejected: r1, rejectRate: r1 / a1, sampleReasons: s1 },
    selfReference: { attempted: a2, rejected: r2, rejectRate: r2 / a2, sampleReasons: s2 },
  };
}

// ---------------------------------------------------------------------------
// C 跨代伪造攻击：编造解 / 伪造签名 / 跳代签高职凭证
// ---------------------------------------------------------------------------

function experimentC() {
  const { genesis, ctx } = setupCtx();
  const N = 100;

  // C1：攻击者伪造一个 gen-0（编造解），试图凭它获得 gen-1 签发资格 → 重放失败。
  let a1 = 0;
  let r1 = 0;
  const s1 = [];
  for (let i = 0; i < N; i++) {
    const attacker = createNode();
    const holder = createNode();
    const fakeGen0 = {
      work: makeTask(`c1-seed-${i}`, 2),
      solution: crypto.randomBytes(32).toString('hex'),
      auditors: [{ id: genesis.id, sig: 'AAAA' }],
      generation: 0,
      holder: attacker.id,
      prior: null,
      ts: new Date().toISOString(),
      forgedBy: { kind: 'fabricatedSolution' },
    };
    const res = issueCredential({
      task: makeTask(`c1-holder-${i}`, 2),
      holder: holder.id,
      auditors: [{ ...attacker, priorCredential: fakeGen0 }],
      generation: 1,
      priorCredential: fakeGen0,
      ctx,
    });
    a1 += 1;
    if (!res.ok) {
      r1 += 1;
      if (s1.length < 2) s1.push(res.reasons);
    } else {
      throw new Error('C1: unexpected acceptance');
    }
  }

  // C2：攻击者真干了活（正确解）但伪造创世锚签名 → 验签失败。
  let a2 = 0;
  let r2 = 0;
  const s2 = [];
  for (let i = 0; i < N; i++) {
    const attacker = createNode();
    const holder = createNode();
    const work = makeTask(`c2-seed-${i}`, 2);
    const fakeGen0 = {
      work,
      solution: solveTask(work),
      auditors: [{ id: genesis.id, sig: crypto.randomBytes(64).toString('base64') }],
      generation: 0,
      holder: attacker.id,
      prior: null,
      ts: new Date().toISOString(),
      forgedBy: { kind: 'fabricatedSignature' },
    };
    const res = issueCredential({
      task: makeTask(`c2-holder-${i}`, 2),
      holder: holder.id,
      auditors: [{ ...attacker, priorCredential: fakeGen0 }],
      generation: 1,
      priorCredential: fakeGen0,
      ctx,
    });
    a2 += 1;
    if (!res.ok) {
      r2 += 1;
      if (s2.length < 2) s2.push(res.reasons);
    } else {
      throw new Error('C2: unexpected acceptance');
    }
  }

  // C3：合法 gen-0 持有者直接签 gen-2（跳代）→ 资格代际不符。
  let a3 = 0;
  let r3 = 0;
  const s3 = [];
  for (let i = 0; i < N; i++) {
    const qa = makeQualifiedAuditor(ctx, genesis, `c3-gen0-${i}`);
    const holder = createNode();
    const res = issueCredential({
      task: makeTask(`c3-seed-${i}`, 2),
      holder: holder.id,
      auditors: [{ ...qa.node, priorCredential: qa.gen0 }],
      generation: 2,
      priorCredential: qa.gen0,
      ctx,
    });
    a3 += 1;
    if (!res.ok) {
      r3 += 1;
      if (s3.length < 2) s3.push(res.reasons);
    } else {
      throw new Error('C3: unexpected acceptance');
    }
  }

  return {
    label: 'cross-generation forgery attack',
    fabricatedSolution: { attempted: a1, rejected: r1, rejectRate: r1 / a1, sampleReasons: s1 },
    fabricatedSignature: { attempted: a2, rejected: r2, rejectRate: r2 / a2, sampleReasons: s2 },
    crossGeneration: { attempted: a3, rejected: r3, rejectRate: r3 / a3, sampleReasons: s3 },
  };
}

// ---------------------------------------------------------------------------
// D 放水攻击与追责：合格审计者故意签伪造凭证
// ---------------------------------------------------------------------------

function experimentD() {
  const { genesis, ctx } = setupCtx();
  const qa = makeQualifiedAuditor(ctx, genesis, 'd-gen0-seed');
  const victim = registerNode(ctx, createNode());

  // 合格审计者 qa.node（持合法 gen-0）故意放水：签一个解错误的 gen-1 凭证。
  const fakeTask = makeTask('d-lax-gen1-seed', 2);
  const fakeTemplate = {
    work: fakeTask,
    solution: crypto.randomBytes(32).toString('hex'),
    auditors: [],
    generation: 1,
    holder: victim.id,
    prior: [{ auditorId: qa.node.id, credentialId: qa.gen0.credentialId, credential: qa.gen0 }],
    ts: new Date().toISOString(),
    forgedBy: null,
  };
  const lax = forgeLaxSign(qa.node, fakeTemplate);
  registerCredential(ctx, lax);

  // 留痕：审计者签名记录写入其 trail。
  const trailDir = cleanDir(path.join(PHASE05_DIR, 'trails-d'));
  const trail = signAuditTrail(qa.node, lax, trailDir);

  // 验证门抓出（重放失败），trail 留痕可追责。
  const verifyRes = verifyCredentialChain(lax, ctx);
  const audit = auditQuality(trail.file, verifyFnFor(ctx), { sampleRatio: 1 });

  const accountabilityComplete =
    verifyRes.pass === false &&
    verifyRes.reasons.some((r) => r.includes('solution recomputation mismatch')) &&
    audit.evidence.some((e) => e.auditorId === qa.node.id && e.credentialId === lax.credentialId);

  return {
    label: 'lax-sign attack and accountability',
    qualifiedAuditorId: qa.node.id,
    victimHolderId: victim.id,
    laxCredentialId: lax.credentialId,
    laxVerifyPass: verifyRes.pass,
    laxVerifyReasons: verifyRes.reasons,
    trailFile: trail.file,
    trailEntry: trail.line,
    audit: {
      checked: audit.checked,
      passed: audit.passed,
      failed: audit.failed,
      failRate: audit.failRate,
      evidence: audit.evidence,
    },
    accountabilityComplete,
  };
}

// ---------------------------------------------------------------------------
// E 独立复核抽查：100 凭证混入放水件，抽查 20%
// ---------------------------------------------------------------------------

function experimentE() {
  const { genesis, ctx } = setupCtx();
  const qa = makeQualifiedAuditor(ctx, genesis, 'e-gen0-seed');

  const TOTAL = 100;
  const BAD = 20;
  const SAMPLE_RATIO = 0.2;
  const trailDir = cleanDir(path.join(PHASE05_DIR, 'trails-e'));

  const badIds = new Set();
  const goodIds = new Set();

  for (let i = 0; i < TOTAL; i++) {
    const isBad = i < BAD;
    const task = makeTask(`e-cred-${i}`, 2);
    const holderId = `e-holder-${i}`;
    const prior = [{ auditorId: qa.node.id, credentialId: qa.gen0.credentialId, credential: qa.gen0 }];

    let cred;
    if (isBad) {
      // 放水件：合格审计者签一个解错误的 gen-1。
      cred = forgeLaxSign(qa.node, {
        work: task,
        solution: crypto.randomBytes(32).toString('hex'),
        auditors: [],
        generation: 1,
        holder: holderId,
        prior,
        ts: new Date().toISOString(),
        forgedBy: null,
      });
      badIds.add(cred.credentialId);
    } else {
      const res = issueCredential({
        task,
        holder: holderId,
        auditors: [{ ...qa.node, priorCredential: qa.gen0 }],
        generation: 1,
        priorCredential: qa.gen0,
        ctx,
      });
      if (!res.ok) throw new Error(`E good cred ${i}: ${res.reasons.join('; ')}`);
      cred = res.credential;
      goodIds.add(cred.credentialId);
    }
    registerCredential(ctx, cred);
    signAuditTrail(qa.node, cred, trailDir);
  }

  // 复核者抽查 20%。
  const trailFile = path.join(trailDir, `trail-${qa.node.id}.jsonl`);
  const audit = auditQuality(trailFile, verifyFnFor(ctx), { sampleRatio: SAMPLE_RATIO });

  let badInSample = 0;
  let badDetected = 0;
  let goodInSample = 0;
  let goodFlagged = 0;
  for (const id of audit.sampledCredentialIds) {
    if (badIds.has(id)) badInSample += 1;
    else if (goodIds.has(id)) goodInSample += 1;
  }
  for (const e of audit.evidence) {
    if (badIds.has(e.credentialId)) badDetected += 1;
    else if (goodIds.has(e.credentialId)) goodFlagged += 1;
  }

  const detectionRate = badInSample === 0 ? null : badDetected / badInSample;
  const falsePositiveRate = goodInSample === 0 ? 0 : goodFlagged / goodInSample;
  const fullSetRecall = BAD === 0 ? null : badDetected / BAD;

  return {
    label: 'audit spot-check',
    total: TOTAL,
    bad: BAD,
    good: TOTAL - BAD,
    sampleRatio: SAMPLE_RATIO,
    sampled: audit.checked,
    badInSample,
    badDetected,
    detectionRate,
    fullSetRecall,
    goodInSample,
    goodFlagged,
    falsePositiveRate,
    overallFailRate: audit.failRate,
    evidenceCount: audit.evidence.length,
  };
}

// ---------------------------------------------------------------------------
// 结论汇总
// ---------------------------------------------------------------------------

function buildConclusion(A, B, C, D, E) {
  const chainHolds = A.allPass && A.rootReached && A.chainExtendedToGen3;
  const selfEndorsementInfeasible =
    B.selfMadeNoQualification.rejectRate === 1 && B.selfReference.rejectRate === 1;
  const crossGenerationForgeryRejected =
    C.fabricatedSolution.rejectRate === 1 &&
    C.fabricatedSignature.rejectRate === 1 &&
    C.crossGeneration.rejectRate === 1;
  const laxSignAccountable = D.accountabilityComplete;
  const spotCheckEffective = E.detectionRate > 0 && E.falsePositiveRate === 0;

  const bootstrapHolds =
    chainHolds &&
    selfEndorsementInfeasible &&
    crossGenerationForgeryRejected &&
    laxSignAccountable &&
    spotCheckEffective;

  return {
    chainHolds,
    selfEndorsementInfeasible,
    crossGenerationForgeryRejected,
    laxSignAccountable,
    spotCheckEffective,
    bootstrapHolds,
    genesisAnchorNote: '唯一中心化假设：创世锚（诚实标注）；其余信任由代际凭证链 + 审计留痕 + 独立复核抽查推导',
    verdict: bootstrapHolds
      ? '自举成立：除创世锚外无中心化假设，代际链可延伸至 gen-3，自我背书与跨代伪造 100% 拒，放水可追责，独立复核抽查有效'
      : '自举不成立：见 A-E 各项失败原因',
  };
}

// ---------------------------------------------------------------------------
// 运行 + 输出
// ---------------------------------------------------------------------------

const A = experimentA();
const B = experimentB();
const C = experimentC();
const D = experimentD();
const E = experimentE();
const bootstrapConclusion = buildConclusion(A, B, C, D, E);

const summary = {
  experiment: 'phase05-bootstrap-forge',
  generatedAt: new Date().toISOString(),
  zeroDependency: true,
  A,
  B,
  C,
  D,
  E,
  bootstrapConclusion,
};

const json = JSON.stringify(summary, null, 2);
process.stdout.write(json + '\n');

fs.mkdirSync(__dirname, { recursive: true });
fs.writeFileSync(path.join(__dirname, 'phase05-results.json'), json + '\n', 'utf8');

// 硬性验收自检。
const ok = bootstrapConclusion.bootstrapHolds;
if (!ok) {
  process.stderr.write('PHASE05 EXPERIMENT FAILED: acceptance criteria not met.\n');
  process.exitCode = 1;
} else {
  process.stderr.write(
    `PHASE05 OK: chain=${bootstrapConclusion.chainHolds} ` +
    `selfEndorsementRejected=${bootstrapConclusion.selfEndorsementInfeasible} ` +
    `crossGenRejected=${bootstrapConclusion.crossGenerationForgeryRejected} ` +
    `laxAccountable=${bootstrapConclusion.laxSignAccountable} ` +
    `spotCheckEffective=${bootstrapConclusion.spotCheckEffective}\n`,
  );
}
