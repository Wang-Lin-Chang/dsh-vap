// phase1/experiments/phase1-experiment.mjs —— VAP Phase 1 SPI 实测装置（独立可运行）
//
// 在 HttpTransport（SPI 形状）上重跑中环四场景 + 身份绑定攻击拦截，零第三方依赖。
//   S1 链转发：  A(peers=[B])→B(peers=[C])→C，节点 X 经 SPI send 到 A，信封达 C，验签 + 三闸入账；
//   S2 伪造拦截：无签名信封经 SPI 送达后被身份闸拦截；
//   S3 重放 409：同一信封第二次 send 返回 409（不落盘）；
//   S4 环路终止：A↔B 互连，relayed 去重 + nonce 双兜底，转发终止（无死循环）；
//   I1 身份绑定：攻击者用传输层密钥签名、from 冒充受害者协议身份 → 验证门必拒。
// 输出结构化 JSON（spiLossless / identityBindingHolds）；判定失败以非零退出码报告。
//
// 运行：node phase1/experiments/phase1-experiment.mjs（在 dsh-vap/ 下）

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';

import { createVapNode, createBrain, makeLaws, canonicalJson } from '../../vap-core.mjs';
import { createFileTransport, createHttpTransport, transportConformance } from '../transport-spi.mjs';

function makeRoot(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `vap-phase1-${tag}-`));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

function validParams() {
  return {
    to: 'brain',
    claim: { type: 'report', body: { work: 'phase1' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:phase1' },
    boundary: 'L2a',
    report: { summary: 'Phase1 SPI 实测', keyNumbers: [1], request: '' },
  };
}

function waitFor(cond, timeoutMs = 3000, intervalMs = 20) {
  return new Promise((resolve) => {
    const start = Date.now();
    const tick = () => {
      if (cond()) return resolve(true);
      if (Date.now() - start >= timeoutMs) return resolve(cond());
      setTimeout(tick, intervalMs);
    };
    tick();
  });
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

// 测试脚手架：重建签名对象字段（镜像 vap-core §1 签名规范，含 nonce），用任意私钥签名。
function signPayloadFields(envelope) {
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

function signWithKey(privateKey, envelope) {
  return crypto
    .sign(null, Buffer.from(canonicalJson(signPayloadFields(envelope)), 'utf8'), privateKey)
    .toString('base64');
}

// ---------------------------------------------------------------------------
// S1 链转发：真信封 A→B→C，C 验签 + 三闸入账
// ---------------------------------------------------------------------------

async function runChainForward() {
  const rootC = makeRoot('s1-c');
  const tC = createHttpTransport({ port: 0, root: rootC });
  const portC = await tC.start();
  const rootB = makeRoot('s1-b');
  const tB = createHttpTransport({ port: 0, root: rootB, peers: [`http://127.0.0.1:${portC}`] });
  const portB = await tB.start();
  const rootA = makeRoot('s1-a');
  const tA = createHttpTransport({ port: 0, root: rootA, peers: [`http://127.0.0.1:${portB}`] });
  const portA = await tA.start();

  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot('s1-x') });
  const tX = createHttpTransport({ port: 0, root: makeRoot('s1-x-net'), baseUrl: `http://127.0.0.1:${portA}` });

  const verifier = createVapNode({ nodeId: 'verifier', root: rootC });
  const rootBrain = makeRoot('s1-brain');
  const brain = createBrain({ root: rootBrain });
  const ftBrain = createFileTransport({ root: rootBrain });

  const env = nodeX.send(validParams());
  const posted = await tX.send(env);
  const atC = await waitFor(() => tC.recv().some((e) => e.id === env.id));
  const received = atC ? tC.recv().find((e) => e.id === env.id) : null;
  const verifyResult = received ? verifier.verify(received) : null;
  let credited = false;
  if (received) {
    ftBrain.send(received);
    const verdicts = brain.consume();
    const v = verdicts.find((c) => c.envelopeId === received.id);
    credited = Boolean(v && v.pass) && fs.existsSync(path.join(rootBrain, 'done', `${received.id}.json`));
  }
  const ok = posted.status === 202 && atC && verifyResult && verifyResult.pass === true && credited;

  await tX.close();
  await tA.close();
  await tB.close();
  await tC.close();

  return {
    ports: { A: portA, B: portB, C: portC },
    envelopeId: env.id,
    postStatus: posted.status,
    reachedC: atC,
    verifyPass: verifyResult ? verifyResult.pass : null,
    credited,
    ok,
  };
}

// ---------------------------------------------------------------------------
// S2 伪造拦截：无签名信封经链送达后被身份闸拦截
// ---------------------------------------------------------------------------

async function runForgeryIntercept() {
  // S2 钉的是「SPI 只搬运、伪信封由接收方三道闸拦截」这条语义。修复批次 1（M7）后
  // 网关默认前置验签（无签名 → 403），故本场景显式退回只搬运模式；
  // 「网关前置 403」本身由 tests/security-regression.test.mjs 钉死。
  const carryOnly = { requireInboundSignature: false };
  const rootC = makeRoot('s2-c');
  const tC = createHttpTransport({ port: 0, root: rootC, ...carryOnly });
  const portC = await tC.start();
  const rootB = makeRoot('s2-b');
  const tB = createHttpTransport({ port: 0, root: rootB, peers: [`http://127.0.0.1:${portC}`], ...carryOnly });
  const portB = await tB.start();
  const rootA = makeRoot('s2-a');
  const tA = createHttpTransport({ port: 0, root: rootA, peers: [`http://127.0.0.1:${portB}`], ...carryOnly });
  const portA = await tA.start();

  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot('s2-x') });
  const tX = createHttpTransport({ port: 0, root: makeRoot('s2-x-net'), baseUrl: `http://127.0.0.1:${portA}`, ...carryOnly });
  const verifier = createVapNode({ nodeId: 'verifier', root: rootC });

  const forged = nodeX.send(validParams());
  forged.sig = '';
  const posted = await tX.send(forged);
  const atC = await waitFor(() => tC.recv().some((e) => e.id === forged.id));
  const received = atC ? tC.recv().find((e) => e.id === forged.id) : null;
  const verdict = received ? verifier.verify(received) : null;
  const intercepted = Boolean(verdict && !verdict.pass && verdict.gates.identity.pass === false) &&
    (verdict.gates.laws.reasons || []).some((r) => r.startsWith('SIG_REQUIRED:'));
  const ok = posted.status === 202 && atC && intercepted;

  await tX.close();
  await tA.close();
  await tB.close();
  await tC.close();

  return {
    ports: { A: portA, B: portB, C: portC },
    envelopeId: forged.id,
    postStatus: posted.status,
    reachedC: atC,
    verifyPass: verdict ? verdict.pass : null,
    intercepted,
    ok,
  };
}

// ---------------------------------------------------------------------------
// S3 重放 409：同一信封第二次 send 被拒且不落盘
// ---------------------------------------------------------------------------

async function runReplay409() {
  const rootG = makeRoot('s3-g');
  const tG = createHttpTransport({ port: 0, root: rootG });
  const portG = await tG.start();
  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot('s3-x') });
  const tX = createHttpTransport({ port: 0, root: makeRoot('s3-x-net'), baseUrl: `http://127.0.0.1:${portG}` });

  const env = nodeX.send(validParams());
  const first = await tX.send(env);
  const second = await tX.send(env);
  const inboxCount = tG.recv().length;
  const ok = first.status === 202 && second.status === 409 && inboxCount === 1;

  await tX.close();
  await tG.close();

  return {
    envelopeId: env.id,
    firstStatus: first.status,
    secondStatus: second.status,
    secondError: second.error,
    inboxCount,
    ok,
  };
}

// ---------------------------------------------------------------------------
// S4 环路终止：A↔B 互连，relayed + nonce 双兜底，转发终止
// ---------------------------------------------------------------------------

async function runLoopTermination() {
  const portA = await getFreePort();
  const portB = await getFreePort();
  const rootA = makeRoot('s4-a');
  const rootB = makeRoot('s4-b');
  const tA = createHttpTransport({ port: portA, root: rootA, peers: [`http://127.0.0.1:${portB}`] });
  const tB = createHttpTransport({ port: portB, root: rootB, peers: [`http://127.0.0.1:${portA}`] });
  await tA.start();
  await tB.start();

  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot('s4-x') });
  const tX = createHttpTransport({ port: 0, root: makeRoot('s4-x-net'), baseUrl: `http://127.0.0.1:${portA}` });

  const env = nodeX.send(validParams());
  const post = await tX.send(env);
  await new Promise((r) => setTimeout(r, 800)); // 等异步转发尘埃落定

  const healthA = tA.health();
  const healthB = tB.health();
  const inboxA = tA.recv().length;
  const inboxB = tB.recv().length;
  const terminated = healthA.relayed === 1 && healthB.relayed === 1 && inboxA === 1 && inboxB === 1;

  await tX.close();
  await tA.close();
  await tB.close();

  return {
    ports: { A: portA, B: portB },
    envelopeId: env.id,
    postStatus: post.status,
    relayedA: healthA.relayed,
    relayedB: healthB.relayed,
    inboxA,
    inboxB,
    terminated,
    ok: terminated,
  };
}

// ---------------------------------------------------------------------------
// I1 身份绑定攻击：传输层密钥签名、from 冒充受害者协议身份 → 验证门必拒
// ---------------------------------------------------------------------------

async function runIdentityImpersonation() {
  const victim = createVapNode({ nodeId: 'victim', root: makeRoot('i1-victim') });
  victim.register();
  const attacker = createVapNode({ nodeId: 'attacker', root: makeRoot('i1-attacker') });

  const base = {
    v: 1,
    id: 'evt-impersonation',
    nonce: crypto.randomBytes(8).toString('hex'),
    ts: new Date().toISOString(),
    to: 'brain',
    claim: { type: 'report', body: {} },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:i1' },
    boundary: 'L2a',
    report: { summary: 'impersonation', keyNumbers: [], request: '' },
  };

  const impersonation = { ...base, from: { nodeId: 'victim', pubKey: victim.pubKey }, sig: '' };
  impersonation.sig = signWithKey(attacker.privateKey, impersonation);

  const verdict = victim.verify(impersonation);
  const intercepted = !verdict.pass && verdict.gates.identity.pass === false;

  return {
    attackerPubKey: attacker.pubKey,
    victimPubKey: victim.pubKey,
    keysDiffer: attacker.pubKey !== victim.pubKey,
    fromClaimsVictim: impersonation.from.pubKey === victim.pubKey,
    signedByAttacker: impersonation.from.pubKey !== attacker.pubKey,
    verdictPass: verdict.pass,
    identityGatePass: verdict.gates.identity.pass,
    identityReason: verdict.gates.identity.reason,
    intercepted,
  };
}

// ---------------------------------------------------------------------------
// 汇总
// ---------------------------------------------------------------------------

async function main() {
  const s1 = await runChainForward();
  const s2 = await runForgeryIntercept();
  const s3 = await runReplay409();
  const s4 = await runLoopTermination();
  const i1 = await runIdentityImpersonation();

  // SPI 一致性：对 File 与 Http 两种形状各做一次诊断（无损判据的一部分）。
  const fileDiag = transportConformance(createFileTransport({ root: makeRoot('diag-f') }));
  const httpDiag = transportConformance(createHttpTransport({ port: 0, root: makeRoot('diag-h') }));

  const spiLossless = s1.ok && s2.ok && s3.ok && s4.ok;
  const identityBindingHolds = i1.intercepted;

  const summary = {
    experiment: 'phase1-experiment',
    conformance: {
      file: fileDiag,
      http: httpDiag,
    },
    scenarios: {
      chainForward: s1,
      forgeryIntercept: s2,
      replay409: s3,
      loopTermination: s4,
      identityImpersonation: i1,
    },
    spiLossless,
    identityBindingHolds,
    allPass: spiLossless && identityBindingHolds,
  };

  console.log(JSON.stringify(summary, null, 2));

  if (!summary.allPass) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(JSON.stringify({
    experiment: 'phase1-experiment',
    error: String((err && err.message) || err),
  }, null, 2));
  process.exitCode = 1;
});
