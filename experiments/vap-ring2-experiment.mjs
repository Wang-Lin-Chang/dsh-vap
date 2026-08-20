// experiments/vap-ring2-experiment.mjs —— VAP 中环二期实测装置（独立可运行）
//
// 真 HTTP 本地回环，零第三方依赖。三个子实验：
//   R1 重放：同一信封 POST 两次 → 202 然后 409（nonce 防重放）；
//   R2 链式组网：A(peers=[B]) → B(peers=[C]) → C；节点 X 经 A 发真信封 →
//      节点 Y 从 C 拉到 → 验签 + 三闸通过入账；伪信封（无签名）同样经链送达后被身份闸拦截；
//   R3 环路：A(peers=[B]) 与 B(peers=[A]) 互连，信封经 A 进入 → 转发终止（无死循环）。
// 输出结构化 JSON 总结；任一判定失败时以非零退出码报告。
//
// 运行：node experiments/vap-ring2-experiment.mjs

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';

import { createVapNode, createBrain, makeLaws } from '../vap-core.mjs';
import { createFileTransport, createHttpGateway, createHttpClient } from '../vap-transport.mjs';

function makeRoot(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `vap-ring2-${tag}-`));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

function validParams() {
  return {
    to: 'brain',
    claim: { type: 'report', body: { work: 'ring2' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:ring2' },
    boundary: 'L2a',
    report: { summary: '中环二期实测', keyNumbers: [2], request: '' },
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

function countInboxJson(root) {
  const dir = path.join(root, 'inbox-http');
  try {
    return fs.readdirSync(dir).filter((n) => n.endsWith('.json')).length;
  } catch {
    return 0;
  }
}

function readRelayLog(root) {
  const file = path.join(root, 'relay-log.jsonl');
  try {
    return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// R1：重放防护
// ---------------------------------------------------------------------------

async function runR1() {
  const root = makeRoot('r1');
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  const client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
  const node = createVapNode({ nodeId: 'x', root: makeRoot('r1-node') });
  const env = node.send(validParams());
  const first = await client.post(env);
  const second = await client.post(env);
  await gw.stop();
  const replayRejected = first.status === 202 && second.status === 409;
  return {
    port,
    envelope: { id: env.id, hasNonce: typeof env.nonce === 'string' && env.nonce.length > 0 },
    first: { status: first.status, ok: first.ok },
    second: { status: second.status, ok: second.ok, error: second.error },
    replayRejected,
  };
}

// ---------------------------------------------------------------------------
// R2：链式组网 A→B→C，真入账 / 伪拦截
// ---------------------------------------------------------------------------

async function runR2() {
  // R2 钉的是「网关只搬运、伪信封由接收方三道闸拦截」这条链路语义。
  // 修复批次 1（M7）后网关默认前置验签（无签名 → 403），故本场景显式退回只搬运模式；
  // 「网关前置 403」本身由 tests/security-regression.test.mjs 钉死。
  const carryOnly = { requireInboundSignature: false };
  const rootC = makeRoot('r2-c');
  const gwC = createHttpGateway({ port: 0, root: rootC, ...carryOnly });
  const portC = await gwC.start();
  const rootB = makeRoot('r2-b');
  const gwB = createHttpGateway({ port: 0, root: rootB, peers: [`http://127.0.0.1:${portC}`], ...carryOnly });
  const portB = await gwB.start();
  const rootA = makeRoot('r2-a');
  const gwA = createHttpGateway({ port: 0, root: rootA, peers: [`http://127.0.0.1:${portB}`], ...carryOnly });
  const portA = await gwA.start();
  const clientA = createHttpClient({ baseUrl: `http://127.0.0.1:${portA}` });

  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot('r2-x') });
  nodeX.register();
  const nodeY = createVapNode({ nodeId: 'y', root: makeRoot('r2-y') });
  const brainY = createBrain({ root: nodeY.root });
  const ftY = createFileTransport({ root: nodeY.root });

  function consumeAtY(received) {
    if (!received) return { verdict: null, credited: false };
    const verifyResult = nodeY.verify(received);
    ftY.send(received);
    const consumed = brainY.consume();
    const verdict = consumed.find((c) => c.envelopeId === received.id) || null;
    const credited = Boolean(verdict && verdict.pass) &&
      fs.existsSync(path.join(nodeY.root, 'done', `${received.id}.json`));
    return { verifyResult, verdict, credited };
  }

  // 真信封：经 A → B → C 链送达，Y 从 C 拉到并验三闸入账
  const real = nodeX.send(validParams());
  const realPost = await clientA.post(real);
  const realAtC = await waitFor(() => fs.existsSync(path.join(rootC, 'inbox-http', `${real.id}.json`)));
  const realReceived = realAtC
    ? JSON.parse(fs.readFileSync(path.join(rootC, 'inbox-http', `${real.id}.json`), 'utf8'))
    : null;
  const realOutcome = consumeAtY(realReceived);

  // 伪信封（无签名）：同样经链送达，被身份闸拦截
  const forged = nodeX.send(validParams());
  forged.sig = '';
  const forgedPost = await clientA.post(forged);
  const forgedAtC = await waitFor(() => fs.existsSync(path.join(rootC, 'inbox-http', `${forged.id}.json`)));
  const forgedReceived = forgedAtC
    ? JSON.parse(fs.readFileSync(path.join(rootC, 'inbox-http', `${forged.id}.json`), 'utf8'))
    : null;
  const forgedOutcome = consumeAtY(forgedReceived);
  const forgedIntercepted = Boolean(forgedOutcome.verdict && !forgedOutcome.verdict.pass) &&
    (forgedOutcome.verdict.reasons || []).some((r) => r.includes('SIG_REQUIRED'));

  const health = { A: gwA.health(), B: gwB.health(), C: gwC.health() };
  await gwA.stop();
  await gwB.stop();
  await gwC.stop();

  return {
    ports: { A: portA, B: portB, C: portC },
    health,
    real: {
      id: real.id,
      post: { status: realPost.status },
      reachedC: realAtC,
      verifyPass: realOutcome.verifyResult ? realOutcome.verifyResult.pass : null,
      verdict: realOutcome.verdict
        ? { pass: realOutcome.verdict.pass, reasons: realOutcome.verdict.reasons }
        : null,
      credited: realOutcome.credited,
    },
    forged: {
      id: forged.id,
      signed: Boolean(forged.sig),
      post: { status: forgedPost.status },
      reachedC: forgedAtC,
      verifyPass: forgedOutcome.verifyResult ? forgedOutcome.verifyResult.pass : null,
      verdict: forgedOutcome.verdict
        ? { pass: forgedOutcome.verdict.pass, reasons: forgedOutcome.verdict.reasons }
        : null,
      intercepted: forgedIntercepted,
    },
    ok: realOutcome.credited && forgedIntercepted,
  };
}

// ---------------------------------------------------------------------------
// R3：环路 A↔B，转发终止
// ---------------------------------------------------------------------------

async function runR3() {
  const portA = await getFreePort();
  const portB = await getFreePort();
  const rootA = makeRoot('r3-a');
  const rootB = makeRoot('r3-b');
  const gwA = createHttpGateway({ port: portA, root: rootA, peers: [`http://127.0.0.1:${portB}`] });
  const gwB = createHttpGateway({ port: portB, root: rootB, peers: [`http://127.0.0.1:${portA}`] });
  await gwA.start();
  await gwB.start();
  const client = createHttpClient({ baseUrl: `http://127.0.0.1:${portA}` });
  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot('r3-x') });
  const env = nodeX.send(validParams());
  const post = await client.post(env);
  await new Promise((r) => setTimeout(r, 800)); // 等异步转发尘埃落定

  const healthA = gwA.health();
  const healthB = gwB.health();
  const inboxA = countInboxJson(rootA);
  const inboxB = countInboxJson(rootB);
  const relayLogA = readRelayLog(rootA);
  const relayLogB = readRelayLog(rootB);

  await gwA.stop();
  await gwB.stop();

  const terminated = healthA.relayed === 1 && healthB.relayed === 1 && inboxA === 1 && inboxB === 1;
  return {
    ports: { A: portA, B: portB },
    post: { status: post.status },
    envelope: { id: env.id },
    healthA,
    healthB,
    inboxA,
    inboxB,
    relayLogA,
    relayLogB,
    terminated,
  };
}

async function main() {
  const r1 = await runR1();
  const r2 = await runR2();
  const r3 = await runR3();

  const summary = {
    experiment: 'vap-ring2-experiment',
    r1,
    r2,
    r3,
    verdict: {
      r1ReplayRejected: r1.replayRejected,
      r2ChainRealCreditedForgedIntercepted: r2.ok,
      r3LoopTerminated: r3.terminated,
      allPass: r1.replayRejected && r2.ok && r3.terminated,
    },
  };

  console.log(JSON.stringify(summary, null, 2));

  if (!summary.verdict.allPass) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(JSON.stringify({
    experiment: 'vap-ring2-experiment',
    error: String((err && err.message) || err),
  }, null, 2));
  process.exitCode = 1;
});
