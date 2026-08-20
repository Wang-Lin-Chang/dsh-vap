// phase1/tests/transport-spi.test.mjs —— VAP Phase 1 传输 SPI 单测（node:test，零第三方依赖）
//
// 覆盖三大块（对应 brief.md 交付物 4）：
//   ① SPI 无损：File/Http 两种 transport 跑通 send/recv，信封经 SPI 往返后验签 + 三闸不破；
//   ② 身份绑定违规：构造「信封 from.pubKey ≠ 传输层持有者密钥」的攻击 → 验证门必拒；
//   ③ transportConformance 对缺能力/缺方法实现报诊断。
// 不伪造测试、不依赖外部进程；HTTP 异步转发用轮询兜底（非真实长等待）。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { createVapNode, createBrain, makeLaws, canonicalJson } from '../../vap-core.mjs';
import {
  createFileTransport,
  createHttpTransport,
  transportConformance,
} from '../transport-spi.mjs';

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-spi-'));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

function validSendParams(overrides = {}) {
  return {
    to: 'brain',
    claim: { type: 'report', body: { work: 'spi' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:spi' },
    boundary: 'L2a',
    report: { summary: 'spi lossless', keyNumbers: [1], request: '' },
    ...overrides,
  };
}

// 测试脚手架：重建签名对象字段（镜像 vap-core §1 签名规范，含 nonce），
// 用任意私钥给信封签名。仅用于构造「传输层密钥冒充协议身份」的攻击与对照，非生产逻辑。
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

async function waitFor(cond, timeoutMs = 2000, intervalMs = 20) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return cond();
}

// ---------------------------------------------------------------------------
// File SPI：形状 + 往返无损
// ---------------------------------------------------------------------------

test('File SPI：形状完整（name/capabilities/send/recv/peers/close）', () => {
  const t = createFileTransport({ root: makeRoot() });
  assert.equal(t.name, 'file');
  assert.deepEqual(t.capabilities, ['send', 'recv']);
  for (const m of ['send', 'recv', 'peers', 'close']) {
    assert.equal(typeof t[m], 'function', m);
  }
  const diag = transportConformance(t);
  assert.equal(diag.ok, true, JSON.stringify(diag));
  assert.deepEqual(diag.missing, []);
  assert.deepEqual(diag.diagnostics, []);
  assert.deepEqual(t.peers(), []);
  t.close(); // 无句柄，调用不抛
});

test('File SPI：send → recv 往返，信封验签 + 三闸不破', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-spi', root });
  node.register();
  const t = createFileTransport({ root });

  const env = node.send(validSendParams());
  const sent = t.send(env);
  assert.equal(sent, env);
  const received = t.recv();
  assert.equal(received.length, 1);
  assert.equal(received[0].id, env.id);
  assert.deepEqual(received[0], env);

  const verdict = node.verify(received[0]);
  assert.equal(verdict.pass, true);
  assert.equal(verdict.gates.identity.pass, true);
  assert.equal(verdict.gates.laws.pass, true);
  assert.equal(verdict.gates.boundary.pass, true);
});

test('File SPI：信封经 SPI 往返后脑进程入账（无损）', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-spi', root });
  node.register();
  const brain = createBrain({ root });
  const t = createFileTransport({ root });

  const env = node.send(validSendParams());
  t.send(env);
  const received = t.recv();
  assert.equal(received.length, 1);

  const verdicts = brain.consume();
  assert.equal(verdicts.length, 1);
  assert.equal(verdicts[0].envelopeId, env.id);
  assert.equal(verdicts[0].pass, true);
  assert.ok(fs.existsSync(path.join(root, 'done', `${env.id}.json`)));
});

// ---------------------------------------------------------------------------
// Http SPI：形状 + 往返无损 + 中环回归（链转发/伪造拦截/重放 409）
// ---------------------------------------------------------------------------

test('Http SPI：形状完整（name/capabilities/send/recv/peers/close/start）', async () => {
  const t = createHttpTransport({ port: 0, root: makeRoot() });
  assert.equal(t.name, 'http');
  assert.deepEqual(t.capabilities, ['dial', 'send', 'recv', 'peers']);
  for (const m of ['send', 'recv', 'peers', 'close']) {
    assert.equal(typeof t[m], 'function', m);
  }
  const diag = transportConformance(t);
  assert.equal(diag.ok, true, JSON.stringify(diag));
  assert.deepEqual(t.peers(), []);
  await t.close();
});

test('Http SPI：send → recv 往返，信封验签 + 三闸不破', async () => {
  const rootG = makeRoot();
  const tG = createHttpTransport({ port: 0, root: rootG });
  const portG = await tG.start();
  const nodeX = createVapNode({ nodeId: 'node-x', root: makeRoot() });
  const tX = createHttpTransport({ port: 0, root: makeRoot(), baseUrl: `http://127.0.0.1:${portG}` });
  try {
    const env = nodeX.send(validSendParams());
    const posted = await tX.send(env);
    assert.equal(posted.status, 202);
    assert.equal(posted.ok, true);

    const received = tG.recv();
    assert.equal(received.length, 1);
    assert.equal(received[0].id, env.id);

    const verifier = createVapNode({ nodeId: 'verifier', root: rootG });
    const verdict = verifier.verify(received[0]);
    assert.equal(verdict.pass, true);
    assert.equal(verdict.gates.identity.pass, true);
    assert.equal(verdict.gates.laws.pass, true);
    assert.equal(verdict.gates.boundary.pass, true);
  } finally {
    await tX.close();
    await tG.close();
  }
});

test('Http SPI：链式转发 A→B→C（SPI 无损）', async () => {
  const rootC = makeRoot();
  const tC = createHttpTransport({ port: 0, root: rootC });
  const portC = await tC.start();
  const rootB = makeRoot();
  const tB = createHttpTransport({ port: 0, root: rootB, peers: [`http://127.0.0.1:${portC}`] });
  const portB = await tB.start();
  const rootA = makeRoot();
  const tA = createHttpTransport({ port: 0, root: rootA, peers: [`http://127.0.0.1:${portB}`] });
  const portA = await tA.start();
  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot() });
  const tX = createHttpTransport({ port: 0, root: makeRoot(), baseUrl: `http://127.0.0.1:${portA}` });
  try {
    const env = nodeX.send(validSendParams());
    const posted = await tX.send(env);
    assert.equal(posted.status, 202);
    const atC = await waitFor(() => tC.recv().some((e) => e.id === env.id));
    assert.equal(atC, true, '信封应经链 A→B→C 送达 C');
  } finally {
    await tX.close();
    await tA.close();
    await tB.close();
    await tC.close();
  }
});

test('Http SPI：无签名伪造经 SPI 被三闸拦截', async () => {
  const rootG = makeRoot();
  // 修复批次 1（M7）后网关默认前置验签（无签名 → 403）。本条钉的是 SPI 只搬运、
  // 判定归三道闸的语义，故显式关闭前置验签保留原断言。
  const tG = createHttpTransport({ port: 0, root: rootG, requireInboundSignature: false });
  const portG = await tG.start();
  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot() });
  const tX = createHttpTransport({ port: 0, root: makeRoot(), baseUrl: `http://127.0.0.1:${portG}` });
  try {
    const forged = nodeX.send(validSendParams());
    forged.sig = ''; // 伪造：无签名
    const posted = await tX.send(forged);
    assert.equal(posted.status, 202);

    const received = tG.recv().find((e) => e.id === forged.id);
    assert.ok(received);
    const verifier = createVapNode({ nodeId: 'verifier', root: rootG });
    const verdict = verifier.verify(received);
    assert.equal(verdict.pass, false);
    assert.equal(verdict.gates.identity.pass, false);
    assert.ok(verdict.gates.laws.reasons.some((r) => r.startsWith('SIG_REQUIRED:')));
  } finally {
    await tX.close();
    await tG.close();
  }
});

test('Http SPI：重放 409（同一信封第二次 send 被拒，不落盘）', async () => {
  const rootG = makeRoot();
  const tG = createHttpTransport({ port: 0, root: rootG });
  const portG = await tG.start();
  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot() });
  const tX = createHttpTransport({ port: 0, root: makeRoot(), baseUrl: `http://127.0.0.1:${portG}` });
  try {
    const env = nodeX.send(validSendParams());
    const first = await tX.send(env);
    assert.equal(first.status, 202);
    const second = await tX.send(env);
    assert.equal(second.status, 409);
    assert.equal(second.ok, false);
    assert.equal(second.error, 'replay rejected');
    assert.equal(tG.recv().length, 1, '重放不落盘：inbox-http 仍只有第一封');
  } finally {
    await tX.close();
    await tG.close();
  }
});

// ---------------------------------------------------------------------------
// 身份绑定违规：传输层密钥冒充协议身份必拒
// ---------------------------------------------------------------------------

test('身份绑定：传输层密钥冒充协议身份必拒（from.pubKey ≠ 持有者密钥）', () => {
  const victim = createVapNode({ nodeId: 'victim', root: makeRoot() });
  victim.register();
  // 攻击者 = 传输层持有者（本地密钥，例如未来的 libp2p PeerID 对应角色）。
  const attacker = createVapNode({ nodeId: 'attacker', root: makeRoot() });
  assert.notEqual(attacker.pubKey, victim.pubKey, '前提：两把密钥不同');

  const base = {
    v: 1,
    id: 'evt-impersonation',
    nonce: crypto.randomBytes(8).toString('hex'),
    ts: new Date().toISOString(),
    to: 'brain',
    claim: { type: 'report', body: {} },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:imp' },
    boundary: 'L2a',
    report: { summary: 'impersonation', keyNumbers: [], request: '' },
  };

  // 对照：攻击者用自己的协议身份签名 → 验签通过（证明脚手架签名本身合法）。
  const selfClaimed = { ...base, from: { nodeId: 'attacker', pubKey: attacker.pubKey }, sig: '' };
  selfClaimed.sig = signWithKey(attacker.privateKey, selfClaimed);
  assert.equal(attacker.verify(selfClaimed).pass, true, '对照：attacker 自签应通过');

  // 攻击：from 冒充 victim 的协议身份，但用 attacker（传输层持有者）的密钥签名。
  const impersonation = { ...base, from: { nodeId: 'victim', pubKey: victim.pubKey }, sig: '' };
  impersonation.sig = signWithKey(attacker.privateKey, impersonation);

  // 验证门必拒：协议身份（from.pubKey=victim）≠ 信封签名者（attacker 的密钥）。
  const verdict = victim.verify(impersonation);
  assert.equal(verdict.pass, false);
  assert.equal(verdict.gates.identity.pass, false);
  assert.equal(verdict.gates.identity.reason, 'signature verification failed');
  assert.ok(verdict.gates.laws.reasons.some((r) => r.startsWith('SIG_REQUIRED:')));
});

// ---------------------------------------------------------------------------
// transportConformance：缺能力/缺方法实现报诊断
// ---------------------------------------------------------------------------

test('transportConformance：对缺能力/缺方法实现报诊断', () => {
  // 非对象 → 直接诊断。
  const none = transportConformance(null);
  assert.equal(none.ok, false);
  assert.ok(none.missing.includes('transport'));
  assert.ok(none.diagnostics.length > 0);

  // 缺 name 与 send（但 recv/peers/close 在）。
  const broken = {
    capabilities: ['send', 'recv'],
    recv() { return []; },
    peers() { return []; },
    close() {},
  };
  const r1 = transportConformance(broken);
  assert.equal(r1.ok, false);
  assert.ok(r1.missing.includes('name'));
  assert.ok(r1.missing.includes('send'));
  assert.ok(r1.diagnostics.some((d) => d.includes('send')));

  // 声明能力但方法缺失 + 未知能力位。
  const wrong = {
    name: 'weird',
    capabilities: ['send', 'dial', 'teleport'],
    recv() { return []; },
    peers() { return []; },
    close() {},
  };
  const r2 = transportConformance(wrong);
  assert.equal(r2.ok, false);
  assert.ok(r2.missing.includes('send'), 'capabilities 声明 send 但无 send()');
  assert.ok(r2.diagnostics.some((d) => d.includes("unknown capability 'teleport'")));
});
