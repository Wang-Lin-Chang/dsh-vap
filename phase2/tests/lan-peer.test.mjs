// phase2/tests/lan-peer.test.mjs —— VAP Phase 2 LAN P2P 单测（node:test，零第三方依赖）
//
// 覆盖 brief.md 交付物 2 的五个用例，全部本机回环、短超时（≤5s）：
//   ① 发现：两节点经 UDP 组播互相发现（peer 表含对方）；
//   ② 洪泛投递：A 发 → B 收到且三闸验签通过；
//   ③ 去重：同 id 信封二次到达不触发回调；
//   ④ TTL 递减：TTL≤1 不转发（TTL=2 才转发一跳）；
//   ⑤ 身份绑定：信封 from.pubKey 与 announce 注册的 pubKey 不一致 → 拒收（identity mismatch）。
// 不伪造测试、不依赖真实局域网；组播只用于「发现」用例，其余用例用 addPeer 确定性拓扑。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { createVapNode, makeLaws, canonicalJson } from '../../vap-core.mjs';
import { createLanPeer } from '../lan-peer.mjs';

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-lan-test-'));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

function makeKeyPair() {
  return crypto.generateKeyPairSync('ed25519');
}

function pubKeyOf(keyPair) {
  return keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}

function validParams() {
  return {
    to: 'brain',
    claim: { type: 'report', body: { work: 'phase2-lan' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:phase2-lan' },
    boundary: 'L2a',
    report: { summary: 'Phase2 LAN 单测', keyNumbers: [1], request: '' },
  };
}

// 测试脚手架：镜像 vap-core §1 签名对象（含 nonce），用任意私钥签名。
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

async function startPeer(peer) {
  peer.start();
  await peer.ready;
  return peer;
}

async function waitFor(cond, timeoutMs = 3000, intervalMs = 20) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return cond();
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function linkPeers(a, b) {
  a.addPeer({ nodeId: b.nodeId, pubKey: b.pubKey, addr: '127.0.0.1', port: b.port });
  b.addPeer({ nodeId: a.nodeId, pubKey: a.pubKey, addr: '127.0.0.1', port: a.port });
}

// ---------------------------------------------------------------------------
// ① 发现：两节点互相发现
// ---------------------------------------------------------------------------

test('发现：两节点经 UDP 组播互相发现（peer 表含对方）', async () => {
  // M17：组播发现走本机回环需显式传 mcastInterface（默认已改为 OS 出接口）。
  const a = createLanPeer({ port: 0, nodeId: 'node-a', keyPair: makeKeyPair(), mcastInterface: '127.0.0.1' });
  const b = createLanPeer({ port: 0, nodeId: 'node-b', keyPair: makeKeyPair(), mcastInterface: '127.0.0.1' });
  await startPeer(a);
  await startPeer(b);
  try {
    const found = await waitFor(
      () => a.peers().some((p) => p.nodeId === 'node-b') && b.peers().some((p) => p.nodeId === 'node-a'),
      5000,
    );
    assert.equal(found, true, '两节点应在 5s 内互相发现');
    // 组播 announce 与单播 socket 的时序竞争：首播可能携带来不及更新的字段。
    // 等待「公钥与端口都一致」再断言（实现有真 bug 时此等待仍会失败，不掩盖错误）。
    const consistent = await waitFor(() => {
      const aSeesB = a.peers().find((p) => p.nodeId === 'node-b');
      return !!aSeesB && aSeesB.pubKey === b.pubKey && aSeesB.port === b.port;
    }, 5000);
    const aSeesB = a.peers().find((p) => p.nodeId === 'node-b');
    assert.equal(consistent, true, '发现的登记信息应与对方真实公钥/端口最终一致');
    assert.equal(aSeesB.pubKey, b.pubKey, '发现登记的公钥应与对方真实公钥一致');
    assert.equal(aSeesB.port, b.port, '发现登记的端口应为对方单播端口');
  } finally {
    a.stop();
    b.stop();
  }
});

// ---------------------------------------------------------------------------
// ② 洪泛投递：A 发 → B 收到且验签通过
// ---------------------------------------------------------------------------

test('洪泛投递：A 发 → B 收到且三闸验签通过', async () => {
  const kpA = makeKeyPair();
  const a = createLanPeer({ port: 0, nodeId: 'node-a', keyPair: kpA });
  const b = createLanPeer({ port: 0, nodeId: 'node-b', keyPair: makeKeyPair() });
  await startPeer(a);
  await startPeer(b);
  linkPeers(a, b);

  const nodeA = createVapNode({ nodeId: 'node-a', root: makeRoot(), keyPair: kpA });
  const received = [];
  b.onEnvelope((env) => received.push(env));
  try {
    const env = nodeA.send(validParams());
    a.sendEnvelope(env);
    const got = await waitFor(() => received.some((e) => e.id === env.id), 3000);
    assert.equal(got, true, 'B 应收到信封');
    const atB = received.find((e) => e.id === env.id);
    assert.deepEqual(atB, env, '信封经 UDP 往返应无损');

    // 独立复核三闸
    const verifier = createVapNode({ nodeId: 'verifier', root: makeRoot() });
    const verdict = verifier.verify(atB);
    assert.equal(verdict.pass, true);
    assert.equal(verdict.gates.identity.pass, true);
    assert.equal(verdict.gates.laws.pass, true);
    assert.equal(verdict.gates.boundary.pass, true);
  } finally {
    a.stop();
    b.stop();
  }
});

// ---------------------------------------------------------------------------
// ③ 去重：同 id 信封二次到达不触发回调
// ---------------------------------------------------------------------------

test('去重：同 id 信封二次到达不触发回调', async () => {
  const kpA = makeKeyPair();
  const a = createLanPeer({ port: 0, nodeId: 'node-a', keyPair: kpA });
  const b = createLanPeer({ port: 0, nodeId: 'node-b', keyPair: makeKeyPair() });
  await startPeer(a);
  await startPeer(b);
  linkPeers(a, b);

  const nodeA = createVapNode({ nodeId: 'node-a', root: makeRoot(), keyPair: kpA });
  let count = 0;
  b.onEnvelope(() => { count += 1; });
  try {
    const env = nodeA.send(validParams());
    a.sendEnvelope(env);
    await waitFor(() => count >= 1, 3000);
    await sleep(200); // 让首封投递尘埃落定
    const before = count;
    a.sendEnvelope(env); // 重放同一信封
    await sleep(300);
    assert.equal(count, before, '二次到达不应触发回调');
    assert.equal(count, 1, '同 id 信封应恰好投递一次');
    assert.equal(b.stats().deduped, 1, '二次到达应被 messageId 去重计数');
  } finally {
    a.stop();
    b.stop();
  }
});

// ---------------------------------------------------------------------------
// ④ TTL 递减：TTL≤1 不转发
// ---------------------------------------------------------------------------

test('TTL 递减：TTL≤1 不转发（TTL=2 才转发一跳）', async () => {
  const kpA = makeKeyPair();
  const a = createLanPeer({ port: 0, nodeId: 'node-a', keyPair: kpA });
  const b = createLanPeer({ port: 0, nodeId: 'node-b', keyPair: makeKeyPair() });
  const c = createLanPeer({ port: 0, nodeId: 'node-c', keyPair: makeKeyPair() });
  await startPeer(a);
  await startPeer(b);
  await startPeer(c);

  // 链式拓扑 a → b → c
  a.addPeer({ nodeId: 'node-b', pubKey: b.pubKey, addr: '127.0.0.1', port: b.port });
  b.addPeer({ nodeId: 'node-a', pubKey: a.pubKey, addr: '127.0.0.1', port: a.port });
  b.addPeer({ nodeId: 'node-c', pubKey: c.pubKey, addr: '127.0.0.1', port: c.port });
  c.addPeer({ nodeId: 'node-b', pubKey: b.pubKey, addr: '127.0.0.1', port: b.port });

  const recvB = [];
  const recvC = [];
  b.onEnvelope((e) => recvB.push(e));
  c.onEnvelope((e) => recvC.push(e));

  const nodeA = createVapNode({ nodeId: 'node-a', root: makeRoot(), keyPair: kpA });
  try {
    // TTL=1：B 收到但不转发，C 收不到
    const env1 = nodeA.send(validParams());
    a.sendEnvelope(env1, 1);
    const bGot1 = await waitFor(() => recvB.some((e) => e.id === env1.id), 3000);
    assert.equal(bGot1, true, 'TTL=1 时 B 应收到');
    await sleep(300);
    assert.equal(recvC.some((e) => e.id === env1.id), false, 'TTL=1 不应转发到 C');

    // TTL=2：B 转发（TTL=1）到 C，C 收到
    const env2 = nodeA.send(validParams());
    a.sendEnvelope(env2, 2);
    const cGot2 = await waitFor(() => recvC.some((e) => e.id === env2.id), 3000);
    assert.equal(cGot2, true, 'TTL=2 应转发一跳到 C');
  } finally {
    a.stop();
    b.stop();
    c.stop();
  }
});

// ---------------------------------------------------------------------------
// ⑤ 身份绑定：pubKey 不匹配信封签名者 → 拒收
// ---------------------------------------------------------------------------

test('身份绑定：信封 from.pubKey 与 announce 注册 pubKey 不一致 → 拒收', async () => {
  const kpA = makeKeyPair();
  const kpAttack = makeKeyPair();
  const a = createLanPeer({ port: 0, nodeId: 'node-a', keyPair: kpA });
  const b = createLanPeer({ port: 0, nodeId: 'node-b', keyPair: makeKeyPair() });
  await startPeer(a);
  await startPeer(b);
  linkPeers(a, b);

  const rejects = [];
  const delivered = [];
  b.onReject((r) => rejects.push(r));
  b.onEnvelope((e) => delivered.push(e));
  try {
    // 伪造信封：声称 from.nodeId=node-a（A 已以 kpA 登记），但 from.pubKey=攻击者公钥、
    // 用攻击者私钥签名。三闸会放行（攻击者自签自claim），身份绑定必须拦截。
    const base = {
      v: 1,
      id: 'evt-identity-mismatch',
      nonce: crypto.randomBytes(8).toString('hex'),
      ts: new Date().toISOString(),
      to: 'brain',
      claim: { type: 'report', body: {} },
      evidence: { devices: ['E01'], bills: {}, digest: 'sha256:mismatch' },
      boundary: 'L2a',
      report: { summary: 'mismatch', keyNumbers: [], request: '' },
    };
    const forged = { ...base, from: { nodeId: 'node-a', pubKey: pubKeyOf(kpAttack) }, sig: '' };
    forged.sig = signWithKey(kpAttack.privateKey, forged);

    // 对照：该伪造信封若走纯三闸，身份闸会通过（攻击者自签），证明身份绑定是独立一闸。
    const verifier = createVapNode({ nodeId: 'verifier', root: makeRoot() });
    assert.equal(verifier.verify(forged).pass, true, '对照：三闸不拦自签自claim，需身份绑定拦');

    a.sendEnvelope(forged);
    const rejected = await waitFor(() => rejects.length >= 1, 3000);
    assert.equal(rejected, true, '应触发拒收回调');
    assert.equal(rejects[0].reason, 'identity mismatch', '拒收原因应为 identity mismatch');
    assert.equal(delivered.some((e) => e.id === forged.id), false, '身份不一致信封不应送达');
    assert.equal(b.stats().identityRejected, 1, '身份绑定拒收计数应为 1');
  } finally {
    a.stop();
    b.stop();
  }
});
