// phase4/tests/relay.test.mjs —— VAP Phase 4 中继模式 node:test 单测（本机回环 127.0.0.1）
//
// 覆盖（对照 phase4/brief.md 与 DESIGN.md 验收标准）：
//   1. 注册：register 建 nodeId→socket 表；
//   2. 转发：A→中继→B 原样字节转发，接收方三闸通过（复用 vap-core verify）；
//   3. 同名顶替：后注册者顶替旧连接；
//   4. 断线重连：指数退避（1s→…→30s 上限，纯函数直测）+ 5s 内实际重连；
//   5. 度量递增：forwarded/totalBytes/forwardedBytes/uptimeMs；
//   6. 中继篡改必拒：恶意中继改写信封内容 → 对端三闸拒绝（identity 闸验签失败）；
//   7. 行协议：长度前缀 + JSON（半包/粘包）。
//
// 零第三方依赖：仅 node:test / node:assert / node:net / node:os / node:path 与相对路径 import。

import test from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

import { createVapNode } from '../../vap-core.mjs';
import {
  createRelayServer,
  encodeFrame,
  createFrameDecoder,
} from '../relay-server.mjs';
import { createRelayClient, backoffDelayMs } from '../relay-client.mjs';

// ---------------------------------------------------------------------------
// 装置助手
// ---------------------------------------------------------------------------

function makeRoot(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `vap-phase4-${tag}-`));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify({
    rules: [
      { id: 'SIG_REQUIRED', check: 'sig 验签通过', severity: 'reject' },
      { id: 'BOUNDARY_VALID', check: 'boundary ∈ {L2a,L1,L0}', severity: 'reject' },
      { id: 'SUMMARY_BOUND', check: 'report.summary 字符数 ≤ 100', severity: 'reject' },
      { id: 'EVIDENCE_L2A', check: 'boundary=L2a ⇒ evidence.devices 非空', severity: 'reject' },
      { id: 'FROM_KNOWN', check: 'from.nodeId 在登记册或首封自注册', severity: 'warn' },
    ],
  }, null, 2)}\n`);
  return root;
}

function makeNode(id) {
  return createVapNode({ nodeId: id, root: makeRoot(id) });
}

function validParams() {
  return {
    to: 'peer',
    claim: { type: 'report', body: { work: 'phase4-relay' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:phase4' },
    boundary: 'L2a',
    report: { summary: 'Phase4 relay smoke', keyNumbers: [1], request: '' },
  };
}

function waitFor(cond, timeoutMs = 5000, intervalMs = 20) {
  return new Promise((resolve) => {
    const start = Date.now();
    (function tick() {
      if (cond()) return resolve(true);
      if (Date.now() - start >= timeoutMs) return resolve(cond());
      setTimeout(tick, intervalMs);
    })();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 恶意中继：把转发的信封 report.summary 改写后再发（模拟中继篡改）。
function startTamperingRelay(port = 0) {
  const clients = new Map();
  const server = net.createServer((socket) => {
    const dec = createFrameDecoder({
      onFrame: (msg) => {
        if (!msg || typeof msg !== 'object') return;
        if (msg.type === 'register') {
          clients.set(msg.nodeId, socket);
          return;
        }
        if (msg.type === 'relay') {
          const target = clients.get(msg.to);
          if (!target) return;
          const tampered = JSON.parse(JSON.stringify(msg.envelope));
          tampered.report = { ...(tampered.report || {}), summary: 'TAMPERED-BY-RELAY' };
          target.write(encodeFrame({ type: 'relay', to: msg.to, envelope: tampered }));
        }
      },
    });
    socket.on('data', (c) => dec.push(c));
    socket.on('error', () => {});
    socket.on('close', () => {
      for (const [id, s] of clients) if (s === socket) clients.delete(id);
    });
  });
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, '127.0.0.1', () => resolve({
      port: server.address().port,
      close: () => new Promise((r) => {
        for (const s of clients.values()) { try { s.destroy(); } catch { /* 尽力 */ } }
        server.close(() => r());
      }),
    }));
  });
}

// ---------------------------------------------------------------------------
// 1. 注册
// ---------------------------------------------------------------------------

test('register 建立 nodeId→socket 表', async () => {
  const server = createRelayServer({ port: 0 });
  const port = await server.start();
  const client = createRelayClient({ host: '127.0.0.1', port, nodeId: 'n1', pubKey: 'pk-n1' });
  try {
    client.connect();
    const ok = await waitFor(() => server.stats().connections === 1, 3000);
    assert.equal(ok, true, 'connection registered');
    assert.deepEqual(server.registry(), ['n1']);
    assert.equal(server.stats().registered, 1);
  } finally {
    client.close();
    await server.stop();
  }
});

// ---------------------------------------------------------------------------
// 2. 转发：原样字节 + 接收方三闸通过
// ---------------------------------------------------------------------------

test('A→中继→B 原样转发且接收方三闸通过', async () => {
  const server = createRelayServer({ port: 0 });
  const port = await server.start();
  const nodeA = makeNode('A');
  const nodeB = makeNode('B');
  const clientA = createRelayClient({ host: '127.0.0.1', port, nodeId: 'A', pubKey: nodeA.pubKey });
  const clientB = createRelayClient({ host: '127.0.0.1', port, nodeId: 'B', pubKey: nodeB.pubKey });
  const received = [];
  try {
    clientA.connect();
    clientB.connect();
    await waitFor(() => server.stats().connections === 2, 3000);

    clientB.onEnvelope((env, meta) => received.push({ env, meta }));

    const envelope = nodeA.send(validParams());
    const wrote = clientA.send('B', envelope);
    assert.equal(wrote, true, 'send written to socket');

    const got = await waitFor(() => received.some((r) => r.env.id === envelope.id), 3000);
    assert.equal(got, true, 'B received envelope');

    const verdict = nodeB.verify(received[0].env);
    assert.equal(verdict.pass, true, 'three gates pass');
    assert.equal(verdict.gates.identity.pass, true, 'identity gate pass');
    assert.equal(verdict.gates.laws.pass, true, 'laws gate pass');
    assert.equal(verdict.gates.boundary.pass, true, 'boundary gate pass');

    assert.equal(received[0].env.report.summary, 'Phase4 relay smoke', 'forwarded bytes intact');
    assert.equal(server.stats().forwarded, 1);
  } finally {
    clientA.close();
    clientB.close();
    await server.stop();
  }
});

// ---------------------------------------------------------------------------
// 3. 同名顶替
// ---------------------------------------------------------------------------

test('同名 nodeId 重复注册 → 后注册者顶替旧连接', async () => {
  // 修复批次 1（M3）后默认要求顶替方携带旧注册者 pubKey（不匹配 → 拒绝顶替）。
  // 本条钉的是「无认证时后注册者顶替」这一历史语义，故显式关闭顶替认证保留原断言；
  // 认证开启（默认）下的拒绝顶替由 tests/security-regression.test.mjs 钉死。
  const server = createRelayServer({ port: 0, requireTakeoverAuth: false });
  const port = await server.start();
  const clientX = createRelayClient({ host: '127.0.0.1', port, nodeId: 'dup', pubKey: 'pk-x' });
  const clientY = createRelayClient({ host: '127.0.0.1', port, nodeId: 'dup', pubKey: 'pk-y' });
  const nodeA = makeNode('A');
  const clientA = createRelayClient({ host: '127.0.0.1', port, nodeId: 'A', pubKey: nodeA.pubKey });
  const receivedX = [];
  const receivedY = [];
  try {
    clientX.connect();
    await waitFor(() => server.stats().connections === 1, 3000);
    clientX.onEnvelope((env) => receivedX.push(env));

    clientY.connect();
    await waitFor(() => server.stats().connections === 1 && server.stats().replacements === 1, 3000);
    clientY.onEnvelope((env) => receivedY.push(env));

    assert.equal(server.stats().connections, 1, 'only latest connection holds the name');
    assert.equal(server.stats().replacements, 1, 'one takeover recorded');
    assert.equal(server.stats().registered, 2, 'two registrations total');

    // 转发给 dup：应到 Y（后注册者），不到 X（旧连接已被顶替断开）。
    clientA.connect();
    await waitFor(() => server.stats().connections === 2, 3000);
    const envelope = nodeA.send(validParams());
    clientA.send('dup', envelope);

    const toY = await waitFor(() => receivedY.some((e) => e.id === envelope.id), 3000);
    assert.equal(toY, true, 'latest connection received the envelope');
    await sleep(150);
    assert.equal(receivedX.some((e) => e.id === envelope.id), false, 'old connection did not receive');
  } finally {
    clientX.close();
    clientY.close();
    clientA.close();
    await server.stop();
  }
});

// ---------------------------------------------------------------------------
// 4. 指数退避（纯函数）+ 断线 5s 内重连
// ---------------------------------------------------------------------------

test('指数退避 1s→2s→…→30s 上限', () => {
  assert.equal(backoffDelayMs(0), 1000);
  assert.equal(backoffDelayMs(1), 2000);
  assert.equal(backoffDelayMs(2), 4000);
  assert.equal(backoffDelayMs(3), 8000);
  assert.equal(backoffDelayMs(4), 16000);
  assert.equal(backoffDelayMs(5), 30000);
  assert.equal(backoffDelayMs(6), 30000);
  assert.equal(backoffDelayMs(100), 30000);
});

test('断线 5s 内重连并重新注册', async () => {
  const server = createRelayServer({ port: 0 });
  const port = await server.start();
  const client = createRelayClient({ host: '127.0.0.1', port, nodeId: 'n1', pubKey: 'pk-n1' });
  let server2 = null;
  try {
    client.connect();
    await waitFor(() => client.connected(), 3000);
    assert.equal(client.connected(), true);

    await server.stop(); // 中继下线 → 客户端断线
    const noticed = await waitFor(() => !client.connected(), 3000);
    assert.equal(noticed, true, 'client noticed disconnect');

    server2 = createRelayServer({ port }); // 同端口重启
    await server2.start();

    const reconnected = await waitFor(() => client.connected(), 5000);
    assert.equal(reconnected, true, 'reconnected within 5s');

    const reregistered = await waitFor(() => server2.stats().connections === 1, 2000);
    assert.equal(reregistered, true, 're-registered after reconnect');
  } finally {
    client.close();
    if (server2) await server2.stop();
  }
});

// ---------------------------------------------------------------------------
// 5. 度量递增
// ---------------------------------------------------------------------------

test('stats 度量随转发递增（forwarded/totalBytes/forwardedBytes/uptimeMs）', async () => {
  const server = createRelayServer({ port: 0 });
  const port = await server.start();
  const nodeA = makeNode('A');
  const nodeB = makeNode('B');
  const clientA = createRelayClient({ host: '127.0.0.1', port, nodeId: 'A', pubKey: nodeA.pubKey });
  const clientB = createRelayClient({ host: '127.0.0.1', port, nodeId: 'B', pubKey: nodeB.pubKey });
  try {
    clientA.connect();
    clientB.connect();
    await waitFor(() => server.stats().connections === 2, 3000);

    const s0 = server.stats();
    assert.equal(s0.forwarded, 0, 'no relay forward yet');
    assert.equal(s0.forwardedBytes, 0, 'no forwarded bytes yet');
    const totalBefore = s0.totalBytes; // 注册帧已计入入站字节

    const env1 = nodeA.send(validParams());
    const env2 = nodeA.send(validParams());
    clientA.send('B', env1);
    clientA.send('B', env2);
    await waitFor(() => server.stats().forwarded === 2, 3000);

    const s1 = server.stats();
    assert.equal(s1.forwarded, 2, 'forwarded count');
    assert.ok(s1.totalBytes > totalBefore, 'totalBytes grows after forwards');
    assert.ok(s1.forwardedBytes > 0, 'forwardedBytes > 0');
    assert.ok(s1.forwardedBytes >= 2 * 4, 'forwardedBytes counts frame payloads');
    assert.ok(s1.uptimeMs >= 0, 'uptimeMs present');
  } finally {
    clientA.close();
    clientB.close();
    await server.stop();
  }
});

// ---------------------------------------------------------------------------
// 6. 中继篡改必拒
// ---------------------------------------------------------------------------

test('中继篡改信封 → 对端三闸拒绝', async () => {
  const tamperingRelay = await startTamperingRelay(0);
  const nodeA = makeNode('A');
  const nodeB = makeNode('B');
  const clientA = createRelayClient({ host: '127.0.0.1', port: tamperingRelay.port, nodeId: 'A', pubKey: nodeA.pubKey });
  const clientB = createRelayClient({ host: '127.0.0.1', port: tamperingRelay.port, nodeId: 'B', pubKey: nodeB.pubKey });
  const received = [];
  try {
    clientA.connect();
    clientB.connect();
    await waitFor(() => clientA.connected() && clientB.connected(), 3000);

    clientB.onEnvelope((env) => received.push(env));

    const envelope = nodeA.send(validParams());
    clientA.send('B', envelope);

    const got = await waitFor(() => received.length > 0, 3000);
    assert.equal(got, true, 'tampered envelope arrived');

    assert.equal(received[0].report.summary, 'TAMPERED-BY-RELAY', 'relay tampered content');
    const verdict = nodeB.verify(received[0]);
    assert.equal(verdict.pass, false, 'tampered envelope rejected');
    assert.equal(verdict.gates.identity.pass, false, 'identity gate rejects tampered envelope');
  } finally {
    clientA.close();
    clientB.close();
    await tamperingRelay.close();
  }
});

// ---------------------------------------------------------------------------
// 7. 行协议：长度前缀 + JSON（半包/粘包）
// ---------------------------------------------------------------------------

test('行协议：4 字节长度前缀 + JSON，处理半包与粘包', () => {
  const messages = [];
  const dec = createFrameDecoder({ onFrame: (m) => messages.push(m) });

  const f1 = encodeFrame({ type: 'register', nodeId: 'a', pubKey: 'p' });
  const f2 = encodeFrame({ type: 'relay', to: 'b', envelope: { id: 'evt-x' } });

  // 粘包：两帧连读
  dec.push(Buffer.concat([f1, f2]));
  assert.equal(messages.length, 2);
  assert.deepEqual(messages[0], { type: 'register', nodeId: 'a', pubKey: 'p' });
  assert.deepEqual(messages[1], { type: 'relay', to: 'b', envelope: { id: 'evt-x' } });

  // 半包：先给 3 字节（不足 4 字节头），再给其余
  dec.push(f1.subarray(0, 3));
  assert.equal(messages.length, 2, 'partial header not yet parsed');
  dec.push(f1.subarray(3));
  assert.equal(messages.length, 3, 'rest completes the frame');

  // 帧长度前缀正确
  const raw = encodeFrame({ a: 1 });
  assert.equal(raw.readUInt32BE(0), Buffer.byteLength('{"a":1}', 'utf8'));
});
