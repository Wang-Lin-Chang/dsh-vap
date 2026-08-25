// tests/vap-transport.test.mjs —— VAP 中环 v0 传输单测（node:test，真 HTTP 本地回环）
//
// 每个断言对应 brief-ring.md 的一条要求；不伪造测试、不依赖外部进程与真实等待。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import crypto from 'node:crypto';

import { createVapNode, createBrain, makeLaws, canonicalJson } from '../vap-core.mjs';
import {
  createFileTransport,
  createHttpGateway,
  createHttpClient,
  DEFAULT_MAX_BODY_BYTES,
} from '../vap-transport.mjs';

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-ring-'));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

function validSendParams(overrides = {}) {
  return {
    to: 'brain',
    claim: { type: 'report', body: { work: 'scout' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:abcd' },
    boundary: 'L2a',
    report: { summary: 'transport ok', keyNumbers: [1], request: '' },
    ...overrides,
  };
}

function rawRequest(port, method, pathname, body, { chunked = false, headers: extraHeaders = {} } = {}) {
  return new Promise((resolve, reject) => {
    const headers = { ...extraHeaders };
    if (body !== undefined && body !== null) {
      headers['content-type'] = 'application/json';
      if (!chunked) headers['content-length'] = Buffer.byteLength(body);
    }
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let data = null;
        try { data = text ? JSON.parse(text) : null; } catch { data = null; }
        resolve({ status: res.statusCode, data, text });
      });
    });
    req.on('error', reject);
    if (body !== undefined && body !== null) req.write(body);
    req.end();
  });
}

function rawGet(port, pathname) {
  return rawRequest(port, 'GET', pathname);
}

function rawPost(port, pathname, body, opts) {
  return rawRequest(port, 'POST', pathname, body, opts);
}

// 轮询等待条件成立（异步转发为尽力而为，测试需等待转发落盘）。
async function waitFor(cond, timeoutMs = 2000, intervalMs = 20) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return cond();
}

// 取一个空闲回环端口（互连环状 peers 需两端口在 start 前都已知）。
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
  return fs.readdirSync(path.join(root, 'inbox-http')).filter((n) => n.endsWith('.json')).length;
}

// 构造 v0 无 nonce 信封的合法签名（签名对象不含 nonce，等价旧版 signPayload）。
function signV0Payload(node, envelope) {
  const payload = {
    v: envelope.v,
    id: envelope.id,
    ts: envelope.ts,
    'from.nodeId': envelope.from.nodeId,
    'from.pubKey': envelope.from.pubKey,
    to: envelope.to,
    claim: envelope.claim,
    evidence: envelope.evidence,
    boundary: envelope.boundary,
    report: envelope.report,
  };
  return crypto.sign(null, Buffer.from(canonicalJson(payload), 'utf8'), node.privateKey).toString('base64');
}

// ---------------------------------------------------------------------------
// FileTransport：Transport 形状（send/read/markDelivered/countUndelivered）
// ---------------------------------------------------------------------------

test('FileTransport：send 原子写 outbox（tmp+rename，无 tmp 残留）', () => {
  const root = makeRoot();
  const ft = createFileTransport({ root });
  const envelope = { id: 'evt-0001', v: 1, from: {}, claim: {} };
  const returned = ft.send(envelope);
  assert.equal(returned, envelope);
  const file = path.join(root, 'outbox', 'evt-0001.json');
  assert.ok(fs.existsSync(file));
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), envelope);
  const leftovers = fs.readdirSync(path.join(root, 'outbox')).filter((n) => n.includes('.tmp-'));
  assert.equal(leftovers.length, 0);
});

test('FileTransport：read 返回未投递信封（按文件名排序，排除非 .json 文件）', () => {
  const root = makeRoot();
  const ft = createFileTransport({ root });
  ft.send({ id: 'evt-bbb', from: { nodeId: 'b' } });
  ft.send({ id: 'evt-aaa', from: { nodeId: 'a' } });
  fs.writeFileSync(path.join(root, 'outbox', 'evt-aaa.verdict'), '{}');
  fs.writeFileSync(path.join(root, 'outbox', 'evt-bbb.delivered'), '');
  const read = ft.read();
  assert.deepEqual(read.map((e) => e.id), ['evt-aaa']);
});

test('FileTransport：markDelivered 后 read 不再返回该信封', () => {
  const root = makeRoot();
  const ft = createFileTransport({ root });
  ft.send({ id: 'evt-111' });
  ft.send({ id: 'evt-222' });
  ft.markDelivered('evt-111');
  assert.deepEqual(ft.read().map((e) => e.id), ['evt-222']);
  assert.equal(ft.countUndelivered(), 1);
});

test('FileTransport：read({ after }) 游标按文件名字典序过滤', () => {
  const root = makeRoot();
  const ft = createFileTransport({ root });
  ft.send({ id: 'evt-aaa' });
  ft.send({ id: 'evt-bbb' });
  ft.send({ id: 'evt-ccc' });
  assert.deepEqual(ft.read({ after: 'evt-aaa' }).map((e) => e.id), ['evt-bbb', 'evt-ccc']);
  assert.deepEqual(ft.read({ after: 'evt-bbb' }).map((e) => e.id), ['evt-ccc']);
  assert.deepEqual(ft.read({ after: 'evt-ccc' }).map((e) => e.id), []);
});

test('FileTransport：与 v0 一致——node.send 写信封、transport 读、脑进程裁决', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-ring', root });
  node.register();
  const brain = createBrain({ root });
  const ft = createFileTransport({ root });

  const envelope = node.send(validSendParams());
  const read = ft.read();
  assert.equal(read.length, 1);
  assert.equal(read[0].id, envelope.id);

  const verdicts = brain.consume();
  assert.equal(verdicts.length, 1);
  assert.equal(verdicts[0].envelopeId, envelope.id);
  assert.equal(verdicts[0].pass, true);
  assert.ok(fs.existsSync(path.join(root, 'done', `${envelope.id}.json`)));
});

// ---------------------------------------------------------------------------
// HttpGateway：启动/健康/入站/出站/上限/释放
// ---------------------------------------------------------------------------

test('HttpGateway：port=0 自动分配端口，/health 返回状态计数', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  assert.ok(Number.isInteger(port) && port > 0);
  assert.equal(gw.port, port);
  try {
    const resp = await rawGet(port, '/health');
    assert.equal(resp.status, 200);
    assert.deepEqual(resp.data, { ok: true, envelopesIn: 0, envelopesOut: 0, peers: 0, relayed: 0 });
  } finally {
    await gw.stop();
  }
});

test('HttpGateway：POST /envelopes 入站落盘 inbox-http 并返回 202 + envelopeId', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  const client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
  const node = createVapNode({ nodeId: 'sender', root: makeRoot() });
  const env = node.send(validSendParams());
  try {
    const res = await client.post(env);
    assert.equal(res.status, 202);
    assert.equal(res.ok, true);
    assert.equal(res.envelopeId, env.id);
    const landed = JSON.parse(fs.readFileSync(path.join(root, 'inbox-http', `${env.id}.json`), 'utf8'));
    assert.deepEqual(landed, env);
    assert.deepEqual(gw.health(), { ok: true, envelopesIn: 1, envelopesOut: 0, peers: 0, relayed: 0 });
  } finally {
    await gw.stop();
  }
});

test('HttpGateway：POST 非法 JSON 返回 400', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  try {
    const resp = await rawPost(port, '/envelopes', '{ not json');
    assert.equal(resp.status, 400);
    assert.equal(resp.data.ok, false);
  } finally {
    await gw.stop();
  }
});

test('HttpGateway：POST 缺 envelope.id 返回 400', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  try {
    const resp = await rawPost(port, '/envelopes', JSON.stringify({ v: 1, from: {} }));
    assert.equal(resp.status, 400);
    assert.equal(resp.data.ok, false);
  } finally {
    await gw.stop();
  }
});

test('HttpGateway：POST 请求体超过 1MB 返回 413（content-length 快速拦截）', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  try {
    const big = { id: 'evt-big', payload: 'x'.repeat(DEFAULT_MAX_BODY_BYTES + 1024) };
    const resp = await rawPost(port, '/envelopes', JSON.stringify(big));
    assert.equal(resp.status, 413);
    assert.equal(resp.data.ok, false);
    assert.ok(!fs.existsSync(path.join(root, 'inbox-http', 'evt-big.json')));
  } finally {
    await gw.stop();
  }
});

test('HttpGateway：分块请求体超过 1MB 返回 413（流式计数）', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  try {
    const big = { id: 'evt-big-chunk', payload: 'x'.repeat(DEFAULT_MAX_BODY_BYTES + 1024) };
    const resp = await rawPost(port, '/envelopes', JSON.stringify(big), { chunked: true });
    assert.equal(resp.status, 413);
    assert.equal(resp.data.ok, false);
    assert.ok(!fs.existsSync(path.join(root, 'inbox-http', 'evt-big-chunk.json')));
  } finally {
    await gw.stop();
  }
});

test('HttpGateway：GET /envelopes 出站投递并标记 .delivered', async () => {
  const root = makeRoot();
  const ft = createFileTransport({ root });
  ft.send({ id: 'evt-out-1', v: 1, to: 'brain' });
  ft.send({ id: 'evt-out-2', v: 1, to: 'brain' });
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  const client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
  try {
    const first = await client.poll();
    assert.deepEqual(first.map((e) => e.id).sort(), ['evt-out-1', 'evt-out-2']);
    const second = await client.poll();
    assert.deepEqual(second, []);
    assert.ok(fs.existsSync(path.join(root, 'outbox', 'evt-out-1.delivered')));
    assert.ok(fs.existsSync(path.join(root, 'outbox', 'evt-out-2.delivered')));
    assert.deepEqual(gw.health(), { ok: true, envelopesIn: 0, envelopesOut: 0, peers: 0, relayed: 0 });
  } finally {
    await gw.stop();
  }
});

test('HttpGateway：GET /envelopes?after= 游标过滤（客户端 poll）', async () => {
  const root = makeRoot();
  const ft = createFileTransport({ root });
  ft.send({ id: 'evt-aaa' });
  ft.send({ id: 'evt-bbb' });
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  const client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
  try {
    const got = await client.poll({ after: 'evt-aaa' });
    assert.deepEqual(got.map((e) => e.id), ['evt-bbb']);
  } finally {
    await gw.stop();
  }
});

test('HttpGateway：stop 后端口释放', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  assert.ok(port > 0);
  await gw.stop();
  assert.equal(gw.port, null);
  // 端口应可被再次占用
  const probe = net.createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(port, '127.0.0.1', () => resolve());
  });
  await new Promise((resolve) => probe.close(() => resolve()));
});

// ---------------------------------------------------------------------------
// HttpClient：post/poll 真 HTTP 本地回环完整往返
// ---------------------------------------------------------------------------

test('HttpClient：post/poll 真 HTTP 本地回环完整往返', async () => {
  const rootA = makeRoot();
  const rootB = makeRoot();
  const gwA = createHttpGateway({ port: 0, root: rootA });
  const portA = await gwA.start();
  const clientB = createHttpClient({ baseUrl: `http://127.0.0.1:${portA}` });
  const nodeA = createVapNode({ nodeId: 'node-a', root: rootA });
  const nodeB = createVapNode({ nodeId: 'node-b', root: rootB });
  try {
    // A → B：A 写 outbox，B poll 拉取
    const envA = nodeA.send(validSendParams());
    const polled = await clientB.poll();
    assert.equal(polled.length, 1);
    assert.equal(polled[0].id, envA.id);

    // 已投递，重复拉取为空
    assert.deepEqual(await clientB.poll(), []);

    // B → A：B post 信封，A 的 inbox-http 落盘
    const envB = nodeB.send(validSendParams());
    const posted = await clientB.post(envB);
    assert.equal(posted.status, 202);
    assert.equal(posted.ok, true);
    assert.equal(posted.envelopeId, envB.id);
    const landed = JSON.parse(fs.readFileSync(path.join(rootA, 'inbox-http', `${envB.id}.json`), 'utf8'));
    assert.deepEqual(landed, envB);
  } finally {
    await gwA.stop();
  }
});

// ---------------------------------------------------------------------------
// 跨节点验证门：HTTP 来的信封复用 vap-core 三闸（真通过 / 伪造拦截）
// ---------------------------------------------------------------------------

test('跨节点验证门：HTTP 来的真信封 verify 通过并入账', async () => {
  const rootA = makeRoot();
  const rootB = makeRoot();
  const gwA = createHttpGateway({ port: 0, root: rootA });
  const portA = await gwA.start();
  const clientB = createHttpClient({ baseUrl: `http://127.0.0.1:${portA}` });
  const nodeA = createVapNode({ nodeId: 'node-a', root: rootA });
  // 脑进程用独立工作区：其 nonce 查重与网关 entry 认领互不干扰（网关根与脑根分离）。
  const rootBrain = makeRoot();
  const brainA = createBrain({ root: rootBrain });
  const ftA = createFileTransport({ root: rootBrain });
  const nodeB = createVapNode({ nodeId: 'node-b', root: rootB });
  try {
    const env = nodeB.send(validSendParams());
    const posted = await clientB.post(env);
    assert.equal(posted.status, 202);

    const received = JSON.parse(fs.readFileSync(path.join(rootA, 'inbox-http', `${env.id}.json`), 'utf8'));
    const verdict = nodeA.verify(received);
    assert.equal(verdict.pass, true);
    assert.equal(verdict.gates.identity.pass, true);
    assert.equal(verdict.gates.laws.pass, true);
    assert.equal(verdict.gates.boundary.pass, true);

    // 脑进程入账：收到的信封转入 outbox 后 consume 入账
    ftA.send(received);
    const consumed = brainA.consume();
    assert.equal(consumed.length, 1);
    assert.equal(consumed[0].pass, true);
    assert.ok(fs.existsSync(path.join(rootBrain, 'done', `${env.id}.json`)));
  } finally {
    await gwA.stop();
  }
});

test('跨节点验证门：无签名伪造经 HTTP 被三闸拦截', async () => {
  const rootA = makeRoot();
  const rootB = makeRoot();
  // 修复批次 1（M7）后网关默认前置验签（无签名 → 403）。本条钉的是「网关只搬运、
  // 军法由下游三道闸裁决」这一语义，故显式关闭前置验签保留原断言。
  const gwA = createHttpGateway({ port: 0, root: rootA, requireInboundSignature: false });
  const portA = await gwA.start();
  const clientB = createHttpClient({ baseUrl: `http://127.0.0.1:${portA}` });
  const nodeA = createVapNode({ nodeId: 'node-a', root: rootA });
  const rootBrain = makeRoot();
  const brainA = createBrain({ root: rootBrain });
  const ftA = createFileTransport({ root: rootBrain });
  const nodeB = createVapNode({ nodeId: 'node-b', root: rootB });
  try {
    const env = nodeB.send(validSendParams());
    env.sig = ''; // 伪造：无签名
    const posted = await clientB.post(env);
    assert.equal(posted.status, 202);

    const received = JSON.parse(fs.readFileSync(path.join(rootA, 'inbox-http', `${env.id}.json`), 'utf8'));
    const verdict = nodeA.verify(received);
    assert.equal(verdict.pass, false);
    assert.equal(verdict.gates.identity.pass, false);
    assert.ok(verdict.gates.laws.reasons.some((r) => r.startsWith('SIG_REQUIRED:')));

    ftA.send(received);
    const consumed = brainA.consume();
    assert.equal(consumed[0].pass, false);
    assert.ok(consumed[0].reasons.some((r) => r.includes('SIG_REQUIRED')));
    assert.ok(!fs.existsSync(path.join(rootBrain, 'done', `${env.id}.json`)));
  } finally {
    await gwA.stop();
  }
});

test('跨节点验证门：坏边界伪造经 HTTP 被拦截（签名有效）', async () => {
  const rootA = makeRoot();
  const rootB = makeRoot();
  const gwA = createHttpGateway({ port: 0, root: rootA });
  const portA = await gwA.start();
  const clientB = createHttpClient({ baseUrl: `http://127.0.0.1:${portA}` });
  const nodeA = createVapNode({ nodeId: 'node-a', root: rootA });
  const rootBrain = makeRoot();
  const brainA = createBrain({ root: rootBrain });
  const ftA = createFileTransport({ root: rootBrain });
  const nodeB = createVapNode({ nodeId: 'node-b', root: rootB });
  try {
    const env = nodeB.send(validSendParams({ boundary: 'L9' })); // node.send 用 L9 签名
    const posted = await clientB.post(env);
    assert.equal(posted.status, 202);

    const received = JSON.parse(fs.readFileSync(path.join(rootA, 'inbox-http', `${env.id}.json`), 'utf8'));
    const verdict = nodeA.verify(received);
    assert.equal(verdict.gates.identity.pass, true, '签名有效，仅军法拦截');
    assert.equal(verdict.gates.laws.pass, false);
    assert.ok(verdict.gates.laws.reasons.some((r) => r.startsWith('BOUNDARY_VALID:')));
    assert.equal(verdict.pass, false);

    ftA.send(received);
    const consumed = brainA.consume();
    assert.equal(consumed[0].pass, false);
    assert.ok(consumed[0].reasons.some((r) => r.includes('BOUNDARY_VALID')));
    assert.ok(!fs.existsSync(path.join(rootBrain, 'done', `${env.id}.json`)));
  } finally {
    await gwA.stop();
  }
});

// ---------------------------------------------------------------------------
// 中环二期：nonce 防重放（模块 A）
// ---------------------------------------------------------------------------

test('nonce：send 自动带 nonce（16 hex）', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const envelope = node.send(validSendParams());
  assert.equal(typeof envelope.nonce, 'string');
  assert.match(envelope.nonce, /^[0-9a-f]{16,32}$/);
});

test('nonce：签名绑定 nonce（篡改 nonce 验签失败）', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const envelope = node.send(validSendParams());
  assert.equal(node.verify(envelope).pass, true, '未篡改应通过');
  envelope.nonce = 'deadbeefdeadbeef'; // 篡改 nonce 为不同值
  const tampered = node.verify(envelope);
  assert.equal(tampered.gates.identity.pass, false);
  assert.equal(tampered.pass, false);
});

test('nonce：重复 nonce 第二次 409（replay rejected）', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  const client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
  const node = createVapNode({ nodeId: 'sender', root: makeRoot() });
  const env = node.send(validSendParams());
  try {
    const first = await client.post(env);
    assert.equal(first.status, 202);
    assert.equal(first.ok, true);
    const second = await client.post(env);
    assert.equal(second.status, 409);
    assert.equal(second.ok, false);
    assert.equal(second.error, 'replay rejected');
    // 重放不落盘：inbox-http 仍只有第一次的那一封
    assert.equal(countInboxJson(root), 1);
    assert.ok(fs.existsSync(path.join(root, 'inbox-http', `${env.id}.json`)));
  } finally {
    await gw.stop();
  }
});

test('nonce：无 nonce 入站 400（missing nonce）', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  try {
    const env = { v: 1, id: 'evt-no-nonce', from: { nodeId: 'x' }, claim: {} };
    const resp = await rawPost(port, '/envelopes', JSON.stringify(env));
    assert.equal(resp.status, 400);
    assert.equal(resp.data.ok, false);
    assert.equal(resp.data.error, 'missing nonce');
    assert.ok(!fs.existsSync(path.join(root, 'inbox-http', 'evt-no-nonce.json')));
  } finally {
    await gw.stop();
  }
});

test('脑进程：重复 nonce 被 replay rejected 且不入账', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  node.register();
  const brain = createBrain({ root });
  const env1 = node.send(validSendParams());
  const first = brain.consume();
  assert.equal(first.length, 1);
  assert.equal(first[0].pass, true);

  // 构造同 nonce 不同 id 的重放（改 id 落到不同文件；nonce 查重短路于三闸之前）
  const replay = { ...env1, id: `evt-replay-${env1.nonce.slice(0, 8)}` };
  fs.mkdirSync(path.join(root, 'outbox'), { recursive: true });
  fs.writeFileSync(path.join(root, 'outbox', `${replay.id}.json`), JSON.stringify(replay));
  const second = brain.consume();
  const v = second.find((x) => x.envelopeId === replay.id);
  assert.ok(v);
  assert.equal(v.pass, false);
  assert.deepEqual(v.reasons, ['replay rejected']);
  assert.ok(!fs.existsSync(path.join(root, 'done', `${replay.id}.json`)));
});

test('向后兼容：无 nonce 信封在脑进程 consume 仍按 v0 放行', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-old', root });
  node.register();
  const brain = createBrain({ root });
  // 手工构造 v0 旧信封（无 nonce），签名对象不含 nonce（等价旧版 signPayload）
  const legacy = {
    v: 1,
    id: 'evt-legacy-no-nonce',
    ts: new Date().toISOString(),
    from: { nodeId: 'scout-old', pubKey: node.pubKey },
    to: 'brain',
    sig: '',
    claim: { type: 'report', body: { work: 'legacy' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:abcd' },
    boundary: 'L2a',
    report: { summary: 'legacy v0 envelope', keyNumbers: [1], request: '' },
  };
  legacy.sig = signV0Payload(node, legacy);
  fs.mkdirSync(path.join(root, 'outbox'), { recursive: true });
  fs.writeFileSync(path.join(root, 'outbox', `${legacy.id}.json`), JSON.stringify(legacy));

  const verdicts = brain.consume();
  const v = verdicts.find((x) => x.envelopeId === legacy.id);
  assert.ok(v);
  assert.equal(v.pass, true);
  assert.deepEqual(v.reasons, []);
  assert.ok(fs.existsSync(path.join(root, 'done', `${legacy.id}.json`)));
});

// ---------------------------------------------------------------------------
// 中环二期：多网关组网（模块 B）
// ---------------------------------------------------------------------------

test('组网：两网关互连转发送达（A→B）', async () => {
  const rootB = makeRoot();
  const gwB = createHttpGateway({ port: 0, root: rootB });
  const portB = await gwB.start();
  const rootA = makeRoot();
  const gwA = createHttpGateway({ port: 0, root: rootA, peers: [`http://127.0.0.1:${portB}`] });
  const portA = await gwA.start();
  const clientA = createHttpClient({ baseUrl: `http://127.0.0.1:${portA}` });
  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot() });
  const env = nodeX.send(validSendParams());
  try {
    const posted = await clientA.post(env);
    assert.equal(posted.status, 202);
    assert.ok(fs.existsSync(path.join(rootA, 'inbox-http', `${env.id}.json`)));
    const arrived = await waitFor(() => fs.existsSync(path.join(rootB, 'inbox-http', `${env.id}.json`)));
    assert.equal(arrived, true, '信封应从 A 转发到 B');
    assert.deepEqual(gwA.health(), { ok: true, envelopesIn: 1, envelopesOut: 0, peers: 1, relayed: 1 });
    assert.deepEqual(gwB.health(), { ok: true, envelopesIn: 1, envelopesOut: 0, peers: 0, relayed: 0 });
  } finally {
    await gwA.stop();
    await gwB.stop();
  }
});

test('组网：链式多跳 A→B→C 转发送达', async () => {
  const rootC = makeRoot();
  const gwC = createHttpGateway({ port: 0, root: rootC });
  const portC = await gwC.start();
  const rootB = makeRoot();
  const gwB = createHttpGateway({ port: 0, root: rootB, peers: [`http://127.0.0.1:${portC}`] });
  const portB = await gwB.start();
  const rootA = makeRoot();
  const gwA = createHttpGateway({ port: 0, root: rootA, peers: [`http://127.0.0.1:${portB}`] });
  const portA = await gwA.start();
  const clientA = createHttpClient({ baseUrl: `http://127.0.0.1:${portA}` });
  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot() });
  const env = nodeX.send(validSendParams());
  try {
    const posted = await clientA.post(env);
    assert.equal(posted.status, 202);
    const atC = await waitFor(() => fs.existsSync(path.join(rootC, 'inbox-http', `${env.id}.json`)));
    assert.equal(atC, true, '信封应经链 A→B→C 送达 C');
    assert.ok(fs.existsSync(path.join(rootA, 'inbox-http', `${env.id}.json`)));
    assert.ok(fs.existsSync(path.join(rootB, 'inbox-http', `${env.id}.json`)));
  } finally {
    await gwA.stop();
    await gwB.stop();
    await gwC.stop();
  }
});

test('组网：同 envelopeId 不重复转发（relayed 标记去重）', async () => {
  const rootB = makeRoot();
  // 本条用手工无签名信封 + 自定义 id 'evt-dup' 钉 relayed 去重语义；修复批次 1 后
  // 网关默认要求 id 形如 evt-<16 hex>（M1）且前置验签（M7），故两端显式退回兼容模式
  // （兼容模式仍禁止路径穿越字符，见 vap-transport 的 SAFE_NAME_PATTERN）。
  const legacyOpts = { strictEnvelopeId: false, requireInboundSignature: false };
  const gwB = createHttpGateway({ port: 0, root: rootB, ...legacyOpts });
  const portB = await gwB.start();
  const rootA = makeRoot();
  const gwA = createHttpGateway({ port: 0, root: rootA, peers: [`http://127.0.0.1:${portB}`], ...legacyOpts });
  const portA = await gwA.start();
  try {
    const env1 = { v: 1, id: 'evt-dup', nonce: 'aaaaaaaaaaaaaaaa', from: { nodeId: 'x' }, claim: {} };
    const env2 = { v: 1, id: 'evt-dup', nonce: 'bbbbbbbbbbbbbbbb', from: { nodeId: 'x' }, claim: {} };
    let resp = await rawPost(portA, '/envelopes', JSON.stringify(env1));
    assert.equal(resp.status, 202);
    await waitFor(() => fs.existsSync(path.join(rootB, 'inbox-http', 'evt-dup.json')));

    // 同 id 不同 nonce：relayed 标记已存在 → 不重复转发
    resp = await rawPost(portA, '/envelopes', JSON.stringify(env2));
    assert.equal(resp.status, 202);
    await new Promise((r) => setTimeout(r, 300)); // 给潜在的二次转发留窗口
    assert.equal(countInboxJson(rootB), 1, 'B 只应收到一次（不重复转发）');
    assert.equal(gwA.health().relayed, 1, 'A 只转发过一次');
  } finally {
    await gwA.stop();
    await gwB.stop();
  }
});

test('组网：环内 relay 信封不二次转发（relayed + nonce 双兜底终止）', async () => {
  // A(peers=[B]) 与 B(peers=[A]) 互连（先取两空闲端口再互设 peers）
  const portA = await getFreePort();
  const portB = await getFreePort();
  const rootA = makeRoot();
  const rootB = makeRoot();
  const gwA = createHttpGateway({ port: portA, root: rootA, peers: [`http://127.0.0.1:${portB}`] });
  const gwB = createHttpGateway({ port: portB, root: rootB, peers: [`http://127.0.0.1:${portA}`] });
  await gwA.start();
  await gwB.start();
  const client = createHttpClient({ baseUrl: `http://127.0.0.1:${portA}` });
  const nodeX = createVapNode({ nodeId: 'x', root: makeRoot() });
  const env = nodeX.send(validSendParams());
  try {
    const posted = await client.post(env);
    assert.equal(posted.status, 202);
    await new Promise((r) => setTimeout(r, 500)); // 等异步转发尘埃落定
    assert.equal(gwA.health().relayed, 1, 'A 对该信封只转发一次');
    assert.equal(gwB.health().relayed, 1, 'B 对该信封只转发一次');
    assert.equal(countInboxJson(rootA), 1, 'A 对回弹重放 409 不落盘');
    assert.equal(countInboxJson(rootB), 1);
  } finally {
    await gwA.stop();
    await gwB.stop();
  }
});
