// tests/security-regression.test.mjs —— 修复批次 1（安全）回归测试
//
// 运行：在 dsh-vap/ 下 `node --test`（或 `node --test tests/security-regression.test.mjs`）
// 一条测试钉一个已修复的漏洞；每条都先复现攻击输入，再断言"被拒且不崩、不留越界痕迹"。
//
// 覆盖：F1 nonce 白名单 / F2 host 参数 / F6 slash 证据 pubKey 绑定 / F7 endorsements 类型守卫
//       M1 envelope.id 白名单 / M2 rotate 新钥校验 / M3 relay 注册白名单+顶替认证+帧限速
//       M4 consume 仅 pass 登记 / M5 taskId 白名单 / M6 ledgerFile 文件名 / M7 网关验签前置 403
//
// 零第三方依赖：仅 node: 内置模块 + 本仓库相对 import。

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';

import {
  createVapNode,
  createBrain,
  makeLaws,
  canonicalJson,
  claimNonce,
  nonceSeen,
} from '../vap-core.mjs';
import { createHttpGateway, createHttpClient, ENVELOPE_ID_PATTERN } from '../vap-transport.mjs';
import { createHttpTransport } from '../phase1/transport-spi.mjs';
import { verifyDoubleSignEvidence, verifyDoubleSignEvidenceBound } from '../phase3/endorse-core.mjs';
import { createRelayServer, encodeFrame } from '../phase4/relay-server.mjs';
import { createNode, GENESIS_HASH, ledgerFileNameFor } from '../phase5/vap-to.mjs';
import { createMembershipNode } from '../phase6/vap-to-membership.mjs';

// ---------------------------------------------------------------------------
// 装置助手
// ---------------------------------------------------------------------------

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-sec-'));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

function validSendParams(overrides = {}) {
  return {
    to: 'brain',
    claim: { type: 'report', body: { work: 'scout' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:abcd' },
    boundary: 'L2a',
    report: { summary: 'security regression', keyNumbers: [1], request: '' },
    ...overrides,
  };
}

function rawPost(port, pathname, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const h = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...headers };
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method: 'POST', headers: h }, (res) => {
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
    req.write(body);
    req.end();
  });
}

async function waitFor(cond, timeoutMs = 3000, intervalMs = 20) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return cond();
}

function makeKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey,
    privateKey,
    pubKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}

function signText(text, privateKey) {
  return crypto.sign(null, Buffer.from(text, 'utf8'), privateKey).toString('base64');
}

function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

const MEMBERSHIP_IDS = ['n1', 'n2', 'n3', 'n4'];

function buildMembershipWorld() {
  const keys = MEMBERSHIP_IDS.map(() => makeKeys());
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-sec-mem-'));
  const peers = MEMBERSHIP_IDS.map((id, i) => ({ nodeId: id, pubKey: keys[i].pubKey }));
  const nodes = MEMBERSHIP_IDS.map((id, i) =>
    createMembershipNode({ nodeId: id, keyPair: keys[i], n: 4, f: 1, peers, ledgerDir: dir }),
  );
  return { keys, peers, nodes, dir };
}

// 造一份"密码学上真实可验"的双签证据：同 (nodeId, envelopeId) 两份冲突内容各签一次。
function makeDoubleSignEvidence({ nodeId, signer }) {
  const contentA = canonicalJson({ view: 1, payload: 'A' });
  const contentB = canonicalJson({ view: 1, payload: 'B' });
  return {
    nodeId,
    envelopeId: '1',
    pubKey: signer.pubKey,
    contentA,
    contentB,
    sigA: signText(contentA, signer.privateKey),
    sigB: signText(contentB, signer.privateKey),
  };
}

// ---------------------------------------------------------------------------
// F1 nonce 路径穿越 DoS
// ---------------------------------------------------------------------------

test('F1 nonce 白名单：claimNonce 对越界 nonce 直接拒绝且完全不碰文件系统', () => {
  const root = makeRoot();
  const badNonces = [
    '../../evil',
    'a/b',
    '..\\..\\evil',
    '/etc/passwd',
    'ABCDEF0123456789',   // 大写不在白名单
    '0123456789abcde',    // 15 位
    '0123456789abcdef0',  // 17 位
    '',
    null,
    123,
  ];
  for (const bad of badNonces) {
    assert.equal(claimNonce(root, bad), false, `claimNonce 必须拒绝 ${String(bad)}`);
    assert.equal(nonceSeen(root, bad), false, `nonceSeen 必须拒绝 ${String(bad)}`);
  }
  // 关键证据：一次非法 nonce 都不该让 seen-nonces 目录被创建（更不该落文件）。
  assert.equal(fs.existsSync(path.join(root, 'seen-nonces')), false, '非法 nonce 不得创建 seen-nonces 目录');

  // 合法 nonce 行为不变：首次 true、重复 false。
  assert.equal(claimNonce(root, '0123456789abcdef'), true);
  assert.equal(claimNonce(root, '0123456789abcdef'), false);
  assert.deepEqual(fs.readdirSync(path.join(root, 'seen-nonces')), ['0123456789abcdef']);
});

test('F1 网关：nonce 含 / 或 .. → 400 bad nonce，网关不崩且不留越界文件', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  const node = createVapNode({ nodeId: 'sender', root: makeRoot() });
  try {
    const env = node.send(validSendParams());
    for (const badNonce of ['../../../etc/passwd', 'a/b', 'no-hex-nonce!!']) {
      const resp = await rawPost(port, '/envelopes', JSON.stringify({ ...env, nonce: badNonce }));
      assert.equal(resp.status, 400, `nonce=${badNonce} 应 400`);
      assert.equal(resp.data.error, 'bad nonce');
    }
    // 不崩：紧接着的合法信封照常 202（同一网关进程仍在服务）。
    const client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
    const ok = await client.post(env);
    assert.equal(ok.status, 202);
    assert.equal(ok.ok, true);
    // 只留合法 nonce 的标记文件，没有任何越界痕迹。
    assert.deepEqual(fs.readdirSync(path.join(root, 'seen-nonces')), [env.nonce]);
    assert.equal(fs.existsSync(path.join(path.dirname(root), 'etc')), false);
  } finally {
    await gw.stop();
  }
});

// ---------------------------------------------------------------------------
// M1 envelope.id 路径穿越
// ---------------------------------------------------------------------------

test('M1 envelope.id 白名单：含 ../ 或非 evt-<16hex> → 400，且不越出 inbox-http', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  const node = createVapNode({ nodeId: 'sender', root: makeRoot() });
  try {
    const env = node.send(validSendParams());
    const badIds = ['../../evil', '../evil', 'evt-notahex0000000', 'evt-XYZ', 'evt-/../x', ''];
    for (const badId of badIds) {
      const resp = await rawPost(port, '/envelopes', JSON.stringify({ ...env, id: badId }));
      assert.equal(resp.status, 400, `id=${badId} 应 400`);
      assert.ok(
        resp.data.error === 'bad envelope id' || resp.data.error === 'envelope.id is required',
        `id=${badId} 错误信息应为白名单拒绝，实际 ${resp.data.error}`,
      );
    }
    // 越界文件一个都不许出现（root/inbox-http/../../evil.json → root 的上层目录）。
    assert.equal(fs.existsSync(path.join(path.dirname(root), 'evil.json')), false);
    assert.equal(fs.existsSync(path.join(root, 'evil.json')), false);
    assert.deepEqual(fs.readdirSync(path.join(root, 'inbox-http')), []);
    // 合法 id（node.send 的生成格式）照常 202。
    assert.match(env.id, ENVELOPE_ID_PATTERN);
    const client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
    assert.equal((await client.post(env)).status, 202);
  } finally {
    await gw.stop();
  }
});

test('M1 兼容模式（strictEnvelopeId:false）允许自定义 id，但仍拒绝路径穿越', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root, strictEnvelopeId: false, requireInboundSignature: false });
  const port = await gw.start();
  try {
    const legacy = { v: 1, id: 'evt-legacy-id', nonce: 'aaaaaaaaaaaaaaaa', from: { nodeId: 'x' }, claim: {} };
    assert.equal((await rawPost(port, '/envelopes', JSON.stringify(legacy))).status, 202);
    const traversal = { ...legacy, id: '../../evil', nonce: 'bbbbbbbbbbbbbbbb' };
    const resp = await rawPost(port, '/envelopes', JSON.stringify(traversal));
    assert.equal(resp.status, 400);
    assert.equal(resp.data.error, 'bad envelope id');
    assert.deepEqual(fs.readdirSync(path.join(root, 'inbox-http')), ['evt-legacy-id.json']);
  } finally {
    await gw.stop();
  }
});

// ---------------------------------------------------------------------------
// M7 网关验签前置
// ---------------------------------------------------------------------------

test('M7 网关验签前置：无签名 / 被篡改的信封 → 403 且不落盘、不消耗 nonce', async () => {
  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, root });
  const port = await gw.start();
  const node = createVapNode({ nodeId: 'sender', root: makeRoot() });
  try {
    const env = node.send(validSendParams());

    // ① 无签名
    const unsigned = { ...env, sig: '' };
    const r1 = await rawPost(port, '/envelopes', JSON.stringify(unsigned));
    assert.equal(r1.status, 403);
    assert.equal(r1.data.error, 'signature verification failed');

    // ② 签名有效但内容被篡改（签名不再匹配 payload）
    const tampered = { ...env, report: { ...env.report, summary: 'tampered by man in the middle' } };
    const r2 = await rawPost(port, '/envelopes', JSON.stringify(tampered));
    assert.equal(r2.status, 403);

    assert.deepEqual(fs.readdirSync(path.join(root, 'inbox-http')), [], '403 的信封不许落盘');
    assert.equal(fs.existsSync(path.join(root, 'seen-nonces', env.nonce)), false, '验签失败不许消耗 nonce');

    // ③ 原封（签名完整）仍然 202：验签前置不影响真信封。
    const client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
    assert.equal((await client.post(env)).status, 202);
    assert.deepEqual(fs.readdirSync(path.join(root, 'inbox-http')), [`${env.id}.json`]);
  } finally {
    await gw.stop();
  }
});

// ---------------------------------------------------------------------------
// F2 HTTP 网关 host 参数
// ---------------------------------------------------------------------------

test('F2 host 参数：默认回环不变，显式 0.0.0.0 绑定成功且可从回环拨号', async () => {
  const defaultGw = createHttpGateway({ port: 0, root: makeRoot() });
  assert.equal(defaultGw.host, '127.0.0.1', '安全默认：不传 host 仍只绑回环');

  const root = makeRoot();
  const gw = createHttpGateway({ port: 0, host: '0.0.0.0', root });
  const port = await gw.start();
  const node = createVapNode({ nodeId: 'sender', root: makeRoot() });
  try {
    assert.ok(Number.isInteger(port) && port > 0, 'port=0 应分配到真实端口');
    assert.equal(gw.host, '0.0.0.0');
    assert.equal(gw.baseUrl, `http://127.0.0.1:${port}`, '通配地址的可拨号 base URL 映射为回环');
    const client = createHttpClient({ baseUrl: gw.baseUrl });
    const env = node.send(validSendParams());
    assert.equal((await client.post(env)).status, 202);
    assert.equal(gw.health().envelopesIn, 1);
  } finally {
    await gw.stop();
  }
});

test('F2 host 透传：createHttpTransport({ host }) 传到网关', async () => {
  const t = createHttpTransport({ port: 0, host: '0.0.0.0', root: makeRoot() });
  const port = await t.start();
  try {
    assert.equal(t.host, '0.0.0.0');
    assert.equal(t.gateway.host, '0.0.0.0');
    assert.equal(t.baseUrl, `http://127.0.0.1:${port}`);
  } finally {
    await t.close();
  }
});

// ---------------------------------------------------------------------------
// F6 slash 证据 pubKey 绑定（嫁祸）
// ---------------------------------------------------------------------------

test('F6 slash 证据必须绑定被指控者的 roster 公钥（嫁祸无辜者失败）', () => {
  const { nodes, keys } = buildMembershipWorld();
  const attacker = makeKeys();

  // 攻击者用自己的密钥造一份"真实可验"的双签证据，只把 nodeId 写成无辜的 n4。
  const framed = makeDoubleSignEvidence({ nodeId: 'n4', signer: attacker });
  assert.equal(verifyDoubleSignEvidence(framed), true, '证据自身可验 —— 这正是嫁祸的危险之处');
  assert.equal(verifyDoubleSignEvidenceBound(framed, keys[3].pubKey), false, '绑定校验必须识破嫁祸');

  const framedTx = {
    type: 'membership', op: 'slash', nodeId: 'n4', evidence: framed, from: 'n1', nonce: 'slash-framed',
  };
  const framedRes = nodes[0].checkMembershipTx(framedTx);
  assert.equal(framedRes.pass, false, '嫁祸 slash 必须被拒');
  assert.ok(
    framedRes.reasons.some((r) => r.includes('evidence.pubKey does not match')),
    `拒绝理由应指出公钥未绑定，实际 ${framedRes.reasons.join('; ')}`,
  );

  // 举报入口同样拒绝打包嫁祸证据。
  const packed = nodes[0].expelByEquivocation(framed);
  assert.equal(packed.ok, false);
  assert.ok(String(packed.reason).includes('does not match'));

  // 正例：真作恶者（n4 自己的钥）的冲突签名 → 绑定通过、判定放行（修复没有把真除名打死）。
  const real = makeDoubleSignEvidence({ nodeId: 'n4', signer: keys[3] });
  assert.equal(verifyDoubleSignEvidenceBound(real, keys[3].pubKey), true);
  const realRes = nodes[0].checkMembershipTx({
    type: 'membership', op: 'slash', nodeId: 'n4', evidence: real, from: 'n1', nonce: 'slash-real',
  });
  assert.equal(realRes.pass, true, realRes.reasons.join('; '));
  assert.equal(nodes[0].expelByEquivocation(real).ok, true);
});

test('F6 verifyDoubleSignEvidenceBound：缺期望公钥或证据不可验一律 false', () => {
  const signer = makeKeys();
  const ev = makeDoubleSignEvidence({ nodeId: 'n9', signer });
  assert.equal(verifyDoubleSignEvidenceBound(ev, signer.pubKey), true);
  assert.equal(verifyDoubleSignEvidenceBound(ev, null), false);
  assert.equal(verifyDoubleSignEvidenceBound(ev, undefined), false);
  assert.equal(verifyDoubleSignEvidenceBound(ev, makeKeys().pubKey), false);
  assert.equal(verifyDoubleSignEvidenceBound({ ...ev, contentB: ev.contentA }, signer.pubKey), false);
  assert.equal(verifyDoubleSignEvidenceBound(null, signer.pubKey), false);
  // KeyObject 与 base64 两种写法等价（比较前统一规范化）。
  assert.equal(verifyDoubleSignEvidenceBound(ev, signer.publicKey), true);
});

// ---------------------------------------------------------------------------
// F7 endorsements 类型守卫 + 判定链路异常边界
// ---------------------------------------------------------------------------

test('F7 tx.endorsements 非数组 → reject 且不抛 TypeError', () => {
  const { nodes } = buildMembershipWorld();
  for (const bad of [123, 'endorsements', { nodeId: 'n2' }, true]) {
    const tx = {
      type: 'membership', op: 'join', nodeId: 'n5', endorsements: bad, from: 'n1', nonce: `bad-${String(bad)}`,
    };
    let res;
    assert.doesNotThrow(() => { res = nodes[0].checkMembershipTx(tx); }, `endorsements=${String(bad)} 不许抛`);
    assert.equal(res.pass, false);
    assert.ok(
      res.reasons.some((r) => r.includes('must be an array')),
      `应报类型守卫，实际 ${res.reasons.join('; ')}`,
    );
  }
});

test('F7 判定链路（safetyRule→vote）遇畸形交易只拒投，不抛异常', () => {
  const { nodes } = buildMembershipWorld();
  const badTx = {
    type: 'membership', op: 'join', nodeId: 'n5', endorsements: 42, from: 'n1', nonce: 'bad-endorsements',
  };
  // n1 是 view 0 的 leader：用它签一个含畸形交易的提案。
  const proposal = nodes[0].signProposal({ view: 0, leader: 'n1', parentHash: GENESIS_HASH, txs: [badTx] });

  for (const voter of [nodes[1], nodes[2], nodes[3]]) {
    let safety;
    assert.doesNotThrow(() => { safety = voter.safetyRule(proposal); });
    assert.equal(safety.pass, false);
    let voteRes;
    assert.doesNotThrow(() => { voteRes = voter.vote(proposal); });
    assert.equal(voteRes.voted, false, '诚实节点对畸形交易 0 票');
    assert.equal(typeof voteRes.reason, 'string');
  }

  // 畸形 subject 进军法闸也只判拒（不崩）。
  for (const subject of [null, 42, 'x', []]) {
    let lr;
    assert.doesNotThrow(() => { lr = nodes[0].checkLaws(subject); });
    assert.equal(lr.pass, false);
  }
  // 完全畸形的 tx 同样只判拒。
  for (const tx of [null, 42, 'x', []]) {
    let res;
    assert.doesNotThrow(() => { res = nodes[0].checkMembershipTx(tx); });
    assert.equal(res.pass, false);
  }
});

test('F7 join credential 缺 work → reject（不抛 TypeError）', () => {
  const { nodes } = buildMembershipWorld();
  const applicant = makeKeys();
  for (const cred of [{ holder: 'n5' }, { holder: 'n5', work: 'not-an-object' }, { work: null }]) {
    const tx = {
      type: 'membership',
      op: 'join',
      nodeId: 'n5',
      pubKey: applicant.pubKey,
      credential: cred,
      endorsements: [],
      from: 'n1',
      nonce: `join-bad-${Math.random().toString(16).slice(2)}`,
    };
    let res;
    assert.doesNotThrow(() => { res = nodes[0].checkMembershipTx(tx); });
    assert.equal(res.pass, false);
    assert.ok(
      res.reasons.some((r) => r.includes('malformed credential')),
      `应报凭证结构非法，实际 ${res.reasons.join('; ')}`,
    );
  }
});

// ---------------------------------------------------------------------------
// M2 rotate 新钥校验
// ---------------------------------------------------------------------------

test('M2 rotate 新钥非法 → 发起被拒且判定被拒（非法钥不上链）', () => {
  const { nodes, keys } = buildMembershipWorld();
  const n3 = nodes[2];

  // ① 发起侧：rotateKey 直接拒绝非法新钥。
  for (const badKey of ['not-a-key', 'AAAA', '']) {
    const res = n3.rotateKey({ oldPubKey: n3.pubKey, newPubKey: badKey });
    assert.equal(res.ok, false, `newPubKey=${badKey} 应被拒`);
  }

  // ② 判定侧：手工绕过 rotateKey 构造的非法 rotate 交易也必须被拒。
  const badNew = 'AAAA'; // 合法 base64，但不是 Ed25519 spki 公钥
  const subject = { op: 'rotate', nodeId: 'n3', oldPubKey: n3.pubKey, newPubKey: badNew };
  const badTx = {
    type: 'membership',
    op: 'rotate',
    nodeId: 'n3',
    oldPubKey: n3.pubKey,
    newPubKey: badNew,
    sig: signText(canonicalJson(subject), keys[2].privateKey),
    from: 'n3',
    nonce: 'rotate-bad',
  };
  let res;
  assert.doesNotThrow(() => { res = nodes[0].checkMembershipTx(badTx); });
  assert.equal(res.pass, false);
  assert.ok(
    res.reasons.some((r) => r.includes('not a usable public key')),
    `应报新钥不可用，实际 ${res.reasons.join('; ')}`,
  );

  // ③ 正例：合法新钥仍可轮换（修复没有把正常轮换打死）。
  const fresh = makeKeys();
  const ok = n3.rotateKey({ oldPubKey: n3.pubKey, newPubKey: fresh.pubKey, newPrivateKey: fresh.privateKey });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(nodes[0].checkMembershipTx(ok.tx).pass, true);
});

// ---------------------------------------------------------------------------
// M3 relay 注册白名单 + 顶替认证 + 帧限速
// ---------------------------------------------------------------------------

function connectRaw(port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => resolve(sock));
    sock.on('error', reject);
  });
}

test('M3 relay 注册白名单：越界 nodeId 拒绝注册（不进转发表）', async () => {
  const server = createRelayServer({ port: 0 });
  const port = await server.start();
  const sock = await connectRaw(port);
  try {
    for (const badId of ['../evil', 'a/b', 'x'.repeat(65), '', 'has space']) {
      sock.write(encodeFrame({ type: 'register', nodeId: badId, pubKey: 'pk' }));
    }
    await waitFor(() => server.stats().rejectedRegistrations >= 4);
    assert.ok(server.stats().rejectedRegistrations >= 4, JSON.stringify(server.stats()));
    assert.deepEqual(server.registry(), [], '非法 nodeId 一个都不许进表');
    assert.equal(server.stats().registered, 0);

    // 合法 nodeId 照常注册。
    sock.write(encodeFrame({ type: 'register', nodeId: 'node-1', pubKey: 'pk-1' }));
    await waitFor(() => server.registry().length === 1);
    assert.deepEqual(server.registry(), ['node-1']);
  } finally {
    sock.destroy();
    await server.stop();
  }
});

test('M3 relay 顶替认证：pubKey 不匹配 → 拒绝顶替，旧连接继续收信封', async () => {
  const server = createRelayServer({ port: 0 });
  const port = await server.start();
  const owner = await connectRaw(port);
  const attacker = await connectRaw(port);
  const sender = await connectRaw(port);
  const ownerFrames = [];
  const attackerFrames = [];
  owner.on('data', (c) => ownerFrames.push(c));
  attacker.on('data', (c) => attackerFrames.push(c));
  try {
    owner.write(encodeFrame({ type: 'register', nodeId: 'dup', pubKey: 'pk-owner' }));
    await waitFor(() => server.registry().includes('dup'));
    sender.write(encodeFrame({ type: 'register', nodeId: 'sender', pubKey: 'pk-sender' }));
    await waitFor(() => server.registry().includes('sender'));

    // 攻击者知道 nodeId，但拿不出旧注册者的 pubKey → 顶替被拒。
    attacker.write(encodeFrame({ type: 'register', nodeId: 'dup', pubKey: 'pk-attacker' }));
    await waitFor(() => server.stats().rejectedTakeovers === 1);
    assert.equal(server.stats().rejectedTakeovers, 1);
    assert.equal(server.stats().replacements, 0, '不许发生顶替');
    assert.equal(owner.destroyed, false, '旧连接不许被踢');

    // 发给 dup 的信封仍旧到达 owner，不到 attacker。
    sender.write(encodeFrame({ type: 'relay', to: 'dup', envelope: { id: 'evt-x' } }));
    await waitFor(() => ownerFrames.length > 0);
    assert.ok(ownerFrames.length > 0, 'owner 应收到信封');
    assert.equal(attackerFrames.length, 0, 'attacker 不许截获信封');

    // 携带正确 pubKey 的重连仍可顶替（掉线重连不被误伤）。
    const reconnect = await connectRaw(port);
    try {
      reconnect.write(encodeFrame({ type: 'register', nodeId: 'dup', pubKey: 'pk-owner' }));
      await waitFor(() => server.stats().replacements === 1);
      assert.equal(server.stats().replacements, 1);
    } finally {
      reconnect.destroy();
    }
  } finally {
    owner.destroy();
    attacker.destroy();
    sender.destroy();
    await server.stop();
  }
});

test('M3 relay 帧限速：单连接超过每秒帧数上限 → 断连', async () => {
  const server = createRelayServer({ port: 0, maxFramesPerSec: 5 });
  const port = await server.start();
  const sock = await connectRaw(port);
  let closed = false;
  sock.on('close', () => { closed = true; });
  try {
    for (let i = 0; i < 40; i++) {
      sock.write(encodeFrame({ type: 'register', nodeId: `flood-${i}`, pubKey: 'pk' }));
    }
    const gotClosed = await waitFor(() => closed && server.stats().rateLimited >= 1);
    assert.equal(gotClosed, true, `超限应断连，stats=${JSON.stringify(server.stats())}`);
    assert.ok(server.stats().rateLimited >= 1);
  } finally {
    sock.destroy();
    await server.stop();
  }
});

// ---------------------------------------------------------------------------
// M4 consume 仅 pass 登记
// ---------------------------------------------------------------------------

test('M4 consume 仅 pass 才写 registry.json（被拒信封不污染登记册）', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-bad', root });
  const brain = createBrain({ root });
  const registryPath = path.join(root, 'registry.json');

  // ① 军法必拒的信封（坏边界）→ 不登记。
  const rejected = node.send(validSendParams({ boundary: 'L9' }));
  const v1 = brain.consume().find((v) => v.envelopeId === rejected.id);
  assert.equal(v1.pass, false);
  assert.equal(fs.existsSync(registryPath), false, '被拒信封不许创建 registry.json');

  // ② 无签名伪造件 → 不登记。
  const forged = node.send(validSendParams());
  forged.sig = '';
  fs.writeFileSync(path.join(root, 'outbox', `${forged.id}.json`), JSON.stringify(forged));
  const v2 = brain.consume().find((v) => v.envelopeId === forged.id);
  assert.equal(v2.pass, false);
  assert.equal(fs.existsSync(registryPath), false);

  // ③ 裁决通过的信封 → 照常首封自注册。
  const ok = node.send(validSendParams());
  const v3 = brain.consume().find((v) => v.envelopeId === ok.id);
  assert.equal(v3.pass, true, JSON.stringify(v3 && v3.reasons));
  const reg = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  assert.equal(reg['scout-bad'], node.pubKey);
});

// ---------------------------------------------------------------------------
// M5 heartbeat/complete taskId 白名单
// ---------------------------------------------------------------------------

test('M5 taskId 白名单：heartbeat/complete 对越界 taskId 抛错拒绝操作', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const badIds = ['../../evil', '..', 'a/b', 'a\\b', 'x'.repeat(65), 'has space'];
  for (const taskId of badIds) {
    assert.throws(() => node.heartbeat({ taskId }), /invalid taskId/, `heartbeat ${taskId}`);
    assert.throws(() => node.complete({ taskId }, { status: 'done' }), /invalid taskId/, `complete ${taskId}`);
  }
  // 越界写入一个都没发生。
  assert.equal(fs.existsSync(path.join(path.dirname(root), 'evil.lock')), false);
  assert.equal(fs.existsSync(path.join(path.dirname(root), 'evil.json')), false);

  // 合法 taskId 行为不变：认领 → 心跳 → 完成。
  fs.mkdirSync(path.join(root, 'inbox'), { recursive: true });
  fs.writeFileSync(path.join(root, 'inbox', 'task-42.json'), JSON.stringify({ work: 'scout' }));
  const claimed = node.claimTask();
  assert.equal(claimed.taskId, '42');
  assert.equal(node.heartbeat(claimed).taskId, '42');
  assert.equal(node.complete(claimed, { status: 'done' }).taskId, '42');
  assert.ok(fs.existsSync(path.join(root, 'done', '42.json')));
});

// ---------------------------------------------------------------------------
// M6 ledgerFile nodeId 安全
// ---------------------------------------------------------------------------

test('M6 ledgerFile：越界 nodeId 用 sha256 文件名且不越出 ledgerDir，账本行内保留 nodeId', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-sec-ledger-'));
  const evilId = '../evil';
  const keys = makeKeys();
  const node = createNode({
    nodeId: evilId,
    keyPair: keys,
    n: 1,
    f: 0,
    peers: [{ nodeId: evilId, pubKey: keys.pubKey }],
    ledgerDir: dir,
  });

  assert.equal(path.dirname(node.ledgerFile), dir, '账本文件必须留在 ledgerDir 内');
  assert.equal(path.basename(node.ledgerFile), `ledger-sha256-${sha256hex(evilId)}.jsonl`);
  assert.equal(ledgerFileNameFor(evilId), `ledger-sha256-${sha256hex(evilId)}.jsonl`);
  assert.equal(ledgerFileNameFor('n1'), 'ledger-n1.jsonl', '白名单内 nodeId 保留可读文件名');

  // 落一个真区块（3-chain 提交：连推 3 个 view）：文件名是摘要，但账本行内保留 nodeId 本体。
  node.submitTx({ type: 'commit', from: 'client', nonce: 'sec-1', payload: { pay: 1 } });
  for (let v = 0; v < 3; v++) {
    const pr = node.propose(v);
    assert.ok(pr.proposal, JSON.stringify(pr));
    const voteRes = node.vote(pr.proposal);
    assert.equal(voteRes.voted, true, voteRes.reason);
    const qc = node.collectQC([voteRes.vote]);
    assert.equal(qc.ok, true, JSON.stringify(qc));
    node.commitCheck();
  }
  assert.equal(node.committedHeight, 1);

  const lines = fs.readFileSync(node.ledgerFile, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).nodeId, evilId, '账本内容行内必须保留 nodeId');
  assert.deepEqual(
    fs.readdirSync(dir),
    [`ledger-sha256-${sha256hex(evilId)}.jsonl`],
    'ledgerDir 内只应出现摘要文件名',
  );
  assert.equal(fs.existsSync(path.join(path.dirname(dir), 'evil.jsonl')), false);
});
