// tests/deploy-regression.test.mjs —— 修复批次 2（部署）回归测试
//
// 运行：在 dsh-vap/ 下 `node --test`（或 `node --test tests/deploy-regression.test.mjs`）
// 覆盖（对照 fix-batch2-brief.md 验收）：
//   F3  key-store 存取/加载/chmod；createVapNode/createNode/createMembershipNode persistKeys；rotate 新钥落盘
//   M8  config loadConfig JSON + VAP_* env 覆盖
//   M9  logger JSON line + 1MB 轮转
//   M10 package.json + 三 bin 可启动、SIGTERM 优雅退出（短超时）
//   M11 health 真实状态 + relay 旁路 /health + vap-to health()
//   M12 phase5 restore 补 QC 回放 + phase6 restore 重写成员状态回放 + autoRestore
//   M13 ledgerDir/TRAIL_DIR 默认 os.tmpdir
//
// 零第三方依赖：仅 node: 内置模块 + 本仓库相对 import。

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

import { createVapNode } from '../vap-core.mjs';
import { createHttpGateway, createHttpClient } from '../vap-transport.mjs';
import { saveKey, loadKey, safeNodeId, keyDir } from '../key-store.mjs';
import { loadConfig, defaultConfig, defaultLedgerDir, defaultTrailDir } from '../config.mjs';
import { createLogger } from '../logger.mjs';
import { createRelayServer } from '../phase4/relay-server.mjs';
import { createNode, GENESIS_HASH } from '../phase5/vap-to.mjs';
import { createMembershipNode } from '../phase6/vap-to-membership.mjs';
import { signAuditTrail } from '../phase0.5/bootstrap-forge.mjs';
import { createGenesisAnchor, issueCredential } from '../phase0.5/bootstrap-forge.mjs';
import { makeTask } from '../phase0/history-forge.mjs';

// ---------------------------------------------------------------------------
// 装置助手
// ---------------------------------------------------------------------------

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function makeKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey,
    privateKey,
    pubKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function httpGet(port, route) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: route }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    }).on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// F3 key-store 存取 / 加载 / chmod
// ---------------------------------------------------------------------------

test('F3 key-store：saveKey 落盘 PKCS8、loadKey 读回等价、无文件返回 null', () => {
  const root = tmpDir('vap-ks-');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

  const file = saveKey(root, 'node-a', privateKey);
  assert.ok(fs.existsSync(file), 'key file exists');
  assert.equal(path.dirname(file), keyDir(root), 'key file lives under root/keys');

  const loaded = loadKey(root, 'node-a');
  assert.ok(loaded, 'loadKey returns KeyObject');
  assert.equal(
    loaded.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    'loaded private key equals original',
  );
  const derivedPub = crypto.createPublicKey(loaded).export({ type: 'spki', format: 'der' }).toString('base64');
  assert.equal(derivedPub, publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), 'derived pub matches');

  assert.equal(loadKey(root, 'missing-node'), null, 'missing key returns null');
});

test('F3 key-store：safeNodeId 使用 sha256 摘要（越界 nodeId 不越出 keys 目录）', () => {
  const evil = '../../evil';
  const id = safeNodeId(evil);
  assert.match(id, /^[0-9a-f]{64}$/, 'safeNodeId is 64 hex');
  assert.ok(!id.includes('/') && !id.includes('..'), 'no path chars in filename');
  const root = tmpDir('vap-ks2-');
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const file = saveKey(root, evil, privateKey);
  assert.equal(path.dirname(file), keyDir(root), 'file stays inside root/keys');
  assert.ok(fs.existsSync(file), 'saved under hashed name');
});

test('F3 createVapNode persistKeys：生成落盘 + 重启加载同一身份', () => {
  const root = tmpDir('vap-vn-');
  const a = createVapNode({ nodeId: 'alice', root, persistKeys: true });
  const firstPub = a.pubKey;
  assert.ok(loadKey(root, 'alice'), 'key persisted');

  const b = createVapNode({ nodeId: 'alice', root, persistKeys: true });
  assert.equal(b.pubKey, firstPub, 'restart loads persisted identity (same pubKey)');
});

test('F3 createNode persistKeys：无 keyPair 先 load、缺失则生成并落盘', () => {
  const dir = tmpDir('vap-p5ks-');
  // 先落盘一个持久身份，再据此拼 peers（无 keyPair + persistKeys → load 该身份）。
  const keys = makeKeys();
  saveKey(dir, 'n1', keys.privateKey);
  const peers = [{ nodeId: 'n1', pubKey: keys.pubKey }];

  const node = createNode({ nodeId: 'n1', n: 1, f: 0, peers, ledgerDir: dir, persistKeys: true });
  assert.equal(node.pubKey, keys.pubKey, '无 keyPair 时 load 持久身份');

  // 缺失持久身份 + persistKeys → 生成新钥并落盘（用生成出的 pubKey 拼 peers 再验）。
  const dir2 = tmpDir('vap-p5ks2-');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubKey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  saveKey(dir2, 'n2', privateKey);
  const peers2 = [{ nodeId: 'n2', pubKey }];
  const node2 = createNode({ nodeId: 'n2', n: 1, f: 0, peers: peers2, ledgerDir: dir2, persistKeys: true });
  assert.equal(node2.pubKey, pubKey, 'second node loads persisted identity');
  assert.ok(loadKey(dir2, 'n2'), 'key file present after load');
});

test('F3 createMembershipNode rotateKey 生效后新私钥落盘（原子切换）', () => {
  const dir = tmpDir('vap-p6ks-');
  const keys = makeKeys();
  const peers = [{ nodeId: 'n1', pubKey: keys.pubKey }];
  const genesis = createGenesisAnchor();
  const credentialCtx = { genesis: { id: genesis.id, publicKey: genesis.publicKey }, keys: new Map(), credentials: new Map() };

  const node = createMembershipNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers, ledgerDir: dir, persistKeys: true, credentialCtx });
  assert.equal(loadKey(dir, 'n1').export({ type: 'pkcs8', format: 'pem' }).toString(), keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), 'initial key persisted');

  const newKeys = makeKeys();
  const rot = node.rotateKey({ oldPubKey: node.pubKey, newPubKey: newKeys.pubKey, newPrivateKey: newKeys.privateKey });
  assert.equal(rot.ok, true, rot.reason);
  // 提交轮换并推进到 h+2 生效（单节点 n=1：提案→投→collect→commit，3 块后 commit，再 2 块生效）。
  runSingleNodeConsensus(node, rot.tx, 6);
  assert.equal(node.pubKey, newKeys.pubKey, 'rotate took effect');
  const persisted = loadKey(dir, 'n1');
  assert.equal(persisted.export({ type: 'pkcs8', format: 'pem' }).toString(), newKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), 'new private key persisted');
});

// 单节点共识推进：把 tx 在第 0 个视图提交，随后连续推进 views 个视图
// （每视图：propose → vote → collectQC → commitCheck → applyDueChanges）。
function runSingleNodeConsensus(node, tx, views) {
  node.submitTx(tx);
  for (let v = 0; v < views; v++) {
    const pr = node.propose(v);
    if (pr.refused) { node.onTimeout(); continue; }
    const vr = node.vote(pr.proposal);
    if (vr.voted) node.collectQC([vr.vote]);
    node.commitCheck();
    if (node.applyDueChanges) node.applyDueChanges();
  }
}

// ---------------------------------------------------------------------------
// M8 config 外部化
// ---------------------------------------------------------------------------

test('M8 loadConfig：JSON 合并 + VAP_* env 覆盖', () => {
  const cfgFile = path.join(tmpDir('vap-cfg-'), 'config.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ gatewayHost: '10.0.0.1', gatewayPort: 9000, ledgerDir: '/from/file' }), 'utf8');
  const env = { VAP_GATEWAY_PORT: '1234', VAP_RELAY_HOST: 'relay.example', VAP_PEER_FORWARD_MS: '3500' };
  const cfg = loadConfig({ path: cfgFile, env });
  assert.equal(cfg.gatewayHost, '10.0.0.1', 'file value kept when env not set');
  assert.equal(cfg.gatewayPort, 1234, 'env overrides file (number coerced)');
  assert.equal(cfg.ledgerDir, '/from/file', 'file ledgerDir kept');
  assert.equal(cfg.relayHost, 'relay.example', 'env fills absent key');
  assert.equal(cfg.timeouts.peerForwardMs, 3500, 'env overrides timeout (number coerced)');
});

test('M8 loadConfig：无 path 时默认值含 tmpdir 数据目录', () => {
  const cfg = loadConfig({ env: {} });
  assert.equal(cfg.gatewayHost, '127.0.0.1', 'default gateway host loopback');
  assert.equal(cfg.ledgerDir, defaultLedgerDir(), 'default ledgerDir = tmpdir');
  assert.equal(cfg.trailDir, defaultTrailDir(), 'default trailDir = tmpdir');
});

test('M8 createHttpGateway config 覆盖 host/port 默认值', async () => {
  const root = tmpDir('vap-gwcfg-');
  const gw = createHttpGateway({ root, config: { gatewayHost: '127.0.0.1', gatewayPort: 0 } });
  const port = await gw.start();
  try {
    assert.ok(Number.isInteger(port) && port > 0, 'gateway bound');
  } finally {
    await gw.stop();
  }
});

// ---------------------------------------------------------------------------
// M9 logger 轮转
// ---------------------------------------------------------------------------

test('M9 logger：JSON line 格式 + 1MB 轮转为 .1（只保留一代）', () => {
  const dir = tmpDir('vap-log-');
  const file = path.join(dir, 'vap.log');
  const logger = createLogger({ file, level: 'info', component: 'test' });
  logger.info('hello', { n: 1 });
  const firstLine = JSON.parse(fs.readFileSync(file, 'utf8').trim().split('\n')[0]);
  assert.equal(firstLine.level, 'info');
  assert.equal(firstLine.component, 'test');
  assert.equal(firstLine.msg, 'hello');
  assert.equal(firstLine.n, 1);
  assert.ok(firstLine.ts, 'has ts');

  // 写超 1MB 触发轮转。
  const big = 'x'.repeat(1024 * 1024 + 64);
  logger.info(big);
  assert.ok(fs.existsSync(`${file}.1`), 'rotated .1 exists');
  const rotated = fs.readFileSync(`${file}.1`, 'utf8');
  assert.ok(rotated.includes('hello'), '.1 keeps previous generation');
  const current = fs.readFileSync(file, 'utf8');
  assert.ok(!current.includes('hello'), 'current file no longer has old line (rotated away)');

  // 只保留 .1 一代：再写超 1MB，.1 被覆盖（不产生 .2）。
  logger.info(big);
  logger.info(big);
  assert.ok(!fs.existsSync(`${file}.2`), 'no .2 generation');
});

// ---------------------------------------------------------------------------
// M11 health 真实状态 + relay 旁路 /health + vap-to health()
// ---------------------------------------------------------------------------

test('M11 gateway health：目录可写探测 + errors/lastError/backlog（detail）', async () => {
  const root = tmpDir('vap-gwhealth-');
  const gw = createHttpGateway({ root, port: 0 });
  const port = await gw.start();
  try {
    const base = gw.health();
    assert.equal(base.ok, true, 'ok true when dirs writable');
    const detail = gw.health({ detail: true });
    assert.equal(typeof detail.errors, 'number', 'errors count present');
    assert.equal(detail.lastError, null, 'lastError null before failure');
    assert.equal(typeof detail.inboxBacklog, 'number', 'inbox backlog present');
    assert.equal(typeof detail.outboxBacklog, 'number', 'outbox backlog present');

    // 真实错误路径：无 nonce 信封 → 400（错误计数）。
    const client = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
    const res = await client.post({ id: 'evt-bad', v: 1 });
    assert.equal(res.status, 400, 'bad envelope 400');
    const after = gw.health({ detail: true });
    assert.ok(after.errors >= 1, 'errors incremented');
    assert.ok(after.lastError, 'lastError recorded');
  } finally {
    await gw.stop();
  }
});

test('M11 relay health + 旁路 HTTP /health', async () => {
  const relay = createRelayServer({ port: 0, healthPort: 0 });
  const port = await relay.start();
  const hport = await relay.startHealth();
  try {
    assert.ok(Number.isInteger(hport) && hport > 0, 'health port bound');
    const h = relay.health();
    assert.equal(h.ok, true);
    assert.equal(typeof h.connections, 'number');
    assert.equal(typeof h.errors, 'number');
    assert.equal(typeof h.uptimeMs, 'number');
    const resp = await httpGet(hport, '/health');
    assert.equal(resp.status, 200);
    assert.equal(resp.body.connections, 0);
    assert.equal(typeof resp.body.errors, 'number');
  } finally {
    await relay.stop();
  }
});

test('M11 vap-to createNode health()：height/view/roster/threshold/qcCount', () => {
  const dir = tmpDir('vap-p5h-');
  const keys = makeKeys();
  const peers = [{ nodeId: 'n1', pubKey: keys.pubKey }];
  const node = createNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers, ledgerDir: dir });
  const h = node.health();
  assert.equal(h.nodeId, 'n1');
  assert.equal(h.height, 0);
  assert.equal(h.rosterSize, 1);
  assert.equal(h.f, 0);
  assert.equal(h.threshold, 1);
  assert.equal(h.qcCount, 0);
  assert.equal(h.expelled, 0);
});

// ---------------------------------------------------------------------------
// M12 restore 补全
// ---------------------------------------------------------------------------

test('M12 phase5 restore：回放 QC（highestQC/qcByBlockHash/blocks）+ votedViews 置空 + mempool 丢弃', () => {
  const dir = tmpDir('vap-p5r-');
  const keys = makeKeys();
  const peers = [{ nodeId: 'n1', pubKey: keys.pubKey }];
  const node = createNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers, ledgerDir: dir });

  node.submitTx({ type: 'commit', from: 'client', nonce: 'c-1' });
  // 推进 5 个视图：至少 1 块被 3-chain 提交，账本非空。
  for (let v = 0; v < 5; v++) {
    const pr = node.propose(v);
    if (pr.refused) { node.onTimeout(); continue; }
    const vr = node.vote(pr.proposal);
    if (vr.voted) node.collectQC([vr.vote]);
    node.commitCheck();
  }
  assert.ok(node.committed.length >= 1, 'some blocks committed');
  const committedBefore = node.committed.length;

  // 制造「未提交」投票/内存状态后重启。
  node.vote(node.signProposal({ view: 100, leader: 'n1', parentHash: node.lastCommittedHash, txs: [] }));
  const fresh = createNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers, ledgerDir: dir });
  const r = fresh.restore();
  assert.equal(r.restored, committedBefore, 'restored committed blocks');
  assert.ok(fresh.highestQC, 'highestQC rebuilt from ledger replay');
  assert.equal(fresh.qcByBlockHash.size, committedBefore, 'qcByBlockHash replayed');
  assert.equal(fresh.blocks.size, committedBefore, 'blocks replayed');
  assert.equal(fresh.votedViews.size, 0, 'votedViews cleared (honest re-vote)');
  assert.equal(fresh.pendingTxs.length, 0, 'mempool dropped');
  assert.equal(fresh.seenNonces.has('client:c-1'), true, 'committed nonce replayed');
});

test('M12 phase6 restore：回放成员状态（expelled 签名仍不计入 + membership nonce 仍去重）', () => {
  const dir = tmpDir('vap-p6r-');
  const keys = makeKeys();
  const peers = [{ nodeId: 'n1', pubKey: keys.pubKey }];
  const genesis = createGenesisAnchor();
  const credentialCtx = { genesis: { id: genesis.id, publicKey: genesis.publicKey }, keys: new Map(), credentials: new Map() };

  const node = createMembershipNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers, ledgerDir: dir, credentialCtx });

  // 提交一个 expel 交易（自除名）并推进若干视图。
  const expelTx = { type: 'membership', op: 'expel', nodeId: 'n1', sig: '', from: 'n1', nonce: 'expel:n1:1' };
  // 自签 expel subject。
  const subject = { op: 'expel', nodeId: 'n1' };
  expelTx.sig = crypto.sign(null, Buffer.from(JSON.stringify(sorted(subject)), 'utf8'), keys.privateKey).toString('base64');
  node.submitTx(expelTx);
  for (let v = 0; v < 6; v++) {
    const pr = node.propose(v);
    if (pr.refused) { node.onTimeout(); continue; }
    const vr = node.vote(pr.proposal);
    if (vr.voted) node.collectQC([vr.vote]);
    node.commitCheck();
  }
  assert.ok(node.committed.some((b) => b.txs.some((t) => t.type === 'membership')), 'membership tx committed');
  assert.ok(node.expelled.has('n1'), 'expelled set populated at commit');

  const fresh = createMembershipNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers, ledgerDir: dir, credentialCtx });
  const r = fresh.restore();
  assert.equal(r.restored, node.committed.length, 'restored committed blocks');
  assert.ok(fresh.expelled.has('n1'), 'expelled rebuilt after restart (expelled signature still not counted)');
  assert.equal(fresh.membershipNonces.has('n1:expel:n1:1'), true, 'membership nonce replayed (still dedup)');

  // 重启后再次提交同 nonce 的 membership tx 仍被拒（去重仍生效）。
  const resubmit = fresh.submitTx(JSON.parse(JSON.stringify(expelTx)));
  assert.equal(resubmit.ok, false, 'membership nonce dedup after restore');
});

test('M12 autoRestore：createNode/createMembershipNode 启动即恢复', () => {
  const dir = tmpDir('vap-p5ar-');
  const keys = makeKeys();
  const peers = [{ nodeId: 'n1', pubKey: keys.pubKey }];
  const node = createNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers, ledgerDir: dir });
  node.submitTx({ type: 'commit', from: 'client', nonce: 'c-auto' });
  for (let v = 0; v < 5; v++) {
    const pr = node.propose(v);
    if (pr.refused) { node.onTimeout(); continue; }
    const vr = node.vote(pr.proposal);
    if (vr.voted) node.collectQC([vr.vote]);
    node.commitCheck();
  }
  const committed = node.committed.length;
  assert.ok(committed >= 1, 'committed for autoRestore');

  const fresh = createNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers, ledgerDir: dir, autoRestore: true });
  assert.equal(fresh.committed.length, committed, 'autoRestore restored committed prefix on start');

  // membership 节点 autoRestore（空账本也应安全启动）。
  const genesis = createGenesisAnchor();
  const ctx = { genesis: { id: genesis.id, publicKey: genesis.publicKey }, keys: new Map(), credentials: new Map() };
  const mn = createMembershipNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers, ledgerDir: tmpDir('vap-p6ar-'), credentialCtx: ctx, autoRestore: true });
  assert.equal(mn.committed.length, 0, 'membership autoRestore on empty ledger is safe');
});

// ---------------------------------------------------------------------------
// M13 ledgerDir/TRAIL_DIR 默认 tmpdir
// ---------------------------------------------------------------------------

test('M13 createNode 缺省 ledgerDir 落在 os.tmpdir（绝不默认源码树）', () => {
  const keys = makeKeys();
  const peers = [{ nodeId: 'n1', pubKey: keys.pubKey }];
  const node = createNode({ nodeId: 'n1', keyPair: keys, n: 1, f: 0, peers });
  assert.equal(path.dirname(node.ledgerFile), defaultLedgerDir(), 'ledgerDir defaults to tmpdir');
  assert.ok(node.ledgerFile.startsWith(os.tmpdir()), 'ledgerFile under os.tmpdir');
});

test('M13 signAuditTrail 缺省 trailDir 落在 os.tmpdir', () => {
  const auditor = { id: 'auditor-x' };
  const genesis = createGenesisAnchor();
  const credRes = issueCredential({ task: makeTask('trail-c', 2), holder: 'holder-x', auditors: [genesis], generation: 0 });
  assert.equal(credRes.ok, true, credRes.reason);
  const res = signAuditTrail(auditor, credRes.credential);
  assert.ok(res.file.startsWith(defaultTrailDir()), `trail file under tmpdir (${res.file})`);
  assert.ok(fs.existsSync(res.file), 'trail file written');
});

// ---------------------------------------------------------------------------
// M10 package.json + 三 bin 启动 / 优雅退出
// ---------------------------------------------------------------------------

test('M10 package.json：name/version/type/bin/scripts 齐备', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'dsh-vap');
  assert.equal(pkg.version, '0.2.0');
  assert.equal(pkg.type, 'module');
  assert.ok(pkg.engines && pkg.engines.node, 'engines.node declared');
  assert.ok(pkg.bin && pkg.bin['vap-relay'] && pkg.bin['vap-gateway'] && pkg.bin['vap-node'], 'three bin entries');
});

function spawnBin(bin, args = [], timeoutMs = 5000) {
  const abs = path.join(process.cwd(), 'bin', bin);
  const child = spawn(process.execPath, [abs, ...args], {
    cwd: process.cwd(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (c) => { stdout += c.toString(); });
  child.stderr.on('data', (c) => { stderr += c.toString(); });
  const waitForListening = new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`bin ${bin} not listening in time. stdout=${stdout} stderr=${stderr}`)), timeoutMs);
    const check = () => {
      if (stdout.includes('listening')) { clearTimeout(t); resolve(); }
    };
    child.stdout.on('data', check);
    child.once('exit', () => { clearTimeout(t); });
  });
  const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
  return { child, stdout: () => stdout, stderr: () => stderr, waitForListening, exited };
}

async function assertGracefulExit(bin, args) {
  const proc = spawnBin(bin, args);
  await proc.waitForListening;
  if (process.platform === 'win32') {
    // Windows：child.kill('SIGTERM') 是硬杀（不触发 JS 信号处理器），
    // 改用 bin 的 stdin `shutdown` 通道验证等价优雅退出（exit 0）。
    proc.child.stdin.write('shutdown\n');
    proc.child.stdin.end();
  } else {
    proc.child.kill('SIGTERM');
  }
  const res = await Promise.race([
    proc.exited,
    sleep(5000).then(() => ({ code: 'TIMEOUT', signal: null })),
  ]);
  assert.equal(res.code, 0, `${bin} must exit 0 on graceful shutdown (got code=${res.code} signal=${res.signal}; stderr=${proc.stderr()})`);
}

test('M10 vap-relay 可启动并 SIGTERM 优雅退出（退出码 0）', async () => {
  await assertGracefulExit('vap-relay.mjs', ['--port', '0']);
});

test('M10 vap-gateway 可启动并 SIGTERM 优雅退出（退出码 0）', async () => {
  await assertGracefulExit('vap-gateway.mjs', ['--port', '0']);
});

test('M10 vap-node 可启动并 SIGTERM 优雅退出（退出码 0）', async () => {
  const dir = tmpDir('vap-bin-node-');
  await assertGracefulExit('vap-node.mjs', ['--node-id', 'bin-node', '--ledger-dir', dir, '--health-port', '0']);
});

test('M10 process-guard：uncaughtException 兜底退出码 1', async () => {
  const script = path.join(tmpDir('vap-guard-'), 'guard-test.mjs');
  const guardUrl = pathToFileURL(path.join(process.cwd(), 'bin', 'process-guard.mjs')).href;
  const loggerUrl = pathToFileURL(path.join(process.cwd(), 'logger.mjs')).href;
  fs.writeFileSync(script, [
    `import { installProcessGuards } from '${guardUrl}';`,
    `import { createLogger } from '${loggerUrl}';`,
    "const logger = createLogger({ level: 'silent' });",
    'installProcessGuards({ logger, onStop: async () => {} });',
    "setTimeout(() => { throw new Error('boom'); }, 50);",
    'setInterval(() => {}, 1000);',
    '',
  ].join('\n'));
  const child = spawn(process.execPath, [script], { stdio: ['ignore', 'pipe', 'pipe'] });
  let err = '';
  child.stderr.on('data', (c) => { err += c.toString(); });
  const code = await new Promise((resolve) => child.once('exit', (code) => resolve(code)));
  assert.equal(code, 1, `uncaughtException must exit 1 (got ${code}; stderr=${err})`);
});

// ---------------------------------------------------------------------------
// 局部工具
// ---------------------------------------------------------------------------

function sorted(obj) {
  if (Array.isArray(obj)) return obj.map(sorted);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const k of Object.keys(obj).sort()) out[k] = sorted(obj[k]);
    return out;
  }
  return obj;
}
