// tests/vap-core.test.mjs —— VAP v0 核心单测（node:test，全 mock，零第三方依赖）
//
// 每个断言对应 vap-spec.md 的一条要求；不伪造测试、不依赖外部进程与真实等待。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  createVapNode,
  createBrain,
  canonicalJson,
  makeLaws,
  constants,
} from '../vap-core.mjs';

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-test-'));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

function writeTask(root, taskId, task) {
  fs.mkdirSync(path.join(root, 'inbox'), { recursive: true });
  fs.writeFileSync(path.join(root, 'inbox', `task-${taskId}.json`), JSON.stringify(task));
}

function validSendParams(overrides = {}) {
  return {
    to: 'brain',
    claim: { type: 'report', body: { work: 'scout' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:abcd' },
    boundary: 'L2a',
    report: { summary: 'field report ok', keyNumbers: [3], request: '' },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// canonicalJson：键序无关（两种键序输入输出相同，spec §1 签名规范）
// ---------------------------------------------------------------------------

test('canonicalJson 键序无关：嵌套对象与数组按字典序规范化', () => {
  const a = canonicalJson({ b: 1, a: { d: 2, c: [3, { z: 1, y: 2 }] } });
  const b = canonicalJson({ a: { c: [3, { y: 2, z: 1 }], d: 2 }, b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":{"c":[3,{"y":2,"z":1}],"d":2},"b":1}');
});

// ---------------------------------------------------------------------------
// 签名：合法信封 pass；篡改 claim 后验签 fail（身份闸，spec §1 + §3①）
// ---------------------------------------------------------------------------

test('签名：合法信封身份闸通过', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const envelope = node.send(validSendParams());
  const result = node.verify(envelope);
  assert.equal(result.pass, true);
  assert.equal(result.gates.identity.pass, true);
  assert.equal(result.gates.laws.pass, true);
  assert.equal(result.gates.boundary.pass, true);
});

test('签名：篡改 claim 后验签失败（身份闸 reject）', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const envelope = node.send(validSendParams());
  envelope.claim.body = { tampered: true };
  const result = node.verify(envelope);
  assert.equal(result.pass, false);
  assert.equal(result.gates.identity.pass, false);
  assert.equal(result.gates.identity.reason, 'signature verification failed');
});

test('签名：无签名（sig 缺失）被身份闸 reject', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const envelope = node.send(validSendParams());
  envelope.sig = '';
  const result = node.verify(envelope);
  assert.equal(result.gates.identity.pass, false);
  assert.equal(result.pass, false);
  assert.ok(result.gates.laws.reasons.some((r) => r.startsWith('SIG_REQUIRED:')));
});

// ---------------------------------------------------------------------------
// 军法：summary>100 / boundary 非法 / L2a 无 devices 全部 reject（spec §3②）
// ---------------------------------------------------------------------------

test('军法：summary 超过 100 字符 reject', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const envelope = node.send(validSendParams({
    report: { summary: 'x'.repeat(101), keyNumbers: [], request: '' },
  }));
  const result = node.verify(envelope);
  assert.equal(result.gates.identity.pass, true, '签名应合法，仅军法拦截');
  assert.equal(result.gates.laws.pass, false);
  assert.ok(result.gates.laws.reasons.some((r) => r.startsWith('SUMMARY_BOUND:')));
  assert.equal(result.pass, false);
});

test('军法：boundary 非法值 reject', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const envelope = node.send(validSendParams({ boundary: 'L9' }));
  const result = node.verify(envelope);
  assert.equal(result.gates.identity.pass, true, '签名应合法，仅军法拦截');
  assert.equal(result.gates.laws.pass, false);
  assert.ok(result.gates.laws.reasons.some((r) => r.startsWith('BOUNDARY_VALID:')));
  assert.equal(result.pass, false);
});

test('军法：boundary=L2a 且 evidence.devices 为空 reject', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const envelope = node.send(validSendParams({ evidence: { devices: [], bills: {}, digest: 'sha256:abcd' } }));
  const result = node.verify(envelope);
  assert.equal(result.gates.identity.pass, true, '签名应合法');
  assert.equal(result.gates.laws.pass, false);
  assert.ok(result.gates.laws.reasons.some((r) => r.startsWith('EVIDENCE_L2A:')));
  assert.equal(result.gates.boundary.pass, false);
  assert.equal(result.gates.boundary.suggest, 'L0');
  assert.equal(result.pass, false);
});

// ---------------------------------------------------------------------------
// 正常：合法战报三闸全过，脑进程入账 + verdict（spec §3 + §7-1）
// ---------------------------------------------------------------------------

test('正常：合法战报三闸全过，脑进程入账并留 verdict', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  node.register();
  const brain = createBrain({ root });
  const envelope = node.send(validSendParams());
  const verdicts = brain.consume();
  assert.equal(verdicts.length, 1);
  const verdict = verdicts[0];
  assert.equal(verdict.envelopeId, envelope.id);
  assert.equal(verdict.pass, true);
  assert.deepEqual(verdict.reasons, []);
  assert.equal(verdict.gates.identity.pass, true);
  assert.equal(verdict.gates.laws.pass, true);
  assert.equal(verdict.gates.boundary.pass, true);
  assert.ok(fs.existsSync(path.join(root, 'outbox', `${envelope.id}.verdict`)));
  assert.ok(fs.existsSync(path.join(root, 'done', `${envelope.id}.json`)));
});

test('脑进程：伪造战报被 reject 且 verdict 带 reasons', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const brain = createBrain({ root });
  const envelope = node.send(validSendParams({
    report: { summary: 'x'.repeat(101), keyNumbers: [], request: '' },
  }));
  const verdicts = brain.consume();
  assert.equal(verdicts.length, 1);
  assert.equal(verdicts[0].pass, false);
  assert.ok(verdicts[0].reasons.length > 0);
  assert.ok(verdicts[0].reasons.some((r) => r.includes('SUMMARY_BOUND')));
  assert.ok(!fs.existsSync(path.join(root, 'done', `${envelope.id}.json`)));
});

// ---------------------------------------------------------------------------
// 租约：两个节点竞争同一任务，恰一个 claimTask 成功（spec §2 + brief）
// ---------------------------------------------------------------------------

test('租约：两个节点竞争同一任务，恰一个成功（O_EXCL）', () => {
  const root = makeRoot();
  writeTask(root, '1', { id: '1', work: 'mine' });
  const a = createVapNode({ nodeId: 'scout-a', root });
  const b = createVapNode({ nodeId: 'scout-b', root });
  const claimed = a.claimTask();
  assert.ok(claimed);
  assert.equal(claimed.taskId, '1');
  assert.equal(b.claimTask(), null);
  assert.equal(a.claimTask(), null);
});

test('complete：结果原子写 done + EXIT 记录 + 释放租约', () => {
  const root = makeRoot();
  writeTask(root, '2', { id: '2', work: 'deliver' });
  const node = createVapNode({ nodeId: 'scout-01', root });
  const task = node.claimTask();
  assert.ok(task);
  const record = node.complete(task, { status: 'done', keyNumbers: [1] });
  assert.equal(record.exit, 'EXIT');
  assert.equal(record.taskId, '2');
  assert.ok(fs.existsSync(path.join(root, 'done', '2.json')));
  assert.ok(!fs.existsSync(path.join(root, 'inbox', 'task-2.lock')));
  assert.ok(!fs.existsSync(path.join(root, 'inbox', 'task-2.json')));
});

test('heartbeat：touch 锁 mtime 并更新租约内容', () => {
  const root = makeRoot();
  writeTask(root, '3', { id: '3', work: 'patrol' });
  let t = 1700000000000;
  const node = createVapNode({ nodeId: 'scout-01', root, now: () => new Date(t) });
  const task = node.claimTask();
  const before = fs.readFileSync(path.join(root, 'inbox', 'task-3.lock'), 'utf8');
  t += 3000; // 跨过秒边界，使 startSec 确定性变化（不依赖真实等待）
  const updated = node.heartbeat(task);
  const after = fs.readFileSync(path.join(root, 'inbox', 'task-3.lock'), 'utf8');
  assert.notEqual(after, before);
  assert.match(after, /^scout-01:\d+:\d+$/);
  assert.equal(updated.nodeId, 'scout-01');
  assert.equal(updated.startSec, Math.floor(t / 1000));
});

// ---------------------------------------------------------------------------
// 收养：死现场（pid 不存在 + 超时租约）三证据齐备后重派（spec §7-3）
// ---------------------------------------------------------------------------

test('收养：三证据（pid 死 + startSec 超时 + mtime 超时）齐备后重派', () => {
  const root = makeRoot();
  const deadLetter = path.join(root, 'dead-letter');
  fs.mkdirSync(deadLetter, { recursive: true });
  fs.writeFileSync(path.join(deadLetter, 'task-7.json'), JSON.stringify({ id: '7', work: 'rescue' }));
  const deadPid = 999999999;
  const oldSec = Math.floor(Date.now() / 1000) - 60;
  fs.writeFileSync(path.join(deadLetter, 'task-7.lock'), `scout-x:${deadPid}:${oldSec}`);
  const oldTime = new Date(Date.now() - 60000);
  fs.utimesSync(path.join(deadLetter, 'task-7.lock'), oldTime, oldTime);

  const node = createVapNode({ nodeId: 'rescuer', root });
  const adopted = node.adopt();
  assert.equal(adopted.length, 1);
  assert.equal(adopted[0].taskId, '7');
  assert.deepEqual(adopted[0].evidence, { pidDead: true, startSecExpired: true, mtimeExpired: true });
  assert.ok(fs.existsSync(path.join(root, 'inbox', 'task-7.json')), '任务已重派到 inbox');
  assert.ok(!fs.existsSync(path.join(deadLetter, 'task-7.lock')), '死现场租约已清理');

  const claimed = node.claimTask();
  assert.ok(claimed);
  assert.equal(claimed.taskId, '7');
});

test('收养：pid 仍存活或租约未超时则不收养', () => {
  const root = makeRoot();
  const deadLetter = path.join(root, 'dead-letter');
  fs.mkdirSync(deadLetter, { recursive: true });
  fs.writeFileSync(path.join(deadLetter, 'task-8.json'), JSON.stringify({ id: '8', work: 'hold' }));
  const nowSec = Math.floor(Date.now() / 1000);
  fs.writeFileSync(path.join(deadLetter, 'task-8.lock'), `scout-x:${process.pid}:${nowSec}`);
  const node = createVapNode({ nodeId: 'rescuer', root });
  const adopted = node.adopt();
  assert.equal(adopted.length, 0);
  assert.ok(!fs.existsSync(path.join(root, 'inbox', 'task-8.json')));
});

// ---------------------------------------------------------------------------
// 军法可升级：makeLaws(overrides) 改规则后判定随之变化（规则是数据，spec §7-4）
// ---------------------------------------------------------------------------

test('军法可升级：改 severity 后判定随之变化（规则是数据）', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const brain = createBrain({ root });
  const longSummary = 'x'.repeat(101);

  // 默认军法：SUMMARY_BOUND 为 reject
  const before = node.send(validSendParams({ report: { summary: longSummary, keyNumbers: [], request: '' } }));
  const beforeVerdicts = brain.consume();
  const beforeVerdict = beforeVerdicts.find((v) => v.envelopeId === before.id);
  assert.equal(beforeVerdict.pass, false);
  assert.ok(beforeVerdict.reasons.some((r) => r.includes('SUMMARY_BOUND')));

  // 升级 laws.json：SUMMARY_BOUND 降为 warn，无需改代码
  fs.writeFileSync(
    path.join(root, 'laws.json'),
    `${JSON.stringify(makeLaws({ rules: [{ id: 'SUMMARY_BOUND', severity: 'warn' }] }), null, 2)}\n`,
  );

  const after = node.send(validSendParams({ report: { summary: longSummary, keyNumbers: [], request: '' } }));
  const afterVerdicts = brain.consume();
  const afterVerdict = afterVerdicts.find((v) => v.envelopeId === after.id);
  assert.equal(afterVerdict.pass, true);
});

// ---------------------------------------------------------------------------
// 登记册：register 写 { nodeId, pubKey }（spec §4 registry.json）
// ---------------------------------------------------------------------------

test('register：把 { nodeId, pubKey } 写入 registry.json（nodeId → pubKey）', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'scout-01', root });
  const entry = node.register();
  assert.equal(entry.nodeId, 'scout-01');
  assert.equal(entry.pubKey, node.pubKey);
  const reg = JSON.parse(fs.readFileSync(path.join(root, 'registry.json'), 'utf8'));
  assert.equal(reg['scout-01'], node.pubKey);
});

// ---------------------------------------------------------------------------
// constants：SUMMARY_BOUND / LEASE_TIMEOUT_MS / DEFAULT_LAWS（brief 导出契约）
// ---------------------------------------------------------------------------

test('constants 导出 SUMMARY_BOUND、LEASE_TIMEOUT_MS、DEFAULT_LAWS', () => {
  assert.equal(constants.SUMMARY_BOUND, 100);
  assert.equal(constants.LEASE_TIMEOUT_MS, 30000);
  assert.ok(Array.isArray(constants.DEFAULT_LAWS.rules));
  assert.equal(constants.DEFAULT_LAWS.rules.length, 5);
  const ids = constants.DEFAULT_LAWS.rules.map((r) => r.id);
  assert.deepEqual(ids, ['SIG_REQUIRED', 'BOUNDARY_VALID', 'SUMMARY_BOUND', 'EVIDENCE_L2A', 'FROM_KNOWN']);
});
