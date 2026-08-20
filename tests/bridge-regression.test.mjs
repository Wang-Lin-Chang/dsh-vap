// tests/bridge-regression.test.mjs —— 修复批次 3+4（包装与接口）回归测试
//
// 运行：在 dsh-vap/ 下 `node --test`（或 `node --test tests/bridge-regression.test.mjs`）
// 覆盖（对照 fix-batch34-brief.md 验收）：
//   M19 MCP 桥：initialize / tools/list / tools/call(vap_verify) 全链（stdio JSON-RPC）
//   M18 五函数契约：report / doWork / respondExpand 桩行为
//   M20 A2A 桥：a2a-card 生成字段映射 + 可独立运行
//   M17/M23 组播：默认改 OS 出接口 + IPv6 组播字面量显式拒绝
//
// 零第三方依赖：仅 node: 内置模块 + 本仓库相对 import。

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

import { createVapNode, makeLaws } from '../vap-core.mjs';
import { createLanPeer } from '../phase2/lan-peer.mjs';
import { generateAgentCard } from '../bridges/a2a-card.mjs';

// ---------------------------------------------------------------------------
// 装置助手
// ---------------------------------------------------------------------------

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-bridge-'));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

function makeKeys() {
  return crypto.generateKeyPairSync('ed25519');
}

function validParams() {
  return {
    to: 'brain',
    claim: { type: 'report', body: { work: 'bridge' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:bridge' },
    boundary: 'L2a',
    report: { summary: 'bridge regression', keyNumbers: [1], request: '' },
  };
}

// 启动 MCP 桥子进程，返回 { child, request }。request 发送一行 JSON-RPC 并解析下一行响应。
function mcpClient() {
  const abs = path.join(process.cwd(), 'bridges', 'mcp-server.mjs');
  const child = spawn(process.execPath, [abs], { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] });
  let buf = '';
  const waiters = [];
  child.stdout.on('data', (c) => {
    buf += c.toString();
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line && waiters.length > 0) waiters.shift()(line);
    }
  });
  function request(obj, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`mcp timeout: ${JSON.stringify(obj)}`)), timeoutMs);
      waiters.push((line) => { clearTimeout(timer); resolve(line); });
      child.stdin.write(`${JSON.stringify(obj)}\n`);
    });
  }
  return { child, request };
}

// ---------------------------------------------------------------------------
// M19 MCP 桥
// ---------------------------------------------------------------------------

test('M19 MCP 握手：initialize 返回 protocolVersion/capabilities/serverInfo', async () => {
  const { child, request } = mcpClient();
  try {
    const resp = JSON.parse(await request({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'vap-test', version: '1.0.0' } },
    }));
    assert.equal(resp.jsonrpc, '2.0');
    assert.equal(resp.id, 1);
    assert.equal(resp.result.protocolVersion, '2024-11-05');
    assert.equal(resp.result.serverInfo.name, 'vap-mcp');
    assert.ok(resp.result.capabilities && resp.result.capabilities.tools, 'capabilities.tools 应声明');
  } finally {
    child.stdin.end();
    child.kill();
  }
});

test('M19 MCP tools/list + tools/call(vap_verify) 全链：真信封过闸、坏边界被军法拦', async () => {
  const { child, request } = mcpClient();
  try {
    await request({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });

    // 通知：无 id → 服务器不应回复（紧接着的 tools/list 应拿到正确响应）。
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);

    const list = JSON.parse(await request({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }));
    assert.equal(list.id, 2, '通知不应产生响应，tools/list 应拿到自己的结果');
    assert.equal(list.result.tools.length, 1);
    assert.equal(list.result.tools[0].name, 'vap_verify');
    assert.ok(list.result.tools[0].inputSchema && list.result.tools[0].inputSchema.required.includes('envelope'));

    const sender = createVapNode({ nodeId: 'mcp-sender', root: makeRoot() });

    // 真信封：三闸全过。
    const good = sender.send(validParams());
    const callGood = JSON.parse(await request({
      jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: 'vap_verify', arguments: { envelope: good } },
    }));
    assert.equal(callGood.result.isError, false);
    const verdict = JSON.parse(callGood.result.content[0].text);
    assert.equal(verdict.pass, true);
    assert.equal(verdict.gates.identity.pass, true);
    assert.equal(verdict.gates.laws.pass, true);
    assert.equal(verdict.gates.boundary.pass, true);

    // 坏边界信封（签名有效，但 BOUNDARY_VALID 军法拦截）。
    const bad = sender.send({ ...validParams(), boundary: 'L9' });
    const callBad = JSON.parse(await request({
      jsonrpc: '2.0', id: 4, method: 'tools/call',
      params: { name: 'vap_verify', arguments: { envelope: bad } },
    }));
    const badVerdict = JSON.parse(callBad.result.content[0].text);
    assert.equal(badVerdict.pass, false);
    assert.equal(badVerdict.gates.identity.pass, true, '签名仍有效');
    assert.equal(badVerdict.gates.laws.pass, false, '军法闸应拦截坏边界');

    // 未知工具：isError=true。
    const callUnknown = JSON.parse(await request({
      jsonrpc: '2.0', id: 5, method: 'tools/call',
      params: { name: 'nope', arguments: {} },
    }));
    assert.equal(callUnknown.result.isError, true);
  } finally {
    child.stdin.end();
    child.kill();
  }
});

test('M19 MCP tools/call 参数缺 envelope → isError 且不崩', async () => {
  const { child, request } = mcpClient();
  try {
    await request({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    const resp = JSON.parse(await request({
      jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'vap_verify', arguments: {} },
    }));
    assert.equal(resp.result.isError, true);
    assert.match(resp.result.content[0].text, /envelope/);
  } finally {
    child.stdin.end();
    child.kill();
  }
});

// ---------------------------------------------------------------------------
// M18 五函数契约补桩
// ---------------------------------------------------------------------------

test('M18 report：send 的命名别名——写 outbox 且语义一致', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'worker', root });
  const env = node.send(validParams());

  const reported = node.report(env);
  assert.equal(reported, env, 'report 返回原信封');
  assert.ok(fs.existsSync(path.join(root, 'outbox', `${env.id}.json`)), 'report 应落盘 outbox/evt-<id>.json');

  // 缺 envelope.id 拒绝。
  assert.throws(() => node.report({}), /report: envelope.id is required/);
  assert.throws(() => node.report(null), /report: envelope.id is required/);
});

test('M18 doWork：创建 agents/<nodeId>/ 目录并记录 work.jsonl 条目', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'worker', root });
  const task = { work: 'scout', n: 7 };

  const entry = node.doWork(task);
  assert.equal(entry.nodeId, 'worker');
  assert.deepEqual(entry.task, task);
  assert.ok(entry.ts, 'entry 带时间戳');

  const log = path.join(root, 'agents', 'worker', 'work.jsonl');
  assert.ok(fs.existsSync(log), 'work.jsonl 应存在');
  const lines = fs.readFileSync(log, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 1);
  assert.deepEqual(JSON.parse(lines[0]).task, task);

  // 缺 task 也可（task=null）。
  const entry2 = node.doWork(null);
  assert.equal(entry2.task, null);
  assert.equal(fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).length, 2);
});

test('M18 respondExpand：从 expand-resps/ 读字段响应，无则 null', () => {
  const root = makeRoot();
  const node = createVapNode({ nodeId: 'worker', root });

  // 无文件 / 空 taskId → null。
  assert.equal(node.respondExpand('task-1', 'summary'), null);
  assert.equal(node.respondExpand('', 'summary'), null);

  fs.mkdirSync(path.join(root, 'expand-resps'), { recursive: true });
  fs.writeFileSync(
    path.join(root, 'expand-resps', 'task-1.json'),
    JSON.stringify({ summary: 'hi', n: 7 }),
  );

  assert.equal(node.respondExpand('task-1', 'summary'), 'hi');
  assert.equal(node.respondExpand('task-1', 'n'), 7);
  assert.equal(node.respondExpand('task-1', 'missing'), null);
  assert.deepEqual(node.respondExpand('task-1'), { summary: 'hi', n: 7 }, 'field 缺省返回整对象');
});

// ---------------------------------------------------------------------------
// M20 A2A 桥
// ---------------------------------------------------------------------------

test('M20 a2a-card：生成 agent.json 字段映射（name/url/capabilities/skills）', () => {
  const card = generateAgentCard({ name: 'agent-x', url: 'http://127.0.0.1:9000', version: '9.9.9' });
  assert.equal(card.name, 'agent-x');
  assert.equal(card.url, 'http://127.0.0.1:9000');
  assert.equal(card.version, '9.9.9');
  assert.equal(card.capabilities.streaming, false, 'SSE 流式未实现，诚实标注 false');

  // VAP 五层能力映射齐全。
  for (const layer of ['identity', 'trust', 'ordering', 'transport', 'governance']) {
    assert.ok(card.vapCapabilities[layer], `vapCapabilities.${layer} 应存在`);
  }

  // 五函数契约 + 验证工具映射为 skills。
  const ids = card.skills.map((s) => s.id);
  for (const id of ['vap_claim_task', 'vap_do_work', 'vap_heartbeat', 'vap_respond_expand', 'vap_report', 'vap_verify']) {
    assert.ok(ids.includes(id), `skill ${id} 应存在`);
  }
});

test('M20 a2a-card：可独立运行并输出可解析 JSON', async () => {
  const abs = path.join(process.cwd(), 'bridges', 'a2a-card.mjs');
  const child = spawn(process.execPath, [abs, '--name', 'cli-agent'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  child.stdout.on('data', (c) => { out += c.toString(); });
  child.stderr.on('data', (c) => { err += c.toString(); });
  const code = await new Promise((resolve) => child.once('exit', (c) => resolve(c)));
  assert.equal(code, 0, `a2a-card 应退出 0（stderr=${err}）`);
  const card = JSON.parse(out);
  assert.equal(card.name, 'cli-agent');
});

// ---------------------------------------------------------------------------
// M17 / M23 组播默认与 IPv6 声明
// ---------------------------------------------------------------------------

test('M23 IPv6 组播字面量显式拒绝（仅支持 IPv4 组播）', () => {
  assert.throws(() => createLanPeer({ nodeId: 'x', multicast: 'ff02::1' }), /仅支持 IPv4 组播/);
  assert.throws(() => createLanPeer({ nodeId: 'x', multicast: 'ff05::99' }), /仅支持 IPv4 组播/);
  assert.throws(
    () => createLanPeer({ nodeId: 'x', multicast: { addr: 'ff05::99', port: 42666 } }),
    /仅支持 IPv4 组播/,
  );
  // IPv4 字符串/对象形态照常（构造不抛，不启动）。
  assert.doesNotThrow(() => createLanPeer({ nodeId: 'x', multicast: '239.255.42.99:42666', discover: false }));
  assert.doesNotThrow(() => createLanPeer({ nodeId: 'x', multicast: { addr: '239.1.2.3', port: 42666 }, discover: false }));
});

test('M17 组播默认出接口：不传 mcastInterface 仍可启动到 ready', async () => {
  // 不传 mcastInterface → 默认 undefined（走 OS 默认出接口）；组播用独立端口避免与
  // phase2 发现用例的固定端口 42666 争用，只验证「启动到 ready」不被默认值破坏。
  const peer = createLanPeer({
    port: 0,
    nodeId: 'm17',
    keyPair: makeKeys(),
    multicast: { addr: '239.255.42.99', port: 42777 },
  });
  peer.start();
  const ready = await Promise.race([
    peer.ready.then(() => true),
    new Promise((r) => setTimeout(() => r(false), 3000)),
  ]);
  peer.stop();
  assert.equal(ready, true, '未传 mcastInterface 时组播启动应仍到 ready（默认 OS 出接口）');
});
