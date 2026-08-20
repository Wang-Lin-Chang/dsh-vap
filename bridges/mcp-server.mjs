#!/usr/bin/env node
// bridges/mcp-server.mjs —— VAP MCP 桥（最小可运行，零第三方依赖）
//
// 通过 stdio 暴露 MCP（Model Context Protocol）JSON-RPC 2.0 服务：
//   initialize         → protocolVersion / capabilities / serverInfo
//   tools/list         → 声明 1 个工具 vap_verify
//   tools/call         → vap_verify：输入信封 JSON → 输出三闸裁决
//   notifications/*    → 无 id 不回复（JSON-RPC 通知语义）
//
// 协议：每条消息一行（换行分隔 JSON）；stdout 只承载 JSON-RPC 响应，
// 任何诊断一律走 stderr，避免污染协议流。
//
// 复用 vap-core 的验证门（createVapNode.verify 三闸），不复制判定逻辑。
// 验证需要一个含 laws.json 的工作区，服务端在 os.tmpdir() 下惰性创建临时根。

import readline from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createVapNode, makeLaws } from '../vap-core.mjs';

const SERVER_INFO = Object.freeze({ name: 'vap-mcp', version: '0.2.0' });
const PROTOCOL_VERSION = '2024-11-05';

const VAP_VERIFY_TOOL = Object.freeze({
  name: 'vap_verify',
  description: 'Verify a VAP envelope through the three gates (identity / laws / honesty-boundary) and return the verdict.',
  inputSchema: Object.freeze({
    type: 'object',
    properties: Object.freeze({
      envelope: Object.freeze({
        type: 'object',
        description: 'A VAP envelope object (v/id/nonce/ts/from/to/sig/claim/evidence/boundary/report).',
      }),
    }),
    required: Object.freeze(['envelope']),
  }),
});

// 惰性验证节点：临时根 + 默认军法（规则是数据，改 laws.json 即可升级，不改代码）。
let verifyNode = null;
function getVerifyNode() {
  if (verifyNode) return verifyNode;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-mcp-'));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  verifyNode = createVapNode({ nodeId: 'mcp-verifier', root });
  return verifyNode;
}

function send(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

function handleInitialize() {
  return {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: { tools: {} },
    serverInfo: SERVER_INFO,
  };
}

function handleToolsList() {
  return { tools: [VAP_VERIFY_TOOL] };
}

function handleToolsCall(params) {
  const name = params && params.name;
  if (name !== 'vap_verify') {
    return { content: [{ type: 'text', text: `unknown tool: ${String(name)}` }], isError: true };
  }
  const args = (params && typeof params.arguments === 'object' && params.arguments) || {};
  const envelope = args.envelope;
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    return { content: [{ type: 'text', text: 'invalid arguments: "envelope" (object) is required' }], isError: true };
  }
  // 三闸裁决：identity / laws / boundary（见 vap-spec.md §3）。
  const verdict = getVerifyNode().verify(envelope);
  return {
    content: [{ type: 'text', text: JSON.stringify(verdict, null, 2) }],
    isError: false,
  };
}

function dispatch(msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0') {
    return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } };
  }
  const id = msg.id;
  const isNotification = id === undefined || id === null;
  const method = msg.method;

  let result;
  try {
    if (method === 'initialize') {
      result = handleInitialize(msg.params);
    } else if (method === 'tools/list') {
      result = handleToolsList(msg.params);
    } else if (method === 'tools/call') {
      result = handleToolsCall(msg.params);
    } else if (method === 'notifications/initialized' || method === 'notifications/cancelled') {
      return null; // 通知：不回复
    } else {
      if (isNotification) return null; // 未知通知静默忽略
      return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${String(method)}` } };
    }
  } catch (err) {
    if (isNotification) return null;
    return { jsonrpc: '2.0', id, error: { code: -32603, message: String((err && err.message) || err) } };
  }
  if (isNotification) return null;
  return { jsonrpc: '2.0', id, result };
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line) => {
  const text = line.trim();
  if (!text) return;
  let msg;
  try {
    msg = JSON.parse(text);
  } catch {
    send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const resp = dispatch(msg);
  if (resp) send(resp);
});

// 客户端关闭 stdin → 优雅退出（等价于连接断开）。
process.stdin.on('end', () => {
  process.exit(0);
});
