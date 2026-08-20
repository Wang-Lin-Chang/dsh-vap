#!/usr/bin/env node
// bridges/a2a-card.mjs —— VAP A2A 桥：agent-card 生成器（零第三方依赖）
//
// 生成 A2A（Agent2Agent）协议的 `.well-known/agent.json` 内容：
//   name / description / url / version / capabilities / skills / input-output modes。
// 把 VAP 的五层能力（身份/信任/顺序/传输/治理）映射到 A2A 能力与技能表。
//
// 用法：
//   node bridges/a2a-card.mjs [--name X] [--url U] [--version V]
//   或 import { generateAgentCard } from './bridges/a2a-card.mjs'
//
// 诚实标注：仅生成 agent card；完整 A2A 任务状态机（tasks/* + SSE 流式事件）未实现，
// 见同目录 a2a-spec.md 的映射表与缺口说明。

import { pathToFileURL } from 'node:url';

// VAP 五层能力 → A2A 能力/技能映射（对应 vap-spec.md §6）。
const VAP_CAPABILITIES = Object.freeze({
  identity: 'Ed25519 envelope + nonce replay protection + behavior-history scarcity',
  trust: 'three-gate verification + credential-chain bootstrap + distributed 2/3 QC',
  ordering: 'lockstep QC-chain consensus (total order / fork & double-spend prevention)',
  transport: ['file', 'http-gateway', 'udp-lan-p2p', 'relay-nat-traversal'],
  governance: 'dynamic membership + laws-on-chain + slash auto-expulsion',
});

export function generateAgentCard(options = {}) {
  const name = options.name || 'vap-agent';
  const url = options.url || 'http://127.0.0.1/';
  const version = options.version || '0.2.0';
  return {
    name,
    description: 'VAP (Verifiable Agent Protocol) agent: verifiable reports, three-gate adjudication, crash adoption.',
    url,
    version,
    capabilities: {
      streaming: false,                 // SSE 流式未实现（诚实标注）
      pushNotifications: false,
      stateTransitionHistory: false,
    },
    // VAP 五层能力映射（供 A2A 客户端发现可验证性能力）。
    vapCapabilities: { ...VAP_CAPABILITIES },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: [
      { id: 'vap_claim_task', name: 'claimTask', description: 'Claim a task via O_EXCL lease from inbox.' },
      { id: 'vap_do_work', name: 'doWork', description: 'Record work under agents/<id>/ (stub).' },
      { id: 'vap_heartbeat', name: 'heartbeat', description: 'Touch a task lease.' },
      { id: 'vap_respond_expand', name: 'respondExpand', description: 'Read a field response from expand-resps/ (stub).' },
      { id: 'vap_report', name: 'report', description: 'Submit a ≤100-char report envelope through the three gates.' },
      { id: 'vap_verify', name: 'vap_verify', description: 'Run the three-gate verdict over an envelope.' },
    ],
  };
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      args[key] = next;
      i += 1;
    } else {
      args[key] = true;
    }
  }
  return args;
}

const isMain = typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  console.log(JSON.stringify(generateAgentCard({
    name: args.name,
    url: args.url,
    version: args.version,
  }), null, 2));
}
