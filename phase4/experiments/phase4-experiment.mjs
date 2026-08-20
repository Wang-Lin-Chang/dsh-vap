// phase4/experiments/phase4-experiment.mjs —— VAP Phase 4 跨 NAT 中继实测装置（R1-R4）
//
// 运行：node phase4/experiments/phase4-experiment.mjs（在 dsh-vap/ 下）
// 输出：结构化 JSON（stdout + phase4/experiments/phase4-results.json）
//
// R1 跨"网段"通信：两组各 3 节点只经中继可达（不直连）→ 互发真信封，全部验签+三闸通过；
// R2 伪造经中继   ：伪造（无签名）信封经中继转发 → 对端三闸拦截（rejected，不入账）；
// R3 审查检测     ：中继选择性丢弃节点 A 的 1 封消息 → 对端对账（expected 2 只到 1）→ detected + 证据；
// R4 无激励基线   ：50/200/500 并发连接、每连接 10 封 → CPU/内存/字节转发率（无激励中继承载力数据）。
//
// 复用（零改动）：vap-core（信封/三闸/canonicalJson）；中继只转发不解密不验签。
// 零第三方依赖：仅 node:crypto / node:fs / node:os / node:path / node:url 与相对路径 import。

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createVapNode } from '../../vap-core.mjs';
import { createRelayServer } from '../relay-server.mjs';
import { createRelayClient } from '../relay-client.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

function makeParams(to) {
  return {
    to,
    claim: { type: 'report', body: { work: 'phase4-relay' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:phase4' },
    boundary: 'L2a',
    report: { summary: 'Phase4 cross-NAT relay', keyNumbers: [1], request: '' },
  };
}

function makeNode(id) {
  return createVapNode({ nodeId: id, root: makeRoot(id) });
}

function waitFor(cond, timeoutMs = 8000, intervalMs = 20) {
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
const round = (x) => Math.round(x * 1000) / 1000;

// ---------------------------------------------------------------------------
// R1 跨"网段"通信：两组各 3 节点只经中继互发真信封
// ---------------------------------------------------------------------------

async function runR1() {
  const server = createRelayServer({ port: 0 });
  const port = await server.start();

  const group1 = ['A1', 'A2', 'A3'];
  const group2 = ['B1', 'B2', 'B3'];
  const ids = [...group1, ...group2];

  const nodes = {};
  const clients = {};
  const received = {}; // id -> [{ env, verdict }]
  for (const id of ids) {
    const node = makeNode(id);
    nodes[id] = node;
    clients[id] = createRelayClient({ host: '127.0.0.1', port, nodeId: id, pubKey: node.pubKey });
    received[id] = [];
  }

  try {
    for (const id of ids) clients[id].connect();
    const allUp = await waitFor(() => server.stats().connections === 6, 8000);

    for (const id of ids) {
      clients[id].onEnvelope((env) => {
        received[id].push({ env, verdict: nodes[id].verify(env) });
      });
    }

    // 互发：组 1 每节点 → 组 2 每节点，反之亦然（3×3×2 = 18 封）
    const sent = [];
    for (const a of group1) {
      for (const b of group2) {
        const env = nodes[a].send(makeParams(b));
        clients[a].send(b, env);
        sent.push({ from: a, to: b, id: env.id });
      }
    }
    for (const b of group2) {
      for (const a of group1) {
        const env = nodes[b].send(makeParams(a));
        clients[b].send(a, env);
        sent.push({ from: b, to: a, id: env.id });
      }
    }

    const allReceived = await waitFor(
      () => sent.every((s) => received[s.to].some((r) => r.env.id === s.id)),
      10000,
    );

    const perRecipient = ids.map((id) => ({
      nodeId: id,
      expected: sent.filter((s) => s.to === id).length,
      received: received[id].length,
    }));

    const allGatesPass = sent.every((s) => {
      const r = received[s.to].find((x) => x.env.id === s.id);
      if (!r) return false;
      const v = r.verdict;
      return v.pass === true
        && v.gates.identity.pass === true
        && v.gates.laws.pass === true
        && v.gates.boundary.pass === true;
    });

    const r1_allPass = allUp && allReceived && allGatesPass;

    return {
      groups: { group1, group2 },
      connected: server.stats().connections,
      envelopesSent: sent.length,
      allReceived,
      allGatesPass,
      perRecipient,
      relayForwarded: server.stats().forwarded,
      r1_allPass,
    };
  } finally {
    for (const id of ids) clients[id].close();
    await server.stop();
  }
}

// ---------------------------------------------------------------------------
// R2 伪造经中继：无签名信封 → 对端三闸拦截（不入账）
// ---------------------------------------------------------------------------

async function runR2() {
  const server = createRelayServer({ port: 0 });
  const port = await server.start();

  const forger = makeNode('F');
  const victim = makeNode('V');
  const clientF = createRelayClient({ host: '127.0.0.1', port, nodeId: 'F', pubKey: forger.pubKey });
  const clientV = createRelayClient({ host: '127.0.0.1', port, nodeId: 'V', pubKey: victim.pubKey });

  const accepted = [];
  const rejected = [];

  try {
    clientF.connect();
    clientV.connect();
    await waitFor(() => server.stats().connections === 2, 8000);

    clientV.onEnvelope((env) => {
      const verdict = victim.verify(env);
      if (verdict.pass) accepted.push({ env, verdict });
      else rejected.push({ env, verdict });
    });

    const forged = forger.send(makeParams('V'));
    forged.sig = ''; // 伪造：无签名（中继无感知，照常转发）
    clientF.send('V', forged);

    const arrived = await waitFor(() => rejected.some((r) => r.env.id === forged.id), 8000);

    const intercepted = arrived && rejected.some((r) => r.env.id === forged.id);
    const notRecorded = !accepted.some((r) => r.env.id === forged.id);
    const relayForwardedForged = server.stats().forwarded === 1; // 中继不验签，照样转发

    const r2_intercepted = intercepted && notRecorded && relayForwardedForged;

    return {
      forgedEnvelopeId: forged.id,
      arrived,
      intercepted,
      notRecorded,
      relayForwardedForged,
      rejectReasons: (rejected.find((r) => r.env.id === forged.id) || {}).verdict
        ? (rejected.find((r) => r.env.id === forged.id).verdict.gates.identity.reason
            || 'signature verification failed')
        : null,
      r2_intercepted,
    };
  } finally {
    clientF.close();
    clientV.close();
    await server.stop();
  }
}

// ---------------------------------------------------------------------------
// R3 审查检测：中继选择性丢弃节点 A 的 1 封消息 → 对端对账检测
// ---------------------------------------------------------------------------

async function runR3() {
  let droppedCount = 0;
  const server = createRelayServer({
    port: 0,
    drop: (msg) => {
      // 选择性丢弃：只丢 from=A 的第一封 relay 消息（其余照常转发）
      if (msg && msg.type === 'relay'
        && msg.envelope && msg.envelope.from
        && msg.envelope.from.nodeId === 'A') {
        if (droppedCount === 0) {
          droppedCount += 1;
          return true;
        }
      }
      return false;
    },
  });
  const port = await server.start();

  const nodeA = makeNode('A');
  const nodeB = makeNode('B');
  const clientA = createRelayClient({ host: '127.0.0.1', port, nodeId: 'A', pubKey: nodeA.pubKey });
  const clientB = createRelayClient({ host: '127.0.0.1', port, nodeId: 'B', pubKey: nodeB.pubKey });

  const sendConfirmations = [];   // A 的发送确认（本地记录）
  const arrivalConfirmations = []; // B 的到达确认

  try {
    clientA.connect();
    clientB.connect();
    await waitFor(() => server.stats().connections === 2, 8000);

    clientB.onEnvelope((env) => arrivalConfirmations.push(env.id));

    const expected = 2;
    const e1 = nodeA.send(makeParams('B'));
    const e2 = nodeA.send(makeParams('B'));
    clientA.send('B', e1);
    sendConfirmations.push(e1.id);
    clientA.send('B', e2);
    sendConfirmations.push(e2.id);

    await sleep(600); // 等转发尘埃落定

    const receivedIds = arrivalConfirmations.filter((id) => sendConfirmations.includes(id));
    const missing = sendConfirmations.filter((id) => !arrivalConfirmations.includes(id));
    const detected = missing.length > 0 && receivedIds.length < expected;

    const r3_detected = detected && server.stats().dropped === 1;

    return {
      expected,
      sent: sendConfirmations.length,
      received: receivedIds.length,
      relayDropped: server.stats().dropped,
      missing,
      evidence: {
        sendConfirmations,
        arrivalConfirmations,
        missing,
        conclusion: detected
          ? 'censorship/丢包 detected：发送确认 2 vs 到达确认 1'
          : 'no loss detected',
      },
      r3_detected,
    };
  } finally {
    clientA.close();
    clientB.close();
    await server.stop();
  }
}

// ---------------------------------------------------------------------------
// R4 无激励基线：50/200/500 并发连接，每连接 10 封 → CPU/内存/字节
// ---------------------------------------------------------------------------

async function runR4() {
  const sizes = [50, 200, 500];
  const perClient = 10; // 每连接 10 封（名义速率 10 封/秒窗口内的突发量）
  const table = [];

  for (const N of sizes) {
    const server = createRelayServer({ port: 0 });
    const port = await server.start();

    const clients = [];
    const nodes = [];
    for (let i = 0; i < N; i += 1) {
      const id = `n${i}`;
      const node = makeNode(`r4-${N}-${i}`);
      nodes.push(node);
      clients.push(createRelayClient({ host: '127.0.0.1', port, nodeId: id, pubKey: node.pubKey }));
    }

    try {
      for (const c of clients) c.connect();
      const allUp = await waitFor(() => server.stats().connections === N, 15000);

      const cpuBefore = process.cpuUsage();
      const memBefore = process.memoryUsage().rss;
      const t0 = Date.now();

      // 环状配对：节点 i 发 10 封给节点 (i+1)%N → 每封都经中继转发
      for (let i = 0; i < N; i += 1) {
        const to = `n${(i + 1) % N}`;
        for (let k = 0; k < perClient; k += 1) {
          const env = nodes[i].send(makeParams(to));
          clients[i].send(to, env);
        }
      }

      const allForwarded = await waitFor(() => server.stats().forwarded === N * perClient, 30000);

      const t1 = Date.now();
      const cpuAfter = process.cpuUsage();
      const memAfter = process.memoryUsage().rss;

      const durationSec = (t1 - t0) / 1000;
      const cpuMs = (cpuAfter.user + cpuAfter.system - cpuBefore.user - cpuBefore.system) / 1000;
      const s = server.stats();

      table.push({
        connections: N,
        connectionsEstablished: s.connections,
        envelopesPerConnection: perClient,
        envelopesSent: N * perClient,
        forwarded: s.forwarded,
        allForwarded,
        totalBytes: s.totalBytes,
        forwardedBytes: s.forwardedBytes,
        durationSec: round(durationSec),
        cpuMs: round(cpuMs),
        memRssBefore: memBefore,
        memRssAfter: memAfter,
        memRssDelta: memAfter - memBefore,
        bytesPerSec: round(s.forwardedBytes / Math.max(durationSec, 0.001)),
        envelopesPerSec: round(s.forwarded / Math.max(durationSec, 0.001)),
      });
    } finally {
      for (const c of clients) c.close();
      await server.stop();
    }
  }

  const r4_produced = table.length === sizes.length && table.every((r) => r.allForwarded === true);

  return {
    sizes,
    perClient,
    table,
    r4_baseline: table,
    r4_produced,
  };
}

// ---------------------------------------------------------------------------
// 汇总 + 输出
// ---------------------------------------------------------------------------

async function main() {
  const R1 = await runR1();
  const R2 = await runR2();
  const R3 = await runR3();
  const R4 = await runR4();

  const allPass = R1.r1_allPass && R2.r2_intercepted && R3.r3_detected && R4.r4_produced;

  const summary = {
    experiment: 'phase4-relay',
    generatedAt: new Date().toISOString(),
    zeroDependency: true,
    reusedModules: ['../vap-core.mjs'],
    r1_allPass: R1.r1_allPass,
    r2_intercepted: R2.r2_intercepted,
    r3_detected: R3.r3_detected,
    r4_baseline: R4.r4_baseline,
    allPass,
    R1,
    R2,
    R3,
    R4,
    honestBoundaries: [
      '中继是中心化点：只见明文、不可伪造（验签必败）、可选择性丢弃——信任边界 = 不可信但不可作恶，作恶=审查可被检测',
      '打洞未做（决策见 NAT-PUNCHING-DECISION.md）',
      '本机回环测试（127.0.0.1），真实跨 NAT 实测待公网环境',
      '无激励基线是单机模拟（中继与客户端同进程，CPU/内存含客户端开销），公网带宽成本另算',
    ],
  };

  const json = JSON.stringify(summary, null, 2);
  process.stdout.write(json + '\n');

  fs.mkdirSync(__dirname, { recursive: true });
  fs.writeFileSync(path.join(__dirname, 'phase4-results.json'), json + '\n', 'utf8');

  if (!allPass) {
    process.stderr.write('PHASE4 EXPERIMENT FAILED: acceptance criteria not met.\n');
    process.exitCode = 1;
  } else {
    process.stderr.write(
      `PHASE4 OK: R1=${R1.r1_allPass} R2=${R2.r2_intercepted} ` +
      `R3=${R3.r3_detected} R4=${R4.r4_produced}\n`,
    );
  }
}

main().catch((err) => {
  process.stderr.write(`${JSON.stringify({
    experiment: 'phase4-relay',
    error: String((err && err.message) || err),
  }, null, 2)}\n`);
  process.exitCode = 1;
});
