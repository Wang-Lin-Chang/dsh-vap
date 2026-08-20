// phase2/experiments/phase2-experiment.mjs —— VAP Phase 2 LAN P2P 实测装置（独立可运行）
//
// 本机多端口模拟 5 节点，零第三方依赖，跑通四个验收场景：
//   P2-1 一发四收：5 节点全互连（组播发现），节点 1 发真信封 → 其余 4 节点收到且三闸通过；
//   P2-2 重放：节点 1 再次洪泛同一信封 → 其他节点 receivedCount 不增（去重）；
//   P2-3 伪造：节点 5 洪泛无签名信封 → 到达但三闸拦截（receivedButRejected）；
//   P2-4 风暴：5 节点环状拓扑，洪泛 → 每节点至多 1 次、转发次数有界（≤ 边数）。
// 输出结构化 JSON：p2_1_received4of4 / p2_2_noReplay / p2_3_intercepted / p2_4_bounded；
// 任一硬性判据失败以非零退出码报告。
//
// 运行：node phase2/experiments/phase2-experiment.mjs（在 dsh-vap/ 下）

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { createVapNode, makeLaws } from '../../vap-core.mjs';
import { createLanPeer } from '../lan-peer.mjs';

function makeRoot(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `vap-phase2-${tag}-`));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

function makeKeyPair() {
  return crypto.generateKeyPairSync('ed25519');
}

function validParams() {
  return {
    to: 'brain',
    claim: { type: 'report', body: { work: 'phase2' } },
    evidence: { devices: ['E01'], bills: {}, digest: 'sha256:phase2' },
    boundary: 'L2a',
    report: { summary: 'Phase2 LAN 实测', keyNumbers: [1], request: '' },
  };
}

async function waitFor(cond, timeoutMs = 5000, intervalMs = 25) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return cond();
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function startPeer(peer) {
  peer.start();
  await peer.ready;
  return peer;
}

// ---------------------------------------------------------------------------
// P2-1 / P2-2 / P2-3：5 节点全互连（组播发现）
// ---------------------------------------------------------------------------

async function runMesh() {
  const N = 5;
  const keyPairs = Array.from({ length: N }, () => makeKeyPair());
  const nodes = [];
  const peers = [];

  for (let i = 0; i < N; i += 1) {
    const nodeId = `node-${i + 1}`;
    const root = makeRoot(`mesh-${i + 1}`);
    nodes.push(createVapNode({ nodeId, root, keyPair: keyPairs[i] }));
    // M17：本机组播发现显式走回环出接口（默认已改为 OS 出接口）。
    peers.push(createLanPeer({ port: 0, nodeId, keyPair: keyPairs[i], mcastInterface: '127.0.0.1' }));
  }
  for (const p of peers) p.start();
  await Promise.all(peers.map((p) => p.ready));

  // 等待全互连：每个节点发现其余 4 个
  const discovered = await waitFor(() => peers.every((p) => p.peers().length >= N - 1), 7000);
  if (!discovered) {
    for (const p of peers) p.stop();
    return { discovered: false, peerCounts: peers.map((p) => p.peers().length) };
  }

  // 接收/拒收记录（按节点）
  const received = Array.from({ length: N }, () => []);   // received[i] = [{ env, verdict }]
  const rejected = Array.from({ length: N }, () => []);   // rejected[i] = [{ envelope, reason }]
  for (let i = 0; i < N; i += 1) {
    peers[i].onEnvelope((env, meta) => received[i].push({ env, verdict: meta.verdict }));
    peers[i].onReject((r) => rejected[i].push(r));
  }

  // ---- P2-1 一发四收：节点 1 发真信封 ----
  const env1 = nodes[0].send(validParams());
  peers[0].sendEnvelope(env1);
  const p21ok = await waitFor(
    () => received.slice(1).every((arr) => arr.some((r) => r.env.id === env1.id)),
    5000,
  );

  const receivers = received.slice(1); // 节点 2..5
  const got4of4 = receivers.every((arr) => arr.some((r) => r.env.id === env1.id));
  const allGatesPass = got4of4 && receivers.every((arr) => {
    const r = arr.find((x) => x.env.id === env1.id);
    const v = r.verdict;
    return v.pass === true && v.gates.identity.pass === true
      && v.gates.laws.pass === true && v.gates.boundary.pass === true;
  });

  // ---- P2-2 重放：同一信封再次洪泛，receivedCount 不增 ----
  const countOf = (arr, id) => arr.filter((r) => r.env.id === id).length;
  const beforeReplay = received.slice(1).map((arr) => countOf(arr, env1.id));
  peers[0].sendEnvelope(env1); // 重放
  await sleep(600);            // 等重放尘埃落定
  const afterReplay = received.slice(1).map((arr) => countOf(arr, env1.id));
  const noReplay = beforeReplay.every((c, i) => c === 1 && afterReplay[i] === c);

  // ---- P2-3 伪造：节点 5 洪泛无签名信封 → 到达但三闸拦截 ----
  const forged = nodes[4].send(validParams());
  forged.sig = ''; // 伪造：无签名
  peers[4].sendEnvelope(forged);
  const p23ok = await waitFor(
    () => rejected.slice(0, 4).every((arr) => arr.some((r) => r.envelope.id === forged.id)),
    5000,
  );
  const intercepted = rejected.slice(0, 4).every((arr) => arr.some((r) => r.envelope.id === forged.id));
  const forgedNotDelivered = received.slice(0, 4).every((arr) => !arr.some((r) => r.env.id === forged.id));

  const result = {
    discovered,
    peerCounts: peers.map((p) => p.peers().length),
    p2_1: {
      envelopeId: env1.id,
      got4of4,
      allGatesPass,
      perNodeDelivered: received.slice(1).map((arr) => countOf(arr, env1.id)),
    },
    p2_2: {
      beforeReplay,
      afterReplay,
      noReplay,
    },
    p2_3: {
      envelopeId: forged.id,
      intercepted,
      forgedNotDelivered,
      perNodeRejected: rejected.slice(0, 4).map((arr) => arr.filter((r) => r.envelope.id === forged.id).length),
    },
    stats: peers.map((p) => p.stats()),
  };

  for (const p of peers) p.stop();
  return result;
}

// ---------------------------------------------------------------------------
// P2-4 风暴：5 节点环状拓扑，洪泛有界
// ---------------------------------------------------------------------------

async function runRing() {
  const N = 5;
  const keyPairs = Array.from({ length: N }, () => makeKeyPair());
  const nodes = [];
  const peers = [];

  for (let i = 0; i < N; i += 1) {
    const nodeId = `node-${i + 1}`;
    nodes.push(createVapNode({ nodeId, root: makeRoot(`ring-${i + 1}`), keyPair: keyPairs[i] }));
    // discover:false → 不组播发现，只用手动环状拓扑（确定性）。
    peers.push(createLanPeer({ port: 0, nodeId, keyPair: keyPairs[i], discover: false }));
  }
  for (const p of peers) p.start();
  await Promise.all(peers.map((p) => p.ready));

  // 环状接线：节点 i 连 (i-1) 与 (i+1) mod 5
  for (let i = 0; i < N; i += 1) {
    const prev = (i - 1 + N) % N;
    const next = (i + 1) % N;
    peers[i].addPeer({ nodeId: peers[prev].nodeId, pubKey: peers[prev].pubKey, addr: '127.0.0.1', port: peers[prev].port });
    peers[i].addPeer({ nodeId: peers[next].nodeId, pubKey: peers[next].pubKey, addr: '127.0.0.1', port: peers[next].port });
  }

  const delivered = Array.from({ length: N }, () => []);
  for (let i = 0; i < N; i += 1) {
    peers[i].onEnvelope((env) => delivered[i].push(env));
  }

  const env = nodes[0].send(validParams());
  peers[0].sendEnvelope(env);
  // 等洪泛在环上走完（每节点至多一次，无爆炸，短等待即可）
  await sleep(800);

  const perNode = delivered.map((arr) => arr.filter((e) => e.id === env.id).length);
  const edges = N; // 5 节点环的边数
  const totalForwarded = peers.reduce((sum, p) => sum + p.stats().forwarded, 0);

  // 每节点至多 1 次；源节点 0 次；其余 4 节点各恰 1 次；转发有界（≤ 边数）。
  const eachAtMostOnce = perNode.every((c) => c <= 1);
  const nonOriginExactlyOnce = perNode.slice(1).every((c) => c === 1);
  const originZero = perNode[0] === 0;
  const boundedForward = totalForwarded <= edges;

  const result = {
    envelopeId: env.id,
    perNode,
    origin: perNode[0],
    nonOrigin: perNode.slice(1),
    totalForwarded,
    edges,
    eachAtMostOnce,
    nonOriginExactlyOnce,
    originZero,
    boundedForward,
    ok: eachAtMostOnce && nonOriginExactlyOnce && originZero && boundedForward,
    stats: peers.map((p) => p.stats()),
  };

  for (const p of peers) p.stop();
  return result;
}

// ---------------------------------------------------------------------------
// 汇总
// ---------------------------------------------------------------------------

async function main() {
  const mesh = await runMesh();

  const p2_1_received4of4 = mesh.discovered === true
    && mesh.p2_1.got4of4 === true
    && mesh.p2_1.allGatesPass === true;
  const p2_2_noReplay = mesh.discovered === true && mesh.p2_2.noReplay === true;
  const p2_3_intercepted = mesh.discovered === true
    && mesh.p2_3.intercepted === true
    && mesh.p2_3.forgedNotDelivered === true;

  const ring = await runRing();
  const p2_4_bounded = ring.ok === true;

  const allPass = p2_1_received4of4 && p2_2_noReplay && p2_3_intercepted && p2_4_bounded;

  const summary = {
    experiment: 'phase2-experiment',
    p2_1_received4of4,
    p2_2_noReplay,
    p2_3_intercepted,
    p2_4_bounded,
    allPass,
    mesh,
    ring,
  };

  console.log(JSON.stringify(summary, null, 2));

  if (!allPass) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(JSON.stringify({
    experiment: 'phase2-experiment',
    error: String((err && err.message) || err),
  }, null, 2));
  process.exitCode = 1;
});
