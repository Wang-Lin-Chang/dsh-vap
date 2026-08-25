// experiments/graynet-experiment.mjs —— VAP 公网灰度实测装置（跨机角色模式）
//
// 角色：
//   relay : node experiments/graynet-experiment.mjs relay --host <bindIp> --port <p> --stats <file>
//   site  : node experiments/graynet-experiment.mjs site --site A|B --relayHost <ip> --relayPort <p> --root <dir> --out <results.json> --anchorPub <pubkey>
//
// 协议：
//   site A 主动：A1..A3 每节点向 B1..B3 各发 1 封真信封（9 封），A1 向 B1 加发 1 封无签名伪造；
//   site B：收真信封 → 验签+三闸 → 记账 → 每收 1 封回信 1 封（回给发件人）；收伪造 → 拒（不入账）；
//   site A：收 B 回信 → 验签+三闸 → 记账。
// 判据：
//   siteA: sentTrue=9, repliesReceived=9, repliesVerifiedAll=true, forgedSent=1
//   siteB: trueReceived=9, trueVerifiedAll=true, repliesSent=9, forgedArrived=1, forgedRejected=true
// K：密钥 persistKeys 落盘 root/keys（600 权限），重启同 pubKey；
// G：anchorPub 双站一致写入 registry.json。
// 零第三方依赖。

import fs from 'node:fs';
import path from 'node:path';

import { createVapNode, makeLaws } from '../vap-core.mjs';
import { createRelayServer } from '../phase4/relay-server.mjs';
import { createRelayClient } from '../phase4/relay-client.mjs';

function parseArgs() {
  const a = {};
  for (let i = 2; i < process.argv.length; i += 1) {
    const t = process.argv[i];
    if (t.startsWith('--')) {
      const k = t.slice(2);
      const n = process.argv[i + 1];
      if (n !== undefined && !n.startsWith('--')) { a[k] = n; i += 1; } else a[k] = 'true';
    }
  }
  return a;
}
const args = parseArgs();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function ensureRoot(nodeRoot) {
  fs.mkdirSync(nodeRoot, { recursive: true });
  fs.writeFileSync(path.join(nodeRoot, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return nodeRoot;
}

function makeParams(to, tag) {
  return {
    to,
    claim: { type: 'report', body: { work: 'graynet' } },
    evidence: { devices: ['G1'], bills: {}, digest: `sha256:graynet:${tag}` },
    boundary: 'L2a',
    report: { summary: `graynet ${tag}`, keyNumbers: [1], request: '' },
  };
}

function waitFor(cond, timeoutMs, intervalMs = 50) {
  return new Promise((resolve) => {
    const start = Date.now();
    (function tick() {
      if (cond()) return resolve(true);
      if (Date.now() - start >= timeoutMs) return resolve(cond());
      setTimeout(tick, intervalMs);
    })();
  });
}

async function runRelay() {
  const host = args.host || '0.0.0.0';
  const port = Number(args.port || 42050);
  const statsFile = args.stats;
  let droppedCount = 0;
  const dropFrom = args.dropFrom || ''; // R3：选择性丢弃该 nodeId 的第一封 relay 消息
  const server = createRelayServer({
    port,
    host,
    verbose: args.verbose === 'true' || args.verbose === '1',
    drop: dropFrom ? (msg) => {
      if (msg && msg.type === 'relay' && msg.envelope && msg.envelope.from
        && msg.envelope.from.nodeId === dropFrom && droppedCount === 0) {
        droppedCount += 1;
        return true;
      }
      return false;
    } : undefined,
  });
  await server.start();
  const write = () => {
    if (statsFile) {
      fs.writeFileSync(statsFile, JSON.stringify({ at: new Date().toISOString(), ...server.stats() }, null, 2) + '\n');
    }
  };
  const iv = setInterval(write, 2000);
  write();
  process.stdout.write(`GRAYNET-RELAY-UP host=${host} port=${port}\n`);
  process.on('SIGTERM', async () => { clearInterval(iv); await server.stop(); process.exit(0); });
  process.on('SIGINT', async () => { clearInterval(iv); await server.stop(); process.exit(0); });
}

async function runSite() {
  const site = args.site === 'B' ? 'B' : 'A';
  const relayHost = args.relayHost || '127.0.0.1';
  const relayPort = Number(args.relayPort || 42050);
  const base = args.root || (site === 'A' ? 'C:/Users/王霖昌/Documents/DeepSeek/graynet-siteA' : '/home/ubuntu/graynet-siteB');
  const outFile = args.out;
  const anchorPub = args.anchorPub || '';

  const ids = site === 'A' ? ['A1', 'A2', 'A3'] : ['B1', 'B2', 'B3'];
  const peerIds = site === 'A' ? ['B1', 'B2', 'B3'] : ['A1', 'A2', 'A3'];
  const nodes = {};
  const clients = {};
  const received = {}; // id -> [{env, verdict}]
  const rejected = {};
  for (const id of ids) {
    ensureRoot(path.join(base, id));
    nodes[id] = createVapNode({ nodeId: id, root: path.join(base, id), persistKeys: true });
    clients[id] = createRelayClient({ host: relayHost, port: relayPort, nodeId: id, pubKey: nodes[id].pubKey });
    received[id] = [];
    rejected[id] = [];
  }
  // registry.json：anchor 公钥带外发布落盘
  fs.writeFileSync(path.join(base, 'registry.json'), JSON.stringify({ anchorPub, updatedAt: new Date().toISOString() }, null, 2) + '\n');

  const keyFiles = ids.map((id) => path.join(base, id, 'keys'));
  const keyPersisted = keyFiles.every((d) => { try { return fs.readdirSync(d).length >= 1; } catch { return false; } });

  const result = {
    site, anchorPub, relayHost, relayPort,
    generatedAt: new Date().toISOString(),
    nodePubKeys: Object.fromEntries(ids.map((id) => [id, nodes[id].pubKey])),
    keyPersisted,
    sentTrue: 0, forgedSent: 0, repliesSent: 0,
    trueReceived: 0, trueVerifiedAll: true,
    forgedArrived: 0, forgedRejected: true,
    repliesReceived: 0, repliesVerifiedAll: true,
    relayStatsAtEnd: null,
  };

  try {
    for (const id of ids) clients[id].connect();
    const connected = await waitFor(() => clients[ids[0]].connected() && clients[ids[1]].connected() && clients[ids[2]].connected(), 15000);

    for (const id of ids) {
      clients[id].onEnvelope((env) => {
        const verdict = nodes[id].verify(env);
        const isForged = !(env && typeof env.sig === 'string' && env.sig.length > 0);
        if (verdict.pass) {
          received[id].push({ env, verdict });
          // site B 回信：每收 1 封真信封回 1 封
          if (site === 'B') {
            const fromId = env && env.from && env.from.nodeId;
            if (fromId && fromId.startsWith('A')) {
              const replyParams = makeParams(fromId, 'reply');
              replyParams.claim.body.origId = env.id; // 回信携带原信封 id，供 A 侧对账
              const reply = nodes[id].send(replyParams);
              clients[id].send(fromId, reply);
              result.repliesSent += 1;
            }
          }
        } else {
          rejected[id].push({ env, verdict });
        }
      });
    }

    if (site === 'A') {
      await sleep(3000); // 等 B 侧全部注册
      for (const a of ids) {
        for (const b of peerIds) {
          const env = nodes[a].send(makeParams(b, `${a}->${b}`));
          clients[a].send(b, env);
          result.sentTrue += 1;
        }
      }
      // 伪造：A1 发无签名信封给 B1
      const forged = nodes['A1'].send(makeParams('B1', 'forged'));
      forged.sig = '';
      clients['A1'].send('B1', forged);
      result.forgedSent = 1;
      // R4 吞吐：A1 → B1 连续 N 封，测跨公网转发/回信往返
      if (args.perf) {
        const N = Number(args.perf) || 200;
        const perfIds = [];
        const t0 = Date.now();
        for (let i = 0; i < N; i += 1) {
          const env = nodes['A1'].send(makeParams('B1', `perf-${i}`));
          clients['A1'].send('B1', env);
          perfIds.push(env.id);
        }
        const t1 = Date.now();
        const tDone = await waitFor(() => {
          const got = received['A1'].filter((r) => r.env && r.env.claim && r.env.claim.body
            && perfIds.includes(r.env.claim.body.origId));
          return got.length >= N;
        }, 80000, 200);
        const t2 = Date.now();
        result.perf = {
          sent: N,
          sentWindowMs: t1 - t0,
          receivedReplies: received['A1'].filter((r) => r.env && r.env.from && r.env.from.nodeId === 'B1').length,
          allPerfDone: tDone,
          totalMs: t2 - t0,
          envelopesPerSec: Number(((N / Math.max(t2 - t0, 1)) * 1000).toFixed(1)),
        };
      }
      // 等待 B 回信
      await sleep(args.perf ? 80000 : 40000);
    } else {
      // site B：被动跑，等 A 的真信封 + 伪造（perf 时窗口更长）
      await sleep(args.perf ? 95000 : 60000);
    }

    for (const id of ids) {
      const ok = received[id].filter((r) => r.verdict.pass === true);
      if (site === 'B') {
        result.trueReceived += received[id].filter((r) => {
          const fromId = r.env && r.env.from && r.env.from.nodeId;
          return fromId && fromId.startsWith('A');
        }).length;
      } else {
        result.repliesReceived += received[id].length;
      }
      for (const r of received[id]) {
        const v = r.verdict;
        const allGates = v && v.pass === true && v.gates.identity.pass === true && v.gates.laws.pass === true && v.gates.boundary.pass === true;
        if (!allGates) { result.trueVerifiedAll = false; }
      }
    }
    // B 侧伪造计数
    for (const id of ids) {
      for (const r of rejected[id]) {
        result.forgedArrived += 1;
        if (r.verdict.pass === true) result.forgedRejected = false;
      }
    }

    const json = JSON.stringify(result, null, 2);
    if (outFile) fs.writeFileSync(outFile, json + '\n');
    process.stdout.write(json + '\n');
    const pass = connected
      && (site === 'A'
        ? (result.sentTrue === 9 && result.repliesReceived === 9 && result.repliesVerifiedAll && result.forgedSent === 1)
        : (result.trueReceived === 9 && result.trueVerifiedAll && result.repliesSent === 9 && result.forgedArrived >= 1 && result.forgedRejected));
    process.stderr.write(`GRAYNET-${site}: connected=${connected} pass=${pass}\n`);
    process.exitCode = pass ? 0 : 1;
  } finally {
    for (const id of ids) clients[id].close();
  }
}

const role = process.argv[2];
if (role === 'relay') runRelay().catch((e) => { process.stderr.write('RELAY ERR: ' + e.message + '\n'); process.exit(1); });
else runSite().catch((e) => { process.stderr.write('SITE ERR: ' + e.message + '\n'); process.exit(1); });
