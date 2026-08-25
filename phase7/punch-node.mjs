// phase7/punch-node.mjs —— 打洞站点脚本（A 本机 NAT 后 / B 公网或 netns NAT 后）
//
// 用法：
//   node phase7/punch-node.mjs --site A --stunHost <ip> --stunPort 3478 \
//     --relayHost <ip> --relayPort <p> --localPort <p> [--classify true] \
//     [--stun2Host <ip>] [--stun2Port <p>] [--tcpPort <p>] [--relayCa <ca.pem>] --out <json>
//
// 流程（R6 起把 nat-classify + punch-plan/punch-chain 接入主流程）：
//   1) 启动即 NAT 自分类 classifyNAT（mappingClass / filter / isPublic）；
//   2) STUN discover 公网映射；3) 经中继交换 { mapping, natClass }；
//   4) buildExecPlan(selfNat, peerNat) 生成策略链，按序执行、失败按链回落：
//       ① direct-connect（一端公网/全锥快车道）② udp-punch（锥↔锥回打实际源）
//       ③ tcp-simultaneous-open（best-effort ≤5s）④ turn-relay（兜底，中继在线即可用）；
//   5) 直连成功后投递 payload；6) 结果 JSON 落盘（含 plan + 每步执行结果）。
//   零第三方依赖（node:crypto / node:net / node:dgram）。

import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import { createHolePuncher } from './hole-punch.mjs';
import { createRelayClient } from '../phase4/relay-client.mjs';
import { classifyNAT } from './nat-classify.mjs';
import { buildExecPlan } from './punch-chain.mjs';
import crypto from 'node:crypto';

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
const site = args.site === 'B' ? 'B' : 'A';
const peerId = site === 'A' ? 'P-B' : 'P-A';
const peerSite = site === 'A' ? 'B' : 'A';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const localPort = Number(args.localPort || (site === 'A' ? 46000 : 46001));
const tcpPort = Number(args.tcpPort || (localPort + 2));
const classifyEnabled = args.classify !== 'false';

// S3 修复：站点握手 token（打洞前经中继交换，直连包必须携带对端 token 才被接受）
const siteToken = crypto.randomBytes(16).toString('hex');

const puncher = createHolePuncher({
  localPort,
  stunHost: args.stunHost,
  stunPort: Number(args.stunPort || 3478),
  nodeId: site,
  myToken: siteToken,
});
await puncher.bind();

// relay 客户端集合在主流程区创建（R1 多中继冗余）

const result = {
  site, generatedAt: new Date().toISOString(),
  selfNat: null, peerNat: null, plan: null,
  stun: null, exchanged: false, peerMapping: null,
  ipv6: { self: [], peer: [] },
  strategyResults: [], executedStrategy: null,
  directEstablished: false, directPayloadReceived: 0,
  pass: false,
};

// IPv6 探测：枚举本机全局单播 v6（排除链路本地 fe80、ULA fc/fd 与 loopback ::1），供 L2 直连判定。
// 注意：GUA 可能全展开（8 组无 :: 压缩，如 2409:8a3c:17d0:5100:dd11:d9bb:f1ad:e71e），
// 因此不能以「含 ::」作为合法性判据（曾误滤全展开 GUA 导致 self 恒空——装置1 抓出的假阴性）。
function globalIpv6() {
  const out = [];
  try {
    const ifs = os.networkInterfaces();
    for (const name of Object.keys(ifs)) {
      for (const a of ifs[name] || []) {
        if (a.family === 'IPv6' && !a.internal) {
          const ip = (a.address || '').toLowerCase().split('%')[0];
          if (ip === '::1' || ip.startsWith('fe80') || ip.startsWith('fc') || ip.startsWith('fd')) continue;
          out.push({ ip, scopeid: a.scopeid || 0 });
        }
      }
    }
  } catch {}
  return out;
}
result.ipv6.self = globalIpv6();

// IPv6 直连 puncher：本端有 GUA 才创建。v6 端口 = localPort + 10（约定偏移，避开
// bindv6only=0 内核上 v4/v6 同端口 EADDRINUSE——SA2 实测；对端 target 端口由 punch-chain 同约定生成）
const v6LocalPort = localPort + 10;
const v6Puncher = result.ipv6.self.length > 0
  ? createHolePuncher({ localPort: v6LocalPort, nodeId: site, family: 'udp6', myToken: siteToken })
  : null;
if (v6Puncher) {
  await v6Puncher.bind();
}

// ---------------------------------------------------------------------------
// TCP simultaneous open（best-effort，≤5s）：同端口 LISTEN + connect 交叉。
// 诚实说明：Node 无法像内核那样用「同一 socket 既 LISTEN 又发 SYN」；此处用
// 「listener 绑 tcpPort + 出站 connect 也绑 localPort=tcpPort」近似。若 OS 拒绝
// 同端口复用（EADDRINUSE），即记录 R5 §10.2 的结构性限制并跳过（不误报成功）。
// ---------------------------------------------------------------------------
function tcpSimultaneousOpen({ localPort: lp, peerIp, peerPort, timeoutMs = 5000 }) {
  return new Promise((resolve) => {
    const r = { directEstablished: false, mode: null, attempts: 0, note: null };
    const t0 = Date.now();
    let settled = false;
    const finish = (extra) => {
      if (settled) return;
      settled = true;
      try { server.close(); } catch {}
      try { clearInterval(iv); } catch {}
      try { clearInterval(guard); } catch {}
      resolve({ ...r, ...extra });
    };

    const server = net.createServer((sock) => {
      if (settled) { try { sock.destroy(); } catch {} return; }
      r.directEstablished = true;
      r.mode = 'accepted';
      sock.on('data', (d) => sock.write(d)); // 回显以证双向
      sock.on('error', () => {});
      finish();
    });
    server.on('error', (err) => {
      // 端口被占/权限不足：记录并跳过（不视为成功）
      r.note = `listen 失败: ${err.code || err.message}`;
      finish();
    });

    let iv = null;
    let guard = null;
    server.listen({ port: lp, host: '0.0.0.0', exclusive: false }, () => {
      const tryConnect = () => {
        if (settled || Date.now() - t0 >= timeoutMs) return finish();
        r.attempts += 1;
        const sock = net.createConnection({ host: peerIp, port: peerPort, localAddress: '0.0.0.0', localPort: lp });
        sock.setTimeout(1200);
        sock.on('connect', () => {
          if (settled) { try { sock.destroy(); } catch {} return; }
          r.directEstablished = true;
          r.mode = 'connected';
          sock.on('data', (d) => sock.write(d));
          sock.on('error', () => {});
          finish();
        });
        sock.on('error', (err) => {
          if (err.code === 'EADDRINUSE') {
            r.note = `同端口 LISTEN+connect 被 OS 拒（${err.code}）——印证 R5 §10.2 的结构性限制`;
          }
          try { sock.destroy(); } catch {}
        });
        sock.on('timeout', () => { try { sock.destroy(); } catch {} });
      };
      tryConnect();
      iv = setInterval(tryConnect, 250);
      guard = setInterval(() => {
        if (Date.now() - t0 >= timeoutMs) finish();
      }, 100);
    });
  });
}

// ---------------------------------------------------------------------------
// 策略链执行器：按 plan.steps 顺序执行，直连成功即停，否则回落下一策略直至 turn-relay。
// ---------------------------------------------------------------------------
async function executePlan(plan, ctx) {
  const results = [];
  for (const step of plan.steps) {
    const rec = { id: step.id, timeoutMs: step.timeoutMs, startedAt: new Date().toISOString(), outcome: 'skipped' };
    if (step.timeoutMs <= 0) {
      rec.outcome = step.id === 'turn-relay' ? 'available' : 'not-applicable';
      rec.note = step.note;
      results.push(rec);
      if (step.id === 'turn-relay') { result.relayAvailable = ctx.relayAvailable; }
      continue;
    }

    if (step.id === 'direct-connect' || step.id === 'udp-punch') {
      const punch = await puncher.punchTo({ ...step.target, from: peerSite, token: result.peerToken }, step.timeoutMs);
      rec.outcome = punch.directEstablished ? 'direct-established' : 'failed';
      rec.received = punch.received;
      rec.elapsedMs = punch.elapsedMs;
      rec.actualPeer = punch.actualPeer || null;
      if (punch.directEstablished) {
        result.directEstablished = true;
        result.executedStrategy = step.id;
      }
    } else if (step.id === 'ipv6-direct') {
      if (!v6Puncher) {
        rec.outcome = 'failed';
        rec.note = '本端无全局单播 IPv6，v6 socket 未创建';
      } else {
        const punch = await v6Puncher.punchTo({ ...step.target, from: peerSite, token: result.peerToken }, step.timeoutMs);
        rec.outcome = punch.directEstablished ? 'direct-established' : 'failed';
        rec.received = punch.received;
        rec.elapsedMs = punch.elapsedMs;
        rec.actualPeer = punch.actualPeer || null;
        rec.note = step.target ? `v6 target ${step.target.ip}:${step.target.port}` : 'no v6 target';
        if (punch.directEstablished) {
          result.directEstablished = true;
          result.executedStrategy = step.id;
        }
      }
    } else if (step.id === 'tcp-simultaneous-open') {
      const t = await tcpSimultaneousOpen({ localPort: tcpPort, peerIp: step.target.ip, peerPort: step.target.port, timeoutMs: step.timeoutMs });
      rec.outcome = t.directEstablished ? 'direct-established' : 'failed';
      rec.mode = t.mode;
      rec.attempts = t.attempts;
      rec.note = t.note;
      if (t.directEstablished) {
        result.directEstablished = true;
        result.executedStrategy = step.id;
      }
    }

    if (rec.outcome === 'skipped') rec.outcome = 'failed';
    results.push(rec);
    if (result.directEstablished) break;
  }
  return results;
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------

// R1（多站点冗余）：--relayHost 支持逗号分隔列表，全部中继同时注册 + 冗余发 mapping。
// 任一站点下线不影响交换（存活站点继续转发）；mapping 幂等，多路冗余无害。
const relayHostList = String(args.relayHost || '').split(',').map((s) => s.trim()).filter(Boolean);
const relays = relayHostList.length > 0 ? relayHostList : ['127.0.0.1'];
const relayClients = relays.map((h) => createRelayClient({
  host: h,
  port: Number(args.relayPort || 42050),
  nodeId: 'P-' + site,
  pubKey: crypto.createHash('sha256').update('vap-punch-' + site).digest('base64'),
  tlsOptions: args.relayCa ? { ca: fs.readFileSync(args.relayCa) } : null,
}));
const relay = relayClients[0]; // 首个为主（保留旧变量语义）；其余为冗余

const mappingMsgs = [];
for (const rc of relayClients) {
  rc.onEnvelope((m0) => {
    const m = m0 && m0.envelope ? m0.envelope : m0;
    if (m && m.type === 'mapping') mappingMsgs.push(m);
  });
}
function sendMapping() {
  for (const rc of relayClients) {
    rc.send(peerId, { type: 'mapping', from: site, mapping: result.stun, natClass: result.selfNat, ipv6: result.ipv6.self, v6Port: v6LocalPort, token: siteToken });
  }
}
const directMsgs = [];
const pushDirectMsg = (payload) => {
  try {
    const j = JSON.parse(payload.toString());
    if (j && j.type === 'payload') { directMsgs.push(j); result.directPayloadReceived = directMsgs.length; }
  } catch {}
};
puncher.onDirect(pushDirectMsg);
if (v6Puncher) v6Puncher.onDirect(pushDirectMsg);

for (const rc of relayClients) rc.connect();
await sleep(2000);

// 1) NAT 自分类（启动即自判；失败不阻断，降级为 unknown 继续；瞬态丢包下重试 ≤3 次）
if (classifyEnabled) {
  const stun2Host = args.stun2Host || 'stun.l.google.com';
  const stun2Port = Number(args.stun2Port || 19302);
  const servers = [
    { host: args.stunHost, port: Number(args.stunPort || 3478) },
    { host: stun2Host, port: stun2Port },
  ];
  result.selfNat = { mappingClass: 'unknown', filter: 'unknown', isPublic: false };
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const r = await classifyNAT({ servers, localPort: 0 });
      result.selfNat = { ...r, classifyAttempts: attempt };
      break;
    } catch (err) {
      result.selfNat = {
        mappingClass: 'unknown', filter: 'unknown', isPublic: false,
        error: String(err && err.message), classifyAttempts: attempt,
      };
    }
  }
}

// 2) STUN discover 公网映射
result.stun = await puncher.discover();

// 3) 经中继交换 { mapping, natClass }（发 5 次 + 循环等 120s，容忍双方启动时序差）
// 同时交换 v6Port（本端 v6 socket 端口 = localPort+10 的显式值；不能用映射端口推算——家庭 NAT 映射随机端口）
for (let i = 0; i < 5; i += 1) {
  sendMapping();
  await sleep(500);
}
const swapT0 = Date.now();
let gotPeerAt = 0; // 首次收到对端 mapping 的时刻；收到后再多发 ~5s 自己的 mapping 才退出
while (Date.now() - swapT0 < 120000) {
  // 只接受新协议消息（带 v6Port 或非空 ipv6）：过滤 relay 里历史残留的旧格式消息
  // （旧 B 的 101.42 映射），旧格式一律忽略，避免打到错误目标
  const peerMsgs = mappingMsgs.filter((m) => m.from === peerSite);
  const fresh = peerMsgs.filter((m) => m.v6Port || (Array.isArray(m.ipv6) && m.ipv6.length > 0));
  const peerMsg = fresh.length > 0 ? fresh[fresh.length - 1] : null;
  if (peerMsg) {
    result.exchanged = true;
    result.peerMapping = peerMsg.mapping;
    result.peerNat = peerMsg.natClass || null;
    result.peerToken = peerMsg.token || null; // S3：对端握手 token
    result.ipv6.peer = peerMsg.ipv6 || [];
    if (peerMsg.v6Port) result.peerMapping.v6Port = peerMsg.v6Port;
    // 根因修复（relay 单向故障）：收到对端后不立即 break，而是继续再发 ~5s 自己的 mapping。
    // 否则「先收到方立刻停发」形成单向竞态——B 先注册、先收到 A 的 mapping 即停发，
    // 而 A 晚注册，B 早先发往 P-A 的消息全部落在 A 注册前被 relay 丢弃，A 永远收不到 B
    // （现象与 B exchanged=true / A exchanged=false 完全吻合）。
    if (!gotPeerAt) gotPeerAt = Date.now();
    if (Date.now() - gotPeerAt >= 5000) break;
  }
  sendMapping();
  await sleep(1500);
}

// 4) 生成策略链并执行
if (result.peerMapping) {
  result.plan = buildExecPlan({
    selfNat: result.selfNat,
    peerNat: result.peerNat,
    selfMapping: result.stun,
    peerMapping: result.peerMapping,
    selfIpv6: result.ipv6.self,
    peerIpv6: result.ipv6.peer,
    tcpPort,
  });
  result.strategyResults = await executePlan(result.plan, { relayAvailable: relay.connected() });
}

// 5) 直连投递 payload（按执行成功的策略选 v4/v6 通道；打洞成功后双方互发 5 封）
if (result.directEstablished) {
  const sender = result.executedStrategy === 'ipv6-direct' ? v6Puncher : puncher;
  for (let i = 0; i < 5; i += 1) {
    sender.sendDirect(Buffer.from(JSON.stringify({ type: 'payload', from: site, seq: i })));
    await sleep(300);
  }
  await sleep(6000);
}
result.directPayloadReceived = directMsgs.length;
result.pass = !!(result.stun && result.exchanged && result.directEstablished && directMsgs.length >= 1);

const json = JSON.stringify(result, null, 2);
if (args.out) fs.writeFileSync(args.out, json + '\n');
process.stdout.write(json + '\n');
for (const rc of relayClients) rc.close(); // R1：关闭全部中继连接（只关第一个会挂住事件循环，进程不退出）
puncher.close();
if (v6Puncher) v6Puncher.close();
process.exitCode = result.pass ? 0 : 1;
