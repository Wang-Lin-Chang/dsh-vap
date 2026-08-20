// phase2/lan-peer.mjs —— VAP Phase 2 LAN P2P 传输（零第三方依赖，node:dgram/node:crypto/node:fs）
//
// 同一局域网内不经 HTTP 的端到端 P2P：节点发现（UDP 组播 mDNS 简化版）+ 信封洪泛
// （floodsub 语义）+ messageId 去重防环 + TTL 上限 + 身份绑定检查。
//
// 原则（见 DESIGN.md）：信封、签名、验证门三闸全部复用 ../vap-core.mjs，零改动——
// 本模块只是新传输，只「搬运与转发」，不复制信封构造/验签/军法/诚实边界等任何判定逻辑。
//
//   createLanPeer({ port, nodeId, keyPair, multicast, host, mcastInterface, discover, root, now })
//     → peer.start() / stop() / sendEnvelope(envelope, ttl?) / broadcast(envelope) /
//       onEnvelope(cb) / onReject(cb) / addPeer(info) / peers() / stats()
//
// 传输层只信任验证门：任何信封到达后先走 vap-core 的 verify（三闸），过闸才投递与转发；
// 身份绑定（announce 注册的 pubKey 必须与信封 from.pubKey 一致）在验证门之前单独拦截，
// 拦截原因 reason='identity mismatch'（见 phase1/IDENTITY.md 决策 4 与 DESIGN §二）。

import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createVapNode, makeLaws } from '../vap-core.mjs';

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

const DEFAULT_MULTICAST = Object.freeze({ addr: '239.255.42.99', port: 42666 });
const ANNOUNCE_INTERVAL_MS = 3000;   // announce 周期（brief：3s）
const PEER_EXPIRE_MS = 10000;        // 10s 未见剔除
const SEEN_EXPIRE_MS = 60000;        // seen 集合清理（60s）
const PRUNE_INTERVAL_MS = 1000;      // 剔除/清理检查周期
const DEFAULT_TTL = 8;               // 洪泛 TTL 上限

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

function normalizeMulticast(multicast) {
  if (multicast == null) return { ...DEFAULT_MULTICAST };
  if (typeof multicast === 'string') {
    const m = /^([^:]+):(\d+)$/.exec(multicast);
    if (m) return { addr: m[1], port: Number.parseInt(m[2], 10) };
    // M23：IPv6 组播字面量（含多组冒号，如 ff02::1 / ff05::99）显式拒绝。
    // 组播 socket 一律用 udp4，IPv6 组播地址无法走 udp4；诚实声明不支持，避免
    // 静默解析成非法地址或绑定到错误协议族。
    if (multicast.includes(':')) {
      throw new Error('仅支持 IPv4 组播');
    }
    return { addr: multicast, port: DEFAULT_MULTICAST.port };
  }
  const addr = multicast.addr || DEFAULT_MULTICAST.addr;
  // 对象形态同样拒绝 IPv6 字面量（addr 含冒号即非 IPv4）。
  if (typeof addr === 'string' && addr.includes(':')) {
    throw new Error('仅支持 IPv4 组播');
  }
  return {
    addr,
    port: Number.isInteger(multicast.port) ? multicast.port : DEFAULT_MULTICAST.port,
  };
}

// 验证节点需要一个工作区放 laws.json/registry.json；verify 只读，故用临时目录即可。
function makeVerifyRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-lan-'));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

// ---------------------------------------------------------------------------
// createLanPeer
// ---------------------------------------------------------------------------

export function createLanPeer(options = {}) {
  const {
    port = 0,
    nodeId,
    keyPair,
    multicast,
    host = '0.0.0.0',
    // M17：默认 undefined = 走 OS 默认出接口（跨机/多网卡场景不把组播锁死在回环）。
    // 需要本机回环发现时显式传 mcastInterface: '127.0.0.1'（测试/实验即如此）。
    mcastInterface = undefined,
    discover = true,
    root,
    now,
  } = options;

  if (!nodeId) throw new Error('createLanPeer: nodeId is required');

  const mcast = normalizeMulticast(multicast);
  const nowMs = typeof now === 'function' ? now : () => Date.now();

  // 复用 vap-core 三闸验证（零改动）：同一密钥对生成验证节点，取协议公钥作为本节点身份。
  const verifyRoot = root || makeVerifyRoot();
  const vapNode = createVapNode({ nodeId, root: verifyRoot, keyPair });
  const pubKey = vapNode.pubKey;

  const peers = new Map();      // nodeId -> { pubKey, addr, port, lastSeen }
  const seen = new Map();       // messageId -> expiresAt（ms 时间戳）
  const envelopeListeners = new Set();
  const rejectListeners = new Set();

  let unicast = null;           // 单播 socket：信封洪泛收发（绑定本节点 port）
  let mcastSock = null;         // 组播 socket：announce 收发（绑定 multicast.port，reuseAddr）
  let announceTimer = null;
  let pruneTimer = null;
  let started = false;
  let boundPort = Number.isInteger(port) ? port : 0;

  const counters = {
    sent: 0,        // sendEnvelope/broadcast 发起次数
    received: 0,    // 收到的 flood 数（含被去重/被拒的）
    delivered: 0,   // onEnvelope 送达次数（过闸）
    forwarded: 0,   // 洪泛转发出的数据报次数
    rejected: 0,    // onReject 触发次数
    deduped: 0,     // 因 messageId 去重丢弃次数
    identityRejected: 0, // 因身份绑定不一致拒收次数
  };

  let resolveReady;
  const ready = new Promise((resolve) => { resolveReady = resolve; });

  // -------------------------------------------------------------------------
  // 内部：peer 表 / seen 清理
  // -------------------------------------------------------------------------

  function prune() {
    const cutoff = nowMs() - PEER_EXPIRE_MS;
    for (const [id, p] of peers) {
      if (p.lastSeen < cutoff) peers.delete(id);
    }
    const exp = nowMs();
    for (const [id, at] of seen) {
      if (at <= exp) seen.delete(id);
    }
  }

  function updatePeer(info) {
    if (!info || typeof info.nodeId !== 'string' || !info.nodeId) return false;
    if (info.nodeId === nodeId) return false; // 不登记自己
    const entry = {
      pubKey: typeof info.pubKey === 'string' ? info.pubKey : '',
      addr: typeof info.addr === 'string' ? info.addr : '127.0.0.1',
      port: Number.isInteger(info.port) ? info.port : 0,
      lastSeen: nowMs(),
    };
    peers.set(info.nodeId, entry);
    return true;
  }

  function announce() {
    if (!mcastSock || boundPort === 0) return;
    const msg = Buffer.from(JSON.stringify({
      type: 'announce',
      nodeId,
      pubKey,
      port: boundPort,
      ts: nowMs(),
    }), 'utf8');
    mcastSock.send(msg, mcast.port, mcast.addr, () => { /* 尽力发送，丢包不重传 */ });
  }

  function sendFloodTo(entry, flood) {
    if (!unicast || !entry || !entry.port) return;
    const msg = Buffer.from(JSON.stringify(flood), 'utf8');
    unicast.send(msg, entry.port, entry.addr, () => { /* 尽力发送 */ });
  }

  // -------------------------------------------------------------------------
  // 内部：消息处理
  // -------------------------------------------------------------------------

  function handleAnnounce(msg, rinfo) {
    updatePeer({
      nodeId: msg.nodeId,
      pubKey: msg.pubKey,
      addr: rinfo.address,
      port: msg.port,
    });
  }

  function fireReject(envelope, reason, rinfo) {
    counters.rejected += 1;
    for (const cb of rejectListeners) {
      try { cb({ envelope, reason, rinfo }); } catch { /* 回调异常不阻断传输 */ }
    }
  }

  function handleFlood(msg, rinfo) {
    counters.received += 1;
    const envelope = msg.envelope;
    const messageId = envelope && envelope.id;
    if (!messageId) return; // 无 id 无法去重，直接丢弃

    // ① messageId 去重防环：同一 id 永不二次投递/转发
    if (seen.has(messageId)) {
      counters.deduped += 1;
      return;
    }
    seen.set(messageId, nowMs() + SEEN_EXPIRE_MS);

    const ttl = Number.isInteger(msg.ttl) ? msg.ttl : DEFAULT_TTL;
    const from = (envelope && envelope.from) || {};
    const fromNodeId = from.nodeId;
    const fromPubKey = from.pubKey;

    // ② 身份绑定检查：信封 from.pubKey 必须与 announce 注册的 pubKey 一致。
    //    不一致 → 拒收（reason='identity mismatch'），不投递、不转发。
    const known = fromNodeId ? peers.get(fromNodeId) : null;
    if (known && known.pubKey && known.pubKey !== fromPubKey) {
      counters.identityRejected += 1;
      fireReject(envelope, 'identity mismatch', rinfo);
      return;
    }

    // ③ 三闸验证（零改动复用 vap-core）：传输层不信任信封，只信任验证门。
    const verdict = vapNode.verify(envelope);
    if (!verdict.pass) {
      fireReject(envelope, collectReasons(verdict), rinfo);
      return;
    }

    // ④ 送达回调（去重 + 身份绑定 + 三闸全过后才送达）
    counters.delivered += 1;
    for (const cb of envelopeListeners) {
      try { cb(envelope, { ttl, rinfo, verdict }); } catch { /* 忽略回调异常 */ }
    }

    // ⑤ TTL 递减洪泛：TTL>1 才转发给其他 peer（TTL-1），不发回上游、不发给自己。
    if (ttl > 1) {
      const next = { type: 'flood', ttl: ttl - 1, srcNodeId: nodeId, envelope };
      for (const [peerNodeId, entry] of peers) {
        if (peerNodeId === msg.srcNodeId) continue;
        if (peerNodeId === nodeId) continue;
        counters.forwarded += 1;
        sendFloodTo(entry, next);
      }
    }
  }

  function handleMessage(buf, rinfo) {
    let msg;
    try {
      msg = JSON.parse(buf.toString('utf8'));
    } catch {
      return; // 解析失败：静默丢弃（传输层尽力）
    }
    if (!msg || typeof msg !== 'object') return;
    if (msg.type === 'announce') handleAnnounce(msg, rinfo);
    else if (msg.type === 'flood') handleFlood(msg, rinfo);
  }

  function collectReasons(verdict) {
    const reasons = [];
    if (verdict.gates.identity.pass === false) {
      reasons.push(`identity: ${verdict.gates.identity.reason || 'signature verification failed'}`);
    }
    for (const r of (verdict.gates.laws.rules || [])) {
      if (!r.ok && r.severity === 'reject') reasons.push(`${r.id}: ${r.note}`);
    }
    if (verdict.gates.boundary.pass === false) {
      reasons.push(`boundary: ${verdict.gates.boundary.reason || 'boundary rejected'}`);
    }
    return reasons.join('; ');
  }

  // -------------------------------------------------------------------------
  // 内部：组播发现
  // -------------------------------------------------------------------------

  function startMulticast() {
    mcastSock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    mcastSock.on('message', handleMessage);
    mcastSock.on('error', () => {
      // 组播失败不阻断单播洪泛；ready 仍放行（发现降级，但不挂起）。
      resolveReady();
    });
    mcastSock.bind(mcast.port, () => {
      try {
        mcastSock.setMulticastLoopback(true);
        mcastSock.setMulticastTTL(1);
        if (mcastInterface) mcastSock.setMulticastInterface(mcastInterface);
        mcastSock.addMembership(mcast.addr, mcastInterface);
      } catch {
        try { mcastSock.addMembership(mcast.addr); } catch { /* 尽力 */ }
      }
      announce(); // 启动即首播，加速发现
      announceTimer = setInterval(announce, ANNOUNCE_INTERVAL_MS);
      resolveReady();
    });
  }

  // -------------------------------------------------------------------------
  // peer 对象
  // -------------------------------------------------------------------------

  const peer = {
    start() {
      if (started) return peer;
      started = true;

      unicast = dgram.createSocket('udp4');
      unicast.on('message', handleMessage);
      unicast.on('error', () => { /* 单播收发错误不抛，尽力传输 */ });
      unicast.bind(boundPort, host, () => {
        boundPort = unicast.address().port;
        if (discover) {
          startMulticast();
        } else {
          resolveReady();
        }
      });

      pruneTimer = setInterval(prune, PRUNE_INTERVAL_MS);
      return peer;
    },

    stop() {
      started = false;
      if (announceTimer) { clearInterval(announceTimer); announceTimer = null; }
      if (pruneTimer) { clearInterval(pruneTimer); pruneTimer = null; }
      if (mcastSock) { try { mcastSock.close(); } catch { /* 已关闭 */ } mcastSock = null; }
      if (unicast) { try { unicast.close(); } catch { /* 已关闭 */ } unicast = null; }
      return peer;
    },

    // 包装 { ttl, envelope } 单播洪泛给所有已知 peer（ttl 默认 8）。
    sendEnvelope(envelope, ttl = DEFAULT_TTL) {
      if (!envelope || !envelope.id) throw new Error('sendEnvelope: envelope.id is required');
      counters.sent += 1;
      // 源头登记 seen，防回环（自己发起的不再二次投递/转发）。
      seen.set(envelope.id, nowMs() + SEEN_EXPIRE_MS);
      const flood = { type: 'flood', ttl, srcNodeId: nodeId, envelope };
      for (const [peerNodeId, entry] of peers) {
        if (peerNodeId === nodeId) continue;
        sendFloodTo(entry, flood);
      }
      return flood;
    },

    // 组播洪泛（把同一包装发给组播组；本机回环下组内节点可收）。
    broadcast(envelope, ttl = DEFAULT_TTL) {
      if (!envelope || !envelope.id) throw new Error('broadcast: envelope.id is required');
      counters.sent += 1;
      seen.set(envelope.id, nowMs() + SEEN_EXPIRE_MS);
      const flood = { type: 'flood', ttl, srcNodeId: nodeId, envelope };
      if (mcastSock) {
        const msg = Buffer.from(JSON.stringify(flood), 'utf8');
        mcastSock.send(msg, mcast.port, mcast.addr, () => { /* 尽力发送 */ });
      }
      return flood;
    },

    // 去重 + 验签 + 三闸全过后的送达回调（cb(envelope, meta)）。
    onEnvelope(cb) {
      if (typeof cb === 'function') envelopeListeners.add(cb);
      return peer;
    },

    // 到达但被拒（身份绑定不一致 / 三闸不过）的回调（cb({ envelope, reason, rinfo })）。
    onReject(cb) {
      if (typeof cb === 'function') rejectListeners.add(cb);
      return peer;
    },

    // 手动注入/更新 peer（用于确定性拓扑：环状 P2-4 与链式 TTL 测试）。
    addPeer(info) {
      updatePeer(info);
      return peer;
    },

    // 当前 peer 表快照。
    peers() {
      prune();
      const snap = [];
      for (const [id, p] of peers) {
        snap.push({ nodeId: id, pubKey: p.pubKey, addr: p.addr, port: p.port, lastSeen: p.lastSeen });
      }
      return snap;
    },

    // 传输计数（供实验统计转发有界/去重/拦截）。
    stats() {
      return { ...counters };
    },

    // 绑定完成（含组播加入）后 resolve 的 Promise；测试 await ready 后即可交互。
    ready,

    get pubKey() { return pubKey; },
    get port() { return boundPort; },
    get nodeId() { return nodeId; },
  };

  return peer;
}
