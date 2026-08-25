// phase7/hole-punch.mjs —— 自研 UDP 打洞客户端（零依赖）
//
// 流程：
//   discover(stunHost, stunPort, localPort)：本地 UDP socket → STUN Binding Request → 解析 XOR-MAPPED-ADDRESS → { ip, port }
//   punch(localPort, peerMapping)：持续向对端公网映射发 UDP 心跳（含握手 token），同时监听回包 → 收到对端直连包 = 洞成
//   exchange 经中继（复用 phase4 relay：discover 结果互发）
//
// 导出：createHolePuncher({ localPort, stunHost, stunPort, nodeId, family })
//   family: 'udp4'（默认，含 STUN discover）| 'udp6'（IPv6 直连，无 STUN，discover 不可用）
//   -> { bind, discover, punchTo(peerMapping, durationMs) -> {directEstablished, received}, sendDirect(peerMapping, payload), onDirect(cb), close() }

import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { appendFingerprint, verifyFingerprint } from './stun-fingerprint.mjs';

const MAGIC = Buffer.from([0x21, 0x12, 0xa4, 0x42]);

function parseXorMappedAddress(attrs) {
  let off = 0;
  while (off + 4 <= attrs.length) {
    const type = attrs.readUInt16BE(off);
    const len = attrs.readUInt16BE(off + 2);
    if (off + 4 + len > attrs.length) break;
    if (type === 0x0020 && len >= 8) {
      const family = attrs.readUInt16BE(off + 4);
      const xorPort = attrs.readUInt16BE(off + 6);
      const port = xorPort ^ MAGIC.readUInt16BE(0);
      if (family === 0x01) {
        const ip = [0, 1, 2, 3].map((i) => attrs[off + 8 + i] ^ MAGIC[i]).join('.');
        return { ip, port };
      }
    }
    off += 4 + len + ((4 - (len % 4)) % 4);
  }
  return null;
}

export function createHolePuncher({ localPort, stunHost, stunPort, nodeId, family = 'udp4', myToken } = {}) {
  const isV6 = family === 'udp6';
  const socket = dgram.createSocket(isV6 ? 'udp6' : 'udp4');
  // S3 修复（生产级安全）：握手 token 认证。myToken 由调用方在打洞前经中继交换给对端；
  // 直连包必须携带「对端经中继发来的 token」（peerToken），缺失或不符一律丢弃——
  // 防「伪造 from 站点名即可劫持直连」的未认证握手漏洞。
  const ownToken = myToken || crypto.randomBytes(16).toString('hex');
  const state = { mapping: null, directPeer: null, actualPeer: null, directReceived: 0, lastDirectAt: 0, peerToken: null };
  const onDirectCbs = [];

  socket.on('message', (msg, rinfo) => {
    // 直连判定：payload 可解析、from 是对端、且 token 与中继交换来的 peerToken 一致
    // （对称 NAT 下映射端口会变，按内容判定而非端口）
    try {
      const j = JSON.parse(msg.toString());
      const from = j && j.from;
      const peer = state.directPeer && state.directPeer.from;
      const tokenOk = typeof j.token === 'string' && state.peerToken !== null && j.token === state.peerToken;
      if (j && (j.type === 'punch' || j.type === 'payload') && peer && from === peer && tokenOk) {
        state.directReceived += 1;
        state.lastDirectAt = Date.now();
        state.actualPeer = { ip: rinfo.address, port: rinfo.port };
        for (const cb of onDirectCbs) cb(msg, rinfo);
        // 打洞确认：立即回发 payload 到实际源（对称 NAT 的洞必须回「实际源」），带本方 token 供对端校验
        const ack = Buffer.from(JSON.stringify({ type: 'payload', from: state.directPeer.self, ack: true, token: ownToken }));
        socket.send(ack, rinfo.port, rinfo.address);
      }
    } catch {}
  });

  function bind() {
    return new Promise((resolve, reject) => {
      // udp6 必须 ipv6Only:true——Node 默认 dual-stack，绑 ::46001 会连带占 v4 同端口（EADDRINUSE 假冲突）
      const opts = isV6
        ? { port: localPort, address: '::', ipv6Only: true }
        : { port: localPort, address: '0.0.0.0' };
      socket.bind(opts, () => resolve(socket.address().port));
      socket.once('error', reject);
    });
  }

  async function discover() {
    if (isV6) throw new Error('discover 不适用于 udp6（IPv6 直连无需 STUN）');
    const txId = crypto.randomBytes(12);
    let req = Buffer.alloc(20);
    req.writeUInt16BE(0x0001, 0);
    req.writeUInt16BE(0, 2);
    MAGIC.copy(req, 4);
    txId.copy(req, 8);
    req = appendFingerprint(req); // S2：请求带 FINGERPRINT → 服务器给认证级限速桶（反射防护协同）
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('STUN discover timeout')), 5000);
      const handler = (msg) => {
        if (msg.length < 20 || msg.readUInt16BE(0) !== 0x0101) return;
        if (!msg.subarray(8, 20).equals(txId)) return;
        // S2：响应若带 FINGERPRINT 则必须校验通过（拒绝被篡改/伪造的响应）
        if (!verifyFingerprint(msg)) return;
        clearTimeout(timeout);
        socket.off('message', handler);
        const mapping = parseXorMappedAddress(msg.subarray(20));
        state.mapping = mapping;
        resolve(mapping);
      };
      socket.on('message', handler);
      socket.send(req, stunPort, stunHost);
    });
  }

  // 打洞：向对端映射发握手包（每 200ms），直到收到对端直连包或超时
  async function punchTo(peerMapping, durationMs = 15000) {
    state.directPeer = { ip: peerMapping.ip, port: peerMapping.port, from: peerMapping.from, self: nodeId };
    state.peerToken = peerMapping.token || null; // S3：对端 token 必须经中继交换获得，否则一切直连包被拒
    const payload = Buffer.from(JSON.stringify({ type: 'punch', from: nodeId, token: ownToken }));
    const t0 = Date.now();
    return new Promise((resolve) => {
      const iv = setInterval(() => { socket.send(payload, peerMapping.port, peerMapping.ip); }, 200);
      const check = setInterval(() => {
        if (state.directReceived > 0 || Date.now() - t0 > durationMs) {
          clearInterval(iv);
          clearInterval(check);
          resolve({ directEstablished: state.directReceived > 0, received: state.directReceived, elapsedMs: Date.now() - t0, actualPeer: state.actualPeer });
        }
      }, 250);
    });
  }

  function sendDirect(payload) {
    const target = state.actualPeer || (state.directPeer ? { ip: state.directPeer.ip, port: state.directPeer.port } : null);
    if (!target) return false;
    socket.send(payload, target.port, target.ip);
    return true;
  }
  function onDirect(cb) { onDirectCbs.push(cb); }
  function close() { try { socket.close(); } catch {} }
  function stats() {
    return { mapping: state.mapping, directPeer: state.directPeer, directReceived: state.directReceived, lastDirectAt: state.lastDirectAt };
  }

  return { bind, discover, punchTo, sendDirect, onDirect, close, stats };
}
