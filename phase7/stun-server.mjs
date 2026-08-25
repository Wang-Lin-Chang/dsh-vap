// phase7/stun-server.mjs —— 自研 STUN 服务器（RFC 5389 最小集，零依赖）
//
// 支持：Binding Request（0x0001）→ Binding Success Response（0x0101）
//      含 XOR-MAPPED-ADDRESS（0x0020，客户端公网映射 IP:port）、SOFTWARE、FINGERPRINT。
// 用法：node phase7/stun-server.mjs [port=3478] [bindHost=0.0.0.0]
//
// 生产级安全（S2）：
//   - 反射攻击防护：按源 IP 令牌桶限速。带 FINGERPRINT 的请求（发送方完整构造了消息）
//     享受认证桶（高容量），裸请求（可能源地址伪造的盲发包）走严格桶。
//   - 响应带 FINGERPRINT（RFC 5389 §15.5），客户端可校验响应完整性。
//   - 日志聚合：不再每请求打一行 stdout（可被伪造洪泛刷爆 journald），只做周期统计。

import dgram from 'node:dgram';
import { findFingerprint, verifyFingerprint, appendFingerprint } from './stun-fingerprint.mjs';

const PORT = Number(process.argv[2] || 3478);
const HOST = process.argv[3] || '0.0.0.0';
const MAGIC = Buffer.from([0x21, 0x12, 0xa4, 0x42]); // STUN magic cookie

// 限速桶（per 源 IP）：{ tokens, last, authed }
// 认证桶（请求带合法 FINGERPRINT）：容量 32、速率 10/s——合法客户端打洞流程远够用；
// 诚实边界（复验轮）：FINGERPRINT 不是认证（CRC-32 可自算），伪造源也能拿认证桶，
// 故认证桶容量从 64 收紧到 32，把伪造源的放大窗口压在 ~1.5KB/源。
// 裸请求桶：容量 16、速率 2/s——容忍少量丢包重试，同时把伪造源的反射输出压到每秒几十字节
const BUCKET_AUTHED = { cap: 32, rate: 10 };
const BUCKET_BARE = { cap: 16, rate: 2 };
const rateLimits = new Map();
let rejected = 0;

function allow(ip, authed) {
  const cfg = authed ? BUCKET_AUTHED : BUCKET_BARE;
  const now = Date.now();
  let e = rateLimits.get(ip);
  if (!e) {
    e = { tokens: cfg.cap, last: now };
    rateLimits.set(ip, e);
  }
  e.tokens = Math.min(cfg.cap, e.tokens + ((now - e.last) / 1000) * cfg.rate);
  e.last = now;
  if (e.tokens < 1) return false;
  e.tokens -= 1;
  return true;
}

function xorPort(port, magic) {
  return port ^ magic.readUInt16BE(0);
}
function encodeXorMappedAddress(ip, port, magic) {
  // 属性：type 0x0020, length 8, family 0x01, xor-port, xor-ip
  const buf = Buffer.alloc(12);
  buf.writeUInt16BE(0x0020, 0);
  buf.writeUInt16BE(8, 2);
  buf[4] = 0; buf[5] = 0x01;
  buf.writeUInt16BE(xorPort(port, magic), 6);
  const parts = ip.split('.').map(Number);
  for (let i = 0; i < 4; i += 1) buf[8 + i] = parts[i] ^ magic[i];
  return buf;
}
function encodeSoftware(name) {
  const len = Buffer.byteLength(name);
  const padded = (len + 3) & ~3;
  const buf = Buffer.alloc(4 + padded);
  buf.writeUInt16BE(0x8022, 0);
  buf.writeUInt16BE(len, 2);
  buf.write(name, 4);
  return buf;
}

const server = dgram.createSocket('udp4');
let requests = 0;
server.on('message', (msg, rinfo) => {
  // 20 字节头：type(2) len(2) magic(4) txid(12)
  if (msg.length < 20) return;
  const type = msg.readUInt16BE(0);
  const magic = msg.subarray(4, 8);
  if (!magic.equals(MAGIC)) return; // 非 STUN
  if (type !== 0x0001) return;      // 仅 Binding Request

  // FINGERPRINT：合法则认证桶，裸请求严格桶（反射防护核心）
  const hasFp = findFingerprint(msg) !== null;
  const fpValid = hasFp && verifyFingerprint(msg);
  if (hasFp && !fpValid) return;    // 带指纹但校验失败：丢弃
  if (!allow(rinfo.address, fpValid)) {
    rejected += 1;
    return;                          // 超限：静默丢弃（不放大、不刷日志）
  }

  const txId = msg.subarray(8, 20);
  requests += 1;
  const attrs = Buffer.concat([
    encodeXorMappedAddress(rinfo.address, rinfo.port, MAGIC, txId),
    encodeSoftware('vap-stun/1.0'),
  ]);
  let resp = Buffer.alloc(20 + attrs.length);
  resp.writeUInt16BE(0x0101, 0);          // Binding Success
  resp.writeUInt16BE(attrs.length, 2);
  MAGIC.copy(resp, 4);
  txId.copy(resp, 8);
  attrs.copy(resp, 20);
  if (fpValid) resp = appendFingerprint(resp); // 请求带合法指纹 → 响应回指纹
  server.send(resp, rinfo.port, rinfo.address);
});
server.bind(PORT, HOST, () => {
  process.stdout.write(`STUN-UP host=${HOST} port=${server.address().port}\n`);
});
setInterval(() => {
  process.stdout.write(`STUN-STATS requests=${requests} rejected=${rejected} buckets=${rateLimits.size}\n`);
  // 清理 5 分钟无活动的桶，防 Map 无限增长（伪造源 IP 洪泛场景）
  const now = Date.now();
  for (const [ip, e] of rateLimits) if (now - e.last > 300000) rateLimits.delete(ip);
}, 60000).unref();
