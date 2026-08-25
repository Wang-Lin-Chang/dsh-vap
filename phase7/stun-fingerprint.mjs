// phase7/stun-fingerprint.mjs —— STUN FINGERPRINT (RFC 5389 §15.5) 共享实现（零依赖）
//
// FINGERPRINT 属性（0x8028，必须是消息最后一个属性）：
//   值 = CRC-32(IEEE 802.3，对「消息从头部到该属性之前的所有字节」) XOR 0x5354554e
//
// 用途（生产级安全 S2）：反射攻击防护——UDP 源地址可伪造，带 FINGERPRINT 的请求
// 意味着发送方完整构造了消息（非盲发伪造包），服务器据此给认证级限速桶；
// 客户端请求带上 FINGERPRINT，服务器响应回 FINGERPRINT，客户端可校验响应完整性。

const FINGERPRINT_TYPE = 0x8028;
const FINGERPRINT_XOR = 0x5354554e;

// CRC-32 (IEEE 802.3, poly 0xEDB88320) 表驱动
const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n += 1) {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
  CRC_TABLE[n] = c >>> 0;
}

export function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// 在消息头（20 字节固定头，第 2-3 字节为属性区长度）之后的属性区里定位 FINGERPRINT，
// 返回 { offset, value, coveredLength }：offset=属性在消息中的起始偏移（0 起），
// coveredLength=该属性之前的总字节数（校验覆盖范围），value=属性携带的 4 字节值。
export function findFingerprint(msg, headerLen = 20) {
  if (msg.length < headerLen + 8) return null;
  const attrLen = msg.readUInt16BE(2);
  const end = Math.min(msg.length, headerLen + attrLen);
  let off = headerLen;
  while (off + 4 <= end) {
    const type = msg.readUInt16BE(off);
    const len = msg.readUInt16BE(off + 2);
    const padded = 4 + len + ((4 - (len % 4)) % 4);
    if (off + padded > end + 4) return null; // 越界，视为损坏
    if (type === FINGERPRINT_TYPE) {
      if (len !== 4) return null;
      if (off + 8 > msg.length) return null;
      return { offset: off, value: msg.readUInt32BE(off + 4), coveredLength: off };
    }
    off += padded;
  }
  return null;
}

// 校验消息（若带 FINGERPRINT 则必须匹配；不带返回 true 仅当 requireFingerprint=false）
export function verifyFingerprint(msg, headerLen = 20, requireFingerprint = false) {
  const fp = findFingerprint(msg, headerLen);
  if (!fp) return !requireFingerprint;
  const expect = (crc32(msg.subarray(0, fp.coveredLength)) ^ FINGERPRINT_XOR) >>> 0;
  return expect === fp.value;
}

// 给已构造的消息（头部长度字段已正确）追加 FINGERPRINT 属性，返回新 Buffer
// 注意（RFC 5389 §15.5 经典坑）：CRC 覆盖「消息到该属性之前的所有字节」，
// 其中头部 length 字段必须已是「含 FINGERPRINT 本身」的总属性长度——
// 因此先写属性并更新 length，再对覆盖范围算 CRC。
export function appendFingerprint(msg) {
  const attrLen = msg.readUInt16BE(2);
  const out = Buffer.alloc(msg.length + 8);
  msg.copy(out, 0);
  out.writeUInt16BE(FINGERPRINT_TYPE, msg.length);
  out.writeUInt16BE(4, msg.length + 2);
  out.writeUInt16BE(attrLen + 8, 2); // 先更新头部长度字段，再算 CRC
  const value = (crc32(out.subarray(0, msg.length)) ^ FINGERPRINT_XOR) >>> 0;
  out.writeUInt32BE(value, msg.length + 4);
  return out;
}
