// key-store.mjs —— 私钥持久化（修复批次 2 · F3 + 生产级加固 S10）
//
// 把节点私钥以 PKCS8 PEM 落盘到 root/keys/<safeNodeId>.key，并在启动时按需加载，
// 解决「私钥完全不落盘，重启换身份信任断链」的 fatal 问题。
//
// 零第三方依赖，仅 node: 内置模块。
//
// 安全说明：
//   - safeNodeId = sha256hex(nodeId)：文件名只取 nodeId 的 sha256 摘要（16 进制小写），
//     任何 nodeId（含 '/'、'\'、'..'、超长）都进不了路径 —— 杜绝路径穿越（呼应 M6）。
//   - 落盘后 fs.chmodSync(path, 0o600)：仅属主可读写。Windows 上 chmod 是 no-op
//     （文件系统不区分属主位），此处调用保留以覆盖 POSIX，失败不抛（尽力而为）。
//   - S10：可选口令加密（saveKey/loadKey 传 passphrase）。提供口令时用
//     scrypt(passphrase, salt, 32) 派生密钥 + AES-256-GCM 加密，落盘不再是明文；
//     不提供口令保持旧明文行为（兼容），但生产部署应当总是提供
//     （从环境变量读取，如 process.env.VAP_KEY_PASSPHRASE）。

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const ENC_HEADER = '-----BEGIN VAP ENCRYPTED KEY-----';
const ENC_FOOTER = '-----END VAP ENCRYPTED KEY-----';
const ENC_VERSION = 'v1';
const SCRYPT_N = 1 << 15; // 成本参数：内存 ~32MB/次，本机验证过 ~50ms 量级
const SCRYPT_MAXMEM = 64 * 1024 * 1024; // Node 默认 scrypt maxmem=32MB，须显式放宽

export function safeNodeId(nodeId) {
  return crypto.createHash('sha256').update(String(nodeId), 'utf8').digest('hex');
}

export function keyDir(root) {
  return path.join(root, 'keys');
}

function keyFilePath(root, nodeId) {
  return path.join(keyDir(root), `${safeNodeId(nodeId)}.key`);
}

// S10：口令加密（AES-256-GCM）。scrypt 派生 32B 密钥；salt/iv/tag 均随机。
export function encryptPrivateKey(pemText, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('encryptPrivateKey: passphrase is required');
  }
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32, { N: SCRYPT_N, maxmem: SCRYPT_MAXMEM });
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(pemText, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload = [
    ENC_VERSION,
    salt.toString('base64'),
    iv.toString('base64'),
    tag.toString('base64'),
    enc.toString('base64'),
  ].join(':');
  return `${ENC_HEADER}\n${payload}\n${ENC_FOOTER}\n`;
}

export function decryptPrivateKey(blob, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('decryptPrivateKey: passphrase is required');
  }
  const body = String(blob).trim();
  if (!body.startsWith(ENC_HEADER)) return null; // 非加密格式：调用方按明文处理
  const inner = body.slice(ENC_HEADER.length, body.length - ENC_FOOTER.length).trim();
  const parts = inner.split(':');
  if (parts.length !== 5 || parts[0] !== ENC_VERSION) {
    throw new Error('decryptPrivateKey: unsupported encrypted key format');
  }
  const [, saltB64, ivB64, tagB64, encB64] = parts;
  const key = crypto.scryptSync(passphrase, Buffer.from(saltB64, 'base64'), 32, { N: SCRYPT_N, maxmem: SCRYPT_MAXMEM });
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const out = Buffer.concat([decipher.update(Buffer.from(encB64, 'base64')), decipher.final()]);
  return out.toString('utf8'); // 错误口令 → GCM tag 校验失败抛错
}

// saveKey(root, nodeId, privateKey, passphrase)：把私钥写成 PKCS8 PEM，落盘后 chmod 0o600。
// privateKey 可为 KeyObject / PKCS8 DER Buffer / base64 / PEM 字符串。
// S10：passphrase 提供时用 AES-256-GCM 加密落盘（生产推荐，口令经环境变量传入）。
export function saveKey(root, nodeId, privateKey, passphrase = null) {
  if (!root) throw new Error('saveKey: root is required');
  if (nodeId == null) throw new Error('saveKey: nodeId is required');
  const key = coercePrivateKey(privateKey);
  const pem = key.export({ type: 'pkcs8', format: 'pem' }).toString('utf8');
  const blob = passphrase ? encryptPrivateKey(pem, passphrase) : pem;
  const file = keyFilePath(root, nodeId);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // 原子写（tmp + rename）后收紧权限；Windows 上 chmod 是 no-op，注释标注。
  const tmp = `${file}.tmp-${crypto.randomBytes(6).toString('hex')}`;
  fs.writeFileSync(tmp, blob, 'utf8');
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    if (err && (err.code === 'EEXIST' || err.code === 'EPERM' || err.code === 'ENOTEMPTY')) {
      try { fs.unlinkSync(file); } catch { /* 目标本就不存在 */ }
      fs.renameSync(tmp, file);
    } else {
      try { fs.unlinkSync(tmp); } catch { /* 尽力清理 */ }
      throw err;
    }
  }
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // 某些平台不支持 chmod（含 Windows 语义 no-op）：忽略，不影响可用性。
  }
  return file;
}

// loadKey(root, nodeId, passphrase)：读文件重建 KeyObject；无文件返回 null。
// S10：文件为加密格式时用 passphrase 解密；错误口令抛错（不返回 null——那是「没读到」，
// 口令错是「读到了但解不开」，调用方必须知道区别）。
export function loadKey(root, nodeId, passphrase = null) {
  if (!root || nodeId == null) return null;
  const file = keyFilePath(root, nodeId);
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return null; // 无文件（或不可读）→ null，调用方按「首次启动」处理
  }
  if (text.includes(ENC_HEADER)) {
    const pem = decryptPrivateKey(text, passphrase); // 口令缺失/错误 → 抛错
    return crypto.createPrivateKey(pem);
  }
  try {
    return crypto.createPrivateKey(text);
  } catch {
    return null; // 内容损坏 → null，调用方重新生成
  }
}

function coercePrivateKey(key) {
  if (key && typeof key === 'object' && typeof key.export === 'function') {
    return key; // 已是 KeyObject
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return crypto.createPrivateKey({ key: Buffer.from(key), format: 'der', type: 'pkcs8' });
  }
  if (typeof key === 'string') {
    const text = key.trim();
    if (text.startsWith('-----BEGIN')) return crypto.createPrivateKey(text);
    return crypto.createPrivateKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'pkcs8' });
  }
  throw new Error('saveKey: unsupported private key value');
}
