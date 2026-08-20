// key-store.mjs —— 私钥持久化（修复批次 2 · F3）
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

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export function safeNodeId(nodeId) {
  return crypto.createHash('sha256').update(String(nodeId), 'utf8').digest('hex');
}

export function keyDir(root) {
  return path.join(root, 'keys');
}

function keyFilePath(root, nodeId) {
  return path.join(keyDir(root), `${safeNodeId(nodeId)}.key`);
}

// saveKey(root, nodeId, privateKey)：把私钥写成 PKCS8 PEM，落盘后 chmod 0o600。
// privateKey 可为 KeyObject / PKCS8 DER Buffer / base64 / PEM 字符串。
export function saveKey(root, nodeId, privateKey) {
  if (!root) throw new Error('saveKey: root is required');
  if (nodeId == null) throw new Error('saveKey: nodeId is required');
  const key = coercePrivateKey(privateKey);
  const pem = key.export({ type: 'pkcs8', format: 'pem' }).toString('utf8');
  const file = keyFilePath(root, nodeId);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // 原子写（tmp + rename）后收紧权限；Windows 上 chmod 是 no-op，注释标注。
  const tmp = `${file}.tmp-${crypto.randomBytes(6).toString('hex')}`;
  fs.writeFileSync(tmp, pem, 'utf8');
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

// loadKey(root, nodeId)：读文件重建 KeyObject；无文件返回 null。
export function loadKey(root, nodeId) {
  if (!root || nodeId == null) return null;
  const file = keyFilePath(root, nodeId);
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return null; // 无文件（或不可读）→ null，调用方按「首次启动」处理
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
