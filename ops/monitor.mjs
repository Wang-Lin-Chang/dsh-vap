// ops/monitor.mjs —— VAP 生产监控（零依赖，node 内置模块）
//
// 检查项（R2 生产级加固）：
//   1) systemd 三服务 active（vap-relay / vap-stun / vap-files）
//   2) 磁盘使用率 < 90%（df -P /）
//   3) relay TCP 42050 可达
//   4) STUN UDP 3478 响应 Binding Request
//   5) 内存使用率 < 95%（/proc/meminfo）
//
// 输出：单行 JSON 到 stdout + 追加 /var/log/vap-monitor.log；
//       任一检查失败 → exit 1（供 systemd timer / OnFailure 联动），
//       并写最近失败详情到 /var/run/vap-monitor-failed.json。
//
// 用法：node ops/monitor.mjs（root 或可写 /var/log 的用户）

import net from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';

const checks = [];
const log = (r) => checks.push(r);

// 1) systemd 服务状态
for (const svc of ['vap-relay', 'vap-stun', 'vap-files']) {
  try {
    const out = execFileSync('systemctl', ['is-active', svc], { encoding: 'utf8' }).trim();
    log({ check: `service:${svc}`, ok: out === 'active', detail: out });
  } catch {
    log({ check: `service:${svc}`, ok: false, detail: 'inactive-or-error' });
  }
}

// 2) 磁盘
try {
  const out = execFileSync('df', ['-P', '/'], { encoding: 'utf8' });
  const pct = Number(out.trim().split('\n')[1].trim().split(/\s+/)[4].replace('%', ''));
  log({ check: 'disk', ok: pct < 90, detail: `${pct}%` });
} catch (e) {
  log({ check: 'disk', ok: false, detail: String(e) });
}

// 3) 内存（/proc/meminfo）
try {
  const mem = fs.readFileSync('/proc/meminfo', 'utf8');
  const total = Number(/MemTotal:\s+(\d+)/.exec(mem)[1]);
  const avail = Number(/MemAvailable:\s+(\d+)/.exec(mem)[1]);
  const pct = Math.round(((total - avail) / total) * 100);
  log({ check: 'memory', ok: pct < 95, detail: `${pct}%` });
} catch (e) {
  log({ check: 'memory', ok: false, detail: String(e) });
}

// 4) relay TCP 42050
const tcpOk = await new Promise((resolve) => {
  const sock = net.createConnection({ host: '127.0.0.1', port: 42050, timeout: 3000 });
  sock.on('connect', () => { sock.destroy(); resolve(true); });
  sock.on('error', () => resolve(false));
  sock.on('timeout', () => { sock.destroy(); resolve(false); });
});
log({ check: 'tcp:relay:42050', ok: tcpOk, detail: tcpOk ? 'connected' : 'refused/timeout' });

// 5) STUN UDP 3478（RFC 5389 Binding Request，20 字节裸请求）
const stunOk = await new Promise((resolve) => {
  const sock = dgram.createSocket('udp4');
  const req = Buffer.alloc(20);
  req.writeUInt16BE(0x0001, 0);
  req.writeUInt16BE(0, 2);
  Buffer.from([0x21, 0x12, 0xa4, 0x42]).copy(req, 4);
  const to = setTimeout(() => { sock.close(); resolve(false); }, 3000);
  sock.on('message', (m) => {
    clearTimeout(to);
    sock.close();
    resolve(m.length >= 20 && m.readUInt16BE(0) === 0x0101);
  });
  sock.send(req, 3478, '127.0.0.1');
});
log({ check: 'udp:stun:3478', ok: stunOk, detail: stunOk ? 'binding-response' : 'no-response' });

// 汇总输出
const ts = new Date().toISOString();
const allOk = checks.every((c) => c.ok);
const line = JSON.stringify({ ts, ok: allOk, checks });
process.stdout.write(`${line}\n`);
try {
  fs.appendFileSync('/var/log/vap-monitor.log', `${line}\n`);
} catch { /* 无权限写日志时不影响退出码判定 */ }
try {
  if (!allOk) {
    fs.writeFileSync('/var/run/vap-monitor-failed.json', `${line}\n`);
  } else if (fs.existsSync('/var/run/vap-monitor-failed.json')) {
    fs.unlinkSync('/var/run/vap-monitor-failed.json'); // 恢复后清除失败标记
  }
} catch { /* 状态文件尽力而为 */ }
process.exit(allOk ? 0 : 1);
