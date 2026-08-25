#!/usr/bin/env node
// ops/backup.mjs —— VAP 数据目录备份/恢复（零依赖：仅 node 内置模块 + 系统 tar）
//
// 备份（把 <dataDir> 打包成带日期戳的 tar.gz 到 <backupDir>，保留最近 <keep> 份并校验完整性）：
//   node ops/backup.mjs --dir /home/ubuntu/dsh-vap/vap-data [--out /var/backups/vap] [--keep 7]
//   或  node ops/backup.mjs /home/ubuntu/dsh-vap/vap-data
// 恢复（解包到 <targetDir>；目标已存在则拒绝，避免覆盖）：
//   node ops/backup.mjs --restore /var/backups/vap/vap-backup-20260825-123456.tar.gz /home/ubuntu/dsh-vap/vap-data
//
// 说明：
//   1) 打包/校验/解包复用系统 tar（服务器必装），脚本本身零 npm 依赖。
//   2) 数据目录通常含 ledger/ registry.json keys/（账本 / 注册表 / 私钥）；私钥已
//      PKCS8 + chmod 600 落盘，备份产物建议 chmod 600 并置于仅 root 可读目录。
//   3) 保留策略：按文件名（含时间戳）排序保留最新 <keep> 份，更旧的自动删除。
//   4) 需要可写 /var/backups/vap 与可读数据目录（root 或授权用户执行）。

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const DEFAULT_BACKUP_DIR = '/var/backups/vap';
const DEFAULT_KEEP = 7;

function fail(msg) {
  process.stderr.write(`✗ backup.mjs: ${msg}\n`);
  process.exit(1);
}

function usage(code) {
  process.stdout.write(
    '用法:\n' +
    '  备份: node ops/backup.mjs [--dir] <dataDir> [--out <backupDir>] [--keep <n>]\n' +
    '  恢复: node ops/backup.mjs --restore <tarfile> <targetDir>\n' +
    '选项:\n' +
    '  --dir <dir>        要备份的 VAP 数据目录（账本/registry/keys）\n' +
    '  --out <dir>        备份落盘目录（默认 /var/backups/vap）\n' +
    '  --keep <n>         保留最近份数（默认 7）\n' +
    '  --restore <f> <t>  从 <f> 恢复到 <t>（<t> 不存在才执行）\n' +
    '  --help, -h         打印本帮助并 exit 0\n'
  );
  process.exit(code);
}

function parseArgs(argv) {
  const a = { dir: null, out: DEFAULT_BACKUP_DIR, keep: DEFAULT_KEEP, restore: null, target: null };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    if (v === '--dir') { a.dir = argv[++i]; }
    else if (v === '--out') { a.out = argv[++i]; }
    else if (v === '--keep') { a.keep = Number(argv[++i]); }
    else if (v === '--restore') { a.restore = argv[++i]; a.target = argv[++i]; }
    else if (v === '--help' || v === '-h') { usage(0); }
    else if (v.startsWith('-')) { fail(`未知参数 '${v}'`); }
    else if (!a.dir && !a.restore) { a.dir = v; }
    else { fail(`多余参数 '${v}'`); }
  }
  if (a.restore) {
    if (!a.restore || !a.target) { usage(2); }
    return a;
  }
  if (!a.dir) { usage(2); }
  if (!Number.isInteger(a.keep) || a.keep < 1) { fail('--keep 必须是正整数'); }
  return a;
}

function timestamp() {
  const d = new Date();
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}` +
    `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function runTar(args) {
  // execFileSync 以数组传参（不做 shell 展开）→ 路径含空格/特殊字符也安全，且无命令注入。
  try {
    execFileSync('tar', args, { stdio: 'ignore' });
  } catch {
    fail(`tar ${args[0]} 失败（归档损坏或 tar 不可用）`);
  }
}

function doBackup(a) {
  const dataDir = path.resolve(a.dir);
  if (!fs.existsSync(dataDir) || !fs.statSync(dataDir).isDirectory()) {
    fail(`数据目录不存在或不是目录: ${dataDir}`);
  }
  fs.mkdirSync(a.out, { recursive: true });

  const name = `vap-backup-${timestamp()}.tar.gz`;
  const file = path.join(a.out, name);
  // 打包数据目录内容（用 -C 进到目录内打 "."，恢复时不带顶层目录名，落到任意 target 更直观）
  runTar(['-czf', file, '-C', dataDir, '.']);

  // 校验：列出归档内容，非零退出码即坏档
  runTar(['-tzf', file]);

  // 保留最近 <keep> 份（文件名含时间戳，字典序即时间序）
  const pattern = /^vap-backup-\d{8}-\d{6}\.tar\.gz$/;
  const kept = fs.readdirSync(a.out)
    .filter((f) => pattern.test(f))
    .sort()
    .reverse();
  for (const old of kept.slice(a.keep)) {
    fs.unlinkSync(path.join(a.out, old));
  }

  process.stdout.write(`✓ 已备份 ${dataDir} → ${file}（tar -tzf 校验通过，保留最近 ${a.keep} 份）\n`);
}

function doRestore(a) {
  const file = path.resolve(a.restore);
  if (!fs.existsSync(file)) { fail(`归档不存在: ${file}`); }
  const target = path.resolve(a.target);
  if (fs.existsSync(target)) { fail(`目标已存在，拒绝覆盖: ${target}`); }
  fs.mkdirSync(target, { recursive: true });
  runTar(['-xzf', file, '-C', target]);
  process.stdout.write(`✓ 已从 ${file} 恢复到 ${target}\n`);
}

const args = parseArgs(process.argv.slice(2));
if (args.restore) { doRestore(args); } else { doBackup(args); }
