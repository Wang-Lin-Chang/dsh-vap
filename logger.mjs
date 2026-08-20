// logger.mjs —— 结构化日志（修复批次 2 · M9）
//
// createLogger({ file, level, component }) → { info, warn, error }
//   - 每行一条 JSON line：{ ts, level, component, msg }（extra 字段展开合并）。
//   - file 轮转：单文件超过 1MB 时，把当前文件改名为 `<file>.1`（只保留 .1，再超重写）。
//   - 无 file：输出到 console（info/warn → console.log，error → console.error）。
//   - level 阈值：debug < info < warn < error < silent；低于阈值的记录直接丢弃。
//
// 零第三方依赖，仅 node: 内置模块。

import fs from 'node:fs';
import path from 'node:path';

export const LOG_LEVELS = ['debug', 'info', 'warn', 'error', 'silent'];
export const DEFAULT_MAX_LOG_BYTES = 1024 * 1024; // 1MB

const RANK = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };

function normalizeLevel(level) {
  if (typeof level === 'string' && RANK[level] !== undefined) return level;
  if (typeof level === 'number') {
    const names = ['debug', 'info', 'warn', 'error'];
    const i = Math.max(0, Math.min(names.length - 1, Math.floor(level)));
    return names[i];
  }
  return 'info';
}

export function createLogger({ file, level = 'info', component = 'vap', maxBytes = DEFAULT_MAX_LOG_BYTES } = {}) {
  const lvl = normalizeLevel(level);
  const threshold = RANK[lvl];

  function enabled(entryLevel) {
    return RANK[entryLevel] >= threshold;
  }

  function lineFor(entryLevel, msg, extra) {
    const rec = { ts: new Date().toISOString(), level: entryLevel, component, msg: String(msg) };
    if (extra && typeof extra === 'object') Object.assign(rec, extra);
    return rec;
  }

  // 轮转：当前文件超过 1MB → 改名为 .1（覆盖旧 .1，只保留一代）。
  function maybeRotate(filePath, incomingLen) {
    let size = 0;
    try {
      size = fs.statSync(filePath).size;
    } catch { /* 不存在视为 0 */ }
    if (size + incomingLen <= maxBytes) return;
    try {
      fs.renameSync(filePath, `${filePath}.1`);
    } catch {
      try { fs.unlinkSync(`${filePath}.1`); } catch { /* 尽力 */ }
      try { fs.renameSync(filePath, `${filePath}.1`); } catch { /* 尽力 */ }
    }
  }

  function write(entryLevel, msg, extra) {
    if (!enabled(entryLevel)) return;
    const rec = lineFor(entryLevel, msg, extra);
    const line = `${JSON.stringify(rec)}\n`;
    if (file) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      maybeRotate(file, Buffer.byteLength(line));
      fs.appendFileSync(file, line, 'utf8');
    } else if (entryLevel === 'error') {
      // 无文件：error 级必显（stderr）；info/warn 静默（避免测试/守护输出刷屏）。
      console.error(line.trimEnd());
    } else if (lvl === 'debug') {
      // 仅在显式 debug 时把 info/warn 打到 stdout，便于本地排障。
      console.log(line.trimEnd());
    }
  }

  return {
    info: (msg, extra) => write('info', msg, extra),
    warn: (msg, extra) => write('warn', msg, extra),
    error: (msg, extra) => write('error', msg, extra),
    debug: (msg, extra) => write('debug', msg, extra),
    get level() {
      return lvl;
    },
    get file() {
      return file || null;
    },
  };
}

// silentLogger()：完全静默的 logger（无 file 时 console 也被抑制）。
export function silentLogger() {
  return createLogger({ level: 'silent' });
}
