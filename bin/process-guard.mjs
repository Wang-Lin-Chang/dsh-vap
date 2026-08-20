// bin/process-guard.mjs —— 进程管理与参数解析公共助手（修复批次 2 · M10；精修批次统一参数）
//
// 四个 CLI（vap-relay / vap-gateway / vap-node / vap-send）共用：
//   - parseCliArgs(argv, spec[, t])：带选项声明的严格解析（未知参数不静默忽略）。
//   - renderHelp(spec[, t])：渲染用法（参数表 + 示例），打印到 stdout。
//   - cliArgs(spec[, argv[, t]])：一行接管 --help（exit 0）与参数错误（exit 2）。
//   - parseArgs(argv)：宽松解析（旧接口，保留兼容）。
//   - installProcessGuards({ logger, onStop })：SIGINT/SIGTERM 优雅退出 +
//     uncaughtException/unhandledRejection 兜底记日志退出码 1。
//
// 统一约定（精修批次验收项）：
//   --help / -h  → 用法打印到 stdout，退出码 0；
//   未知参数     → 错误 + 用法提示打印到 stderr，退出码 2；
//   缺值 / 非数字 → 同样退出码 2（绝不静默忽略而挂住进程）；
//   文案风格     → 成功 `✓`，失败 `✗`，附属信息缩进两格。
//
// 乱码消弭（enc-brief）：所有含中文的用户可见文案经 t() 从双语字典取值（见
// console-adapter.mjs 的 DICT）；t 缺省为 zh（非 TTY 字节透传，测试/重定向保持 UTF-8）。
//
// 零第三方依赖，仅 node: 内置模块。

import { createT, DICT } from '../console-adapter.mjs';

const zhT = createT(DICT, 'zh');

// spec 形状：
//   {
//     name:    'vap-gateway',                    // 程序名（错误前缀）
//     entry:   'bin/vap-gateway.mjs',            // 帮助里的入口路径
//     summary: 'VAP HTTP 网关（HTTP gateway）',   // 一句话说明
//     options: [{ flag: 'port', value: '<n>', type: 'number', desc: '监听端口' }],
//     examples: ['node bin/vap-gateway.mjs --port 3081'],
//     notes:    ['环境变量 VAP_* 亦可覆盖配置'],
//   }
// option.type：'string'（默认，需取值）/ 'number'（需取值且必须是有限数）/ 'boolean'（开关）。

function helpOption(t) {
  return { flag: 'help', alias: 'h', type: 'boolean', desc: t('pg.helpOptionDesc') };
}

function optionList(spec, t = zhT) {
  const declared = Array.isArray(spec && spec.options) ? spec.options : [];
  const hasHelp = declared.some((opt) => opt.flag === 'help');
  return hasHelp ? declared : [...declared, helpOption(t)];
}

function optionIndex(spec, t = zhT) {
  const index = new Map();
  for (const opt of optionList(spec, t)) {
    index.set(opt.flag, opt);
    if (opt.alias) index.set(opt.alias, opt);
  }
  return index;
}

// parseCliArgs(argv, spec[, t]) → { help, error, values }
//   help  = true 表示请求用法（调用方 exit 0）；
//   error = 非空字符串表示参数不合法（调用方打印后 exit 2）；
//   values = { [flag]: string|number|true }（已按 type 转换）。
export function parseCliArgs(argv, spec, t = zhT) {
  const index = optionIndex(spec, t);
  const values = {};
  const tokens = Array.isArray(argv) ? argv : [];

  for (let i = 0; i < tokens.length; i++) {
    const token = String(tokens[i]);
    if (token === '--') continue;
    if (!token.startsWith('-')) {
      return { help: false, error: t('pg.errUnexpectedArg', { token }), values };
    }
    const isLong = token.startsWith('--');
    const body = isLong ? token.slice(2) : token.slice(1);
    const eq = body.indexOf('=');
    const key = eq === -1 ? body : body.slice(0, eq);
    const inlineValue = eq === -1 ? undefined : body.slice(eq + 1);
    const opt = index.get(key);
    if (!opt) {
      return { help: false, error: t('pg.errUnknownOption', { token }), values };
    }
    if (opt.flag === 'help') return { help: true, error: null, values };
    if (opt.type === 'boolean') {
      if (inlineValue !== undefined) {
        return { help: false, error: t('pg.errBooleanValue', { flag: opt.flag, value: inlineValue }), values };
      }
      values[opt.flag] = true;
      continue;
    }
    let raw = inlineValue;
    if (raw === undefined) {
      const next = tokens[i + 1];
      if (next === undefined || String(next).startsWith('--')) {
        return { help: false, error: t('pg.errRequiresValue', { flag: opt.flag, value: opt.value || '<value>' }), values };
      }
      raw = String(next);
      i += 1;
    }
    if (opt.type === 'number') {
      const num = Number(raw);
      if (!Number.isFinite(num)) {
        return { help: false, error: `option '--${opt.flag}' expects a number, got '${raw}'`, values };
      }
      values[opt.flag] = num;
      continue;
    }
    values[opt.flag] = raw;
  }

  return { help: false, error: null, values };
}

// renderHelp(spec[, t]) → 用法文本（末尾带换行，供 stdout 直接写出）。
export function renderHelp(spec, t = zhT) {
  const name = (spec && spec.name) || 'vap';
  const entry = (spec && spec.entry) || `bin/${name}.mjs`;
  const lines = [];
  lines.push(spec && spec.summary ? `${name} — ${spec.summary}` : name);
  lines.push('');
  lines.push(t('pg.usage'));
  lines.push(`  node ${entry} ${t('pg.arg')}`);
  lines.push('');
  lines.push(t('pg.options'));
  const rows = optionList(spec, t).map((opt) => {
    const head = opt.alias ? `-${opt.alias}, --${opt.flag}` : `--${opt.flag}`;
    return [opt.value ? `${head} ${opt.value}` : head, opt.desc || ''];
  });
  const width = rows.reduce((max, [head]) => Math.max(max, head.length), 0);
  for (const [head, desc] of rows) lines.push(`  ${head.padEnd(width)}  ${desc}`);
  const examples = Array.isArray(spec && spec.examples) ? spec.examples : [];
  if (examples.length > 0) {
    lines.push('');
    lines.push(t('pg.examples'));
    for (const example of examples) lines.push(`  ${example}`);
  }
  const notes = Array.isArray(spec && spec.notes) ? spec.notes : [];
  if (notes.length > 0) {
    lines.push('');
    lines.push(t('pg.notes'));
    for (const note of notes) lines.push(`  - ${note}`);
  }
  lines.push('');
  return lines.join('\n');
}

// cliArgs(spec[, argv[, t]])：解析并接管两种终局——
//   --help  → 用法到 stdout，exit 0；
//   参数错误 → `✗ <name>: <error>` + 用法提示到 stderr，exit 2。
// 其余情况返回 values 供调用方使用。
export function cliArgs(spec, argv = process.argv.slice(2), t = zhT) {
  const parsed = parseCliArgs(argv, spec, t);
  const name = (spec && spec.name) || 'vap';
  const entry = (spec && spec.entry) || `bin/${name}.mjs`;
  if (parsed.help) {
    process.stdout.write(renderHelp(spec, t));
    process.exit(0);
  }
  if (parsed.error) {
    process.stderr.write(`${t('pg.failLine', { name, error: parsed.error })}\n`);
    process.stderr.write(`${t('pg.hintUsage', { entry })}\n`);
    process.exit(2);
  }
  return parsed.values;
}

// 展示用主机名：通配监听地址映射成可直接拨号的回环地址。
export function dialHost(host) {
  if (host === '0.0.0.0' || host === '::' || host === '' || host == null) return '127.0.0.1';
  return host;
}

// 旧接口（宽松解析）：保留兼容，不做未知参数校验。新代码请用 parseCliArgs/cliArgs。
export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      args[key] = next;
      i += 1;
    } else {
      args[key] = true;
    }
  }
  return args;
}

// 安装信号与异常兜底。onStop 为 async 清理函数（顺序 stop/close）。
// 返回 shutdown(code)：主动退出（信号路径内部调用；测试无需直接使用）。
//
// 跨平台说明：POSIX 下 SIGINT/SIGTERM 由内核投递、处理器运行、exit 0；
// Windows 下 child.kill('SIGTERM') 是硬杀（不触发 JS 处理器），故额外监听 stdin 的
// `shutdown` 一行作为等价优雅退出通道（测试/运维在 Windows 上写 `shutdown\n` 触发 exit 0）。
//
// 内部日志为纯 ASCII（任何码页安全），不进入双语字典。
export function installProcessGuards({ logger, onStop }) {
  let stopping = false;

  async function shutdown(code) {
    if (stopping) return;
    stopping = true;
    try {
      await onStop();
    } catch (err) {
      logger.error(`shutdown cleanup failed: ${String((err && err.message) || err)}`);
    }
    process.exit(code);
  }

  process.on('SIGINT', () => {
    logger.info('received SIGINT, shutting down gracefully');
    shutdown(0);
  });
  process.on('SIGTERM', () => {
    logger.info('received SIGTERM, shutting down gracefully');
    shutdown(0);
  });

  // stdin `shutdown` 一行 → 优雅退出（Windows 等价通道）。
  if (process.stdin && typeof process.stdin.on === 'function') {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      buf += chunk;
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (line.trim() === 'shutdown') {
          logger.info('received shutdown via stdin, shutting down gracefully');
          shutdown(0);
        }
      }
    });
  }

  process.on('uncaughtException', (err) => {
    logger.error(`uncaughtException: ${String((err && err.stack) || err)}`);
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    logger.error(`unhandledRejection: ${String((reason && reason.stack) || reason)}`);
    process.exit(1);
  });

  return { shutdown };
}
