// console-adapter.mjs —— 控制台乱码消弭适配器（零第三方依赖，仅 node: 内置模块）
//
// 目标：Windows 老控制台（GBK cp936）下的中文乱码由程序自动消弭，用户零操作。
//
// 三路裁决（见 enc-brief.md）：
//   1. 非 TTY（stdout 重定向/管道）：字节透传，文件天然 UTF-8——跳过一切检测，直接 UTF-8 输出；
//   2. TTY 检测：execFileSync 直调 C:\Windows\System32\chcp.com（独立 exe，不经 cmd 派发），
//      解析输出行尾 ASCII 数字（忽略可能本地化/乱码的标签文本）得当前码页 cp；
//   3. 裁决规则（优先级）：
//      - VAP_LANG=zh|en 显式设置 → 直接胜出（逃生舱）；
//      - cp===65001 → 中文（UTF-8 直出）；
//      - cp∈{936,54936}（中文码页）→ 执行 chcp 65001（静默自愈切 UTF-8）→ 中文输出；
//      - 其余（437/850 等非 CJK）→ 英文（纯 ASCII，任何码页安全）。
//
// createT(dict, lang) → t(key)：双语包装器，缺 key 抛错，防字典漂移。
//
// 所有用户可见文案收敛为 key → { zh, en }（见文末 DICT），禁止内联裸中文字面量。

import path from 'node:path';
import { execFileSync } from 'node:child_process';

// ---------------------------------------------------------------------------
// 解析：从 chcp.com 输出里取「行尾 ASCII 数字」。
//   "Active code page: 936"      → 936
//   "活动代码页: 65001"          → 65001
//   乱码标签 + 数字（如 GBK 字节被当 UTF-8 解出的乱码）→ 数字
// 解析不到 / 非有限数 → null。
// ---------------------------------------------------------------------------
export function parseCodePage(output) {
  const text = String(output == null ? '' : output);
  const match = text.match(/(\d+)\s*$/m);
  if (!match) return null;
  const n = Number(match[1]);
  return Number.isFinite(n) ? n : null;
}

// ---------------------------------------------------------------------------
// detectConsoleLang({ isTTY, platform, env, execChcp }) —— 纯函数，依赖可注入。
//   isTTY     = process.stdout.isTTY 的布尔值；
//   platform  = process.platform 的字符串；
//   env       = 环境变量对象（读 VAP_LANG）；
//   execChcp  = 返回 chcp.com stdout 字符串的函数（测试 mock）。
// 返回 { lang: 'zh'|'en', reason }。reason 为 'chcp-936' / 'chcp-54936' 时，
// 表示「需要自愈」：adaptConsole 会补执行 chcp 65001。
// ---------------------------------------------------------------------------
export function detectConsoleLang({ isTTY, platform, env, execChcp } = {}) {
  const e = env || {};
  if (e.VAP_LANG === 'zh' || e.VAP_LANG === 'en') {
    return { lang: e.VAP_LANG, reason: `VAP_LANG=${e.VAP_LANG}` };
  }
  if (!isTTY) return { lang: 'zh', reason: 'non-tty' };
  if (platform !== 'win32') return { lang: 'zh', reason: 'non-win32' };

  let cp = null;
  if (typeof execChcp === 'function') {
    try {
      cp = parseCodePage(execChcp());
    } catch {
      cp = null;
    }
  }
  if (cp === null) return { lang: 'en', reason: 'chcp-failed' };
  if (cp === 65001) return { lang: 'zh', reason: 'utf8' };
  if (cp === 936 || cp === 54936) return { lang: 'zh', reason: `chcp-${cp}` };
  return { lang: 'en', reason: `chcp-${cp}` };
}

// chcp.com 的绝对路径：优先 SystemRoot，缺省 C:\Windows。
function chcpPath() {
  const root = process.env.SystemRoot || 'C:\\Windows';
  return path.join(root, 'System32', 'chcp.com');
}

// ---------------------------------------------------------------------------
// adaptConsole() —— 生产入口。
//   isTTY 前置短路；win32 才跑 chcp；解析/分类/自愈（936/54936 时 chcp 65001，
//   失败吞掉降英文）。
// 返回 { lang, reason }，供调用方 createT(DICT, lang)。
// ---------------------------------------------------------------------------
export function adaptConsole() {
  const isTTY = Boolean(process.stdout && process.stdout.isTTY);
  const result = detectConsoleLang({
    isTTY,
    platform: process.platform,
    env: process.env,
    execChcp: () => execFileSync(chcpPath(), { encoding: 'utf8' }),
  });
  if (result.lang === 'zh' && (result.reason === 'chcp-936' || result.reason === 'chcp-54936')) {
    try {
      execFileSync(chcpPath(), ['65001'], { stdio: 'ignore' });
    } catch {
      return { lang: 'en', reason: 'chcp-self-heal-failed' };
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// createT(dict, lang) → t(key[, vars])：双语取值包装器。
//   - 缺 key 抛错（防字典漂移）；
//   - 缺当前 lang 的值也抛错（强制 zh/en 对等）；
//   - vars 可选：把模板里的 {name} 占位替换为 String(vars[name])。
// ---------------------------------------------------------------------------
export function createT(dict, lang = 'zh') {
  return function t(key, vars) {
    const entry = dict == null ? undefined : dict[key];
    if (!entry || typeof entry !== 'object') {
      throw new Error(`missing i18n key: ${key}`);
    }
    const raw = entry[lang];
    if (raw === undefined || raw === null) {
      throw new Error(`missing i18n value: ${key}.${lang}`);
    }
    let s = String(raw);
    if (vars && typeof vars === 'object') {
      for (const [k, v] of Object.entries(vars)) {
        s = s.split(`{${k}}`).join(String(v));
      }
    }
    return s;
  };
}

// ---------------------------------------------------------------------------
// 双语字典（唯一的「字典定义文件」）。键 → { zh, en }；zh/en 必须对等且非空。
// 命名空间：pg.*（process-guard 共用）、gw.* / relay.* / node.* / send.*（四个 bin）。
// ---------------------------------------------------------------------------
export const DICT = Object.freeze({
  // ---- process-guard 共用 ----
  'pg.usage': { zh: '用法 / Usage', en: 'Usage' },
  'pg.options': { zh: '参数 / Options', en: 'Options' },
  'pg.examples': { zh: '示例 / Examples', en: 'Examples' },
  'pg.notes': { zh: '说明 / Notes', en: 'Notes' },
  'pg.arg': { zh: '[参数]', en: '[options]' },
  'pg.helpOptionDesc': { zh: '打印本用法后退出（exit 0）', en: 'Print this usage and exit (exit 0)' },
  'pg.errUnexpectedArg': { zh: "unexpected argument '{token}'（本命令只接受 --参数 形式）", en: "unexpected argument '{token}' (this command accepts only --option form)" },
  'pg.errUnknownOption': { zh: "unknown option '{token}'（未知参数）", en: "unknown option '{token}' (unknown option)" },
  'pg.errBooleanValue': { zh: "option '--{flag}' 是开关，不接受取值 '{value}'", en: "option '--{flag}' is a switch and takes no value '{value}'" },
  'pg.errRequiresValue': { zh: "option '--{flag}' requires a value（缺少取值 {value}）", en: "option '--{flag}' requires a value (missing {value})" },
  'pg.failLine': { zh: '✗ {name}: {error}', en: '{name}: {error}' },
  'pg.hintUsage': { zh: '  提示：node {entry} --help 查看完整用法', en: '  hint: node {entry} --help for full usage' },
  'pg.markPass': { zh: '✓', en: 'OK' },
  'pg.markFail': { zh: '✗', en: 'FAIL' },

  // ---- vap-gateway ----
  'gw.summary': { zh: 'VAP HTTP 网关：收发信封的 HTTP 入口（POST/GET /envelopes + /health）', en: 'VAP HTTP gateway: HTTP entry for sending/receiving envelopes (POST/GET /envelopes + /health)' },
  'gw.opt.host': { zh: '监听地址（默认 127.0.0.1；跨机部署用 0.0.0.0）', en: 'listen address (default 127.0.0.1; use 0.0.0.0 for remote deployment)' },
  'gw.opt.port': { zh: '监听端口（默认 0 = 由系统随机分配）', en: 'listen port (default 0 = system-assigned)' },
  'gw.opt.root': { zh: '数据目录（默认 <tmpdir>/vap-gateway-data）', en: 'data directory (default <tmpdir>/vap-gateway-data)' },
  'gw.opt.config': { zh: 'JSON 配置文件路径（见 config.mjs）', en: 'JSON config file path (see config.mjs)' },
  'gw.opt.logFile': { zh: '日志文件（默认只输出到控制台）', en: 'log file (default: console only)' },
  'gw.opt.logLevel': { zh: '日志级别 debug|info|warn|error|silent（默认 info）', en: 'log level debug|info|warn|error|silent (default info)' },
  'gw.note.env': { zh: '环境变量 VAP_GATEWAY_HOST / VAP_GATEWAY_PORT / VAP_LOG_FILE / VAP_LOG_LEVEL 亦可覆盖。', en: 'env vars VAP_GATEWAY_HOST / VAP_GATEWAY_PORT / VAP_LOG_FILE / VAP_LOG_LEVEL also override.' },
  'gw.note.stop': { zh: '停止：Ctrl+C（Windows 也可向 stdin 写一行 shutdown）。', en: 'stop: Ctrl+C (on Windows you can also write a "shutdown" line to stdin).' },
  'gw.note.send': { zh: '发信封：node bin/vap-send.mjs --help', en: 'send an envelope: node bin/vap-send.mjs --help' },
  'gw.listening': { zh: '✓ vap-gateway listening http={host}:{port}', en: 'vap-gateway listening http={host}:{port}' },
  'gw.envelopesHint': { zh: '  envelopes : POST {base}/envelopes （GET 同址拉取未投递信封）', en: '  envelopes : POST {base}/envelopes (GET pulls undelivered envelopes)' },
  'gw.seeReadme': { zh: '              详见 README §Quick start / 快速开始', en: '              see README section "Quick start"' },
  'gw.startFailed': { zh: '✗ vap-gateway 启动失败：{msg}', en: 'vap-gateway start failed: {msg}' },

  // ---- vap-relay ----
  'relay.summary': { zh: 'VAP 中继：TCP 注册 + 跨 NAT 转发，旁路 HTTP /health', en: 'VAP relay: TCP registration + cross-NAT forwarding, sidecar HTTP /health' },
  'relay.opt.host': { zh: 'TCP 监听地址（默认 127.0.0.1；跨机部署用 0.0.0.0）', en: 'TCP listen address (default 127.0.0.1; use 0.0.0.0 for remote deployment)' },
  'relay.opt.port': { zh: 'TCP 监听端口（默认 0 = 由系统随机分配）', en: 'TCP listen port (default 0 = system-assigned)' },
  'relay.opt.healthPort': { zh: '旁路 HTTP /health 端口（默认 0 = 随机，仅回环）', en: 'sidecar HTTP /health port (default 0 = random, loopback only)' },
  'relay.opt.config': { zh: 'JSON 配置文件路径（见 config.mjs）', en: 'JSON config file path (see config.mjs)' },
  'relay.opt.logFile': { zh: '日志文件（默认只输出到控制台）', en: 'log file (default: console only)' },
  'relay.opt.logLevel': { zh: '日志级别 debug|info|warn|error|silent（默认 info）', en: 'log level debug|info|warn|error|silent (default info)' },
  'relay.note.env': { zh: '环境变量 VAP_RELAY_HOST / VAP_RELAY_PORT / VAP_LOG_FILE / VAP_LOG_LEVEL 亦可覆盖。', en: 'env vars VAP_RELAY_HOST / VAP_RELAY_PORT / VAP_LOG_FILE / VAP_LOG_LEVEL also override.' },
  'relay.note.stop': { zh: '停止：Ctrl+C（Windows 也可向 stdin 写一行 shutdown）。', en: 'stop: Ctrl+C (on Windows you can also write a "shutdown" line to stdin).' },
  'relay.note.design': { zh: '中继与 NAT 穿透设计见 phase4/DESIGN.md。', en: 'relay and NAT-punching design: see phase4/DESIGN.md.' },
  'relay.listening': { zh: '✓ vap-relay listening tcp={host}:{port}{health}', en: 'vap-relay listening tcp={host}:{port}{health}' },
  'relay.nextHint': { zh: '  next   : 节点以 TCP 连到 {host}:{port} 注册后即可经中继互发信封', en: '  next   : nodes register over TCP to {host}:{port} and then exchange envelopes via the relay' },
  'relay.designHint': { zh: '           跨 NAT 部署与协议细节见 phase4/DESIGN.md；本机试跑先用 vap-gateway + vap-send', en: '           cross-NAT deployment and protocol details: phase4/DESIGN.md; for a local trial use vap-gateway + vap-send' },
  'relay.startFailed': { zh: '✗ vap-relay 启动失败：{msg}', en: 'vap-relay start failed: {msg}' },

  // ---- vap-node ----
  'node.summary': { zh: 'VAP 共识节点：锁步 QC 链 + 动态成员，旁路 HTTP /health', en: 'VAP consensus node: lockstep QC chain + dynamic membership, sidecar HTTP /health' },
  'node.opt.nodeId': { zh: '节点标识（默认 vap-node-1；决定持久私钥文件）', en: 'node id (default vap-node-1; determines the persistent key file)' },
  'node.opt.host': { zh: '/health 监听地址（默认 127.0.0.1）', en: '/health listen address (default 127.0.0.1)' },
  'node.opt.port': { zh: '/health 监听端口（默认 0 = 随机；等价 --health-port）', en: '/health listen port (default 0 = random; same as --health-port)' },
  'node.opt.healthPort': { zh: '同 --port（兼容旧脚本写法）', en: 'same as --port (legacy scripts)' },
  'node.opt.ledgerDir': { zh: '账本与私钥目录（默认 <tmpdir>/vap-ledger）', en: 'ledger and key directory (default <tmpdir>/vap-ledger)' },
  'node.opt.config': { zh: 'JSON 配置文件路径（见 config.mjs）', en: 'JSON config file path (see config.mjs)' },
  'node.opt.logFile': { zh: '日志文件（默认只输出到控制台）', en: 'log file (default: console only)' },
  'node.opt.logLevel': { zh: '日志级别 debug|info|warn|error|silent（默认 info）', en: 'log level debug|info|warn|error|silent (default info)' },
  'node.note.env': { zh: '环境变量 VAP_LEDGER_DIR / VAP_LOG_FILE / VAP_LOG_LEVEL 亦可覆盖。', en: 'env vars VAP_LEDGER_DIR / VAP_LOG_FILE / VAP_LOG_LEVEL also override.' },
  'node.note.roster': { zh: '单进程启动即单节点 roster（n=1, f=0）；多节点组网见 phase6/DESIGN.md。', en: 'starting one process gives a single-node roster (n=1, f=0); multi-node networking: phase6/DESIGN.md.' },
  'node.note.stop': { zh: '停止：Ctrl+C（Windows 也可向 stdin 写一行 shutdown）。', en: 'stop: Ctrl+C (on Windows you can also write a "shutdown" line to stdin).' },
  'node.listening': { zh: '✓ vap-node listening id={id} height={height}{health}', en: 'vap-node listening id={id} height={height}{health}' },
  'node.nextCurl': { zh: '  next   : 查看节点状态 → curl http://{host}:{port}/health', en: '  next   : check node status -> curl http://{host}:{port}/health' },
  'node.nextGateway': { zh: '           发信封走网关：node bin/vap-gateway.mjs --port 3081 + node bin/vap-send.mjs --help', en: '           to send envelopes use the gateway: node bin/vap-gateway.mjs --port 3081 + node bin/vap-send.mjs --help' },
  'node.startFailed': { zh: '✗ vap-node 启动失败：{msg}', en: 'vap-node start failed: {msg}' },

  // ---- vap-send ----
  'send.summary': { zh: '发一封可验证信封到 VAP 网关，并把裁决结果讲成人话', en: 'send a verifiable envelope to the VAP gateway and explain the verdict in plain words' },
  'send.opt.to': { zh: '收件节点（默认 brain）', en: 'recipient node (default brain)' },
  'send.opt.summary': { zh: '战报正文，≤ {bound} 字（不带 --from-file 时必填）', en: 'report body, <= {bound} chars (required without --from-file)' },
  'send.opt.gateway': { zh: '网关地址（默认 {url}）', en: 'gateway URL (default {url})' },
  'send.opt.from': { zh: '发件节点标识（默认 vap-sender；决定持久私钥）', en: 'sender node id (default vap-sender; determines the persistent key)' },
  'send.opt.claimType': { zh: '声明类型（默认 report）', en: 'claim type (default report)' },
  'send.opt.boundary': { zh: '诚实边界（默认：有 evidence.devices 则 L2a，否则 L0）', en: 'honesty boundary (default: L2a with evidence.devices, else L0)' },
  'send.opt.evidence': { zh: "证据 JSON，例 '{\"devices\":[\"E01\"]}'", en: "evidence JSON, e.g. '{\"devices\":[\"E01\"]}'" },
  'send.opt.request': { zh: '战报里的请求字段（默认空）', en: 'request field in the report (default empty)' },
  'send.opt.key': { zh: 'PKCS8 PEM 私钥文件（默认用 --root 下的持久钥）', en: 'PKCS8 PEM private key file (default: persistent key under --root)' },
  'send.opt.root': { zh: '本地工作目录：私钥与 outbox（默认 <tmpdir>/vap-send-data）', en: 'local working directory: key and outbox (default <tmpdir>/vap-send-data)' },
  'send.opt.fromFile': { zh: '直接发这个信封 JSON 文件（不再构造，供脚本/重放试验）', en: 'send this envelope JSON file directly (no construction; for scripts/replay)' },
  'send.opt.timeout': { zh: '投递超时毫秒（默认 10000）', en: 'delivery timeout ms (default 10000)' },
  'send.opt.dryRun': { zh: '只构造并打印信封 JSON，不投递', en: 'only construct and print the envelope JSON, do not deliver' },
  'send.example.inspect': { zh: 'node bin/vap-send.mjs --to brain --summary "巡检完成" --boundary L2a --evidence \'{"devices":["E01"]}\' --gateway {url}', en: 'node bin/vap-send.mjs --to brain --summary "inspection done" --boundary L2a --evidence \'{"devices":["E01"]}\' --gateway {url}' },
  'send.example.key': { zh: 'node bin/vap-send.mjs --to brain --summary "带自己的钥" --key ./my-node.key', en: 'node bin/vap-send.mjs --to brain --summary "with my own key" --key ./my-node.key' },
  'send.example.dryRun': { zh: 'node bin/vap-send.mjs --to brain --summary "只看信封长啥样" --dry-run', en: 'node bin/vap-send.mjs --to brain --summary "see the envelope" --dry-run' },
  'send.note.gateway': { zh: '先起网关：node bin/vap-gateway.mjs --port 3081（另开一个终端）。', en: 'start the gateway first: node bin/vap-gateway.mjs --port 3081 (in another terminal).' },
  'send.note.exitCodes': { zh: '退出码：0 已投递；1 被拒或连不上网关；2 参数用法错。', en: 'exit codes: 0 delivered; 1 rejected or gateway unreachable; 2 usage error.' },
  'send.note.verify': { zh: '网关只放行签名有效的信封；军法与诚实边界由下游裁决，本命令会先做一次本地预检。', en: 'the gateway only accepts validly signed envelopes; laws and honesty boundary are judged downstream, this command runs a local precheck first.' },
  'send.badGatewayUrl': { zh: "--gateway '{url}' 不是合法 URL（形如 http://127.0.0.1:3081）", en: "--gateway '{url}' is not a valid URL (e.g. http://127.0.0.1:3081)" },
  'send.gatewayHttpOnly': { zh: "--gateway 目前只支持 http://（收到 '{proto}'）", en: "--gateway currently supports only http:// (got '{proto}')" },
  'send.gatewayNoPath': { zh: "--gateway 只写到端口即可，不要带路径 '{path}'（例 {url}）", en: "--gateway takes only a port, not a path '{path}' (e.g. {url})" },
  'send.badTimeout': { zh: "--timeout 必须是正数毫秒（收到 '{value}'）", en: "--timeout must be a positive number of ms (got '{value}')" },
  'send.keyReadFail': { zh: "--key 读不到私钥文件 '{file}'：{err}", en: "--key cannot read key file '{file}': {err}" },
  'send.keyInvalid': { zh: "--key '{file}' 不是合法 PKCS8 PEM 私钥：{err}", en: "--key '{file}' is not a valid PKCS8 PEM private key: {err}" },
  'send.fileReadFail': { zh: "--from-file 读不到 '{file}'：{err}", en: "--from-file cannot read '{file}': {err}" },
  'send.fileBadJson': { zh: "--from-file '{file}' 不是合法 JSON：{err}", en: "--from-file '{file}' is not valid JSON: {err}" },
  'send.fileNotObject': { zh: "--from-file '{file}' 必须是一个信封 JSON 对象", en: "--from-file '{file}' must be an envelope JSON object" },
  'send.fileMissingId': { zh: "--from-file '{file}' 缺少 envelope.id", en: "--from-file '{file}' is missing envelope.id" },
  'send.evidenceBadJson': { zh: "--evidence 不是合法 JSON（{err}）；例：--evidence '{\"devices\":[\"E01\"]}'", en: "--evidence is not valid JSON ({err}); e.g. --evidence '{\"devices\":[\"E01\"]}'" },
  'send.evidenceNotObject': { zh: "--evidence 必须是 JSON 对象；例：--evidence '{\"devices\":[\"E01\"]}'", en: "--evidence must be a JSON object; e.g. --evidence '{\"devices\":[\"E01\"]}'" },
  'send.missingSummary': { zh: '缺少 --summary "<战报>"（或用 --from-file <json> 直接发已有信封）', en: 'missing --summary "<report>" (or use --from-file <json> to send an existing envelope)' },
  'send.summaryTooLong': { zh: '--summary 有 {count} 字，超过验证门上限 {bound} 字（军法 SUMMARY_BOUND 会 reject），请精简', en: '--summary has {count} chars, over the verification limit of {bound} (law SUMMARY_BOUND will reject); please shorten' },
  'send.boundaryNoteL2a': { zh: '（有 evidence.devices {count} 项，可声明 L2a）', en: '(evidence.devices has {count} items, can claim L2a)' },
  'send.boundaryNoteL0': { zh: "（未给 --evidence，按诚实边界降级；加 --evidence '{\"devices\":[\"E01\"]}' 才能声明 L2a）", en: "(no --evidence, downgraded by honesty boundary; add --evidence '{\"devices\":[\"E01\"]}' to claim L2a)" },
  'send.badBoundary': { zh: "--boundary 只能是 {list}（收到 '{value}'）", en: "--boundary must be one of {list} (got '{value}')" },
  'send.l2aNeedsEvidence': { zh: "--boundary L2a 需要非空 evidence.devices（诚实边界闸会 reject）；要么加 --evidence '{\"devices\":[\"E01\"]}'，要么改用 --boundary L0", en: "--boundary L2a needs a non-empty evidence.devices (honesty boundary gate will reject); add --evidence '{\"devices\":[\"E01\"]}' or use --boundary L0" },
  'send.prepareIdentityFail': { zh: '✗ 准备身份失败：{err}', en: 'failed to prepare identity: {err}' },
  'send.whyIdentity': { zh: '  为什么 : 无法在 {root} 下读写私钥/目录。', en: '  why: cannot read/write the key/directory under {root}.' },
  'send.fixIdentity': { zh: '  怎么办 : 换一个可写目录 --root <dir>，或检查该目录权限。', en: '  fix: use a writable directory --root <dir>, or check the directory permissions.' },
  'send.timeoutError': { zh: '投递超时（{ms}ms）', en: 'delivery timeout ({ms}ms)' },
  'send.status400.title': { zh: '格式错', en: 'malformed' },
  'send.status400.why': { zh: '信封字段不合规：缺 nonce、nonce 不是 16 位小写十六进制、envelope.id 不是 evt-<16 位十六进制>，或请求体不是合法 JSON。', en: 'envelope fields are invalid: missing nonce, nonce not 16 lowercase hex chars, envelope.id not evt-<16 hex chars>, or the body is not valid JSON.' },
  'send.status400.fix': { zh: '不带 --from-file 让 vap-send 自己构造即可保证格式；若用 --from-file，请检查该 JSON 的 id / nonce 字段。', en: 'without --from-file, vap-send builds a valid envelope; with --from-file, check the id / nonce fields.' },
  'send.status403.title': { zh: '签名无效', en: 'bad signature' },
  'send.status403.why': { zh: 'Ed25519 验签失败：sig 与 from.pubKey 不是同一身份，或信封签名后被改动过（改任何字段都会破签）。', en: 'Ed25519 verification failed: sig and from.pubKey are not the same identity, or the envelope was edited after signing (any field change breaks the signature).' },
  'send.status403.fix': { zh: '确认 --key 与信封 from.pubKey 属同一私钥；--from-file 的信封不要手工改字段，重新构造一封。', en: 'make sure --key and the envelope from.pubKey belong to the same private key; do not hand-edit a --from-file envelope, rebuild one.' },
  'send.status409.title': { zh: '重放拦截', en: 'replay blocked' },
  'send.status409.why': { zh: '这个 nonce 网关已经记过账：同一封信封不允许投第二次（防重放，spec §4）。', en: 'this nonce was already recorded by the gateway: the same envelope cannot be delivered twice (replay protection, spec section 4).' },
  'send.status409.fix': { zh: '重新构造一封新信封（不带 --from-file 时每次都会生成新 nonce），不要重复投同一个 JSON 文件。', en: 'rebuild a fresh envelope (without --from-file a new nonce is generated each time); do not resend the same JSON file.' },
  'send.status413.title': { zh: '信封过大', en: 'envelope too large' },
  'send.status413.why': { zh: '请求体超过网关 1MB 上限。', en: 'the request body exceeds the gateway 1MB limit.' },
  'send.status413.fix': { zh: '别把大块内容塞进信封，改放 evidence.digest 摘要。', en: 'do not stuff large content into the envelope; put a digest in evidence.digest instead.' },
  'send.status404.title': { zh: '地址不对', en: 'wrong address' },
  'send.status404.why': { zh: '--gateway 指的不是 VAP 网关的根地址（或该端口上是别的服务）。', en: '--gateway does not point at the VAP gateway root (or another service is on that port).' },
  'send.status404.fix': { zh: '只写到端口，例 --gateway {url}（不要带 /envelopes 路径）。', en: 'only write the port, e.g. --gateway {url} (no /envelopes path).' },
  'send.status500.title': { zh: '网关内部错', en: 'gateway internal error' },
  'send.status500.why': { zh: '网关落盘失败（目录不可写 / 磁盘满）。', en: 'the gateway failed to persist (directory not writable / disk full).' },
  'send.status500.fix': { zh: '看网关那一侧的日志与它的 --root 目录权限。', en: 'check the gateway logs and its --root directory permissions.' },
  'send.netRefused.title': { zh: '连不上网关', en: 'gateway unreachable' },
  'send.netRefused.why': { zh: '目标端口没有服务在监听（网关没起，或端口写错了）。', en: 'nothing is listening on the target port (the gateway is down, or the port is wrong).' },
  'send.netRefused.fix': { zh: '另开一个终端先起网关：node bin/vap-gateway.mjs --port {port}', en: 'start the gateway in another terminal first: node bin/vap-gateway.mjs --port {port}' },
  'send.netNotFound.title': { zh: '连不上网关', en: 'gateway unreachable' },
  'send.netNotFound.why': { zh: "主机名 '{host}' 解析不到。", en: "hostname '{host}' cannot be resolved." },
  'send.netNotFound.fix': { zh: '检查 --gateway 里的主机名，本机试跑直接用 127.0.0.1。', en: 'check the hostname in --gateway; for a local trial use 127.0.0.1.' },
  'send.netTimeout.title': { zh: '投递超时', en: 'delivery timeout' },
  'send.netTimeout.why': { zh: '网关在超时时间内没有回应（网络不通或对端卡住）。', en: 'the gateway did not respond within the timeout (network down or peer stuck).' },
  'send.netTimeout.fix': { zh: '确认网关在跑、地址可达；必要时加大 --timeout。', en: 'confirm the gateway is running and reachable; increase --timeout if needed.' },
  'send.netReset.title': { zh: '连接被重置', en: 'connection reset' },
  'send.netReset.why': { zh: '连接建立后被对端断开（对端可能不是 VAP 网关，或中途退出）。', en: 'the peer dropped the connection after it was established (it may not be a VAP gateway, or it exited).' },
  'send.netReset.fix': { zh: '确认 --gateway 指向 vap-gateway，并查看网关日志。', en: 'confirm --gateway points at vap-gateway, and check the gateway logs.' },
  'send.netUnknown.title': { zh: '投递失败', en: 'delivery failed' },
  'send.netUnknown.fix': { zh: '确认网关地址可达；node bin/vap-gateway.mjs --help 查看如何起网关。', en: 'confirm the gateway address is reachable; node bin/vap-gateway.mjs --help shows how to start it.' },
  'send.unknownStatus.title': { zh: '网关拒收', en: 'gateway rejected' },
  'send.unknownStatus.why': { zh: '网关返回了未预期的状态码 {code}。', en: 'the gateway returned an unexpected status code {code}.' },
  'send.unknownStatus.fix': { zh: '看网关日志确认原因；node bin/vap-send.mjs --help 查看用法。', en: 'check the gateway logs for the cause; node bin/vap-send.mjs --help shows usage.' },
  'send.gateIdentity': { zh: '身份 {mark}', en: 'identity {mark}' },
  'send.gateLaws': { zh: '军法 {mark}', en: 'laws {mark}' },
  'send.gateBoundary': { zh: '诚实边界 {mark}', en: 'boundary {mark}' },
  'send.verdictLine': { zh: '{verdict}（{marks}）', en: '{verdict} ({marks})' },
  'send.localGatesLine': { zh: '  本地三闸 : {line}', en: '  local gates : {line}' },
  'send.dryRunDone': { zh: '✓ 已构造信封 envelopeId={id}（--dry-run 未投递）', en: 'envelope constructed envelopeId={id} (--dry-run, not delivered)' },
  'send.savedTo': { zh: '  已落盘   : {path}', en: '  saved to  : {path}' },
  'send.dryRunNext': { zh: '  next     : 去掉 --dry-run 即投递到 {url}', en: '  next     : remove --dry-run to deliver to {url}' },
  'send.delivered': { zh: '✓ 已投递 envelopeId={id} 网关已接收（HTTP 202 Accepted）', en: 'delivered envelopeId={id} (HTTP 202 Accepted)' },
  'send.verdictHint': { zh: '  裁决     : 网关验签通过并落盘 inbox-http/（军法与诚实边界由下游裁决）', en: '  verdict   : gateway verified the signature and stored it under inbox-http/ (laws and honesty boundary are judged downstream)' },
  'send.deliveredNext': { zh: '  next     : 看网关计数 → curl {url}/health   （envelopesIn 会 +1）', en: '  next     : check gateway counter -> curl {url}/health   (envelopesIn will +1)' },
  'send.localPrecheckFail': { zh: '  注意     : 本地预检未过——网关收下了，但下游裁决会拒：', en: '  note     : local precheck failed -- gateway accepted it, but downstream will reject:' },
  'send.rejectedLine': { zh: '✗ 拒绝: {title}（网关返回 HTTP {code} {reason}）', en: 'rejected: {title} (HTTP {code} {reason})' },
  'send.whyLabel': { zh: '  为什么 : {text}', en: '  why: {text}' },
  'send.fixLabel': { zh: '  怎么办 : {text}', en: '  fix: {text}' },
  'send.networkFailLine': { zh: '✗ {title}: {url}（{code}）', en: '{title}: {url} ({code})' },
  'send.envelopeSavedNote': { zh: '  envelope : {id}（已构造好，可稍后 --from-file 重发）', en: '  envelope : {id} (constructed; you can resend later with --from-file)' },
  'send.unexpectedFail': { zh: '✗ vap-send 意外失败：{err}', en: 'vap-send unexpected failure: {err}' },
});
