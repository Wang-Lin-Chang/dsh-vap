// tests/cli.test.mjs —— CLI 体验回归测试（精修批次 · 用户验收）
//
// 运行：在 dsh-vap/ 下 `node --test`（或 `node --test tests/cli.test.mjs`）
// 覆盖（对照 polish-brief.md 验收）：
//   ① 四个 CLI（vap-relay / vap-gateway / vap-node / vap-send）--help → exit 0 且打印用法（stdout）
//   ② 未知参数 / 缺值 / 非数字 → exit 2 且报错走 stderr（绝不静默忽略挂住）
//   ③ 启动输出含「下一步」提示（vap-gateway 首行仍是 listening 就绪信号）
//   ④ vap-send 端到端：真信封 202 人话输出、伪签名 403、缺 nonce 400、重放 409、
//      网关未启动 ECONNREFUSED 友好报错，退出码分别为 0 / 1
//   ⑤ parseCliArgs 单元行为：--flag=value、数字转换、布尔开关、位置参数拒收
//
// 零第三方依赖：仅 node: 内置模块 + 本仓库相对 import。

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';

import { createVapNode } from '../vap-core.mjs';
import { createHttpGateway } from '../vap-transport.mjs';
import { parseCliArgs, renderHelp, dialHost } from '../bin/process-guard.mjs';

const BIN_DIR = path.join(process.cwd(), 'bin');
const CLIS = ['vap-relay.mjs', 'vap-gateway.mjs', 'vap-node.mjs', 'vap-send.mjs'];

// ---------------------------------------------------------------------------
// 装置助手
// ---------------------------------------------------------------------------

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// 跑一个 CLI 到退出，收集 stdout/stderr/退出码（默认 20s 上限，超时按失败处理）。
function runCli(bin, args = [], timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(BIN_DIR, bin), ...args], {
      cwd: process.cwd(),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`${bin} ${args.join(' ')} 未在 ${timeoutMs}ms 内退出（stdout=${stdout} stderr=${stderr}）`));
    }, timeoutMs);
    child.once('exit', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// 启动常驻 bin，等 stdout 出现 listening（就绪信号），返回句柄与优雅停止函数。
function startBin(bin, args = [], timeoutMs = 10000) {
  const child = spawn(process.execPath, [path.join(BIN_DIR, bin), ...args], {
    cwd: process.cwd(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (c) => { stdout += c.toString(); });
  child.stderr.on('data', (c) => { stderr += c.toString(); });
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${bin} 未在 ${timeoutMs}ms 内就绪（stdout=${stdout} stderr=${stderr}）`)), timeoutMs);
    const check = () => {
      if (stdout.includes('listening')) { clearTimeout(timer); resolve(); }
    };
    child.stdout.on('data', check);
    child.once('exit', () => { clearTimeout(timer); });
  });
  // 就绪信号（首行 listening）之后还有若干提示行：等 stdout 静默 quietMs 再断言，
  // 免得只读到第一个 chunk 就误判「没有下一步提示」。
  async function readyAndSettled(quietMs = 250, maxMs = 4000) {
    await ready;
    const deadline = Date.now() + maxMs;
    let seen = -1;
    while (stdout.length !== seen && Date.now() < deadline) {
      seen = stdout.length;
      await new Promise((r) => setTimeout(r, quietMs));
    }
    return stdout;
  }
  const exited = new Promise((resolve) => child.once('exit', (code) => resolve(code)));
  async function stop() {
    if (child.exitCode === null) {
      // Windows 上 SIGTERM 是硬杀，统一走 bin 的 stdin `shutdown` 优雅通道。
      try { child.stdin.write('shutdown\n'); child.stdin.end(); } catch { /* 已退出 */ }
      await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
      if (child.exitCode === null) child.kill();
    }
    return exited;
  }
  return { child, stdout: () => stdout, stderr: () => stderr, ready, readyAndSettled, exited, stop };
}

// 找一个当前空闲的回环端口（用于「网关没起」用例：确保没人监听）。
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function withGateway(run) {
  const root = tmpDir('vap-cli-gw-');
  const gateway = createHttpGateway({ root, port: 0, host: '127.0.0.1' });
  const port = await gateway.start();
  try {
    return await run({ gateway, port, root, baseUrl: `http://127.0.0.1:${port}` });
  } finally {
    await gateway.stop();
  }
}

// 造一封真信封（签名有效）并写成 JSON 文件，供 --from-file 用例复用。
function writeEnvelopeFile(dir, mutate) {
  const nodeRoot = path.join(dir, 'sender');
  const node = createVapNode({ nodeId: 'cli-test-sender', root: nodeRoot });
  const envelope = node.send({
    to: 'brain',
    claim: { type: 'report', body: {} },
    evidence: { devices: ['E01'], bills: {}, digest: '' },
    boundary: 'L2a',
    report: { summary: 'cli test envelope', keyNumbers: [], request: '' },
  });
  const finalEnvelope = typeof mutate === 'function' ? mutate({ ...envelope }) : envelope;
  const file = path.join(dir, `${finalEnvelope.id || 'envelope'}-${Math.random().toString(16).slice(2, 8)}.json`);
  fs.writeFileSync(file, `${JSON.stringify(finalEnvelope, null, 2)}\n`, 'utf8');
  return { file, envelope: finalEnvelope };
}

// ---------------------------------------------------------------------------
// ① --help：exit 0 + 用法到 stdout
// ---------------------------------------------------------------------------

for (const bin of CLIS) {
  test(`CLI ${bin} --help 打印用法并 exit 0`, async () => {
    const res = await runCli(bin, ['--help']);
    assert.equal(res.code, 0, `--help must exit 0 (got ${res.code}; stderr=${res.stderr})`);
    assert.equal(res.stderr, '', '帮助不许写 stderr');
    assert.match(res.stdout, /用法 \/ Usage/, '含用法段');
    assert.match(res.stdout, /参数 \/ Options/, '含参数表');
    assert.match(res.stdout, /示例 \/ Examples/, '含示例');
    assert.match(res.stdout, /--help/, '参数表列出 --help');
    assert.match(res.stdout, new RegExp(bin.replace('.mjs', '')), '含程序名');
  });

  test(`CLI ${bin} -h 与 --help 等价（exit 0）`, async () => {
    const res = await runCli(bin, ['-h']);
    assert.equal(res.code, 0, `-h must exit 0 (got ${res.code}; stderr=${res.stderr})`);
    assert.match(res.stdout, /用法 \/ Usage/);
  });
}

test('CLI 三个服务 bin 的 --help 都列出 --host/--port/--config（统一参数）', async () => {
  for (const bin of ['vap-relay.mjs', 'vap-gateway.mjs', 'vap-node.mjs']) {
    const res = await runCli(bin, ['--help']);
    assert.equal(res.code, 0);
    assert.match(res.stdout, /--host <ip>/, `${bin} 应支持 --host`);
    assert.match(res.stdout, /--port <n>/, `${bin} 应支持 --port`);
    assert.match(res.stdout, /--config <path>/, `${bin} 应支持 --config`);
  }
  const nodeHelp = await runCli('vap-node.mjs', ['--help']);
  assert.match(nodeHelp.stdout, /--node-id <id>/, 'vap-node 应支持 --node-id');
});

// ---------------------------------------------------------------------------
// ② 参数错误：exit 2 + 报错到 stderr
// ---------------------------------------------------------------------------

for (const bin of CLIS) {
  test(`CLI ${bin} 未知参数 exit 2 且提示 --help`, async () => {
    const res = await runCli(bin, ['--totally-unknown-flag']);
    assert.equal(res.code, 2, `未知参数必须 exit 2 (got ${res.code}; stdout=${res.stdout} stderr=${res.stderr})`);
    assert.match(res.stderr, /unknown option '--totally-unknown-flag'/, '错误信息点名该参数');
    assert.match(res.stderr, /--help/, '提示怎么看用法');
    assert.equal(res.stdout, '', '错误不许写 stdout');
  });
}

test('CLI vap-gateway --port 缺值 exit 2（不静默启动）', async () => {
  const res = await runCli('vap-gateway.mjs', ['--port']);
  assert.equal(res.code, 2, `缺值必须 exit 2 (got ${res.code}; stderr=${res.stderr})`);
  assert.match(res.stderr, /requires a value/);
});

test('CLI vap-gateway --port 非数字 exit 2', async () => {
  const res = await runCli('vap-gateway.mjs', ['--port', 'abc']);
  assert.equal(res.code, 2, `非数字必须 exit 2 (got ${res.code}; stderr=${res.stderr})`);
  assert.match(res.stderr, /expects a number/);
});

test('CLI vap-send 位置参数（漏写 --）exit 2', async () => {
  const res = await runCli('vap-send.mjs', ['hello']);
  assert.equal(res.code, 2, `位置参数必须 exit 2 (got ${res.code}; stderr=${res.stderr})`);
  assert.match(res.stderr, /unexpected argument 'hello'/);
});

test('CLI vap-send 缺 --summary exit 2 且指路 --from-file', async () => {
  const res = await runCli('vap-send.mjs', ['--to', 'brain']);
  assert.equal(res.code, 2, `缺必填项必须 exit 2 (got ${res.code}; stderr=${res.stderr})`);
  assert.match(res.stderr, /--summary/);
  assert.match(res.stderr, /--from-file/);
});

test('CLI vap-send --boundary L2a 无证据 exit 2 并给降级建议', async () => {
  const res = await runCli('vap-send.mjs', ['--summary', 'no evidence', '--boundary', 'L2a']);
  assert.equal(res.code, 2, `L2a 无证据必须 exit 2 (got ${res.code}; stderr=${res.stderr})`);
  assert.match(res.stderr, /evidence\.devices/);
  assert.match(res.stderr, /L0/);
});

// ---------------------------------------------------------------------------
// ③ 启动输出：就绪信号 + 下一步提示
// ---------------------------------------------------------------------------

test('CLI vap-gateway 启动输出含 listening 与「下一步」提示（含 vap-send 示例）', async () => {
  const root = tmpDir('vap-cli-gwbin-');
  const proc = startBin('vap-gateway.mjs', ['--port', '0', '--root', root, '--log-level', 'silent']);
  try {
    const text = await proc.readyAndSettled();
    assert.match(text, /vap-gateway listening http=127\.0\.0\.1:\d+/, '首行是就绪信号');
    assert.match(text, /health\s+: http:\/\/127\.0\.0\.1:\d+\/health/, '给出 health 地址');
    assert.match(text, /next\s+:/, '含下一步提示行');
    assert.match(text, /bin\/vap-send\.mjs/, '下一步提示指向 vap-send');
    assert.match(text, /README/, '下一步提示指向 README');
  } finally {
    const code = await proc.stop();
    assert.equal(code, 0, '优雅退出码 0');
  }
});

test('CLI vap-node --port 等价 --health-port 且启动输出含下一步提示', async () => {
  const ledger = tmpDir('vap-cli-node-');
  const proc = startBin('vap-node.mjs', ['--node-id', 'cli-node', '--port', '0', '--ledger-dir', ledger, '--log-level', 'silent']);
  try {
    const text = await proc.readyAndSettled();
    assert.match(text, /vap-node listening id=cli-node/, '就绪信号含节点 id');
    assert.match(text, /health\s+: http:\/\/127\.0\.0\.1:\d+\/health/, '--port 生效为 health 端口');
    assert.match(text, /next\s+:/, '含下一步提示行');
  } finally {
    const code = await proc.stop();
    assert.equal(code, 0, '优雅退出码 0');
  }
});

test('CLI vap-relay 启动输出含 listening 与下一步提示', async () => {
  const proc = startBin('vap-relay.mjs', ['--port', '0', '--log-level', 'silent']);
  try {
    const text = await proc.readyAndSettled();
    assert.match(text, /vap-relay listening tcp=127\.0\.0\.1:\d+/, '就绪信号');
    assert.match(text, /next\s+:/, '含下一步提示行');
  } finally {
    const code = await proc.stop();
    assert.equal(code, 0, '优雅退出码 0');
  }
});

// ---------------------------------------------------------------------------
// ④ vap-send 端到端
// ---------------------------------------------------------------------------

test('vap-send 端到端：真信封 202 → ✓ 已投递人话输出 + 网关落盘', async () => {
  await withGateway(async ({ baseUrl, root }) => {
    const sendRoot = tmpDir('vap-cli-send-');
    const res = await runCli('vap-send.mjs', [
      '--to', 'brain',
      '--summary', 'hello vap',
      '--gateway', baseUrl,
      '--root', sendRoot,
    ]);
    assert.equal(res.code, 0, `成功投递退出码 0 (got ${res.code}; stderr=${res.stderr})`);
    assert.match(res.stdout, /^✓ 已投递 envelopeId=evt-[0-9a-f]{16} 网关已接收（HTTP 202 Accepted）/m, '人话成功行');
    assert.match(res.stdout, /gateway\s+:/, '回显网关地址');
    assert.match(res.stdout, /本地三闸 : pass/, '给出本地三闸预检结论');
    assert.match(res.stdout, /next\s+:/, '给出下一步（看裁决）');
    assert.equal(res.stderr, '', '成功不写 stderr');

    const stored = fs.readdirSync(path.join(root, 'inbox-http')).filter((f) => /^evt-.*\.json$/.test(f));
    assert.equal(stored.length, 1, '网关 inbox-http 落盘一封');
    const envelopeId = res.stdout.match(/envelopeId=(evt-[0-9a-f]{16})/)[1];
    assert.equal(stored[0], `${envelopeId}.json`, '落盘文件名与输出的 envelopeId 一致');
  });
});

test('vap-send 端到端：L2a + evidence 投递成功且 boundary 回显 L2a', async () => {
  await withGateway(async ({ baseUrl }) => {
    const sendRoot = tmpDir('vap-cli-send-l2a-');
    const res = await runCli('vap-send.mjs', [
      '--to', 'brain',
      '--summary', '巡检完成',
      '--boundary', 'L2a',
      '--evidence', '{"devices":["E01"]}',
      '--gateway', baseUrl,
      '--root', sendRoot,
    ]);
    assert.equal(res.code, 0, `L2a 投递应成功 (stderr=${res.stderr})`);
    assert.match(res.stdout, /boundary : L2a/);
    assert.match(res.stdout, /✓ 已投递/);
  });
});

test('vap-send 端到端：默认无证据自动降级 L0（诚实边界）并投递成功', async () => {
  await withGateway(async ({ baseUrl }) => {
    const sendRoot = tmpDir('vap-cli-send-l0-');
    const res = await runCli('vap-send.mjs', ['--summary', 'no evidence', '--gateway', baseUrl, '--root', sendRoot]);
    assert.equal(res.code, 0, `默认应降级 L0 后成功 (stderr=${res.stderr})`);
    assert.match(res.stdout, /boundary : L0/);
    assert.match(res.stdout, /本地三闸 : pass/);
  });
});

test('vap-send 端到端：伪签名 → 403 ✗ 拒绝「签名无效」人话输出 exit 1', async () => {
  await withGateway(async ({ baseUrl, root }) => {
    const dir = tmpDir('vap-cli-badsig-');
    const { file } = writeEnvelopeFile(dir, (env) => ({ ...env, sig: Buffer.alloc(64, 7).toString('base64') }));
    const res = await runCli('vap-send.mjs', ['--from-file', file, '--gateway', baseUrl]);
    assert.equal(res.code, 1, `被拒必须非 0 退出 (got ${res.code}; stdout=${res.stdout})`);
    assert.match(res.stderr, /^✗ 拒绝: 签名无效（网关返回 HTTP 403/m, '人话拒绝行点名 403 签名无效');
    assert.match(res.stderr, /为什么 :/, '解释原因');
    assert.match(res.stderr, /怎么办 :/, '给出办法');
    assert.equal(res.stdout, '', '失败不写 stdout');
    const stored = fs.readdirSync(path.join(root, 'inbox-http')).filter((f) => /^evt-.*\.json$/.test(f));
    assert.equal(stored.length, 0, '伪签名不得落盘');
  });
});

test('vap-send 端到端：缺 nonce → 400 ✗ 拒绝「格式错」人话输出 exit 1', async () => {
  await withGateway(async ({ baseUrl }) => {
    const dir = tmpDir('vap-cli-nononce-');
    const { file } = writeEnvelopeFile(dir, (env) => {
      const copy = { ...env };
      delete copy.nonce;
      return copy;
    });
    const res = await runCli('vap-send.mjs', ['--from-file', file, '--gateway', baseUrl]);
    assert.equal(res.code, 1, `被拒必须非 0 退出 (got ${res.code}; stdout=${res.stdout})`);
    assert.match(res.stderr, /^✗ 拒绝: 格式错（网关返回 HTTP 400/m);
    assert.match(res.stderr, /nonce/);
  });
});

test('vap-send 端到端：同一信封投两次 → 409 ✗ 拒绝「重放拦截」人话输出 exit 1', async () => {
  await withGateway(async ({ baseUrl }) => {
    const dir = tmpDir('vap-cli-replay-');
    const { file } = writeEnvelopeFile(dir);
    const first = await runCli('vap-send.mjs', ['--from-file', file, '--gateway', baseUrl]);
    assert.equal(first.code, 0, `第一次应成功 (stderr=${first.stderr})`);
    const second = await runCli('vap-send.mjs', ['--from-file', file, '--gateway', baseUrl]);
    assert.equal(second.code, 1, `重放必须非 0 退出 (got ${second.code}; stdout=${second.stdout})`);
    assert.match(second.stderr, /^✗ 拒绝: 重放拦截（网关返回 HTTP 409/m);
    assert.match(second.stderr, /nonce/);
  });
});

test('vap-send 端到端：网关没起 → ECONNREFUSED 友好报错 exit 1 且指路起网关', async () => {
  const port = await freePort();
  const sendRoot = tmpDir('vap-cli-offline-');
  const res = await runCli('vap-send.mjs', [
    '--summary', 'offline test',
    '--gateway', `http://127.0.0.1:${port}`,
    '--root', sendRoot,
  ]);
  assert.equal(res.code, 1, `连不上必须非 0 退出 (got ${res.code}; stdout=${res.stdout})`);
  assert.match(res.stderr, /^✗ 连不上网关: http:\/\/127\.0\.0\.1:\d+（ECONNREFUSED）/m, '人话网络错误行');
  assert.match(res.stderr, /bin\/vap-gateway\.mjs --port/, '指路怎么起网关');
  assert.match(res.stderr, /已构造好，可稍后 --from-file 重发/, '告知信封已落盘可重发');
});

test('vap-send --dry-run 只构造不投递（打印信封 JSON，exit 0）', async () => {
  const port = await freePort(); // 故意给一个没人监听的端口，证明 dry-run 不发网络
  const sendRoot = tmpDir('vap-cli-dry-');
  const res = await runCli('vap-send.mjs', [
    '--summary', 'dry run',
    '--gateway', `http://127.0.0.1:${port}`,
    '--root', sendRoot,
    '--dry-run',
  ]);
  assert.equal(res.code, 0, `dry-run 应 exit 0 (stderr=${res.stderr})`);
  assert.match(res.stdout, /✓ 已构造信封 envelopeId=evt-[0-9a-f]{16}（--dry-run 未投递）/);
  // 信封 JSON 是最后一段（独占若干行、以行首 { 开头）——不要被提示行里的 JSON 例子骗到。
  const jsonMatch = res.stdout.match(/\n(\{[\s\S]*\})\s*$/);
  assert.ok(jsonMatch, `dry-run 应打印信封 JSON（stdout=${res.stdout}）`);
  const json = JSON.parse(jsonMatch[1]);
  assert.match(json.id, /^evt-[0-9a-f]{16}$/, '打印的是完整信封 JSON');
  assert.equal(json.to, 'brain');
  assert.match(json.nonce, /^[0-9a-f]{16}$/);
});

test('vap-send --key 用指定私钥发（身份 = 该私钥）', async () => {
  await withGateway(async ({ baseUrl, root }) => {
    const dir = tmpDir('vap-cli-key-');
    // 先用 key-store 生成一把持久钥，再把 PEM 交给 --key。
    const keyRoot = path.join(dir, 'keyroot');
    const node = createVapNode({ nodeId: 'key-owner', root: keyRoot, persistKeys: true });
    const pem = node.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString('utf8');
    const keyFile = path.join(dir, 'my-node.key');
    fs.writeFileSync(keyFile, pem, 'utf8');

    const res = await runCli('vap-send.mjs', [
      '--from', 'key-owner',
      '--summary', 'sent with my own key',
      '--gateway', baseUrl,
      '--root', path.join(dir, 'sendroot'),
      '--key', keyFile,
    ]);
    assert.equal(res.code, 0, `--key 应能成功投递 (stderr=${res.stderr})`);
    const stored = fs.readdirSync(path.join(root, 'inbox-http')).filter((f) => /^evt-.*\.json$/.test(f));
    assert.equal(stored.length, 1);
    const delivered = JSON.parse(fs.readFileSync(path.join(root, 'inbox-http', stored[0]), 'utf8'));
    assert.equal(delivered.from.pubKey, node.pubKey, '投出去的身份就是 --key 那把钥');
  });
});

test('vap-send --key 指向不存在的文件 exit 2', async () => {
  const res = await runCli('vap-send.mjs', ['--summary', 'x', '--key', path.join(tmpDir('vap-cli-nokey-'), 'missing.key')]);
  assert.equal(res.code, 2, `坏 --key 必须 exit 2 (got ${res.code}; stderr=${res.stderr})`);
  assert.match(res.stderr, /--key/);
});

test('vap-send --gateway 带路径 / 非 http 一律 exit 2', async () => {
  const withPath = await runCli('vap-send.mjs', ['--summary', 'x', '--gateway', 'http://127.0.0.1:3081/envelopes']);
  assert.equal(withPath.code, 2, `带路径应 exit 2 (stderr=${withPath.stderr})`);
  assert.match(withPath.stderr, /不要带路径/);
  const https = await runCli('vap-send.mjs', ['--summary', 'x', '--gateway', 'https://127.0.0.1:3081']);
  assert.equal(https.code, 2, `https 暂不支持应 exit 2 (stderr=${https.stderr})`);
  assert.match(https.stderr, /只支持 http/);
});

test('vap-send --summary 超过 100 字 exit 2（提前挡住军法 SUMMARY_BOUND）', async () => {
  const res = await runCli('vap-send.mjs', ['--summary', 'x'.repeat(101)]);
  assert.equal(res.code, 2, `超长战报应 exit 2 (stderr=${res.stderr})`);
  assert.match(res.stderr, /100/);
});

// ---------------------------------------------------------------------------
// ⑤ parseCliArgs / renderHelp 单元行为
// ---------------------------------------------------------------------------

const UNIT_SPEC = {
  name: 'demo',
  entry: 'bin/demo.mjs',
  summary: '单元测试用 spec',
  options: [
    { flag: 'host', value: '<ip>', type: 'string', desc: '主机' },
    { flag: 'port', value: '<n>', type: 'number', desc: '端口' },
    { flag: 'verbose', type: 'boolean', desc: '开关' },
  ],
  examples: ['node bin/demo.mjs --port 1'],
};

test('parseCliArgs：--flag value / --flag=value / 布尔开关', () => {
  const a = parseCliArgs(['--host', '0.0.0.0', '--port', '3081', '--verbose'], UNIT_SPEC);
  assert.equal(a.error, null);
  assert.deepEqual(a.values, { host: '0.0.0.0', port: 3081, verbose: true });
  const b = parseCliArgs(['--host=127.0.0.1', '--port=0'], UNIT_SPEC);
  assert.equal(b.error, null);
  assert.deepEqual(b.values, { host: '127.0.0.1', port: 0 });
});

test('parseCliArgs：--help / -h 置 help 标志', () => {
  assert.equal(parseCliArgs(['--help'], UNIT_SPEC).help, true);
  assert.equal(parseCliArgs(['-h'], UNIT_SPEC).help, true);
  assert.equal(parseCliArgs(['--port', '1', '--help'], UNIT_SPEC).help, true);
});

test('parseCliArgs：未知参数 / 缺值 / 非数字 / 位置参数都给 error', () => {
  assert.match(parseCliArgs(['--nope'], UNIT_SPEC).error, /unknown option '--nope'/);
  assert.match(parseCliArgs(['--port'], UNIT_SPEC).error, /requires a value/);
  assert.match(parseCliArgs(['--port', 'abc'], UNIT_SPEC).error, /expects a number/);
  assert.match(parseCliArgs(['hello'], UNIT_SPEC).error, /unexpected argument 'hello'/);
  assert.match(parseCliArgs(['--verbose=1'], UNIT_SPEC).error, /开关/);
});

test('renderHelp：含用法/参数表/示例，且参数按声明顺序列出', () => {
  const text = renderHelp(UNIT_SPEC);
  assert.match(text, /^demo — 单元测试用 spec/);
  assert.match(text, /用法 \/ Usage/);
  assert.match(text, /--host <ip>/);
  assert.match(text, /--port <n>/);
  assert.match(text, /-h, --help/);
  assert.ok(text.indexOf('--host') < text.indexOf('--port'), '按声明顺序');
});

test('dialHost：通配监听地址映射为可拨号回环地址', () => {
  assert.equal(dialHost('0.0.0.0'), '127.0.0.1');
  assert.equal(dialHost('::'), '127.0.0.1');
  assert.equal(dialHost(''), '127.0.0.1');
  assert.equal(dialHost(undefined), '127.0.0.1');
  assert.equal(dialHost('192.168.1.9'), '192.168.1.9');
});

// ---------------------------------------------------------------------------
// ⑥ 文案与版本一致性（用户验收问题 1/3：文档不许自相矛盾）
// ---------------------------------------------------------------------------

test('package.json：engines >= 22 且四个 bin 入口齐备（含 vap-send）', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'));
  assert.equal(pkg.engines.node, '>=22', 'engines 与 README 的 Node.js 22+ 一致');
  assert.ok(pkg.bin['vap-send'], 'bin 暴露 vap-send');
  assert.equal(pkg.bin['vap-send'], 'bin/vap-send.mjs');
  assert.ok(pkg.scripts.send, 'scripts 有 send 快捷方式');
});

test('README 双语版本要求统一 Node.js 22+，且给固定端口与 vap-send 体验流', () => {
  for (const file of ['README.md', 'README.zh-CN.md']) {
    const text = fs.readFileSync(path.join(process.cwd(), file), 'utf8');
    assert.match(text, /Node\.js \*{0,2}22\+/, `${file} 声明 Node.js 22+`);
    assert.ok(!/engines\D{0,20}>= ?18/.test(text), `${file} 不得再写 engines >= 18（与 package.json 矛盾）`);
    assert.match(text, /git clone https:\/\/github\.com\//, `${file} 给出获取代码方式`);
    assert.match(text, /vap-gateway\.mjs --port 3081/, `${file} 用固定端口示例`);
    assert.match(text, /bin\/vap-send\.mjs --to brain --summary "hello vap"/, `${file} 给出发信命令`);
    assert.match(text, /curl http:\/\/127\.0\.0\.1:3081\/health/, `${file} 给出裁决/计数查看方式`);
    assert.match(text, /node --test/, `${file} 给出跑测试方式`);
    assert.match(text, /409/, `${file} 解释重放拦截`);
  }
});

test('坏词清单：CLI 代码与精修文档一个都不许出现', () => {
  // 坏词一律用 \u 码点写（含注释也不写原字），免得这份检查器自己成为「含坏词的文件」。
  // 顺序与 polish-brief.md 纪律 1 的清单一致，共 8 个词。
  const banned = [
    '\u7089',
    '\u70e7',
    '\u8001\u54e5',
    '\u684c\u9762',
    '\u5411\u4e0a',
    '\u56de\u7089',
    '\u7194\u7089',
    '\u953b\u9020',
  ];
  assert.equal(banned.length, 8, '清单 8 个词一个不少');
  const files = [
    'README.md',
    'README.zh-CN.md',
    'tests/cli.test.mjs',
    'progress-polish.md',
    'report-polish.md',
    ...fs.readdirSync(BIN_DIR).filter((f) => f.endsWith('.mjs')).map((f) => path.join('bin', f)),
  ].filter((f) => fs.existsSync(path.join(process.cwd(), f)));
  for (const file of files) {
    const text = fs.readFileSync(path.join(process.cwd(), file), 'utf8');
    for (const word of banned) {
      assert.ok(!text.includes(word), `${file} 含坏词 '${word}'`);
    }
  }
});
