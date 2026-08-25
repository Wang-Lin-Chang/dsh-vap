// ops/dual-relay-repro.mjs —— 本地双中继复现装置（R1 调试）
// 起 2 个本地 relay（127.0.0.1 / 127.0.0.2 同端口 42051）+ 1 个本地 STUN（42053），
// 然后 spawn A/B 两个 punch-node（relayHost 逗号双站），断言交换成功。
import { spawn } from 'node:child_process';
import { createRelayServer } from '../phase4/relay-server.mjs';
import { createHolePuncher } from '../phase7/hole-punch.mjs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUNCH_NODE = path.join(HERE, '..', 'phase7', 'punch-node.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const relay1 = createRelayServer({ port: 42051, host: '127.0.0.1' });
const relay2 = createRelayServer({ port: 42051, host: '127.0.0.2' });
await relay1.start();
await relay2.start();
console.log('relays up: 127.0.0.1:42051 + 127.0.0.2:42051');

// 本地 STUN：直接用 createHolePuncher 无法当服务器；用 stun-server.mjs 子进程
const stun = spawn(process.execPath, [path.join(HERE, '..', 'phase7', 'stun-server.mjs'), '42053', '127.0.0.1'], { stdio: 'ignore' });
await sleep(1000);
console.log('stun up: 127.0.0.1:42053');

function runNode(args, outFile) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [PUNCH_NODE, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = '';
    p.stderr.on('data', (d) => { err += d; });
    const to = setTimeout(() => {
      console.log('TIMEOUT kill:', outFile, 'err so far:', err.slice(-300));
      try { p.kill('SIGKILL'); } catch {}
    }, 200000);
    p.on('exit', (code) => { clearTimeout(to); resolve({ code, err: err.slice(-400) }); });
  });
}

const common = [
  '--stunHost', '127.0.0.1', '--stunPort', '42053',
  '--relayHost', '127.0.0.1,127.0.0.2', '--relayPort', '42051',
  '--classify', 'false',
];

const bArgs = [...common, '--site', 'B', '--localPort', '50001', '--out', path.join(HERE, '..', '..', '..', 'repro-B.json')];
const aArgs = [...common, '--site', 'A', '--localPort', '46000', '--out', path.join(HERE, '..', '..', '..', 'repro-A.json')];

const bP = runNode(bArgs);
await sleep(1500);
const aP = runNode(aArgs);
const [bR, aR] = await Promise.all([bP, aP]);
console.log('B exit:', bR.code, bR.err || '(clean)');
console.log('A exit:', aR.code, aR.err || '(clean)');

let aJson = null;
try {
  aJson = JSON.parse(await (await import('node:fs')).readFileSync(path.join(HERE, '..', '..', '..', 'repro-A.json'), 'utf8'));
} catch { console.log('A result file missing'); }

if (aJson) {
  console.log('A exchanged =', aJson.exchanged, '| executed =', aJson.executedStrategy, '| pass =', aJson.pass);
  if (!aJson.exchanged) process.exitCode = 1;
} else {
  process.exitCode = 1;
}
relay1.stop(); relay2.stop(); stun.kill();
