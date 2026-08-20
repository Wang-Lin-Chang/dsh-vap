#!/usr/bin/env node
// bin/vap-node.mjs —— 共识节点入口（M10；精修批次统一参数与启动提示）
//
// 组装 createMembershipNode（persistKeys + ledgerDir + autoRestore），
// 旁路 HTTP /health 默认仅回环；SIGINT/SIGTERM 优雅退出 +
// uncaughtException/unhandledRejection 兜底退出码 1。
//
// 参数体验统一走 process-guard 的 cliArgs：--help exit 0、未知参数 exit 2。
// 乱码消弭：adaptConsole() 前置裁决语言，文案经 t() 从双语字典取值。
//
// 零第三方依赖，仅 node: 内置模块与相对路径 import。

import http from 'node:http';
import crypto from 'node:crypto';

import { createMembershipNode } from '../phase6/vap-to-membership.mjs';
import { createLogger } from '../logger.mjs';
import { loadConfig, defaultLedgerDir } from '../config.mjs';
import { cliArgs, dialHost, installProcessGuards } from './process-guard.mjs';
import { saveKey, loadKey } from '../key-store.mjs';
import { adaptConsole, createT, DICT } from '../console-adapter.mjs';

const { lang } = adaptConsole();
const t = createT(DICT, lang);

const SPEC = {
  name: 'vap-node',
  entry: 'bin/vap-node.mjs',
  summary: t('node.summary'),
  options: [
    { flag: 'node-id', value: '<id>', type: 'string', desc: t('node.opt.nodeId') },
    { flag: 'host', value: '<ip>', type: 'string', desc: t('node.opt.host') },
    { flag: 'port', value: '<n>', type: 'number', desc: t('node.opt.port') },
    { flag: 'health-port', value: '<n>', type: 'number', desc: t('node.opt.healthPort') },
    { flag: 'ledger-dir', value: '<dir>', type: 'string', desc: t('node.opt.ledgerDir') },
    { flag: 'config', value: '<path>', type: 'string', desc: t('node.opt.config') },
    { flag: 'log-file', value: '<path>', type: 'string', desc: t('node.opt.logFile') },
    { flag: 'log-level', value: '<level>', type: 'string', desc: t('node.opt.logLevel') },
  ],
  examples: [
    'node bin/vap-node.mjs --node-id brain --port 3083',
    'node bin/vap-node.mjs --node-id brain --port 3083 --ledger-dir ./data/ledger',
    'node bin/vap-node.mjs --config ./vap.config.json',
  ],
  notes: [
    t('node.note.env'),
    t('node.note.roster'),
    t('node.note.stop'),
  ],
};

const args = cliArgs(SPEC, process.argv.slice(2), t);

let cfg;
try {
  cfg = loadConfig({ path: args.config });
} catch (err) {
  console.error(t('pg.failLine', { name: 'vap-node', error: String((err && err.message) || err) }));
  process.exit(1);
}

const logger = createLogger({
  file: args['log-file'] || process.env.VAP_LOG_FILE || undefined,
  level: args['log-level'] || process.env.VAP_LOG_LEVEL || 'info',
  component: 'node',
});

const nodeId = args['node-id'] || 'vap-node-1';
const ledgerDir = args['ledger-dir'] || cfg.ledgerDir || defaultLedgerDir();
// --port 与 --health-port 等价（统一参数体验：三个 bin 都认 --port）。
const healthPort = Number(args['health-port'] ?? args.port ?? 0);
const healthHost = args.host || '127.0.0.1';

// 共识节点需要 peers 表，且本节点 pubKey 必须匹配表内条目。用持久钥（先 load 或
// 生成）拼出单节点 roster（n=1, f=0）。
function buildNode() {
  let keyPair;
  const loaded = loadKey(ledgerDir, nodeId);
  if (loaded) {
    keyPair = { publicKey: crypto.createPublicKey(loaded), privateKey: loaded };
  } else {
    const gen = crypto.generateKeyPairSync('ed25519');
    saveKey(ledgerDir, nodeId, gen.privateKey);
    keyPair = gen;
  }
  const pubKey = keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const peers = [{ nodeId, pubKey }];
  return createMembershipNode({
    nodeId,
    keyPair,
    n: 1,
    f: 0,
    peers,
    ledgerDir,
    persistKeys: true,
    autoRestore: true,
  });
}

const node = buildNode();

let healthServer = null;

async function startHealth() {
  // 始终启动旁路 HTTP /health（healthPort 0 = 自动分配端口），
  // 也作为常驻进程的事件循环持有者（共识节点本无长连接服务器）。
  healthServer = http.createServer((req, res) => {
    if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) {
      const body = JSON.stringify(node.health());
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
      res.end(body);
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'not found' }));
  });
  await new Promise((resolve, reject) => {
    healthServer.on('error', reject);
    healthServer.listen(healthPort, healthHost, resolve);
  });
}

async function main() {
  await startHealth();
  const hport = healthServer ? healthServer.address().port : null;
  logger.info(`node ready id=${nodeId} ledger=${ledgerDir} height=${node.committedHeight} health=${hport == null ? 'off' : `${healthHost}:${hport}`}`);
  const healthSuffix = hport == null ? '' : ` health=${healthHost}:${hport}`;
  // 首行保持 `vap-node listening id=<id> ...`（就绪信号），其后是「下一步」提示。
  console.log(t('node.listening', { id: nodeId, height: node.committedHeight, health: healthSuffix }));
  if (hport != null) console.log(`  health : http://${dialHost(healthHost)}:${hport}/health`);
  console.log(`  ledger : ${ledgerDir}`);
  console.log(t('node.nextCurl', { host: dialHost(healthHost), port: hport }));
  console.log(t('node.nextGateway'));
}

main().catch((err) => {
  logger.error(`node start failed: ${String((err && err.stack) || err)}`);
  console.error(t('node.startFailed', { msg: String((err && err.message) || err) }));
  process.exit(1);
});

installProcessGuards({
  logger,
  onStop: async () => {
    if (healthServer) {
      await new Promise((resolve) => healthServer.close(() => resolve()));
      healthServer = null;
    }
    logger.info('node stopped');
  },
});
