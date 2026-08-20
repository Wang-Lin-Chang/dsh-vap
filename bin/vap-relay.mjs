#!/usr/bin/env node
// bin/vap-relay.mjs —— 中继服务入口（M10；精修批次统一参数与启动提示）
//
// 组装 createRelayServer（config + logger + SIGINT/SIGTERM 优雅退出 +
// uncaughtException/unhandledRejection 兜底退出码 1）。
// 启动后可经 TCP 注册/转发，旁路 HTTP /health 默认仅回环。
//
// 参数体验统一走 process-guard 的 cliArgs：--help exit 0、未知参数 exit 2。
// 乱码消弭：adaptConsole() 前置裁决语言，文案经 t() 从双语字典取值。
//
// 零第三方依赖，仅 node: 内置模块与相对路径 import。

import { createRelayServer } from '../phase4/relay-server.mjs';
import { createLogger } from '../logger.mjs';
import { loadConfig } from '../config.mjs';
import { cliArgs, dialHost, installProcessGuards } from './process-guard.mjs';
import { adaptConsole, createT, DICT } from '../console-adapter.mjs';

const { lang } = adaptConsole();
const t = createT(DICT, lang);

const SPEC = {
  name: 'vap-relay',
  entry: 'bin/vap-relay.mjs',
  summary: t('relay.summary'),
  options: [
    { flag: 'host', value: '<ip>', type: 'string', desc: t('relay.opt.host') },
    { flag: 'port', value: '<n>', type: 'number', desc: t('relay.opt.port') },
    { flag: 'health-port', value: '<n>', type: 'number', desc: t('relay.opt.healthPort') },
    { flag: 'config', value: '<path>', type: 'string', desc: t('relay.opt.config') },
    { flag: 'log-file', value: '<path>', type: 'string', desc: t('relay.opt.logFile') },
    { flag: 'log-level', value: '<level>', type: 'string', desc: t('relay.opt.logLevel') },
  ],
  examples: [
    'node bin/vap-relay.mjs --port 3082',
    'node bin/vap-relay.mjs --port 3082 --health-port 3084',
    'node bin/vap-relay.mjs --host 0.0.0.0 --port 3082 --log-level debug',
  ],
  notes: [
    t('relay.note.env'),
    t('relay.note.stop'),
    t('relay.note.design'),
  ],
};

const args = cliArgs(SPEC, process.argv.slice(2), t);

let cfg;
try {
  cfg = loadConfig({ path: args.config });
} catch (err) {
  console.error(t('pg.failLine', { name: 'vap-relay', error: String((err && err.message) || err) }));
  process.exit(1);
}

const logger = createLogger({
  file: args['log-file'] || process.env.VAP_LOG_FILE || undefined,
  level: args['log-level'] || process.env.VAP_LOG_LEVEL || 'info',
  component: 'relay',
});

const port = Number(args.port ?? cfg.relayPort);
const host = args.host ?? cfg.relayHost;
const healthPort = Number(args['health-port'] ?? 0);

const relay = createRelayServer({ port, host, healthPort });

async function main() {
  const bound = await relay.start();
  const healthBound = await relay.startHealth();
  logger.info(`relay listening tcp=${host}:${bound} health=${healthBound == null ? 'off' : `127.0.0.1:${healthBound}`}`);
  const healthSuffix = healthBound == null ? '' : ` health=127.0.0.1:${healthBound}`;
  // 首行保持 `vap-relay listening tcp=<host>:<port>`（就绪信号），其后是「下一步」提示。
  console.log(t('relay.listening', { host, port: bound, health: healthSuffix }));
  if (healthBound != null) console.log(`  health : http://127.0.0.1:${healthBound}/health`);
  console.log(t('relay.nextHint', { host: dialHost(host), port: bound }));
  console.log(t('relay.designHint'));
}

main().catch((err) => {
  logger.error(`relay start failed: ${String((err && err.stack) || err)}`);
  console.error(t('relay.startFailed', { msg: String((err && err.message) || err) }));
  process.exit(1);
});

installProcessGuards({
  logger,
  onStop: async () => {
    await relay.stop();
    logger.info('relay stopped');
  },
});
