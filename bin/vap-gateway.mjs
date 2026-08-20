#!/usr/bin/env node
// bin/vap-gateway.mjs —— HTTP 网关入口（M10；精修批次统一参数与启动提示）
//
// 组装 createHttpGateway（config + logger + SIGINT/SIGTERM 优雅退出 +
// uncaughtException/unhandledRejection 兜底退出码 1）。
//
// 参数体验统一走 process-guard 的 cliArgs：--help exit 0、未知参数 exit 2。
// 乱码消弭：adaptConsole() 前置裁决语言（非 TTY 字节透传 / cp936 自愈 chcp 65001），
// 全部用户可见文案经 t() 从双语字典取值。
//
// 零第三方依赖，仅 node: 内置模块与相对路径 import。

import os from 'node:os';
import path from 'node:path';

import { createHttpGateway } from '../vap-transport.mjs';
import { createLogger } from '../logger.mjs';
import { loadConfig } from '../config.mjs';
import { cliArgs, dialHost, installProcessGuards } from './process-guard.mjs';
import { adaptConsole, createT, DICT } from '../console-adapter.mjs';

const { lang } = adaptConsole();
const t = createT(DICT, lang);

const SPEC = {
  name: 'vap-gateway',
  entry: 'bin/vap-gateway.mjs',
  summary: t('gw.summary'),
  options: [
    { flag: 'host', value: '<ip>', type: 'string', desc: t('gw.opt.host') },
    { flag: 'port', value: '<n>', type: 'number', desc: t('gw.opt.port') },
    { flag: 'root', value: '<dir>', type: 'string', desc: t('gw.opt.root') },
    { flag: 'config', value: '<path>', type: 'string', desc: t('gw.opt.config') },
    { flag: 'log-file', value: '<path>', type: 'string', desc: t('gw.opt.logFile') },
    { flag: 'log-level', value: '<level>', type: 'string', desc: t('gw.opt.logLevel') },
  ],
  examples: [
    'node bin/vap-gateway.mjs --port 3081',
    'node bin/vap-gateway.mjs --host 0.0.0.0 --port 3081 --log-level debug',
    'node bin/vap-gateway.mjs --config ./vap.config.json',
  ],
  notes: [
    t('gw.note.env'),
    t('gw.note.stop'),
    t('gw.note.send'),
  ],
};

const args = cliArgs(SPEC, process.argv.slice(2), t);

let cfg;
try {
  cfg = loadConfig({ path: args.config });
} catch (err) {
  console.error(t('pg.failLine', { name: 'vap-gateway', error: String((err && err.message) || err) }));
  process.exit(1);
}

const logger = createLogger({
  file: args['log-file'] || process.env.VAP_LOG_FILE || undefined,
  level: args['log-level'] || process.env.VAP_LOG_LEVEL || 'info',
  component: 'gateway',
});

const root = args.root || path.join(os.tmpdir(), 'vap-gateway-data');
const port = Number(args.port ?? cfg.gatewayPort);
const host = args.host ?? cfg.gatewayHost;

const gateway = createHttpGateway({ root, port, host, logger });

async function main() {
  const bound = await gateway.start();
  logger.info(`gateway listening http=${host}:${bound}`);
  const base = `http://${dialHost(host)}:${bound}`;
  // 首行保持 `vap-gateway listening http=<host>:<port>`（运维/测试的就绪信号），
  // 其后是「下一步」提示：让用户不必翻文档就知道该做什么。
  console.log(t('gw.listening', { host, port: bound }));
  console.log(`  health    : ${base}/health`);
  console.log(t('gw.envelopesHint', { base }));
  console.log(`  data      : ${root}`);
  console.log(`  next      : send envelopes via POST /envelopes — node bin/vap-send.mjs --to brain --summary "hello vap" --gateway ${base}`);
  console.log(t('gw.seeReadme'));
}

main().catch((err) => {
  logger.error(`gateway start failed: ${String((err && err.stack) || err)}`);
  console.error(t('gw.startFailed', { msg: String((err && err.message) || err) }));
  process.exit(1);
});

installProcessGuards({
  logger,
  onStop: async () => {
    await gateway.stop();
    logger.info('gateway stopped');
  },
});
