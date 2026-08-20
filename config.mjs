// config.mjs —— 配置外部化（修复批次 2 · M8）
//
// loadConfig({ path, env })：读 JSON 配置文件 + 环境变量覆盖（VAP_* 前缀），返回合并配置。
// 环境变量名规则：VAP_<KEY>，key 里的点/连字符统一替换为下划线（见 ENV_KEY 映射）。
//
// 数据目录默认值（M13）：绝不默认 __dirname —— 一律落在 os.tmpdir() 下：
//   ledgerDir = <os.tmpdir()>/vap-ledger
//   trailDir  = <os.tmpdir()>/vap-trails
//
// 零第三方依赖，仅 node: 内置模块。

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function defaultLedgerDir() {
  return path.join(os.tmpdir(), 'vap-ledger');
}

export function defaultTrailDir() {
  return path.join(os.tmpdir(), 'vap-trails');
}

// 缺省配置（部署项全集）。timeouts 为毫秒。
export function defaultConfig() {
  return {
    gatewayHost: '127.0.0.1',
    gatewayPort: 0,
    relayHost: '127.0.0.1',
    relayPort: 0,
    multicastAddr: '239.255.42.99',
    multicastPort: 42666,
    // M17：空串 = 未显式指定组播出接口（走 OS 默认出接口）。需要本机回环发现时
    // 显式设 '127.0.0.1'。
    multicastInterface: '',
    ledgerDir: defaultLedgerDir(),
    trailDir: defaultTrailDir(),
    timeouts: {
      peerForwardMs: 2000,
    },
  };
}

// 配置键 → 环境变量名（不含 VAP_ 前缀）。
const ENV_KEYS = [
  ['gatewayHost', 'GATEWAY_HOST'],
  ['gatewayPort', 'GATEWAY_PORT'],
  ['relayHost', 'RELAY_HOST'],
  ['relayPort', 'RELAY_PORT'],
  ['multicastAddr', 'MULTICAST_ADDR'],
  ['multicastPort', 'MULTICAST_PORT'],
  ['multicastInterface', 'MULTICAST_INTERFACE'],
  ['ledgerDir', 'LEDGER_DIR'],
  ['trailDir', 'TRAIL_DIR'],
  ['peerForwardMs', 'PEER_FORWARD_MS'],
];

// 根据目标值类型强制转换 env 字符串：数字 → Number，布尔 → true/false。
function coerceEnv(value, sample) {
  if (typeof sample === 'number') {
    const n = Number(value);
    return Number.isFinite(n) ? n : sample;
  }
  if (typeof sample === 'boolean') {
    return value === 'true' || value === '1';
  }
  return value;
}

function applyEnv(config, env) {
  if (!env || typeof env !== 'object') return config;
  const out = { ...config, timeouts: { ...(config.timeouts || {}) } };
  for (const [key, envName] of ENV_KEYS) {
    const raw = env[`VAP_${envName}`];
    if (raw === undefined || raw === null || raw === '') continue;
    if (key === 'peerForwardMs') {
      out.timeouts.peerForwardMs = coerceEnv(raw, out.timeouts.peerForwardMs);
    } else {
      out[key] = coerceEnv(raw, out[key]);
    }
  }
  return out;
}

// loadConfig({ path, env })：
//   path = JSON 配置文件路径（可缺省）；env = 环境变量对象（可缺省，默认 process.env）。
export function loadConfig({ path: configPath, env = process.env } = {}) {
  const base = defaultConfig();
  if (configPath) {
    let fileCfg = null;
    try {
      fileCfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (err) {
      throw new Error(`loadConfig: cannot read config file '${configPath}': ${String((err && err.message) || err)}`);
    }
    if (!fileCfg || typeof fileCfg !== 'object' || Array.isArray(fileCfg)) {
      throw new Error(`loadConfig: config file '${configPath}' must contain a JSON object`);
    }
    for (const key of Object.keys(fileCfg)) {
      if (key === 'timeouts' && fileCfg.timeouts && typeof fileCfg.timeouts === 'object') {
        base.timeouts = { ...base.timeouts, ...fileCfg.timeouts };
      } else if (Object.prototype.hasOwnProperty.call(base, key)) {
        base[key] = fileCfg[key];
      }
    }
  }
  return applyEnv(base, env);
}
