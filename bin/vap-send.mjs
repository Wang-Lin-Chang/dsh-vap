#!/usr/bin/env node
// bin/vap-send.mjs —— 发信封 CLI（精修批次 · 用户验收问题 7）
//
// 一条命令走完「拿密钥 → 构造信封 → POST 到网关 → 说人话」的全流程，让第一次用 VAP
// 的人不用写代码就能把一封可验证信封投出去，并看懂裁决结果。
//
// 流程：
//   ① 密钥：--key <pem> 指定私钥，或用 key-store 在 --root 下持久生成（重启同一身份）；
//   ② 构造：vap-core createVapNode().send() 签名信封（nonce 随机、签名绑定 nonce）；
//   ③ 预检：本地跑一遍验证门三闸，先告诉用户这封信封自己能不能过；
//   ④ 投递：POST <gateway>/envelopes；
//   ⑤ 人话：202 / 400 / 403 / 409 / 413 / 连不上，逐种给「为什么 + 怎么办」。
//
// 退出码：0 成功；1 被拒或连不上网关；2 参数用法错（同其余三个 bin）。
//
// 乱码消弭：adaptConsole() 前置裁决语言，文案经 t() 从双语字典取值。
//
// 零第三方依赖，仅 node: 内置模块与相对路径 import。

import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { createVapNode, constants } from '../vap-core.mjs';
import { cliArgs } from './process-guard.mjs';
import { adaptConsole, createT, DICT } from '../console-adapter.mjs';

const { lang } = adaptConsole();
const t = createT(DICT, lang);

const DEFAULT_GATEWAY = 'http://127.0.0.1:3081';
const BOUNDARIES = ['L2a', 'L1', 'L0'];

const SPEC = {
  name: 'vap-send',
  entry: 'bin/vap-send.mjs',
  summary: t('send.summary'),
  options: [
    { flag: 'to', value: '<nodeId>', type: 'string', desc: t('send.opt.to') },
    { flag: 'summary', value: '<text>', type: 'string', desc: t('send.opt.summary', { bound: constants.SUMMARY_BOUND }) },
    { flag: 'gateway', value: '<url>', type: 'string', desc: t('send.opt.gateway', { url: DEFAULT_GATEWAY }) },
    { flag: 'from', value: '<nodeId>', type: 'string', desc: t('send.opt.from') },
    { flag: 'claim-type', value: '<type>', type: 'string', desc: t('send.opt.claimType') },
    { flag: 'boundary', value: '<L2a|L1|L0>', type: 'string', desc: t('send.opt.boundary') },
    { flag: 'evidence', value: '<json>', type: 'string', desc: t('send.opt.evidence') },
    { flag: 'request', value: '<text>', type: 'string', desc: t('send.opt.request') },
    { flag: 'key', value: '<keyFile>', type: 'string', desc: t('send.opt.key') },
    { flag: 'root', value: '<dir>', type: 'string', desc: t('send.opt.root') },
    { flag: 'from-file', value: '<json>', type: 'string', desc: t('send.opt.fromFile') },
    { flag: 'timeout', value: '<ms>', type: 'number', desc: t('send.opt.timeout') },
    { flag: 'dry-run', type: 'boolean', desc: t('send.opt.dryRun') },
  ],
  examples: [
    `node bin/vap-send.mjs --to brain --summary "hello vap" --gateway ${DEFAULT_GATEWAY}`,
    t('send.example.inspect', { url: DEFAULT_GATEWAY }),
    t('send.example.key'),
    t('send.example.dryRun'),
    `node bin/vap-send.mjs --from-file ./evt-xxxx.json --gateway ${DEFAULT_GATEWAY}`,
  ],
  notes: [
    t('send.note.gateway'),
    t('send.note.exitCodes'),
    t('send.note.verify'),
  ],
};

const args = cliArgs(SPEC, process.argv.slice(2), t);

// ---------------------------------------------------------------------------
// 输出助手（文案统一：成功 ✓ 到 stdout，失败 ✗ 到 stderr，附属信息缩进两格）
// ---------------------------------------------------------------------------

function out(lines) {
  for (const line of lines) process.stdout.write(`${line}\n`);
}

function usageFail(message) {
  process.stderr.write(`${t('pg.failLine', { name: 'vap-send', error: message })}\n`);
  process.stderr.write(`${t('pg.hintUsage', { entry: SPEC.entry })}\n`);
  process.exit(2);
}

function rejectFail(lines) {
  for (const line of lines) process.stderr.write(`${line}\n`);
  process.exit(1);
}

function errText(err) {
  return String((err && err.message) || err);
}

// ---------------------------------------------------------------------------
// 参数落地
// ---------------------------------------------------------------------------

const gatewayUrl = String(args.gateway || DEFAULT_GATEWAY).replace(/\/+$/, '');
let parsedGateway;
try {
  parsedGateway = new URL(gatewayUrl);
} catch {
  usageFail(t('send.badGatewayUrl', { url: gatewayUrl }));
}
if (parsedGateway.protocol !== 'http:') {
  usageFail(t('send.gatewayHttpOnly', { proto: parsedGateway.protocol }));
}
if (parsedGateway.pathname !== '/' && parsedGateway.pathname !== '') {
  usageFail(t('send.gatewayNoPath', { path: parsedGateway.pathname, url: DEFAULT_GATEWAY }));
}

const timeoutMs = args.timeout === undefined ? 10000 : Number(args.timeout);
if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) usageFail(t('send.badTimeout', { value: args.timeout }));

const root = args.root || path.join(os.tmpdir(), 'vap-send-data');
const fromId = args.from || 'vap-sender';
const toId = args.to || 'brain';

// ---------------------------------------------------------------------------
// ① 密钥
// ---------------------------------------------------------------------------

function loadKeyPair() {
  if (!args.key) return null; // 走 key-store 持久钥
  let pem;
  try {
    pem = fs.readFileSync(args.key, 'utf8');
  } catch (err) {
    usageFail(t('send.keyReadFail', { file: args.key, err: errText(err) }));
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(pem);
  } catch (err) {
    usageFail(t('send.keyInvalid', { file: args.key, err: errText(err) }));
  }
  return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}

// ---------------------------------------------------------------------------
// ② 构造信封（--from-file 时直接读文件）
// ---------------------------------------------------------------------------

function readEnvelopeFile(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    usageFail(t('send.fileReadFail', { file, err: errText(err) }));
  }
  let envelope;
  try {
    envelope = JSON.parse(text);
  } catch (err) {
    usageFail(t('send.fileBadJson', { file, err: errText(err) }));
  }
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    usageFail(t('send.fileNotObject', { file }));
  }
  if (!envelope.id) usageFail(t('send.fileMissingId', { file }));
  return envelope;
}

function parseEvidence() {
  const base = { devices: [], bills: {}, digest: '' };
  if (args.evidence === undefined) return base;
  let value;
  try {
    value = JSON.parse(String(args.evidence));
  } catch (err) {
    usageFail(t('send.evidenceBadJson', { err: errText(err) }));
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    usageFail(t('send.evidenceNotObject'));
  }
  return { ...base, ...value };
}

function buildEnvelope() {
  const evidence = parseEvidence();
  const devices = Array.isArray(evidence.devices) ? evidence.devices : [];

  const summary = args.summary === undefined ? undefined : String(args.summary);
  if (summary === undefined) {
    usageFail(t('send.missingSummary'));
  }
  if ([...summary].length > constants.SUMMARY_BOUND) {
    usageFail(t('send.summaryTooLong', { count: [...summary].length, bound: constants.SUMMARY_BOUND }));
  }

  // 诚实边界：显式给了就照办（L2a 无证据直接拦，别让用户到下游才被拒）；
  // 没给就按证据自动选——有 devices 才敢声明 L2a，否则降级 L0（spec §3 建议值）。
  let boundary = args.boundary === undefined ? undefined : String(args.boundary);
  let boundaryNote = '';
  if (boundary === undefined) {
    boundary = devices.length > 0 ? 'L2a' : 'L0';
    boundaryNote = devices.length > 0
      ? t('send.boundaryNoteL2a', { count: devices.length })
      : t('send.boundaryNoteL0');
  } else if (!BOUNDARIES.includes(boundary)) {
    usageFail(t('send.badBoundary', { list: BOUNDARIES.join(' / '), value: boundary }));
  } else if (boundary === 'L2a' && devices.length === 0) {
    usageFail(t('send.l2aNeedsEvidence'));
  }

  let node;
  try {
    const keyPair = loadKeyPair();
    node = createVapNode({ nodeId: fromId, root, keyPair, persistKeys: !keyPair });
  } catch (err) {
    rejectFail([
      t('send.prepareIdentityFail', { err: errText(err) }),
      t('send.whyIdentity', { root }),
      t('send.fixIdentity'),
    ]);
  }

  const envelope = node.send({
    to: toId,
    claim: { type: args['claim-type'] || 'report', body: {} },
    evidence,
    boundary,
    report: { summary, keyNumbers: [], request: args.request === undefined ? '' : String(args.request) },
  });

  // ③ 本地预检：三闸结果先讲给用户听（网关只验签，军法/边界在下游裁决）。
  const verdict = node.verify(envelope);
  return { envelope, boundary, boundaryNote, verdict, savedTo: path.join(root, 'outbox', `${envelope.id}.json`) };
}

// ---------------------------------------------------------------------------
// ④ 投递
// ---------------------------------------------------------------------------

function postEnvelope(envelope) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(envelope);
    const req = http.request(
      new URL('/envelopes', `${gatewayUrl}/`),
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
          accept: 'application/json',
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let data = null;
          try { data = text ? JSON.parse(text) : null; } catch { data = null; }
          resolve({ status: res.statusCode, data, text });
        });
      },
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(Object.assign(new Error(t('send.timeoutError', { ms: timeoutMs })), { code: 'ETIMEDOUT' }));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// ⑤ 人话结果：每种网关状态码都给「为什么 + 怎么办」
// ---------------------------------------------------------------------------

const STATUS_EXPLAIN = {
  400: { title: t('send.status400.title'), why: t('send.status400.why'), fix: t('send.status400.fix') },
  403: { title: t('send.status403.title'), why: t('send.status403.why'), fix: t('send.status403.fix') },
  409: { title: t('send.status409.title'), why: t('send.status409.why'), fix: t('send.status409.fix') },
  413: { title: t('send.status413.title'), why: t('send.status413.why'), fix: t('send.status413.fix') },
  404: { title: t('send.status404.title'), why: t('send.status404.why'), fix: t('send.status404.fix', { url: DEFAULT_GATEWAY }) },
  500: { title: t('send.status500.title'), why: t('send.status500.why'), fix: t('send.status500.fix') },
};

const NETWORK_EXPLAIN = {
  ECONNREFUSED: { title: t('send.netRefused.title'), why: t('send.netRefused.why'), fix: t('send.netRefused.fix', { port: parsedGateway.port || '3081' }) },
  ENOTFOUND: { title: t('send.netNotFound.title'), why: t('send.netNotFound.why', { host: parsedGateway.hostname }), fix: t('send.netNotFound.fix') },
  ETIMEDOUT: { title: t('send.netTimeout.title'), why: t('send.netTimeout.why'), fix: t('send.netTimeout.fix') },
  ECONNRESET: { title: t('send.netReset.title'), why: t('send.netReset.why'), fix: t('send.netReset.fix') },
};

function explainNetworkError(err) {
  const code = (err && err.code) || 'UNKNOWN';
  const hit = NETWORK_EXPLAIN[code] || {
    title: t('send.netUnknown.title'),
    why: errText(err),
    fix: t('send.netUnknown.fix'),
  };
  return { code, ...hit };
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------

function gateSummary(verdict) {
  if (!verdict) return null;
  const g = verdict.gates;
  const mark = (pass) => (pass ? t('pg.markPass') : t('pg.markFail'));
  const marks = [
    t('send.gateIdentity', { mark: mark(g.identity.pass) }),
    t('send.gateLaws', { mark: mark(g.laws.pass) }),
    t('send.gateBoundary', { mark: mark(g.boundary.pass) }),
  ].join(' / ');
  const reasons = [];
  if (!g.identity.pass) reasons.push(g.identity.reason);
  for (const rule of g.laws.rules) if (!rule.ok && rule.severity === 'reject') reasons.push(`${rule.id}: ${rule.note}`);
  if (!g.boundary.pass) reasons.push(g.boundary.reason);
  return { line: t('send.verdictLine', { verdict: verdict.pass ? 'pass' : 'fail', marks }), reasons };
}

async function main() {
  const built = args['from-file'] !== undefined
    ? { envelope: readEnvelopeFile(String(args['from-file'])), boundary: null, boundaryNote: '', verdict: null, savedTo: null }
    : buildEnvelope();

  const { envelope } = built;
  const gates = gateSummary(built.verdict);

  if (args['dry-run']) {
    out([
      t('send.dryRunDone', { id: envelope.id }),
      `  from     : ${envelope.from && envelope.from.nodeId}`,
      `  to       : ${envelope.to}`,
      built.boundary ? `  boundary : ${built.boundary}${built.boundaryNote}` : null,
      gates ? t('send.localGatesLine', { line: gates.line }) : null,
      built.savedTo ? t('send.savedTo', { path: built.savedTo }) : null,
      t('send.dryRunNext', { url: gatewayUrl }),
      '',
      JSON.stringify(envelope, null, 2),
    ].filter((line) => line !== null));
    return;
  }

  let res;
  try {
    res = await postEnvelope(envelope);
  } catch (err) {
    const info = explainNetworkError(err);
    rejectFail([
      t('send.networkFailLine', { title: info.title, url: gatewayUrl, code: info.code }),
      t('send.whyLabel', { text: info.why }),
      t('send.fixLabel', { text: info.fix }),
      t('send.envelopeSavedNote', { id: envelope.id }),
      built.savedTo ? t('send.savedTo', { path: built.savedTo }) : null,
    ].filter((line) => line !== null));
  }

  if (res.status === 202) {
    const envelopeId = (res.data && res.data.envelopeId) || envelope.id;
    out([
      t('send.delivered', { id: envelopeId }),
      `  from     : ${envelope.from && envelope.from.nodeId}`,
      `  to       : ${envelope.to}`,
      built.boundary ? `  boundary : ${built.boundary}${built.boundaryNote}` : null,
      envelope.report && envelope.report.summary ? `  summary  : ${envelope.report.summary}` : null,
      `  gateway  : ${gatewayUrl}`,
      gates ? t('send.localGatesLine', { line: gates.line }) : null,
      t('send.verdictHint'),
      t('send.deliveredNext', { url: gatewayUrl }),
    ].filter((line) => line !== null));
    if (gates && !built.verdict.pass) {
      out([t('send.localPrecheckFail'), ...gates.reasons.map((r) => `             - ${r}`)]);
    }
    return;
  }

  const explain = STATUS_EXPLAIN[res.status] || {
    title: t('send.unknownStatus.title'),
    why: t('send.unknownStatus.why', { code: res.status }),
    fix: t('send.unknownStatus.fix'),
  };
  const reason = (res.data && res.data.error) || res.text || `HTTP ${res.status}`;
  rejectFail([
    t('send.rejectedLine', { title: explain.title, code: res.status, reason }),
    t('send.whyLabel', { text: explain.why }),
    t('send.fixLabel', { text: explain.fix }),
    `  envelope : ${envelope.id}`,
    `  gateway  : ${gatewayUrl}`,
  ]);
}

main().catch((err) => {
  process.stderr.write(`${t('send.unexpectedFail', { err: errText(err) })}\n`);
  process.exit(1);
});
