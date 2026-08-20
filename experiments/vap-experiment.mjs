// experiments/vap-experiment.mjs —— VAP v0 实测装置（E01-E03）
// 真实文件系统端到端：异构节点互动 / 伪造声明拦截对照 / 崩溃收养
// 运行：node experiments/vap-experiment.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createVapNode, createBrain, canonicalJson } from '../vap-core.mjs';

// 用节点私钥对任意（已篡改的）信封重新签名——模拟"节点自己签自己的谎言"
function resign(node, env) {
  const payload = {
    v: env.v, id: env.id, ts: env.ts,
    'from.nodeId': env.from.nodeId, 'from.pubKey': env.from.pubKey,
    to: env.to, claim: env.claim, evidence: env.evidence, boundary: env.boundary, report: env.report,
  };
  return crypto.sign(null, Buffer.from(canonicalJson(payload), 'utf8'), node.privateKey).toString('base64');
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-exp-'));
const results = {};

function reset(name) {
  const p = path.join(root, name);
  fs.rmSync(p, { recursive: true, force: true });
  fs.mkdirSync(p, { recursive: true });
  return p;
}

// ---------------------------------------------------------------------------
// E01 异构节点互动：原生侦察兵 + 模拟框架节点 + 脑进程，全链入账
// ---------------------------------------------------------------------------
{
  const r = reset('e01');
  const brain = createBrain({ root: r });
  const scout = createVapNode({ nodeId: 'scout-01', root: r });
  const frameworkAgent = createVapNode({ nodeId: 'langgraph-01', root: r }); // 模拟框架节点
  scout.register();
  frameworkAgent.register();

  // 脑进程派任务
  fs.mkdirSync(path.join(r, 'inbox'), { recursive: true });
  fs.writeFileSync(path.join(r, 'inbox', 'task-1.json'), JSON.stringify({ kind: 'scan', area: 'threat-1' }));
  // 侦察兵领任务（O_EXCL）
  const task = scout.claimTask();
  const claimed = task !== null && task.taskId === '1';
  // 干活 → 完成
  const rec = scout.complete(task, { found: 'threat-57' });
  // 交战报（L2a 带证据）
  const env = scout.send({
    to: 'brain',
    claim: { type: 'report', body: { verdict: 'threat-57 severity-100' } },
    evidence: { devices: ['E01'], bills: { calls: 1 }, digest: '' },
    boundary: 'L2a',
    report: { summary: '威胁57最大', keyNumbers: [{ k: 'severity', v: 100 }], request: '' },
  });
  // 框架节点也交战报
  const env2 = frameworkAgent.send({
    to: 'brain',
    claim: { type: 'report', body: { verdict: 'threat-3 minor' } },
    evidence: { devices: ['E01'], bills: { calls: 1 }, digest: '' },
    boundary: 'L2a',
    report: { summary: '威胁3次要', keyNumbers: [{ k: 'severity', v: 10 }], request: '' },
  });
  // 脑进程裁决入账
  const verdicts = brain.consume();
  const doneFiles = fs.readdirSync(path.join(r, 'done')).filter((f) => f.startsWith('evt-') && f.endsWith('.json'));
  results.E01 = {
    claimed,
    taskCompleted: fs.existsSync(path.join(r, 'done', '1.json')),
    envelopesSent: 2,
    verdicts: verdicts.map((v) => ({ pass: v.pass })),
    envelopesInLedger: doneFiles.length,
  };
}

// ---------------------------------------------------------------------------
// E02 伪造声明拦截对照：四种伪造全部 reject 且原因正确
// ---------------------------------------------------------------------------
{
  const r = reset('e02');
  const brain = createBrain({ root: r });
  const node = createVapNode({ nodeId: 'forger', root: r });
  node.register();

  const base = node.send({
    to: 'brain',
    claim: { type: 'report', body: {} },
    evidence: { devices: ['E02'], bills: {}, digest: '' },
    boundary: 'L2a',
    report: { summary: '正常战报', keyNumbers: [], request: '' },
  });
  fs.rmSync(path.join(r, 'outbox', `${base.id}.json`)); // 撤下真信封，只放伪造件

  const forged = {};
  // F1 无签名（身份闸拦截）
  const f1 = structuredClone(base); f1.sig = ''; forged.noSig = f1;
  // F2 坏边界（签名有效，军法闸单独拦截）
  const f2 = structuredClone(base); f2.boundary = 'L9'; forged.badBoundary = f2;
  // F3 超长战报（签名有效，军法闸单独拦截）
  const f3 = structuredClone(base); f3.report.summary = '字'.repeat(101); forged.longSummary = f3;
  // F4 L2a 无证据（签名有效，边界闸单独拦截）
  const f4 = structuredClone(base); f4.evidence.devices = []; forged.l2aNoEvidence = f4;

  const out = [];
  for (const [kind, env] of Object.entries(forged)) {
    const id = `evt-${kind}`;
    env.id = id;
    if (kind !== 'noSig') env.sig = resign(node, env); // 先定 id 再签名（签名绑定 id）
    fs.writeFileSync(path.join(r, 'outbox', `${id}.json`), JSON.stringify(env, null, 2));
  }
  const verdicts = brain.consume();
  const map = Object.fromEntries(verdicts.map((v) => [v.envelopeId, v]));
  results.E02 = {
    noSig: { pass: map['evt-noSig']?.pass, reasons: map['evt-noSig']?.reasons },
    badBoundary: { pass: map['evt-badBoundary']?.pass, reasons: map['evt-badBoundary']?.reasons },
    longSummary: { pass: map['evt-longSummary']?.pass, reasons: map['evt-longSummary']?.reasons },
    l2aNoEvidence: { pass: map['evt-l2aNoEvidence']?.pass, reasons: map['evt-l2aNoEvidence']?.reasons },
  };
}

// ---------------------------------------------------------------------------
// E03 崩溃收养：三证据齐备的死现场被收养重派
// ---------------------------------------------------------------------------
{
  const r = reset('e03');
  const brain = createBrain({ root: r });
  const scout = createVapNode({ nodeId: 'scout-02', root: r });

  // 构造死现场：dead-letter 里的任务 + 锁（死 pid + 老 startSec + 老 mtime）
  const dl = path.join(r, 'dead-letter');
  fs.mkdirSync(dl, { recursive: true });
  fs.writeFileSync(path.join(dl, 'task-9.json'), JSON.stringify({ kind: 'scan', area: 'threat-9' }));
  const lockPath = path.join(dl, 'task-9.lock');
  const deadStartSec = Math.floor(Date.now() / 1000) - 120;
  fs.writeFileSync(lockPath, `dead-node:999999:${deadStartSec}`, 'utf8');
  const old = new Date(Date.now() - 120000);
  fs.utimesSync(lockPath, old, old);

  const adopted = scout.adopt();
  const republished = fs.existsSync(path.join(r, 'inbox', 'task-9.json'));
  const reclaimed = scout.claimTask();
  const completed = reclaimed ? scout.complete(reclaimed, { adopted: true }) : null;

  results.E03 = {
    adoptedCount: adopted.length,
    adoptedEvidence: adopted[0]?.evidence,
    republished,
    reclaimedTaskId: reclaimed?.taskId,
    completed,
  };
}

console.log(JSON.stringify(results, null, 2));
fs.rmSync(root, { recursive: true, force: true });
