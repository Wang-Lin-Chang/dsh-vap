// experiments/vap-http-experiment.mjs —— VAP 中环 v0 跨节点实测装置
//
// 真实 HTTP 本地回环：进程内起网关（端口 0 自动分配）+ 节点 A（本地）+
// 节点 B（模拟远端，仅通过 HTTP 交互）。
// A 发 2 封信（1 真签名 + 1 伪无签名）→ B 拉取 → B 脑进程裁决 → 真入账 / 伪拦截。
// 输出结构化 JSON 结果；判定失败时以非零退出码报告，便于脚本化验收。
//
// 运行：node experiments/vap-http-experiment.mjs

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { createVapNode, createBrain, makeLaws } from '../vap-core.mjs';
import { createFileTransport, createHttpGateway, createHttpClient } from '../vap-transport.mjs';

function makeRoot(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `vap-http-${tag}-`));
  fs.writeFileSync(path.join(root, 'laws.json'), `${JSON.stringify(makeLaws(), null, 2)}\n`);
  return root;
}

async function main() {
  const rootA = makeRoot('a');
  const rootB = makeRoot('b');

  // 节点 A（本地）+ 网关（端口 0 自动分配）
  const nodeA = createVapNode({ nodeId: 'node-a', root: rootA });
  nodeA.register();
  const ftA = createFileTransport({ root: rootA });
  const gateway = createHttpGateway({ port: 0, root: rootA });
  const port = await gateway.start();

  // 节点 B（模拟远端，仅通过 HTTP 与 A 交互）+ 脑进程
  const brainB = createBrain({ root: rootB });
  const ftB = createFileTransport({ root: rootB });
  const clientB = createHttpClient({ baseUrl: `http://127.0.0.1:${port}` });

  // A 发 2 封信：1 真（签名）+ 1 伪（无签名）
  const real = nodeA.send({
    to: 'brain',
    claim: { type: 'report', body: { verdict: 'threat-42 severity-100' } },
    evidence: { devices: ['E01'], bills: { calls: 1 }, digest: '' },
    boundary: 'L2a',
    report: { summary: '跨节点实测真信封', keyNumbers: [{ k: 'severity', v: 100 }], request: '' },
  });
  const forged = structuredClone(real);
  forged.id = 'evt-forged-no-sig';
  forged.nonce = crypto.randomBytes(8).toString('hex'); // 独立 nonce：让伪信封走三闸而非被 nonce 重放短路
  forged.sig = '';
  ftA.send(forged); // 伪信封：无签名，直接落 outbox

  const healthBefore = gateway.health();

  // B 拉取 A 的出站信封
  const polled = await clientB.poll();

  const healthAfter = gateway.health();

  // B 脑进程裁决：把拉到的信封写入 B outbox 后 consume
  for (const env of polled) ftB.send(env);
  const verdicts = brainB.consume();
  const byId = Object.fromEntries(verdicts.map((v) => [v.envelopeId, v]));

  const realVerdict = byId[real.id];
  const forgedVerdict = byId['evt-forged-no-sig'];

  const realCredited = Boolean(realVerdict && realVerdict.pass) &&
    fs.existsSync(path.join(rootB, 'done', `${real.id}.json`));
  const forgedIntercepted = Boolean(forgedVerdict && !forgedVerdict.pass);

  const result = {
    experiment: 'vap-http-experiment',
    gateway: {
      port,
      healthBefore,
      healthAfter,
    },
    sent: {
      real: { id: real.id, signed: Boolean(real.sig) },
      forged: { id: forged.id, signed: Boolean(forged.sig) },
    },
    polled: {
      count: polled.length,
      ids: polled.map((e) => e.id),
    },
    verdicts: {
      real: {
        pass: realVerdict ? realVerdict.pass : null,
        reasons: realVerdict ? realVerdict.reasons : null,
        credited: realCredited,
      },
      forged: {
        pass: forgedVerdict ? forgedVerdict.pass : null,
        reasons: forgedVerdict ? forgedVerdict.reasons : null,
      },
    },
    summary: {
      realCredited,
      forgedIntercepted,
    },
  };

  console.log(JSON.stringify(result, null, 2));

  await gateway.stop();
  fs.rmSync(rootA, { recursive: true, force: true });
  fs.rmSync(rootB, { recursive: true, force: true });

  if (!realCredited || !forgedIntercepted) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(JSON.stringify({
    experiment: 'vap-http-experiment',
    error: String((err && err.message) || err),
  }, null, 2));
  process.exitCode = 1;
});
