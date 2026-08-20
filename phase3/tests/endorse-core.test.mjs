// tests/endorse-core.test.mjs —— Phase 3 分布式 2/3 背书单测
//
// 运行：node --test phase3/tests/endorse-core.test.mjs（在 dsh-vap/ 下）
// 复用（零改动）：vap-core（信封/三闸/canonicalJson）、phase0.5（凭证资格链）。
// gateVerify 一律注入 vap-core 的真实 verify，不 mock；三闸被真实调用。

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createVapNode, canonicalJson } from '../../vap-core.mjs';
import { createGenesisAnchor, issueCredential } from '../../phase0.5/bootstrap-forge.mjs';
import { makeTask } from '../../phase0/history-forge.mjs';
import {
  endorse,
  collectQC,
  verifyQC,
  detectDoubleSign,
  verifyDoubleSignEvidence,
  quorumThreshold,
} from '../endorse-core.mjs';

// ---------------------------------------------------------------------------
// 装置助手
// ---------------------------------------------------------------------------

function makeKeypair(id) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId: id,
    pubKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey,
  };
}

function clone(o) {
  return JSON.parse(JSON.stringify(o));
}

function setup() {
  const genesis = createGenesisAnchor();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-p3-test-'));
  const verifier = createVapNode({ nodeId: 'origin', root: tmp });
  const gateVerify = (env) => verifier.verify(env);
  const envelope = verifier.send({
    to: 'brain',
    claim: { type: 'report', body: { n: 1 } },
    evidence: { devices: ['dev-1'], bills: {}, digest: 'sha256:abc' },
    boundary: 'L0',
    report: { summary: 'phase3 test envelope', keyNumbers: [], request: '' },
  });

  const qualified = ['n1', 'n2', 'n3', 'n4'].map((id) => {
    const node = makeKeypair(id);
    const res = issueCredential({
      task: makeTask(`test-${id}`, 2),
      holder: id,
      auditors: [genesis],
      generation: 0,
    });
    assert.ok(res.ok, `issueCredential ${id}: ${res.reasons && res.reasons.join('; ')}`);
    node.credential = res.credential;
    return node;
  });

  const roster = new Map(qualified.map((n) => [n.nodeId, n.pubKey]));
  const credentialCtx = {
    genesis: { id: genesis.id, publicKey: genesis.publicKey },
    keys: new Map(qualified.map((n) => [n.nodeId, n.pubKey])),
    credentials: new Map(qualified.map((n) => [n.nodeId, n.credential])),
  };

  return { genesis, tmp, verifier, gateVerify, envelope, qualified, roster, credentialCtx };
}

// ---------------------------------------------------------------------------
// 门槛
// ---------------------------------------------------------------------------

test('quorumThreshold is ceil(2n/3)', () => {
  assert.equal(quorumThreshold(4), 3);
  assert.equal(quorumThreshold(1), 1);
  assert.equal(quorumThreshold(3), 2);
  assert.equal(quorumThreshold(5), 4);
});

// ---------------------------------------------------------------------------
// endorse：外部有效性谓词 + 资格门 + 签名
// ---------------------------------------------------------------------------

test('endorse signs envelope and returns { nodeId, pubKey, sig }', () => {
  const { envelope, qualified, gateVerify } = setup();
  const e = endorse(envelope, qualified[0], gateVerify);
  assert.equal(e.nodeId, 'n1');
  assert.equal(e.pubKey, qualified[0].pubKey);
  assert.ok(typeof e.sig === 'string' && e.sig.length > 0);
});

test('endorse refuses an envelope that fails three gates (external validity predicate)', () => {
  const { envelope, qualified, gateVerify } = setup();
  const tampered = clone(envelope);
  tampered.claim = { type: 'report', body: { tampered: true } };
  const r = endorse(tampered, qualified[0], gateVerify);
  assert.equal(r.refused, true);
  assert.ok(r.reason.length > 0);
});

test('endorse throws for endorser without qualification credential', () => {
  const { envelope, gateVerify } = setup();
  const outsider = makeKeypair('outsider');
  assert.throws(() => endorse(envelope, outsider, gateVerify), /lacks qualification credential/);
});

// ---------------------------------------------------------------------------
// collectQC：聚合 / 去重 / 验签 / 数量
// ---------------------------------------------------------------------------

test('collectQC aggregates 3 of 4 endorsements into a QC', () => {
  const { envelope, qualified, roster, gateVerify } = setup();
  const endorsements = qualified.slice(0, 3).map((n) => endorse(envelope, n, gateVerify));
  const res = collectQC({ envelope, endorsements, roster });
  assert.equal(res.ok, true);
  assert.equal(res.qc.endorsements.length, 3);
  assert.equal(res.qc.threshold, 3);
  assert.equal(res.qc.rosterSize, 4);
});

test('collectQC dedups duplicates and drops invalid signatures (insufficient)', () => {
  const { envelope, qualified, roster, gateVerify } = setup();
  const e1 = endorse(envelope, qualified[0], gateVerify);
  const e2 = endorse(envelope, qualified[1], gateVerify);
  const forged = { nodeId: 'n3', pubKey: qualified[2].pubKey, sig: crypto.randomBytes(64).toString('base64') };
  const res = collectQC({ envelope, endorsements: [e1, e2, e1, forged], roster });
  assert.equal(res.ok, false);
  assert.equal(res.kept, 2);
  assert.ok(res.reasons.some((r) => r.includes('threshold')));
});

// ---------------------------------------------------------------------------
// verifyQC：逐签 / 互异 / 数量 / 三闸重放 / 资格链
// ---------------------------------------------------------------------------

test('verifyQC passes a valid QC (real three gates, not mocked)', () => {
  const { envelope, qualified, roster, gateVerify, credentialCtx } = setup();
  const endorsements = qualified.slice(0, 3).map((n) => endorse(envelope, n, gateVerify));
  const { qc } = collectQC({ envelope, endorsements, roster });
  const res = verifyQC(qc, roster, gateVerify, credentialCtx);
  assert.equal(res.pass, true, res.reasons.join('; '));
  assert.equal(res.detail.effective, 3);
  assert.equal(res.detail.gatePass, true);
});

test('verifyQC rejects a QC containing a forged endorsement', () => {
  const { envelope, qualified, roster, gateVerify, credentialCtx } = setup();
  const endorsements = qualified.slice(0, 3).map((n) => endorse(envelope, n, gateVerify));
  const forged = { nodeId: 'n4', pubKey: qualified[3].pubKey, sig: crypto.randomBytes(64).toString('base64') };
  const qc = { envelope, endorsements: [...endorsements, forged], rosterSize: 4, threshold: 3 };
  const res = verifyQC(qc, roster, gateVerify, credentialCtx);
  assert.equal(res.pass, false);
  assert.ok(res.reasons.some((r) => r.includes("'n4' signature invalid")));
});

test('verifyQC rejects duplicate signers', () => {
  const { envelope, qualified, roster, gateVerify, credentialCtx } = setup();
  const e1 = endorse(envelope, qualified[0], gateVerify);
  const e2 = endorse(envelope, qualified[1], gateVerify);
  const e3 = endorse(envelope, qualified[2], gateVerify);
  const qc = { envelope, endorsements: [e1, e2, e3, { ...e1 }], rosterSize: 4, threshold: 3 };
  const res = verifyQC(qc, roster, gateVerify, credentialCtx);
  assert.equal(res.pass, false);
  assert.ok(res.reasons.some((r) => r.includes('duplicate endorser')));
});

test('verifyQC does not count an unqualified endorser (⑤ qualification chain)', () => {
  const { envelope, qualified, roster, gateVerify, credentialCtx } = setup();
  const outsider = makeKeypair('n5');
  const rawSig = crypto.sign(null, Buffer.from(canonicalJson(envelope), 'utf8'), outsider.privateKey).toString('base64');
  const raw = { nodeId: 'n5', pubKey: outsider.pubKey, sig: rawSig };
  const roster5 = new Map(roster);
  roster5.set('n5', outsider.pubKey);
  const e1 = endorse(envelope, qualified[0], gateVerify);
  const e2 = endorse(envelope, qualified[1], gateVerify);
  const qc = { envelope, endorsements: [e1, e2, raw], rosterSize: 5, threshold: 4 };
  const res = verifyQC(qc, roster5, gateVerify, credentialCtx);
  assert.equal(res.pass, false);
  assert.ok(res.reasons.some((r) => r.includes("'n5' has no qualification credential")));
  assert.equal(res.detail.effective, 2);
});

test('verifyQC replays three gates and rejects an envelope that fails them (④)', () => {
  const { envelope, qualified, roster, gateVerify, credentialCtx } = setup();
  const tampered = clone(envelope);
  tampered.claim = { type: 'report', body: { tampered: true } };
  // 背书签名对篡改后信封有效（逐签通过），但信封本身过不了三闸 → ④ 拦截。
  const endorsements = qualified.slice(0, 3).map((n) => ({
    nodeId: n.nodeId,
    pubKey: n.pubKey,
    sig: crypto.sign(null, Buffer.from(canonicalJson(tampered), 'utf8'), n.privateKey).toString('base64'),
  }));
  const qc = { envelope: tampered, endorsements, rosterSize: 4, threshold: 3 };
  const res = verifyQC(qc, roster, gateVerify, credentialCtx);
  assert.equal(res.pass, false);
  assert.ok(res.reasons.some((r) => r.includes('fails three gates')));
  assert.equal(res.detail.gatePass, false);
});

// ---------------------------------------------------------------------------
// detectDoubleSign：冲突证据 + 第三方可验
// ---------------------------------------------------------------------------

test('detectDoubleSign detects conflict and evidence is third-party verifiable', () => {
  const { qualified } = setup();
  const n = qualified[2];
  const envA = { v: 1, id: 'evt-X', ts: '2024-01-01T00:00:00.000Z', claim: { n: 1 } };
  const envB = { v: 1, id: 'evt-X', ts: '2024-01-01T00:00:00.000Z', claim: { n: 2 } };
  const sigA = crypto.sign(null, Buffer.from(canonicalJson(envA), 'utf8'), n.privateKey).toString('base64');
  const sigB = crypto.sign(null, Buffer.from(canonicalJson(envB), 'utf8'), n.privateKey).toString('base64');
  const evidence = detectDoubleSign([
    { nodeId: n.nodeId, pubKey: n.pubKey, envelopeId: 'evt-X', content: canonicalJson(envA), sig: sigA },
    { nodeId: n.nodeId, pubKey: n.pubKey, envelopeId: 'evt-X', content: canonicalJson(envB), sig: sigB },
  ]);
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].nodeId, n.nodeId);
  assert.ok(verifyDoubleSignEvidence(evidence[0]));
});

test('detectDoubleSign returns no evidence for identical content', () => {
  const { qualified } = setup();
  const n = qualified[0];
  const env = { v: 1, id: 'evt-Y', claim: { n: 1 } };
  const sig = crypto.sign(null, Buffer.from(canonicalJson(env), 'utf8'), n.privateKey).toString('base64');
  const evidence = detectDoubleSign([
    { nodeId: n.nodeId, pubKey: n.pubKey, envelopeId: 'evt-Y', content: canonicalJson(env), sig },
    { nodeId: n.nodeId, pubKey: n.pubKey, envelopeId: 'evt-Y', content: canonicalJson(env), sig },
  ]);
  assert.equal(evidence.length, 0);
});
