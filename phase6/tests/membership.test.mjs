// tests/membership.test.mjs —— VAP Phase 6 动态成员 + 军法上链单测
//
// 运行：node --test phase6/tests/membership.test.mjs（在 dsh-vap/ 下）
// 复用（零改动）：vap-core（canonicalJson / createVapNode）、phase0.5（createGenesisAnchor / issueCredential）、
//                phase0（makeTask）、phase3（verifyDoubleSignEvidence）、phase5（leaderOf / hashBlock / GENESIS_HASH）。
//
// 覆盖：加入（资格无效拒 / 2/3 背书 h+2 生效）/ 除名（签名立即不计入 + roster 延迟 2 块）/
//       密钥轮换（旧钥失效新钥生效）/ 军法投票前拒（invalid 信封 0 票）/ 延迟窗口无中断推进。

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createVapNode, canonicalJson } from '../../vap-core.mjs';
import { createGenesisAnchor, issueCredential } from '../../phase0.5/bootstrap-forge.mjs';
import { makeTask } from '../../phase0/history-forge.mjs';
import { verifyDoubleSignEvidence } from '../../phase3/endorse-core.mjs';
import { leaderOf, hashBlock, GENESIS_HASH } from '../../phase5/vap-to.mjs';
import { createMembershipNode } from '../vap-to-membership.mjs';

// ---------------------------------------------------------------------------
// 装置助手
// ---------------------------------------------------------------------------

function makeKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey,
    privateKey,
    pubKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}

const IDS = ['n1', 'n2', 'n3', 'n4'];

function buildWorld({ keys, ledgerDir, now } = {}) {
  const kps = keys || IDS.map(() => makeKeys());
  const dir = ledgerDir || fs.mkdtempSync(path.join(os.tmpdir(), 'vap-mem-test-'));
  const peers = IDS.map((id, i) => ({ nodeId: id, pubKey: kps[i].pubKey }));
  const genesis = createGenesisAnchor();
  const credentialCtx = { genesis: { id: genesis.id, publicKey: genesis.publicKey }, keys: new Map(), credentials: new Map() };
  const nodes = IDS.map((id, i) =>
    createMembershipNode({ nodeId: id, keyPair: kps[i], n: 4, f: 1, peers, ledgerDir: dir, now, credentialCtx }),
  );
  return { ids: IDS, keys: kps, peers, nodes, dir, genesis, credentialCtx };
}

function tx(over = {}) {
  return { type: 'commit', from: 'client', nonce: 'nonce-1', payload: { pay: 5 }, ...over };
}

function sortedIds(nodes) {
  return nodes[0].roster.map((r) => r.nodeId);
}

// 一轮：leader 提案 → 全员投票 → collectQC → commitCheck。
// opts.tx 会在提案前提交给该轮 leader；opts.voters 指定投票节点（缺省全员）。
function round(nodes, view, opts = {}) {
  const leaderId = leaderOf(view, sortedIds(nodes));
  const leader = nodes.find((n) => n.nodeId === leaderId);
  if (!leader) return { view, leaderId, refused: 'no leader' };
  if (opts.tx) {
    const sr = leader.submitTx(opts.tx);
    if (!sr.ok) return { view, leaderId, submitRefused: sr.reason };
  }
  const pr = leader.propose(view);
  if (pr.refused) return { view, leaderId, refused: pr.reason };
  const proposal = pr.proposal;
  const voters = opts.voters || nodes;
  const votes = [];
  for (const n of voters) {
    const r = n.vote(proposal);
    if (r.voted) votes.push(r.vote);
  }
  let qc = null;
  const threshold = nodes[0].threshold;
  if (votes.length >= threshold) {
    for (const n of nodes) {
      const c = n.collectQC(votes);
      if (c.ok) qc = c.qc;
    }
  }
  const commits = [];
  for (const n of nodes) commits.push(...n.commitCheck());
  return { view, leaderId, votes: votes.length, qc, commits };
}

// 手工构造一票（绕过 vote 的安全规则，用于拜占庭夹具）。
function rawVote(node, proposal) {
  const target = canonicalJson({
    view: proposal.view,
    blockHash: proposal.blockHash,
    parentHash: proposal.parentHash,
  });
  const sig = crypto.sign(null, Buffer.from(target, 'utf8'), node.privateKey).toString('base64');
  return { nodeId: node.nodeId, pubKey: node.pubKey, sig };
}

// 越过指定 view（推进到大于 view，供拜占庭/除名场景跳过坏视图）。
function skipView(nodes, view) {
  for (const n of nodes) {
    while (n.view <= view) n.onTimeout();
  }
  return nodes[0].view;
}

// ---------------------------------------------------------------------------
// 加入：资格凭证回验 + 2/3 背书 + h+2 生效
// ---------------------------------------------------------------------------

test('proposeJoin rejects invalid credential and accepts a valid one', () => {
  const { nodes, genesis } = buildWorld();
  const n5keys = makeKeys();
  const valid = issueCredential({ task: makeTask('join-ok', 2), holder: 'n5', auditors: [genesis], generation: 0 });
  assert.equal(valid.ok, true);

  // 有效凭证 → 打包 join 交易。
  const ok = nodes[0].proposeJoin({
    nodeId: 'n5',
    pubKey: n5keys.pubKey,
    credential: valid.credential,
    privateKey: n5keys.privateKey,
  });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.tx.type, 'membership');
  assert.equal(ok.tx.op, 'join');

  // 篡改凭证（改 holder）→ 资格回验失败，拒绝。
  const tampered = JSON.parse(JSON.stringify(valid.credential));
  tampered.holder = 'n6';
  const bad = nodes[0].proposeJoin({ nodeId: 'n5', pubKey: n5keys.pubKey, credential: tampered, privateKey: n5keys.privateKey });
  assert.equal(bad.ok, false);
  assert.ok(bad.reason.includes('credential'), bad.reason);
});

test('join activates at h+2 with 2/3 endorsement (roster 4→5, f/threshold recomputed)', () => {
  const { nodes, genesis } = buildWorld();
  const n5keys = makeKeys();
  const credRes = issueCredential({ task: makeTask('join-n5', 2), holder: 'n5', auditors: [genesis], generation: 0 });
  assert.equal(credRes.ok, true);

  round(nodes, 0);
  round(nodes, 1);
  round(nodes, 2);
  assert.equal(nodes[0].committed.length, 1);

  const join = nodes[0].proposeJoin({
    nodeId: 'n5',
    pubKey: n5keys.pubKey,
    credential: credRes.credential,
    privateKey: n5keys.privateKey,
  });
  assert.equal(join.ok, true);
  const endorsements = [];
  for (const n of nodes.slice(0, 3)) {
    const e = n.endorseJoin(join.tx);
    assert.equal(e.ok, true, e.reason);
    endorsements.push(e.endorsement);
  }
  join.tx.endorsements = endorsements;

  // 注入 view 3（leader n4），跑 rounds 3,4,5 → view3（join）在 height 3 提交。
  round(nodes, 3, { tx: join.tx });
  round(nodes, 4);
  round(nodes, 5);
  assert.ok(nodes[0].committed.some((b) => b.view === 3), 'view3 (join) block must be committed');
  assert.equal(nodes[0].roster.length, 4, 'roster must stay 4 before h+2');

  // 再来 1 块（height 4）→ committedHeight 达 h+2 → roster 切到 5。
  round(nodes, 6);
  assert.equal(nodes[0].roster.length, 5, 'roster must be 5 after h+2');
  assert.equal(nodes[0].n, 5);
  assert.equal(nodes[0].f, 1);
  assert.equal(nodes[0].threshold, 4, 'TLC 修正：N=5 门槛 = max(2f+1, ⌈2n/3⌉) = 4');
  assert.ok(nodes[0].peerMap.has('n5'));
});

test('join with insufficient endorsement gets 0 votes (2/3 not met)', () => {
  const { nodes, genesis } = buildWorld();
  const n5keys = makeKeys();
  const credRes = issueCredential({ task: makeTask('join-few', 2), holder: 'n5', auditors: [genesis], generation: 0 });
  assert.equal(credRes.ok, true);

  round(nodes, 0);

  const join = nodes[0].proposeJoin({
    nodeId: 'n5',
    pubKey: n5keys.pubKey,
    credential: credRes.credential,
    privateKey: n5keys.privateKey,
  });
  const endorsements = [];
  for (const n of nodes.slice(0, 2)) { // 只有 2 票 < ceil(2*4/3)=3
    const e = n.endorseJoin(join.tx);
    endorsements.push(e.endorsement);
  }
  join.tx.endorsements = endorsements;

  const r = round(nodes, 1, { tx: join.tx });
  assert.equal(r.votes, 0, 'join with 2/4 endorsement must get 0 votes');
  assert.equal(r.qc, null);
});

// ---------------------------------------------------------------------------
// 除名：equivocation slash 上链 → 签名立即不计入 + roster 延迟 2 块
// ---------------------------------------------------------------------------

test('slash commit → signature immediately not counted, roster delayed 2 blocks', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);
  round(nodes, 1);
  round(nodes, 2);
  const parent = nodes[0].highestQC.blockHash; // view2 块哈希

  // view 3 leader = n4，双签两个冲突提案。
  const n4 = nodes[3];
  const p1 = n4.signProposal({ view: 3, leader: 'n4', parentHash: parent, txs: [tx({ payload: { a: 1 } })] });
  const p2 = n4.signProposal({ view: 3, leader: 'n4', parentHash: parent, txs: [tx({ payload: { a: 2 } })] });

  const evidence = nodes[0].detectEquivocation([p1, p2]);
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].nodeId, 'n4');
  assert.ok(verifyDoubleSignEvidence(evidence[0]));

  // n1 举报 → 打包 slash 交易（不自动提交；由 n1 作为 view4 leader 提交）。
  const slash = nodes[0].expelByEquivocation(evidence[0]);
  assert.equal(slash.ok, true, slash.reason);

  // 越过坏视图 3，推进 views 4,5,6 → view4（slash）在 height 3 提交。
  skipView(nodes, 3);
  round(nodes, 4, { tx: slash.tx, voters: [nodes[0], nodes[1], nodes[2]] });
  round(nodes, 5, { voters: [nodes[0], nodes[1], nodes[2]] });
  round(nodes, 6, { voters: [nodes[0], nodes[1], nodes[2]] });

  // slash 已提交：n4 签名立即不计入，但 roster 表仍含 n4（延迟）。
  assert.ok(nodes[0].expelled.has('n4'), 'equivocator must be expelled at slash commit');
  assert.equal(nodes[0].roster.length, 4, 'roster table must still contain n4 (delayed)');
  assert.equal(nodes[0].threshold, 3);

  // 除名后：n1+n2+n4 三票里 n4 被丢弃 → 2 < 3 → QC 不成立。
  const propAfter = nodes[0].signProposal({ view: 8, leader: 'n1', parentHash: nodes[0].highestQC.blockHash, txs: [] });
  const self = nodes[0].vote(propAfter);
  assert.equal(self.voted, true);
  const after = nodes[0].collectQC([rawVote(nodes[0], propAfter), rawVote(nodes[1], propAfter), rawVote(nodes[3], propAfter)]);
  assert.equal(after.ok, false, 'n4 sig must not count after slash commit');
  assert.equal(after.kept, 2);

  // h+2 后 roster 掉 n4 → n=3、f=0、threshold=max(2f+1, ⌈2n/3⌉)=2（TLC 修正）。
  round(nodes, 9, { voters: [nodes[0], nodes[1], nodes[2]] });
  round(nodes, 10, { voters: [nodes[0], nodes[1], nodes[2]] });
  assert.equal(nodes[0].roster.length, 3, 'roster must drop n4 after h+2');
  assert.equal(nodes[0].n, 3);
  assert.equal(nodes[0].f, 0);
  assert.equal(nodes[0].threshold, 2);
});

// ---------------------------------------------------------------------------
// 密钥轮换：旧钥签变更交易 → h+2 新钥生效（旧钥签名被拒、新钥签名有效）
// ---------------------------------------------------------------------------

test('rotateKey: old key signs change, new key valid and old key rejected after h+2', () => {
  const { nodes, keys } = buildWorld();
  round(nodes, 0);
  round(nodes, 1);
  round(nodes, 2);

  const n3 = nodes[2];
  const oldPubKey = n3.pubKey;
  const oldPrivateKey = keys[2].privateKey;
  const newKeys = makeKeys();

  const rot = n3.rotateKey({ oldPubKey, newPubKey: newKeys.pubKey, newPrivateKey: newKeys.privateKey });
  assert.equal(rot.ok, true, rot.reason);

  round(nodes, 3, { tx: rot.tx });
  round(nodes, 4);
  round(nodes, 5); // rotate 提交（height 3）
  assert.equal(nodes[0].peerMap.get('n3'), oldPubKey, 'old key still active before h+2');

  round(nodes, 6); // height 4 提交 → h+2 到达 → 换钥
  assert.equal(nodes[0].peerMap.get('n3'), newKeys.pubKey, 'new key must be active after h+2');
  assert.equal(n3.pubKey, newKeys.pubKey, 'rotating node must swap to new key');

  // 旧钥签名被拒：用旧钥签一个 leader=n3 的提案（view 10，10%4=2=n3）。
  const v = 10;
  assert.equal(leaderOf(v, nodes[0].roster.map((r) => r.nodeId)), 'n3');
  const parent = nodes[0].highestQC.blockHash;
  const content = { view: v, leader: 'n3', parentHash: parent, txs: [] };
  const staleKeyProposal = { ...content, sig: '' };
  staleKeyProposal.blockHash = hashBlock(staleKeyProposal);
  staleKeyProposal.sig = crypto.sign(null, Buffer.from(canonicalJson(content), 'utf8'), oldPrivateKey).toString('base64');
  const rejected = nodes[0].vote(staleKeyProposal);
  assert.equal(rejected.voted, false);
  assert.ok(rejected.reason.includes('leader signature'), rejected.reason);

  // 新钥签名有效：n3（已持新钥）作为 leader 提案 → 诚实节点接受签名。
  const pr = n3.propose(v);
  assert.ok(pr.proposal, 'n3 must be able to propose as leader with new key');
  const accepted = nodes[0].vote(pr.proposal);
  assert.equal(accepted.voted, true, accepted.reason);
});

// ---------------------------------------------------------------------------
// 军法投票前谓词：invalid 信封 0 票（不进 QC）
// ---------------------------------------------------------------------------

test('laws as vote-before predicate: invalid envelope gets 0 votes (not in QC)', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);

  // 用 vap-core 签发一封超长战报（send 不校验长度，签名有效 → SIG_REQUIRED 过）。
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-mem-env-'));
  const vap = createVapNode({ nodeId: 'n1', root: tmp });
  const env = vap.send({
    to: 'brain',
    claim: { type: 'report', body: { n: 1 } },
    evidence: { devices: ['dev-1'], bills: {}, digest: 'sha256:abc' },
    boundary: 'L0',
    report: { summary: 'x'.repeat(120), keyNumbers: [], request: '' },
  });

  // 信封包成 op=report 窄车道交易；vote 前军法谓词 SUMMARY_BOUND 拒绝 → 0 票。
  const submit = nodes[0].wrapEnvelope(env);
  assert.equal(submit.ok, true, submit.reason);
  const r = round(nodes, 1, { tx: submit.tx });
  assert.equal(r.votes, 0, 'invalid envelope must get 0 votes');
  assert.equal(r.qc, null, 'invalid envelope must not enter QC');

  // 逐条军法谓词：SUMMARY_BOUND 失败，SIG_REQUIRED/BOUNDARY_VALID 通过。
  const laws = nodes[0].checkLaws(env);
  assert.equal(laws.pass, false);
  const summaryRule = laws.rules.find((x) => x.id === 'SUMMARY_BOUND');
  assert.equal(summaryRule.ok, false);
  const sigRule = laws.rules.find((x) => x.id === 'SIG_REQUIRED');
  assert.equal(sigRule.ok, true, 'envelope signature must still verify');
});

// ---------------------------------------------------------------------------
// 延迟窗口：变更提交后、生效前，旧 roster 无中断推进
// ---------------------------------------------------------------------------

test('delay window advances without interruption (old roster 2 blocks)', () => {
  const { nodes, genesis } = buildWorld();
  const n5keys = makeKeys();
  const credRes = issueCredential({ task: makeTask('window-n5', 2), holder: 'n5', auditors: [genesis], generation: 0 });
  assert.equal(credRes.ok, true);

  round(nodes, 0);
  round(nodes, 1);
  round(nodes, 2);

  const join = nodes[0].proposeJoin({
    nodeId: 'n5',
    pubKey: n5keys.pubKey,
    credential: credRes.credential,
    privateKey: n5keys.privateKey,
  });
  const endorsements = [];
  for (const n of nodes.slice(0, 3)) {
    const e = n.endorseJoin(join.tx);
    assert.equal(e.ok, true);
    endorsements.push(e.endorsement);
  }
  join.tx.endorsements = endorsements;

  round(nodes, 3, { tx: join.tx });
  round(nodes, 4);
  round(nodes, 5); // join 提交（height 3），roster 仍 4。
  assert.equal(nodes[0].roster.length, 4, 'roster must stay 4 at join commit');

  // 窗口块（height 4）：旧 roster 照常推进（4 票、成 QC，无中断）。
  const r6 = round(nodes, 6);
  assert.equal(r6.votes, 4, 'window block must gather 4 votes on old roster');
  assert.ok(r6.qc, 'window block must form QC (no interruption)');
  assert.equal(nodes[0].roster.length, 5, 'roster switches to 5 after window');

  // 切换后继续推进（新 roster 5，现有 4 个节点对象仍达 threshold 3）。
  const r7 = round(nodes, 7);
  assert.ok(r7.votes >= 3, 'consensus must keep advancing after roster switch');
});
