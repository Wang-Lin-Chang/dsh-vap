// tests/vap-to.test.mjs —— VAP Phase 5 锁步 QC 链共识内核单测
//
// 运行：node --test phase5/tests/vap-to.test.mjs（在 dsh-vap/ 下）
// 复用（零改动）：vap-core（canonicalJson）、phase3（collectQC / detectDoubleSign / verifyDoubleSignEvidence）。
//
// 覆盖：轮次状态机 / 安全规则（不投冲突提案）/ 3-chain 钉死 / QC 验签 /
//       equivocation 检测+除名（除名后签名不计入）/ 视图切换携带 highestQC /
//       双花投票前拒 / 分车道 / 确定性重放 / 重启恢复。

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { canonicalJson } from '../../vap-core.mjs';
import { verifyDoubleSignEvidence } from '../../phase3/endorse-core.mjs';
import { createNode, leaderOf, hashBlock, GENESIS_HASH } from '../vap-to.mjs';

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
  const dir = ledgerDir || fs.mkdtempSync(path.join(os.tmpdir(), 'vap-to-test-'));
  const peers = IDS.map((id, i) => ({ nodeId: id, pubKey: kps[i].pubKey }));
  const nodes = IDS.map((id, i) =>
    createNode({ nodeId: id, keyPair: kps[i], n: 4, f: 1, peers, ledgerDir: dir, now }),
  );
  return { ids: IDS, keys: kps, peers, nodes, dir };
}

// 一轮：leader 提案 → 全员投票 → collectQC → commitCheck。
function round(nodes, view) {
  const ids = nodes[0].roster.map((r) => r.nodeId);
  const leaderId = leaderOf(view, ids);
  const leader = nodes.find((n) => n.nodeId === leaderId);
  const pr = leader.propose(view);
  if (pr.refused) return { view, leaderId, refused: pr.reason };
  const proposal = pr.proposal;
  const votes = [];
  for (const n of nodes) {
    const r = n.vote(proposal);
    if (r.voted) votes.push(r.vote);
  }
  let qc = null;
  if (votes.length >= 3) {
    for (const n of nodes) {
      const c = n.collectQC(votes);
      if (c.ok) qc = c.qc;
    }
  }
  const commits = [];
  for (const n of nodes) commits.push(...n.commitCheck());
  return { view, leaderId, proposal, votes: votes.length, qc, commits };
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

function tx(over = {}) {
  return { type: 'commit', from: 'client', nonce: 'nonce-1', payload: { pay: 5 }, ...over };
}

// ---------------------------------------------------------------------------
// 轮次状态机 / leader 轮换
// ---------------------------------------------------------------------------

test('leader rotation: leader = view % n and propose/view advance monotonically', () => {
  const { nodes, ids } = buildWorld();
  const sorted = nodes[0].roster.map((r) => r.nodeId);
  assert.equal(sorted[0], 'n1');
  assert.equal(leaderOf(0, sorted), 'n1');
  assert.equal(leaderOf(1, sorted), 'n2');
  assert.equal(leaderOf(3, sorted), 'n4');
  assert.equal(leaderOf(4, sorted), 'n1');

  const r = round(nodes, 0);
  assert.equal(r.refused, undefined);
  assert.equal(r.leaderId, 'n1');
  assert.equal(r.votes, 4);
  assert.equal(r.qc.view, 0);
  assert.ok(nodes.every((n) => n.view >= 0));
});

test('only the view leader may propose; stale view is refused', () => {
  const { nodes } = buildWorld();
  const n1 = nodes[0];
  const n2 = nodes[1];
  const notLeader = n2.propose(0);
  assert.equal(notLeader.refused, true);
  assert.ok(notLeader.reason.includes('not leader'));

  assert.ok(n1.propose(0).proposal);
  n1.onTimeout(); // view -> 1
  const stale = n1.propose(0);
  assert.equal(stale.refused, true);
  assert.ok(stale.reason.includes('view'));
});

// ---------------------------------------------------------------------------
// 安全规则：只投扩展本地最高 QC 的提案 / 不投冲突提案
// ---------------------------------------------------------------------------

test('safety rule refuses a proposal that does not extend local highest QC', () => {
  const { nodes } = buildWorld();
  round(nodes, 0); // QC0，highestQC = block0
  const block0 = nodes[0].highestQC.blockHash;

  // view 1 leader = n2；构造一个 parentHash 指向错误的提案。
  const n2 = nodes[1];
  const wrong = n2.signProposal({ view: 1, leader: 'n2', parentHash: 'DEADBEEF', txs: [tx()] });
  const r = nodes[0].vote(wrong);
  assert.equal(r.voted, false);
  assert.ok(r.reason.includes('parentHash'));

  // 正确的父指针 → 通过。
  const good = n2.signProposal({ view: 1, leader: 'n2', parentHash: block0, txs: [tx()] });
  assert.equal(nodes[0].vote(good).voted, true);
});

test('safety rule refuses conflicting proposals in the same view (no double vote)', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);
  const block0 = nodes[0].highestQC.blockHash;
  const n2 = nodes[1];
  const p1 = n2.signProposal({ view: 1, leader: 'n2', parentHash: block0, txs: [tx({ payload: { pay: 1 } })] });
  const p2 = n2.signProposal({ view: 1, leader: 'n2', parentHash: block0, txs: [tx({ payload: { pay: 2 } })] });

  assert.equal(nodes[0].vote(p1).voted, true); // 第一票
  const r2 = nodes[0].vote(p2); // 同 view 冲突提案
  assert.equal(r2.voted, false);
  assert.ok(r2.reason.includes('already voted'));
});

test('safety rule rejects a proposal from a wrong or expelled leader', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);
  const block0 = nodes[0].highestQC.blockHash;
  const n3 = nodes[2];
  // view 1 leader = n2，但 n3 自称 leader。
  const forgedLeader = n3.signProposal({ view: 1, leader: 'n3', parentHash: block0, txs: [tx()] });
  assert.equal(nodes[0].vote(forgedLeader).voted, false);
  assert.ok(nodes[0].vote(forgedLeader).reason.includes('leader mismatch'));

  // 除名后的 leader 提案被拒。
  nodes[0].expel('n2');
  const n2 = nodes[1];
  const p = n2.signProposal({ view: 1, leader: 'n2', parentHash: block0, txs: [tx()] });
  assert.equal(nodes[0].vote(p).voted, false);
  assert.ok(nodes[0].vote(p).reason.includes('expelled'));
});

// ---------------------------------------------------------------------------
// 3-chain 提交：2 链不提交、3 链才提交（钉死）
// ---------------------------------------------------------------------------

test('3-chain commit: no commit with 2 QCs, commit at the 3rd QC', () => {
  const { nodes } = buildWorld();

  const r0 = round(nodes, 0);
  assert.equal(r0.qc.view, 0);
  assert.equal(nodes[0].committed.length, 0);

  const r1 = round(nodes, 1);
  assert.equal(r1.qc.view, 1);
  assert.equal(nodes[0].committed.length, 0, '2 QCs must not commit');

  const r2 = round(nodes, 2);
  assert.equal(r2.qc.view, 2);
  assert.equal(nodes[0].committed.length, 1, '3 QCs must commit block 0');
  assert.equal(nodes[0].committed[0].view, 0);
  assert.equal(nodes[0].committed[0].parentHash, GENESIS_HASH);

  // 所有节点提交前缀一致。
  for (const n of nodes) {
    assert.equal(n.committed.length, 1);
    assert.equal(n.committed[0].blockHash, nodes[0].committed[0].blockHash);
  }
});

test('a non-QC fork block does not shadow the certified 3-chain', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);
  round(nodes, 1);
  round(nodes, 2); // block0 提交
  const parent = nodes[0].highestQC.blockHash;

  // view 3 leader n4 造分叉提案 fork（父指针=block2），只有 2 票 → 无 QC。
  const n4 = nodes[3];
  const fork = n4.signProposal({ view: 3, leader: 'n4', parentHash: parent, txs: [tx({ payload: { fork: true } })] });
  nodes[0].vote(fork);
  nodes[1].vote(fork);
  assert.equal(nodes[0].qcByBlockHash.has(fork.blockHash), false, 'fork must have no QC');

  // 超时切到 view 4，正常推进 views 4、5 → 认证子块绕过无 QC 的分叉，block1/block2 提交。
  for (const n of nodes) while (n.view <= 3) n.onTimeout();
  round(nodes, 4);
  round(nodes, 5);

  assert.deepEqual(nodes[0].committed.map((b) => b.view), [0, 1, 2]);
});

// ---------------------------------------------------------------------------
// QC 验签：2f+1 个体签名
// ---------------------------------------------------------------------------

test('collectQC requires 2f+1=3 valid signatures and drops forged ones', () => {
  const { nodes } = buildWorld();
  const leader = nodes[0];
  const p = leader.propose(0).proposal;
  const votes = nodes.map((n) => n.vote(p)).map((r) => r.vote); // 4 有效票

  const c2 = leader.collectQC(votes.slice(0, 2));
  assert.equal(c2.ok, false);
  assert.equal(c2.kept, 2);

  const c3 = leader.collectQC(votes.slice(0, 3));
  assert.equal(c3.ok, true);
  assert.equal(c3.qc.sigs.length, 3);
  assert.equal(c3.qc.threshold, 3);

  // 3 有效 + 1 伪造 → 伪造被丢弃，QC 仍成立（kept=3）。
  const forged = { nodeId: votes[3].nodeId, pubKey: votes[3].pubKey, sig: crypto.randomBytes(64).toString('base64') };
  const c4 = leader.collectQC([votes[0], votes[1], votes[2], forged]);
  assert.equal(c4.ok, true);
  assert.equal(c4.qc.sigs.length, 3);
});

test('verifyQC re-verifies a carried QC against the active roster', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);
  const qc0 = nodes[0].highestQC;
  assert.equal(nodes[1].verifyQC(qc0), true);
  // 篡改 QC 的 blockHash → 验签失败。
  const tampered = { ...qc0, blockHash: 'DEADBEEF' };
  assert.equal(nodes[1].verifyQC(tampered), false);
});

// ---------------------------------------------------------------------------
// equivocation 检测 + 自动除名（除名后签名不再计入）
// ---------------------------------------------------------------------------

test('equivocation detection produces third-party-verifiable evidence and auto-expels', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);
  const block0 = nodes[0].highestQC.blockHash;
  const n2 = nodes[1]; // view 1 leader
  const p1 = n2.signProposal({ view: 1, leader: 'n2', parentHash: block0, txs: [tx({ payload: { a: 1 } })] });
  const p2 = n2.signProposal({ view: 1, leader: 'n2', parentHash: block0, txs: [tx({ payload: { a: 2 } })] });

  const node = nodes[0];
  const evidence = node.detectEquivocation([p1, p2]);
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].nodeId, 'n2');
  assert.equal(evidence[0].envelopeId, '1');
  assert.ok(verifyDoubleSignEvidence(evidence[0]), 'evidence must be verifiable by any third party');
  assert.ok(node.expelled.has('n2'), 'equivocator must be auto-expelled');
});

test('expelled node signature no longer counts toward QC', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);
  const block0 = nodes[0].highestQC.blockHash;
  const n2 = nodes[1];
  const p = n2.signProposal({ view: 1, leader: 'n2', parentHash: block0, txs: [tx()] });

  const node = nodes[0];
  const r1 = node.vote(p); // node 先投一票（activeProposal = p）
  assert.equal(r1.voted, true);

  // n2 除名前：n1 + n2 + n3 = 3 → QC 成立。
  const voteN2 = rawVote(n2, p);
  const voteN3 = rawVote(nodes[2], p);
  const before = node.collectQC([r1.vote, voteN2, voteN3]);
  assert.equal(before.ok, true);

  // 除名 n2 后：同一组票里 n2 的签名被丢弃 → n1 + n3 = 2 < 3 → QC 不成立。
  node.expel('n2');
  const after = node.collectQC([r1.vote, voteN2, voteN3]);
  assert.equal(after.ok, false);
  assert.equal(after.kept, 2);
});

// ---------------------------------------------------------------------------
// 视图切换携带 highestQC
// ---------------------------------------------------------------------------

test('onTimeout advances view and carries highestQC', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);
  const qc0 = nodes[0].highestQC;
  const t = nodes[0].onTimeout();
  assert.equal(t.newView, 1);
  assert.equal(t.prevView, 0);
  assert.equal(t.carriedQC.blockHash, qc0.blockHash);

  const t2 = nodes[0].onTimeout();
  assert.equal(t2.newView, 2);
});

test('injectable clock drives timeout detection', () => {
  let t = 0;
  const fakeNow = () => new Date(t);
  const { nodes } = buildWorld({ now: fakeNow });
  const node = nodes[0];
  assert.equal(node.isTimedOut(1000), false);
  t = 1500;
  assert.equal(node.isTimedOut(1000), true);
});

// ---------------------------------------------------------------------------
// 双花：投票前拒（不进 QC）
// ---------------------------------------------------------------------------

test('double-spend is rejected at submit and at vote (before QC)', () => {
  const { nodes } = buildWorld();
  const txA = tx({ from: 'alice', nonce: 'nonce-1', payload: { pay: 5 } });
  const txB = tx({ from: 'alice', nonce: 'nonce-1', payload: { pay: 6 } });

  // 提交进 mempool：第一笔通过，第二笔（同 nonce）被拒。
  assert.equal(nodes[0].submitTx(txA).ok, true);
  const dup = nodes[0].submitTx(txB);
  assert.equal(dup.ok, false);
  assert.ok(dup.reason.includes('double-spend'));

  // 提案内出现同 nonce 两笔交易 → 投票前拒（0 票 → 不进 QC）。
  const bad = nodes[0].signProposal({ view: 0, leader: 'n1', parentHash: GENESIS_HASH, txs: [txA, txB] });
  const votes = [];
  for (const n of nodes) {
    const r = n.vote(bad);
    assert.equal(r.voted, false);
    assert.ok(r.reason.includes('double-spend'), `reason=${r.reason}`);
    if (r.voted) votes.push(r.vote);
  }
  assert.equal(votes.length, 0);
  assert.equal(nodes[0].collectQC([]).ok, false);
});

test('double-spend against committed nonce is rejected', () => {
  const { nodes } = buildWorld();
  nodes[0].submitTx(tx({ from: 'alice', nonce: 'nonce-1', payload: { pay: 5 } }));
  round(nodes, 0);
  round(nodes, 1);
  round(nodes, 2); // block0 提交（含 alice:nonce-1）

  const res = nodes[0].submitTx(tx({ from: 'alice', nonce: 'nonce-1', payload: { pay: 6 } }));
  assert.equal(res.ok, false);
  assert.ok(res.reason.includes('already committed'));
});

// ---------------------------------------------------------------------------
// 分车道：默认车道不进入总序
// ---------------------------------------------------------------------------

test('default-lane (non-commit) tx is not total-ordered', () => {
  const { nodes } = buildWorld();
  const res = nodes[0].submitTx({ type: 'report', from: 'alice', nonce: 'x', payload: {} });
  assert.equal(res.ok, false);
  assert.ok(res.reason.includes('default-lane'));

  const bad = nodes[0].signProposal({ view: 0, leader: 'n1', parentHash: GENESIS_HASH, txs: [{ type: 'report', from: 'alice', nonce: 'x' }] });
  const r = nodes[1].vote(bad);
  assert.equal(r.voted, false);
  assert.ok(r.reason.includes('default-lane'));
});

// ---------------------------------------------------------------------------
// 确定性重放
// ---------------------------------------------------------------------------

test('deterministic replay: identical keys + inputs → byte-identical ledger', () => {
  const keys = IDS.map(() => makeKeys());
  const worldA = buildWorld({ keys });
  const worldB = buildWorld({ keys });

  const run = (nodes) => {
    for (let v = 0; v < 5; v++) {
      const leaderId = leaderOf(v, nodes[0].roster.map((r) => r.nodeId));
      const leader = nodes.find((n) => n.nodeId === leaderId);
      leader.submitTx(tx({ from: 'client', nonce: `t-${v}`, payload: { seq: v } }));
      round(nodes, v);
    }
    return fs.readFileSync(path.join(nodes[0].ledgerFile), 'utf8');
  };

  const ledgerA = run(worldA.nodes);
  const ledgerB = run(worldB.nodes);
  assert.ok(ledgerA.length > 0);
  assert.equal(ledgerA, ledgerB, 'ledger bytes must be identical across replays');
});

// ---------------------------------------------------------------------------
// 重启恢复：哈希链落盘 → 恢复已提交前缀
// ---------------------------------------------------------------------------

test('restore recovers committed prefix and verifies the hash chain', () => {
  const { nodes, keys, dir } = buildWorld();
  nodes[0].submitTx(tx({ from: 'client', nonce: 't-0', payload: { seq: 0 } }));
  round(nodes, 0);
  round(nodes, 1);
  round(nodes, 2);
  const committedBefore = nodes[0].committedDigest();

  // 重启：用同样的密钥 + 同样的账本目录建新节点（内存状态清空）。
  const peers = IDS.map((id, i) => ({ nodeId: id, pubKey: keys[i].pubKey }));
  const fresh = createNode({ nodeId: 'n1', keyPair: keys[0], n: 4, f: 1, peers, ledgerDir: dir });
  const r = fresh.restore();
  assert.equal(r.restored, 1);
  assert.equal(r.blockHashes[0], committedBefore[0].blockHash);
  assert.deepEqual(fresh.committedDigest(), committedBefore);
  assert.equal(fresh.view, 1); // 从最后提交 view 继续

  // 账本链被篡改 → restore 抛错。
  const tamperDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-to-tamper-'));
  fs.copyFileSync(path.join(dir, 'ledger-n1.jsonl'), path.join(tamperDir, 'ledger-n1.jsonl'));
  const lines = fs.readFileSync(path.join(tamperDir, 'ledger-n1.jsonl'), 'utf8').split('\n').filter(Boolean);
  const rec = JSON.parse(lines[0]);
  rec.prevHash = 'TAMPERED';
  lines[0] = JSON.stringify(rec);
  fs.writeFileSync(path.join(tamperDir, 'ledger-n1.jsonl'), lines.join('\n') + '\n', 'utf8');
  const fresh2 = createNode({ nodeId: 'n1', keyPair: keys[0], n: 4, f: 1, peers, ledgerDir: tamperDir });
  assert.throws(() => fresh2.restore(), /chain broken|height mismatch|blockHash mismatch/);
});

// ---------------------------------------------------------------------------
// lock-on-vote 回归（P2）
// ---------------------------------------------------------------------------

test('vote advances lock to the parent block', () => {
  const { nodes } = buildWorld();
  round(nodes, 0); // 创世提案：父块即创世，lock 保持创世（null）
  assert.equal(nodes[0].lock, null);
  const block0 = nodes[0].highestQC.blockHash;

  const r1 = round(nodes, 1); // 投票 block1 → lock 推进到 block0
  assert.ok(r1.qc);
  for (const n of nodes) {
    assert.ok(n.lock, 'lock must be set after voting a non-genesis proposal');
    assert.equal(n.lock.blockHash, block0);
    assert.equal(n.lock.view, 0, 'lock view must equal the parent block view');
  }
});

test('lock rejects a proposal that does not extend the locked block', () => {
  const { nodes } = buildWorld();
  round(nodes, 0);
  round(nodes, 1); // 投票 block1 → node.lock = block0
  const node = nodes[0];
  assert.ok(node.lock && node.lock.blockHash);

  // 隔离 lock 检查：把 lock 推到一条与 highestQC 无关的分支（模拟此前在冲突分支投过票），
  // 再投一个正常扩展 highestQC 的提案 —— baseline 检查通过，但 lock 检查必须拒绝。
  node.lock = { blockHash: 'FOREIGN-BRANCH', view: 999 };

  const view = 2;
  const leaderId = leaderOf(view, node.roster.map((r) => r.nodeId));
  const leader = nodes.find((n) => n.nodeId === leaderId);
  const prop = leader.signProposal({ view, leader: leaderId, parentHash: node.highestQC.blockHash, txs: [] });

  const r = node.vote(prop);
  assert.equal(r.voted, false);
  assert.ok(r.reason.includes('lock'), r.reason);

  // lock 回 null（创世）后，同一提案通过。
  node.lock = null;
  assert.equal(node.vote(prop).voted, true);
});

test('isDescendant walks the parent chain correctly with cycle guard', () => {
  const { nodes } = buildWorld();
  const r0 = round(nodes, 0);
  const r1 = round(nodes, 1);
  const r2 = round(nodes, 2);
  const r3 = round(nodes, 3);
  const b0 = r0.proposal.blockHash;
  const b1 = r1.proposal.blockHash;
  const b2 = r2.proposal.blockHash;
  const b3 = r3.proposal.blockHash;
  const node = nodes[0];

  // 三代链上祖先判定。
  assert.equal(node.isDescendant(b3, b0), true, 'b0 is an ancestor of b3');
  assert.equal(node.isDescendant(b3, b1), true);
  assert.equal(node.isDescendant(b2, b0), true);
  assert.equal(node.isDescendant(b3, b3), true, 'self is its own descendant');

  // 反向 / 无关块判定 false。
  assert.equal(node.isDescendant(b0, b3), false, 'reverse is not a descendant');
  assert.equal(node.isDescendant(b3, 'UNRELATED-HASH'), false);

  // 创世祖先：一切块都扩展创世。
  assert.equal(node.isDescendant(b3, GENESIS_HASH), true);

  // 环保护：自环块在深度上限内返回 false（不挂死）。
  node.blocks.set('SELF-LOOP', {
    view: 999,
    leader: 'n1',
    parentHash: 'SELF-LOOP',
    txs: [],
    blockHash: 'SELF-LOOP',
    sig: '',
  });
  assert.equal(node.isDescendant('SELF-LOOP', 'FOREIGN'), false);
});
