// experiments/phase5-experiment.mjs —— VAP Phase 5 锁步 QC 链共识实测装置（T1-T6）
//
// 运行：node phase5/experiments/phase5-experiment.mjs（在 dsh-vap/ 下）
// 输出：结构化 JSON（stdout + phase5/experiments/phase5-results.json）
//
// T1 正常收敛：4 节点连续 10 轮 → 全节点提交前缀逐字节一致
// T2 崩溃容错：kill 当前 leader → 视图切换 → 新 leader 在超时后提交，已提交前缀不回滚
// T3 分叉注入：拜占庭 leader 对 2 节点发 P1、对 2 节点发 P2 → 至多一支 commit + 证据产出 + 自动除名
// T4 双花拒绝：同 nonce 两交易 → 第二笔被安全规则拒绝（投票前拒，不进 QC）
// T5 确定性重放：同输入跑两次 → 账本逐字节一致
// T6 重启恢复：杀进程重启 → 从磁盘恢复已提交前缀继续推进
//
// 复用（零改动）：vap-core（canonicalJson）、phase3（verifyDoubleSignEvidence）。
// 零第三方依赖：仅 node: 内置模块与相对路径 import。

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../vap-core.mjs';
import { verifyDoubleSignEvidence } from '../../phase3/endorse-core.mjs';
import { createNode, leaderOf, GENESIS_HASH } from '../vap-to.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IDS = ['n1', 'n2', 'n3', 'n4'];
const N = 4;
const F = 1;
const THRESHOLD = 2 * F + 1;

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

function buildWorld({ keys, ledgerDir } = {}) {
  const kps = keys || IDS.map(() => makeKeys());
  const dir = ledgerDir || fs.mkdtempSync(path.join(os.tmpdir(), 'vap-phase5-'));
  const peers = IDS.map((id, i) => ({ nodeId: id, pubKey: kps[i].pubKey }));
  const nodes = IDS.map((id, i) =>
    createNode({ nodeId: id, keyPair: kps[i], n: N, f: F, peers, ledgerDir: dir }),
  );
  return { ids: IDS, keys: kps, peers, nodes, dir };
}

function sortedIds(nodes) {
  return nodes[0].roster.map((r) => r.nodeId);
}

function round(nodes, view) {
  const leaderId = leaderOf(view, sortedIds(nodes));
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
  if (votes.length >= THRESHOLD) {
    for (const n of nodes) {
      const c = n.collectQC(votes);
      if (c.ok) qc = c.qc;
    }
  }
  const commits = [];
  for (const n of nodes) commits.push(...n.commitCheck());
  return { view, leaderId, proposal, votes: votes.length, qc, commits };
}

function submitToLeader(nodes, view, tx) {
  const leaderId = leaderOf(view, sortedIds(nodes));
  const leader = nodes.find((n) => n.nodeId === leaderId);
  return leader.submitTx(tx);
}

function committedDigestOf(nodes) {
  return JSON.stringify(nodes[0].committedDigest());
}

// 越过 crashed view：把所有节点的 view 推进到大于 view。
function skipView(nodes, view) {
  for (const n of nodes) {
    while (n.view <= view) n.onTimeout();
  }
  return nodes[0].view;
}

// 收敛序列：每轮向 leader 注入一笔确定性窄车道交易，跑 rounds 轮。
function runConvergence(nodes, rounds, label) {
  for (let v = 0; v < rounds; v++) {
    submitToLeader(nodes, v, { type: 'commit', from: 'client', nonce: `${label}-${v}`, payload: { seq: v } });
    round(nodes, v);
  }
  return nodes;
}

// ---------------------------------------------------------------------------
// T1 正常收敛：10 轮 → 全节点提交前缀逐字节一致
// ---------------------------------------------------------------------------

function experimentT1() {
  const w = buildWorld();
  runConvergence(w.nodes, 10, 't1');
  const digests = w.nodes.map((n) => JSON.stringify(n.committedDigest()));
  const allIdentical = digests.every((d) => d === digests[0]);
  const committed = w.nodes[0].committed;
  return {
    label: 'normal convergence (10 rounds)',
    rounds: 10,
    committedBlocks: committed.length,
    committedViews: committed.map((b) => b.view),
    firstBlockHash: committed[0] ? committed[0].blockHash : null,
    lastBlockHash: committed[committed.length - 1] ? committed[committed.length - 1].blockHash : null,
    allNodesIdenticalPrefix: allIdentical,
    pass: allIdentical && committed.length === 8,
  };
}

// ---------------------------------------------------------------------------
// T2 崩溃容错：kill 当前 leader → 视图切换 → 新 leader 提交，前缀不回滚
// ---------------------------------------------------------------------------

function experimentT2() {
  const w = buildWorld();
  round(w.nodes, 0);
  round(w.nodes, 1);
  round(w.nodes, 2); // block0 提交（3-chain）
  const beforeCrash = w.nodes[0].committedDigest();

  // view 3 leader = n4 崩溃：不提案；节点超时切换视图。
  const crashedView = 3;
  const crashedLeader = leaderOf(crashedView, sortedIds(w.nodes));
  const newView = skipView(w.nodes, crashedView);

  // 新 leader 在超时后继续推进：views 4、5 → 3-chain 提交 block2（含 block1）。
  round(w.nodes, newView);
  round(w.nodes, newView + 1);

  const afterRecovery = w.nodes[0].committedDigest();
  const prefixNotRolledBack =
    afterRecovery.length >= beforeCrash.length &&
    JSON.stringify(afterRecovery.slice(0, beforeCrash.length)) === JSON.stringify(beforeCrash);
  const recoveryCommittedViews = w.nodes[0].committed.map((b) => b.view);
  const newLeaderCommitted = afterRecovery.length > beforeCrash.length;

  return {
    label: 'crash fault tolerance',
    crashedView,
    crashedLeader,
    newViewAfterTimeout: newView,
    committedBeforeCrashViews: beforeCrash.map((b) => b.view),
    committedAfterRecoveryViews: recoveryCommittedViews,
    prefixNotRolledBack,
    newLeaderCommitted,
    pass: prefixNotRolledBack && newLeaderCommitted,
  };
}

// ---------------------------------------------------------------------------
// T3 分叉注入：拜占庭 leader 双提案 → 至多一支 commit + 证据 + 自动除名
// ---------------------------------------------------------------------------

function experimentT3() {
  const w = buildWorld();
  round(w.nodes, 0);
  round(w.nodes, 1);
  round(w.nodes, 2); // block0 提交
  const parentHash = w.nodes[0].highestQC.blockHash;

  // view 3 leader = n4（拜占庭）：对 2 节点发 P1、对 2 节点发 P2。
  const forkView = 3;
  const byz = w.nodes.find((n) => n.nodeId === leaderOf(forkView, sortedIds(w.nodes)));
  const txA = { type: 'commit', from: 'alice', nonce: 'fork-a', payload: { branch: 'A' } };
  const txB = { type: 'commit', from: 'alice', nonce: 'fork-b', payload: { branch: 'B' } };
  const P1 = byz.signProposal({ view: forkView, leader: byz.nodeId, parentHash, txs: [txA] });
  const P2 = byz.signProposal({ view: forkView, leader: byz.nodeId, parentHash, txs: [txB] });

  // 2 节点投 P1，2 节点投 P2（拜占庭 leader 本人弃票）。
  const recipientsP1 = [w.nodes[0], w.nodes[1]];
  const recipientsP2 = [w.nodes[2], w.nodes[3]];
  const votesP1 = recipientsP1.map((n) => n.vote(P1)).filter((r) => r.voted).map((r) => r.vote);
  const votesP2 = recipientsP2.map((n) => n.vote(P2)).filter((r) => r.voted).map((r) => r.vote);

  // 两支都拿不到 2f+1=3 → 无 QC。
  const qcP1 = w.nodes[0].collectQC(votesP1);
  const qcP2 = w.nodes[2].collectQC(votesP2);

  // 全部节点广播并检测 equivocation → 证据 + 自动除名 n4。
  const evidences = w.nodes.map((n) => n.detectEquivocation([P1, P2]));
  const evidence = evidences.find((e) => e.length > 0);
  const evidenceCount = evidence ? evidence.length : 0;
  const equivocator = evidence ? evidence[0].nodeId : null;
  const evidenceVerifiable = evidence ? verifyDoubleSignEvidence(evidence[0]) : false;
  const allExpelled = w.nodes.every((n) => n.expelled.has(byz.nodeId));

  // 分叉未产生任何提交（至多一支：实为 0 支）。
  const forkCommittedViews = w.nodes[0].committed.map((b) => b.view);
  const branchesCommitted = forkCommittedViews.filter((v) => v === forkView).length;

  // 除名后继续：视图切换 → views 4、5；n4 的签名不再计入 QC（3 诚实节点仍达 3）。
  const newView = skipView(w.nodes, forkView);
  const pr4 = round(w.nodes, newView);
  const postExpelSigCount = pr4.qc ? pr4.qc.sigs.length : 0;
  const postExpelSigs = pr4.qc ? pr4.qc.sigs.map((s) => s.nodeId).sort() : [];
  round(w.nodes, newView + 1);
  const finalCommittedViews = w.nodes[0].committed.map((b) => b.view);

  return {
    label: 'fork injection + equivocation expulsion',
    forkView,
    byzantineLeader: byz.nodeId,
    distinctForkBlockHashes: P1.blockHash !== P2.blockHash,
    p1Votes: votesP1.length,
    p2Votes: votesP2.length,
    qcAtForkView: !!(qcP1.ok || qcP2.ok),
    equivocationEvidenceCount: evidenceCount,
    equivocator,
    evidenceVerifiable,
    autoExpelled: allExpelled,
    branchesCommittedFromFork: branchesCommitted,
    postExpelQcSigs: postExpelSigs,
    postExpelQcSigCount: postExpelSigCount,
    finalCommittedViews,
    pass:
      P1.blockHash !== P2.blockHash &&
      !(qcP1.ok || qcP2.ok) &&
      evidenceCount === 1 &&
      evidenceVerifiable &&
      allExpelled &&
      branchesCommitted === 0 &&
      postExpelSigs.length === THRESHOLD,
  };
}

// ---------------------------------------------------------------------------
// T4 双花拒绝：同 nonce 两交易 → 第二笔在投票前被拒
// ---------------------------------------------------------------------------

function experimentT4() {
  const w = buildWorld();
  // 先提交一笔窄车道交易。
  submitToLeader(w.nodes, 0, { type: 'commit', from: 'alice', nonce: 'ds-1', payload: { pay: 5 } });
  round(w.nodes, 0);
  round(w.nodes, 1);
  round(w.nodes, 2); // block0 提交（含 alice:ds-1）

  // 同 nonce 第二笔（不同内容 = 双花）在 mempool 层被拒。
  const second = submitToLeader(w.nodes, 3, { type: 'commit', from: 'alice', nonce: 'ds-1', payload: { pay: 6 } });
  const mempoolRejected = second.ok === false && second.reason.includes('double-spend');

  // 拜占庭 leader 直接把双花交易塞进提案 → 投票前拒（0 票 → 不进 QC）。
  const parent = w.nodes[0].highestQC.blockHash;
  const badTx = { type: 'commit', from: 'alice', nonce: 'ds-1', payload: { pay: 6 } };
  const byzLeaderId = leaderOf(3, sortedIds(w.nodes));
  const byz = w.nodes.find((n) => n.nodeId === byzLeaderId);
  const bad = byz.signProposal({ view: 3, leader: byz.nodeId, parentHash: parent, txs: [badTx] });
  const votes = [];
  for (const n of w.nodes) {
    const r = n.vote(bad);
    if (r.voted) votes.push(r.vote);
  }
  const qc = w.nodes[0].collectQC(votes);

  return {
    label: 'double-spend rejection',
    nonce: 'alice:ds-1',
    mempoolRejected,
    votesOnDoubleSpendProposal: votes.length,
    doubleSpendEnteredQc: qc.ok,
    rejectedBeforeVote: mempoolRejected && votes.length === 0 && qc.ok === false,
    pass: mempoolRejected && votes.length === 0 && qc.ok === false,
  };
}

// ---------------------------------------------------------------------------
// T5 确定性重放：同输入跑两次 → 账本逐字节一致
// ---------------------------------------------------------------------------

function experimentT5() {
  const keys = IDS.map(() => makeKeys());
  const wA = buildWorld({ keys });
  const wB = buildWorld({ keys });
  runConvergence(wA.nodes, 6, 't5');
  runConvergence(wB.nodes, 6, 't5');
  const ledgerA = fs.readFileSync(wA.nodes[0].ledgerFile, 'utf8');
  const ledgerB = fs.readFileSync(wB.nodes[0].ledgerFile, 'utf8');
  const identical = ledgerA === ledgerB;
  return {
    label: 'deterministic replay',
    rounds: 6,
    ledgerBytesA: Buffer.byteLength(ledgerA, 'utf8'),
    ledgerBytesB: Buffer.byteLength(ledgerB, 'utf8'),
    ledgerSha256A: crypto.createHash('sha256').update(ledgerA, 'utf8').digest('hex'),
    ledgerSha256B: crypto.createHash('sha256').update(ledgerB, 'utf8').digest('hex'),
    byteIdentical: identical,
    pass: identical && ledgerA.length > 0,
  };
}

// ---------------------------------------------------------------------------
// T6 重启恢复：杀进程重启 → 从磁盘恢复已提交前缀继续推进
// ---------------------------------------------------------------------------

function experimentT6() {
  const w = buildWorld();
  runConvergence(w.nodes, 6, 't6'); // 6 轮 → 提交 blocks 0..3
  const beforeRestart = w.nodes[0].committedDigest();

  // 杀进程重启：同样密钥 + 同样账本目录，全新内存状态。
  const peers = IDS.map((id, i) => ({ nodeId: id, pubKey: w.keys[i].pubKey }));
  const fresh = IDS.map((id, i) =>
    createNode({ nodeId: id, keyPair: w.keys[i], n: N, f: F, peers, ledgerDir: w.dir }),
  );
  const restores = fresh.map((n) => n.restore());
  const recoveredIdentical = fresh.every(
    (n) => JSON.stringify(n.committedDigest()) === JSON.stringify(beforeRestart),
  );
  const recoveredBlocks = restores[0].restored;

  // 继续推进：恢复出的节点从已提交前缀继续 views 4、5、6 → 提交 block4。
  const lastCommitted = fresh[0].committed[fresh[0].committed.length - 1];
  const continueFrom = fresh[0].view; // = lastCommittedView + 1
  submitToLeader(fresh, continueFrom, { type: 'commit', from: 'client', nonce: 't6-continue', payload: { seq: 99 } });
  round(fresh, continueFrom);
  round(fresh, continueFrom + 1);
  round(fresh, continueFrom + 2);
  const newCommit = fresh[0].committed[fresh[0].committed.length - 1];
  const extendedRecoveredPrefix = newCommit.parentHash === lastCommitted.blockHash;

  return {
    label: 'restart recovery',
    roundsBeforeRestart: 6,
    recoveredBlocks,
    recoveredIdentical,
    continueFromView: continueFrom,
    newlyCommittedView: newCommit.view,
    newlyCommittedParentHash: newCommit.parentHash,
    lastRecoveredBlockHash: lastCommitted.blockHash,
    extendedRecoveredPrefix,
    pass: recoveredIdentical && recoveredBlocks === 4 && extendedRecoveredPrefix,
  };
}

// ---------------------------------------------------------------------------
// 结论汇总
// ---------------------------------------------------------------------------

function buildConclusion(T1, T2, T3, T4, T5, T6) {
  const allPass = T1.pass && T2.pass && T3.pass && T4.pass && T5.pass && T6.pass;
  return {
    T1_normalConvergence: T1.pass,
    T2_crashFaultTolerance: T2.pass,
    T3_forkInjectionExpulsion: T3.pass,
    T4_doubleSpendRejected: T4.pass,
    T5_deterministicReplay: T5.pass,
    T6_restartRecovery: T6.pass,
    allPass,
    verdict: allPass
      ? '锁步 QC 链共识内核（VAP-TO）T1-T6 全达标：收敛一致、崩溃容错、分叉注入自动除名、双花投票前拒、确定性重放逐字节一致、重启恢复已提交前缀'
      : 'VAP-TO 装置未达标：见 T1-T6 各项失败项',
  };
}

// ---------------------------------------------------------------------------
// 运行 + 输出
// ---------------------------------------------------------------------------

const T1 = experimentT1();
const T2 = experimentT2();
const T3 = experimentT3();
const T4 = experimentT4();
const T5 = experimentT5();
const T6 = experimentT6();
const conclusion = buildConclusion(T1, T2, T3, T4, T5, T6);

const summary = {
  experiment: 'phase5-vap-to',
  generatedAt: new Date().toISOString(),
  zeroDependency: true,
  reusedModules: ['../vap-core.mjs', '../phase3/endorse-core.mjs'],
  n: N,
  f: F,
  qcThreshold: THRESHOLD,
  commitRule: 'HotStuff 3-chain: B has QC and child and grandchild each have QC -> commit B',
  superweaponRulings: [
    'commit 规则 = HotStuff 标准 3-chain（安全优先，最保守）',
    '分车道：窄车道（type=commit）走共识总序；默认车道（报告/任务）走既有 nonce 去重',
    '不引入门限签名：QC = 2f+1 个个体签名集合',
  ],
  T1,
  T2,
  T3,
  T4,
  T5,
  T6,
  conclusion,
};

const json = JSON.stringify(summary, null, 2);
process.stdout.write(json + '\n');

fs.mkdirSync(__dirname, { recursive: true });
fs.writeFileSync(path.join(__dirname, 'phase5-results.json'), json + '\n', 'utf8');

if (!conclusion.allPass) {
  process.stderr.write('PHASE5 EXPERIMENT FAILED: acceptance criteria not met.\n');
  process.exitCode = 1;
} else {
  process.stderr.write(
    `PHASE5 OK: T1=${T1.pass} T2=${T2.pass} T3=${T3.pass} ` +
    `T4=${T4.pass} T5=${T5.pass} T6=${T6.pass}\n`,
  );
}
