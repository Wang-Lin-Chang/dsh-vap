// experiments/phase6-experiment.mjs —— VAP Phase 6 动态成员 + 军法上链实测装置（D1-D5）
//
// 运行：node phase6/experiments/phase6-experiment.mjs（在 dsh-vap/ 下）
// 输出：结构化 JSON（stdout + phase6/experiments/phase6-results.json）
//
// D1 加入生效：新节点持资格凭证 + 2/3 背书 → h+2 后 roster=5 → 5 节点共识继续推进
// D2 除名生效：节点 equivocation → 双签证据上链 → 签名立即不计入 → h+2 后 roster=3 → 3 节点(f=0)继续推进
// D3 密钥轮换：节点换 pubKey（旧钥签变更交易）→ h+2 新钥生效 → 旧钥签名被拒、新钥签名有效
// D4 军法上链：invalid 信封提案 → 投票前 0 票不进 QC + 背书者 equivocation → slash 证据上链除名
// D5 延迟窗口：变更提交后、生效前，旧 roster 照常推进 2 块（无中断）
//
// 复用（零改动）：vap-core / phase0.5 / phase0 / phase3 / phase5。零第三方依赖。

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createVapNode, canonicalJson } from '../../vap-core.mjs';
import { createGenesisAnchor, issueCredential } from '../../phase0.5/bootstrap-forge.mjs';
import { makeTask } from '../../phase0/history-forge.mjs';
import { verifyDoubleSignEvidence } from '../../phase3/endorse-core.mjs';
import { leaderOf, hashBlock } from '../../phase5/vap-to.mjs';
import { createMembershipNode } from '../vap-to-membership.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IDS = ['n1', 'n2', 'n3', 'n4'];

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

function buildWorld4({ keys, ledgerDir } = {}) {
  const kps = keys || IDS.map(() => makeKeys());
  const dir = ledgerDir || fs.mkdtempSync(path.join(os.tmpdir(), 'vap-p6-'));
  const peers = IDS.map((id, i) => ({ nodeId: id, pubKey: kps[i].pubKey }));
  const genesis = createGenesisAnchor();
  const credentialCtx = { genesis: { id: genesis.id, publicKey: genesis.publicKey }, keys: new Map(), credentials: new Map() };
  const nodes = IDS.map((id, i) =>
    createMembershipNode({ nodeId: id, keyPair: kps[i], n: 4, f: 1, peers, ledgerDir: dir, credentialCtx }),
  );
  return { ids: IDS, keys: kps, peers, nodes, dir, genesis, credentialCtx };
}

function tx(over = {}) {
  return { type: 'commit', from: 'client', nonce: 'nonce-1', payload: { pay: 5 }, ...over };
}

function sortedIds(nodes) {
  return nodes[0].roster.map((r) => r.nodeId);
}

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

function rawVote(node, proposal) {
  const target = canonicalJson({ view: proposal.view, blockHash: proposal.blockHash, parentHash: proposal.parentHash });
  const sig = crypto.sign(null, Buffer.from(target, 'utf8'), node.privateKey).toString('base64');
  return { nodeId: node.nodeId, pubKey: node.pubKey, sig };
}

function skipView(nodes, view) {
  for (const n of nodes) {
    while (n.view <= view) n.onTimeout();
  }
  return nodes[0].view;
}

function issueJoinCredential(genesis, holder, seed) {
  return issueCredential({ task: makeTask(seed, 2), holder, auditors: [genesis], generation: 0 });
}

// 完整加入流程：返回 { join, endorsements }（join.tx.endorsements 已填充 2/3）。
function prepareJoin(nodes, genesis, n5keys, holder, seed) {
  const credRes = issueJoinCredential(genesis, holder, seed);
  if (!credRes.ok) return { ok: false, reason: credRes.reasons.join('; ') };
  const join = nodes[0].proposeJoin({ nodeId: holder, pubKey: n5keys.pubKey, credential: credRes.credential, privateKey: n5keys.privateKey });
  if (!join.ok) return { ok: false, reason: join.reason };
  const endorsements = [];
  for (const n of nodes.slice(0, 3)) {
    const e = n.endorseJoin(join.tx);
    if (!e.ok) return { ok: false, reason: e.reason };
    endorsements.push(e.endorsement);
  }
  join.tx.endorsements = endorsements;
  return { ok: true, join, credential: credRes.credential };
}

// ---------------------------------------------------------------------------
// D1 加入生效
// ---------------------------------------------------------------------------

function experimentD1() {
  const w = buildWorld4();
  const n5keys = makeKeys();
  const prep = prepareJoin(w.nodes, w.genesis, n5keys, 'n5', 'd1-join-n5');
  if (!prep.ok) return { label: 'D1 join activation', pass: false, error: prep.reason };

  round(w.nodes, 0);
  round(w.nodes, 1);
  round(w.nodes, 2);
  const baselineCommitted = w.nodes[0].committed.length;

  round(w.nodes, 3, { tx: prep.join.tx });
  round(w.nodes, 4);
  round(w.nodes, 5);
  const joinCommitted = w.nodes[0].committed.some((b) => b.view === 3);
  const rosterBeforeWindow = w.nodes[0].roster.length;

  round(w.nodes, 6);
  const rosterAfter = w.nodes[0].roster.length;
  const n5InRoster = w.nodes[0].peerMap.has('n5');
  const fAfter = w.nodes[0].f;
  const thresholdAfter = w.nodes[0].threshold;

  // 创建 n5 节点，加入 5 节点共识继续推进。
  const peers5 = [...w.peers, { nodeId: 'n5', pubKey: n5keys.pubKey }];
  const n5node = createMembershipNode({
    nodeId: 'n5', keyPair: n5keys, n: 5, f: 1, peers: peers5, ledgerDir: w.dir, credentialCtx: w.credentialCtx,
  });
  const fiveNodes = [...w.nodes, n5node];

  const r7 = round(fiveNodes, 7);
  const r8 = round(fiveNodes, 8);
  const r9 = round(fiveNodes, 9);

  const n5Committed = n5node.committed.length;
  const n5FirstBlock = n5node.committed[0];
  const matchIdx = w.nodes[0].committed.findIndex((b) => b.view === (n5FirstBlock && n5FirstBlock.view));
  const n5Agrees = n5FirstBlock && matchIdx >= 0 && w.nodes[0].committed[matchIdx].blockHash === n5FirstBlock.blockHash;
  const advanced = !!(r7.qc && r8.qc && r9.qc);

  return {
    label: 'D1 join activation (4→5)',
    baselineCommitted,
    joinCommitted,
    rosterBeforeWindow,
    rosterAfter,
    n5InRoster,
    fAfter,
    thresholdAfter,
    n5CommittedBlocks: n5Committed,
    n5FirstBlockView: n5FirstBlock ? n5FirstBlock.view : null,
    n5AgreesWithOriginalNodes: n5Agrees,
    fiveNodeConsensusAdvanced: advanced,
    pass: joinCommitted && rosterBeforeWindow === 4 && rosterAfter === 5 && n5InRoster && fAfter === 1 && thresholdAfter === 3 && n5Committed >= 1 && n5Agrees && advanced,
  };
}

// ---------------------------------------------------------------------------
// D2 除名生效
// ---------------------------------------------------------------------------

function experimentD2() {
  const w = buildWorld4();
  round(w.nodes, 0);
  round(w.nodes, 1);
  round(w.nodes, 2);
  const parent = w.nodes[0].highestQC.blockHash;

  const n4 = w.nodes[3];
  const p1 = n4.signProposal({ view: 3, leader: 'n4', parentHash: parent, txs: [tx({ payload: { a: 1 } })] });
  const p2 = n4.signProposal({ view: 3, leader: 'n4', parentHash: parent, txs: [tx({ payload: { a: 2 } })] });
  const evidence = w.nodes[0].detectEquivocation([p1, p2]);
  const evidenceCount = evidence.length;
  const evidenceVerifiable = evidence.length > 0 && verifyDoubleSignEvidence(evidence[0]);
  const equivocator = evidence.length > 0 ? evidence[0].nodeId : null;

  const slash = evidence.length > 0 ? w.nodes[0].expelByEquivocation(evidence[0]) : { ok: false };
  const slashSubmitted = slash.ok === true;

  skipView(w.nodes, 3);
  round(w.nodes, 4, { tx: slash.ok ? slash.tx : undefined, voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  round(w.nodes, 5, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  round(w.nodes, 6, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });

  const expelledImmediately = w.nodes[0].expelled.has('n4');
  const rosterBeforeWindow = w.nodes[0].roster.length;

  // 签名立即不计入：n1+n2+n4 三票中 n4 被丢弃 → 2 < 3。
  const prop = w.nodes[0].signProposal({ view: 8, leader: 'n1', parentHash: w.nodes[0].highestQC.blockHash, txs: [] });
  const self = w.nodes[0].vote(prop);
  const sigExcluded = self.voted === true &&
    w.nodes[0].collectQC([rawVote(w.nodes[0], prop), rawVote(w.nodes[1], prop), rawVote(w.nodes[3], prop)]).ok === false;

  round(w.nodes, 9, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  round(w.nodes, 10, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  const rosterAfter = w.nodes[0].roster.length;
  const fAfter = w.nodes[0].f;
  const thresholdAfter = w.nodes[0].threshold;

  // 3 节点（f=0）继续推进。
  const r11 = round(w.nodes, 11, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  const r12 = round(w.nodes, 12, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  const r13 = round(w.nodes, 13, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  const threeNodeConsensusAdvanced = !!(r11.qc && r12.qc && r13.qc);

  return {
    label: 'D2 expulsion (equivocation, 4→3)',
    evidenceCount,
    evidenceVerifiable,
    equivocator,
    slashSubmitted,
    expelledImmediately,
    rosterBeforeWindow,
    rosterAfter,
    fAfter,
    thresholdAfter,
    signatureExcludedImmediately: sigExcluded,
    threeNodeConsensusAdvanced,
    pass:
      evidenceCount === 1 &&
      evidenceVerifiable &&
      slashSubmitted &&
      expelledImmediately &&
      rosterBeforeWindow === 4 &&
      rosterAfter === 3 &&
      fAfter === 0 &&
      thresholdAfter === 1 &&
      sigExcluded &&
      threeNodeConsensusAdvanced,
  };
}

// ---------------------------------------------------------------------------
// D3 密钥轮换
// ---------------------------------------------------------------------------

function experimentD3() {
  const w = buildWorld4();
  round(w.nodes, 0);
  round(w.nodes, 1);
  round(w.nodes, 2);

  const n3 = w.nodes[2];
  const oldPubKey = n3.pubKey;
  const oldPrivateKey = w.keys[2].privateKey;
  const newKeys = makeKeys();

  const rot = n3.rotateKey({ oldPubKey, newPubKey: newKeys.pubKey, newPrivateKey: newKeys.privateKey });
  const rotationSubmitted = rot.ok === true;

  round(w.nodes, 3, { tx: rot.tx });
  round(w.nodes, 4);
  round(w.nodes, 5);
  const keyBeforeWindow = w.nodes[0].peerMap.get('n3') === oldPubKey;

  round(w.nodes, 6);
  const keyAfter = w.nodes[0].peerMap.get('n3');
  const newKeyActive = keyAfter === newKeys.pubKey;

  // 旧钥签名被拒（view 10 leader=n3，旧钥签）。
  const v = 10;
  const parent = w.nodes[0].highestQC.blockHash;
  const content = { view: v, leader: 'n3', parentHash: parent, txs: [] };
  const staleProposal = { ...content, sig: '' };
  staleProposal.blockHash = hashBlock(staleProposal);
  staleProposal.sig = crypto.sign(null, Buffer.from(canonicalJson(content), 'utf8'), oldPrivateKey).toString('base64');
  const oldKeyRejected = w.nodes[0].vote(staleProposal).voted === false;

  // 新钥签名有效（n3 以新钥作为 leader 提案 → 被接受）。
  const pr = n3.propose(v);
  const newKeyAccepted = pr.proposal != null && w.nodes[0].vote(pr.proposal).voted === true;

  return {
    label: 'D3 key rotation',
    rotationSubmitted,
    keyBeforeWindow,
    newKeyActive,
    oldKeyRejected,
    newKeyAccepted,
    pass: rotationSubmitted && keyBeforeWindow && newKeyActive && oldKeyRejected && newKeyAccepted,
  };
}

// ---------------------------------------------------------------------------
// D4 军法上链
// ---------------------------------------------------------------------------

function experimentD4() {
  const w = buildWorld4();
  round(w.nodes, 0);
  round(w.nodes, 1);
  round(w.nodes, 2);

  // (a) invalid 信封 → 投票前 0 票，不进 QC（view 3 leader = n4，提案者是 QC 背书者）。
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-p6-env-'));
  const vap = createVapNode({ nodeId: 'n1', root: tmp });
  const badEnv = vap.send({
    to: 'brain',
    claim: { type: 'report', body: { n: 1 } },
    evidence: { devices: ['dev-1'], bills: {}, digest: 'sha256:abc' },
    boundary: 'L0',
    report: { summary: 'x'.repeat(120), keyNumbers: [], request: '' },
  });
  const wrapped = w.nodes[0].wrapEnvelope(badEnv);
  const invalidRound = round(w.nodes, 3, { tx: wrapped.tx });
  const zeroVotes = invalidRound.votes === 0 && invalidRound.qc === null;

  // (b) 同一背书者 n4 equivocation → slash 证据上链 → 自动除名。
  const parent = w.nodes[0].highestQC.blockHash;
  const n4 = w.nodes[3];
  const p1 = n4.signProposal({ view: 3, leader: 'n4', parentHash: parent, txs: [tx({ payload: { a: 1 } })] });
  const p2 = n4.signProposal({ view: 3, leader: 'n4', parentHash: parent, txs: [tx({ payload: { a: 2 } })] });
  const evidence = w.nodes[0].detectEquivocation([p1, p2]);
  const slash = evidence.length > 0 ? w.nodes[0].expelByEquivocation(evidence[0]) : { ok: false };
  const slashEvidenceVerifiable = slash.ok === true && evidence.length > 0 && verifyDoubleSignEvidence(evidence[0]);

  // 提交 slash：跳过坏视图 3，rounds 4（slash）、5、6 → view4（slash）在 height 3 提交。
  skipView(w.nodes, 3);
  round(w.nodes, 4, { tx: slash.ok ? slash.tx : undefined, voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  round(w.nodes, 5, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  round(w.nodes, 6, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  const autoExpelled = w.nodes[0].expelled.has('n4');
  const slashCommitted = w.nodes[0].committed.some(
    (b) => b.view === 4 && (b.txs || []).some((t) => t && t.op === 'slash'),
  );
  const rosterBeforeWindow = w.nodes[0].roster.length;

  // roster 掉 n4（跳过 n4 的 leader 槽 view 7，round 8 提交后 h+2 到达）。
  round(w.nodes, 8, { voters: [w.nodes[0], w.nodes[1], w.nodes[2]] });
  const rosterDropped = w.nodes[0].roster.length === 3;

  return {
    label: 'D4 laws on chain',
    invalidEnvelopeZeroVotes: zeroVotes,
    invalidEnvelopeEnteredQc: invalidRound.qc !== null,
    slashEvidenceVerifiable,
    slashCommitted,
    autoExpelled,
    rosterBeforeWindow,
    rosterDroppedAfterDelay: rosterDropped,
    pass: zeroVotes && slashEvidenceVerifiable && slashCommitted && autoExpelled && rosterBeforeWindow === 4 && rosterDropped,
  };
}

// ---------------------------------------------------------------------------
// D5 延迟窗口无中断
// ---------------------------------------------------------------------------

function experimentD5() {
  const w = buildWorld4();
  const n5keys = makeKeys();
  const prep = prepareJoin(w.nodes, w.genesis, n5keys, 'n5', 'd5-join-n5');
  if (!prep.ok) return { label: 'D5 delay window', pass: false, error: prep.reason };

  round(w.nodes, 0);
  round(w.nodes, 1);
  round(w.nodes, 2);
  round(w.nodes, 3, { tx: prep.join.tx });
  round(w.nodes, 4);
  round(w.nodes, 5); // join 提交（height 3）
  const rosterAtCommit = w.nodes[0].roster.length;

  // 窗口块（height 4）：旧 roster 照常推进（4 票成 QC，无中断）；commit 后 roster 切 5。
  const r6 = round(w.nodes, 6);
  const windowVotes = r6.votes;
  const windowQc = !!r6.qc;
  const rosterAfterWindow = w.nodes[0].roster.length; // commit 后已切 5
  const r7 = round(w.nodes, 7);
  const continuedAfterSwitch = !!r7.qc;

  return {
    label: 'D5 delay window (no interruption)',
    rosterAtCommit,
    windowVotes,
    windowQc,
    rosterAfterWindow,
    continuedAfterSwitch,
    pass:
      rosterAtCommit === 4 &&
      windowVotes === 4 &&
      windowQc &&
      rosterAfterWindow === 5 &&
      continuedAfterSwitch,
  };
}

// ---------------------------------------------------------------------------
// 汇总 + 输出
// ---------------------------------------------------------------------------

function buildConclusion(D1, D2, D3, D4, D5) {
  const allPass = D1.pass && D2.pass && D3.pass && D4.pass && D5.pass;
  return {
    D1_joinActivation: D1.pass,
    D2_expulsion: D2.pass,
    D3_keyRotation: D3.pass,
    D4_lawsOnChain: D4.pass,
    D5_delayWindow: D5.pass,
    allPass,
    verdict: allPass
      ? '动态成员 + 军法上链（VAP-TO 扩展）D1-D5 全达标：加入 4→5、除名签名立即不计入 + roster 延迟、密钥轮换旧钥失效新钥生效、军法投票前 0 票 + slash 上链、延迟窗口无中断'
      : 'Phase 6 装置未达标：见 D1-D5 各项失败项',
  };
}

const D1 = experimentD1();
const D2 = experimentD2();
const D3 = experimentD3();
const D4 = experimentD4();
const D5 = experimentD5();
const conclusion = buildConclusion(D1, D2, D3, D4, D5);

const summary = {
  experiment: 'phase6-membership',
  generatedAt: new Date().toISOString(),
  zeroDependency: true,
  reusedModules: ['../vap-core.mjs', '../phase0.5/bootstrap-forge.mjs', '../phase0/history-forge.mjs', '../phase3/endorse-core.mjs', '../phase5/vap-to.mjs'],
  reusedZeroChange: true,
  n0: 4,
  f0: 1,
  delayBlocks: 2,
  fRecompute: 'floor((n-1)/3)',
  lawsAsVoteBeforePredicate: true,
  D1,
  D2,
  D3,
  D4,
  D5,
  conclusion,
};

const json = JSON.stringify(summary, null, 2);
process.stdout.write(json + '\n');

fs.mkdirSync(__dirname, { recursive: true });
fs.writeFileSync(path.join(__dirname, 'phase6-results.json'), json + '\n', 'utf8');

if (!conclusion.allPass) {
  process.stderr.write('PHASE6 EXPERIMENT FAILED: acceptance criteria not met.\n');
  process.exitCode = 1;
} else {
  process.stderr.write(
    `PHASE6 OK: D1=${D1.pass} D2=${D2.pass} D3=${D3.pass} D4=${D4.pass} D5=${D5.pass}\n`,
  );
}
