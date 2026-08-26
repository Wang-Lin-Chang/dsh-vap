// experiments/graynet-membership.mjs —— VAP 跨机动态成员装置（mnode 角色）
//
// 用法：
//   node experiments/graynet-membership.mjs mnode --nodeId C0 --relayHost <ip> --relayPort <p> \
//     --root <dir> --ledgerDir <dir> --peersJson <file> --anchorId <id> --anchorPub <spki-b64>
//
// 角色：一个 membership 节点，经中继监听控制消息（ctl），执行 op 并回 ctlres：
//   ops: state / submitTx / propose / vote / collectQC / commitCheck / onTimeout /
//        proposeJoin / endorseJoin / submitJoinTx / rawDoubleSign
// 控制消息来自 M-CTL（harness）。零第三方依赖。

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { createMembershipNode } from '../phase6/vap-to-membership.mjs';
import { verifyCredentialChain } from '../phase0.5/bootstrap-forge.mjs';
import { GENESIS_HASH } from '../phase5/vap-to.mjs';
import { createRelayClient } from '../phase4/relay-client.mjs';
import { canonicalJson } from '../vap-core.mjs';

function parseArgs() {
  const a = {};
  for (let i = 2; i < process.argv.length; i += 1) {
    const t = process.argv[i];
    if (t.startsWith('--')) {
      const k = t.slice(2);
      const n = process.argv[i + 1];
      if (n !== undefined && !n.startsWith('--')) { a[k] = n; i += 1; } else a[k] = 'true';
    }
  }
  return a;
}
const args = parseArgs();
const nodeId = args.nodeId;
const relayHost = args.relayHost || '127.0.0.1';
const relayPort = Number(args.relayPort || 42050);
const root = args.root;
const ledgerDir = args.ledgerDir || root;
const peersJson = args.peersJson;

fs.mkdirSync(root, { recursive: true });
fs.mkdirSync(ledgerDir, { recursive: true });

const peers = JSON.parse(fs.readFileSync(peersJson, 'utf8'));
const anchorId = args.anchorId;
const anchorPub = args.anchorPub;
const credentialCtx = {
  genesis: { id: anchorId, publicKey: anchorPub },
  keys: new Map(),
  credentials: new Map(),
};

// 身份注入：--privKeyFile 提供 PEM 私钥时，用它（与 harness peers 表一致）；否则 persistKeys 自生成
let keyPair;
if (args.privKeyFile) {
  const priv = crypto.createPrivateKey(fs.readFileSync(args.privKeyFile, 'utf8'));
  keyPair = { publicKey: crypto.createPublicKey(priv), privateKey: priv };
}

const node = createMembershipNode({
  nodeId,
  keyPair,
  n: peers.length,
  f: Math.floor((peers.length - 1) / 3),
  peers,
  ledgerDir,
  credentialCtx,
  persistKeys: true,
  autoRestore: args.freshStart ? false : true,
});

// freshStart：清空账本（掉线节点重启全量同步路径——绕过增量追块的分叉/衔接问题）
if (args.freshStart) {
  try { fs.truncateSync(node.ledgerFile, 0); } catch {}
}

const client = createRelayClient({ host: relayHost, port: relayPort, nodeId, pubKey: node.pubKey });

function snap() {
  return {
    nodeId,
    pubKey: node.pubKey,
    view: node.view,
    roster: node.roster.map((r) => r.nodeId),
    n: node.n, f: node.f, threshold: node.threshold,
    committedHeights: node.committed.map((b) => b.height),
    committedDigest: node.committed.length ? node.committed[node.committed.length - 1].blockHash : null,
    committedCount: node.committed.length,
    expelled: node.expelled ? [...node.expelled] : [],
    pubKeyMap: Object.fromEntries([...node.peerMap.entries()]),
    membershipLog: node.membershipLog.slice(-8),
  };
}

function reply(reqId, op, result) {
  client.send('M-CTL', { type: 'ctlres', reqId, op, result });
}

function handle(msg) {
  const m = msg && msg.envelope ? msg.envelope : msg;
  if (!m || m.type !== 'ctl') return;
  const { reqId, op } = m;
  try {
    switch (op) {
      case 'state': reply(reqId, op, snap()); break;
      case 'onTimeout': node.onTimeout(); reply(reqId, op, { view: node.view }); break;
      case 'submitTx': {
        const r = node.submitTx(m.tx);
        reply(reqId, op, { ok: r.ok, reason: r.reason || null });
        break;
      }
      case 'propose': {
        const r = node.propose(m.view);
        reply(reqId, op, r.refused ? { refused: r.refused } : { proposal: r.proposal });
        break;
      }
      case 'vote': {
        const r = node.vote(m.proposal);
        reply(reqId, op, r.voted ? { voted: true, vote: r.vote } : { voted: false, reason: r.reason || null });
        break;
      }
      case 'collectQC': {
        const r = node.collectQC(m.votes);
        reply(reqId, op, r.ok ? { ok: true, qc: r.qc } : { ok: false, reason: r.reason || null });
        break;
      }
      case 'commitCheck': {
        const c = node.commitCheck();
        reply(reqId, op, { commits: c.map((b) => ({ view: b.view, height: b.height, blockHash: b.blockHash })) });
        break;
      }
      case 'proposeJoin': {
        const r = node.proposeJoin(m.joinParams);
        reply(reqId, op, r.ok ? { ok: true, tx: r.tx } : { ok: false, reason: r.reason || null });
        break;
      }
      case 'endorseJoin': {
        const r = node.endorseJoin(m.tx);
        reply(reqId, op, r.ok ? { ok: true, endorsement: r.endorsement } : { ok: false, reason: r.reason || null });
        break;
      }
      case 'rawDoubleSign': {
        // 双签证据：对同 view 两个不同 blockHash 用本节点真私钥各签一票（equivocation 证据制造）
        const sigOf = (view, blockHash) => crypto.sign(null, Buffer.from(canonicalJson({ view, blockHash, parentHash: m.parentHash || 'p' }), 'utf8'), node.privateKey).toString('base64');
        const v1 = { nodeId, pubKey: node.pubKey, sig: sigOf(m.view, m.blockHash1), view: m.view, blockHash: m.blockHash1 };
        const v2 = { nodeId, pubKey: node.pubKey, sig: sigOf(m.view, m.blockHash2), view: m.view, blockHash: m.blockHash2 };
        reply(reqId, op, { vote1: v1, vote2: v2 });
        break;
      }
      case 'signProposal': {
        // 对同 view 签两个不同内容的提案（equivocation 制造，与单机 D2 同构）
        const p1 = node.signProposal({ view: m.view, leader: nodeId, parentHash: m.parentHash, txs: [{ type: 'commit', from: 'client', nonce: 'ds-1', payload: { a: 1 } }] });
        const p2 = node.signProposal({ view: m.view, leader: nodeId, parentHash: m.parentHash, txs: [{ type: 'commit', from: 'client', nonce: 'ds-2', payload: { a: 2 } }] });
        reply(reqId, op, { proposal1: p1, proposal2: p2 });
        break;
      }
      case 'detectEquivocation': {
        const ev = node.detectEquivocation(m.proposals);
        reply(reqId, op, { evidenceCount: ev.length, evidence: ev });
        break;
      }
      case 'expelByEquivocation': {
        const r = node.expelByEquivocation(m.evidence);
        reply(reqId, op, r.ok ? { ok: true, tx: r.tx } : { ok: false, reason: r.reason || null });
        break;
      }
      case 'signSubject': {
        // 对本节点私钥签名任意 subject（构造 expel 自签交易等）
        const sig = crypto.sign(null, Buffer.from(canonicalJson(m.subject), 'utf8'), node.privateKey).toString('base64');
        reply(reqId, op, { sig });
        break;
      }
      case 'rotateKey': {
        // K3-K4：旧钥签变更交易 → h+2 新钥生效（新私钥 PEM 注入）
        let newPrivateKey;
        if (m.newPrivateKeyPem) {
          try { newPrivateKey = crypto.createPrivateKey(m.newPrivateKeyPem); } catch (e) { reply(reqId, op, { ok: false, reason: 'bad newPrivateKeyPem' }); break; }
        }
        const r = node.rotateKey({ oldPubKey: node.pubKey, newPubKey: m.newPubKey, newPrivateKey });
        reply(reqId, op, r.ok ? { ok: true, tx: r.tx } : { ok: false, reason: r.reason || null });
        break;
      }
      case 'verifyCredential': {
        // B3 演练：验证凭证链是否回验到本节点信任的创世锚
        let res;
        try {
          res = node.credentialCtx
            ? verifyCredentialChain(m.credential, node.credentialCtx)
            : { pass: false, reasons: ['no credential context'] };
        } catch (e) {
          res = { pass: false, reasons: [String((e && e.message) || e)] };
        }
        reply(reqId, op, { pass: res.pass === true, reasons: res.reasons || [] });
        break;
      }
      default: reply(reqId, op, { err: 'unknown op ' + op });
    }
  } catch (e) {
    reply(reqId, op, { err: String((e && e.message) || e) });
  }
}

client.connect();
if (!args.autonomous) client.onEnvelope(handle);
process.stdout.write(`MNODE-UP ${nodeId} relay=${relayHost}:${relayPort} n=${node.n} f=${node.f} threshold=${node.threshold}\n`);
setTimeout(() => { process.stdout.write('MNODE-ALIVE ' + nodeId + '\n'); }, 1500);

// ---------------------------------------------------------------------------
// 自治模式（--autonomous）：节点自行视图切换/propose/vote/集 QC/提交，经中继 gossip。
// harness 只观察（state 轮询）与故障注入，不逐轮驱动。
// ---------------------------------------------------------------------------
if (args.autonomous) {
  const VIEW_TIMEOUT_MS = Number(args.viewTimeoutMs || 3000);
  let viewStart = Date.now();
  let proposedThisView = false;
  let qcDoneThisView = false;
  let lastBlockRequestAt = 0;
  let bootstrapped = false;
  const voteBuf = {};
  const events = [];

  function blockContentOf(p) {
    return { view: p.view, leader: p.leader, parentHash: p.parentHash, txs: p.txs || [] };
  }
  function verifyBlockSig(p) {
    const leaderPub = node.peerMap.get(p.leader);
    if (!leaderPub) return false;
    try {
      const k = crypto.createPublicKey({ key: Buffer.from(leaderPub, 'base64'), format: 'der', type: 'spki' });
      return crypto.verify(null, Buffer.from(canonicalJson(blockContentOf(p)), 'utf8'), k, Buffer.from(p.sig, 'base64'));
    } catch {
      return false;
    }
  }
  function verifyBlockHash(p) {
    return crypto.createHash('sha256').update(canonicalJson(blockContentOf(p)), 'utf8').digest('hex') === p.blockHash;
  }
  function handleBlockResponse(resp) {
    const list = resp && resp.blocks ? resp.blocks : [];
    if (!list.length) return 0;
    // 分叉/不衔接：若响应从 height 0 开始而本地链与它不衔接 → 重置账本全量重放
    const first = list[0];
    if (first.height === 0 && (node.committedHeight !== 0 || node.lastCommittedHash !== GENESIS_HASH)) {
      resetLedgerAndReplayFrom(list);
      return node.committedHeight;
    }
    let adopted = 0;
    for (const { block, qc, height, prevHash } of list) {
      if (!block) continue;
      if (height !== node.committedHeight) continue;
      if (prevHash !== node.lastCommittedHash && !(height === 0 && prevHash === null)) continue;
      if (!verifyBlockHash(block)) continue;
      if (!verifyBlockSig(block)) continue;
      if (qc && typeof qc === 'object') {
        if (!node.verifyQC(qc)) continue;
        if (qc.blockHash !== block.blockHash) continue;
      }
      node.commitBlock(block);
      if (qc) {
        node.qcByView.set(qc.view, qc);
        node.qcByBlockHash.set(qc.blockHash, qc);
        if (!node.highestQC || Number(qc.view) >= Number(node.highestQC.view)) node.highestQC = qc;
      }
      adopted += 1;
    }
    if (adopted) record({ kind: 'blocks-synced', count: adopted, height: node.committedHeight });
    return adopted;
  }

  function resetLedgerAndReplayFrom(list) {
    // 清空本地账本与提交状态，从创世全量重放（分叉/起晚节点自愈路径）
    try { fs.truncateSync(node.ledgerFile, 0); } catch {}
    node.committed = [];
    node.committedHashes.clear();
    node.committedHeight = 0;
    node.lastCommittedHash = GENESIS_HASH;
    node.highestQC = null;
    node.qcByView.clear();
    node.qcByBlockHash.clear();
    for (const { block, qc } of list) {
      if (!block) continue;
      if (!verifyBlockHash(block)) continue;
      if (!verifyBlockSig(block)) continue;
      if (qc && typeof qc === 'object') {
        if (!node.verifyQC(qc)) continue;
        if (qc.blockHash !== block.blockHash) continue;
      }
      node.commitBlock(block);
      if (qc) {
        node.qcByView.set(qc.view, qc);
        node.qcByBlockHash.set(qc.blockHash, qc);
        if (!node.highestQC || Number(qc.view) >= Number(node.highestQC.view)) node.highestQC = qc;
      }
    }
    record({ kind: 'ledger-reset-replayed', height: node.committedHeight });
  }

  function resetView() {
    viewStart = Date.now();
    proposedThisView = false;
    qcDoneThisView = false;
  }
  function broadcastGossip(kind, payload) {
    for (const p of node.roster) {
      if (p.nodeId !== nodeId) {
        client.send(p.nodeId, { type: 'gossip', from: nodeId, kind, ...payload });
      }
    }
  }
  function record(ev) {
    events.push({ at: Date.now(), ...ev });
    if (events.length > 200) events.shift();
  }

  const tick = () => {
    try {
      if (!bootstrapped) return;
      const now = Date.now();
      const leaderId = node.leaderOf(node.view);
      // 超时推进
      if (!qcDoneThisView && now - viewStart >= VIEW_TIMEOUT_MS) {
        node.onTimeout();
        resetView();
      }
      // leader propose（并自投一票——BFT 里 leader 也是 voter；缺自投则掉 1 节点后 2 票 < quorum 3 卡死）
      if (leaderId === nodeId && !proposedThisView) {
        const pr = node.propose(node.view);
        if (pr.proposal) {
          proposedThisView = true;
          broadcastGossip('proposal', { view: node.view, proposal: pr.proposal });
          const v = node.vote(pr.proposal);
          if (v.voted) {
            const buf = voteBuf[node.view] || (voteBuf[node.view] = []);
            if (!buf.some((x) => x.nodeId === v.vote.nodeId)) buf.push(v.vote);
            broadcastGossip('vote', { view: node.view, vote: v.vote });
            if (buf.length >= node.threshold && !qcDoneThisView) {
              const c = node.collectQC(buf);
              if (c.ok) {
                qcDoneThisView = true;
                const commits = node.commitCheck();
                if (commits.length) record({ kind: 'committed', view: node.view, blocks: commits.length });
                broadcastGossip('qc', { view: node.view, qc: c.qc });
                node.onTimeout();
                resetView();
              }
            }
          }
        }
      }
    } catch (e) {
      record({ kind: 'tick-error', msg: String((e && e.message) || e) });
    }
  };
  setInterval(tick, 400);

  // bootstrap 同步：仅「无账本」节点先请求全链（blockRequest fromHeight=0），追到链尾再开自治。
  // 有账本的掉线节点直接开自治，增量追块由 QC 广播触发。
  setInterval(() => {
    if (bootstrapped) return;
    if (node.committedHeight > 0) { bootstrapped = true; resetView(); return; }
    const now = Date.now();
    if (now - lastBlockRequestAt < 3000) return;
    lastBlockRequestAt = now;
    for (const p of node.roster) {
      if (p.nodeId === nodeId) continue;
      client.send(p.nodeId, { type: 'gossip', from: nodeId, kind: 'blockRequest', fromHeight: 0, count: 200, reqId: 'bs-' + now });
    }
    // 兜底：30s 内无块到达 → 空网络，直接开自治
    setTimeout(() => {
      if (!bootstrapped && node.committedHeight === 0) {
        bootstrapped = true;
        resetView();
        record({ kind: 'bootstrap-timeout-empty', height: 0 });
      }
    }, 30000);
  }, 1000);

  // gossip 处理挂到 handle：扩展 onEnvelope 处理 gossip 消息
  const gossipHandler = (env) => {
    const m = env && env.envelope ? env.envelope : env;
    if (!m || m.type !== 'gossip') return;
    try {
      if (m.kind === 'proposal') {
        const p = m.proposal;
        if (!p || typeof p !== 'object') return;
        // 旧钥/非 roster 钥签名的提案：验证层拒 + 留痕（K4 监控语义）
        if (p.leader && !node.peerMap.has(p.leader)) {
          record({ kind: 'suspicious-proposal', view: p.view, leader: p.leader, reason: 'leader not in roster' });
          return;
        }
        if (p.view > node.view) {
          while (node.view < p.view) node.onTimeout();
        }
        if (p.view === node.view && p.leader === node.leaderOf(p.view)) {
          const v = node.vote(p);
          if (v.voted) broadcastGossip('vote', { view: p.view, vote: v.vote });
          else record({ kind: 'vote-rejected', view: p.view, leader: p.leader, reason: v.reason || null });
        } else if (p.view < node.view) {
          record({ kind: 'stale-proposal', view: p.view, leader: p.leader, reason: 'stale view below current' });
        }
      } else if (m.kind === 'vote') {
        const v = m.vote;
        if (!v) return;
        const buf = voteBuf[m.view] || (voteBuf[m.view] = []);
        if (!buf.some((x) => x.nodeId === v.nodeId)) buf.push(v);
        if (buf.length >= node.threshold && !qcDoneThisView) {
          const c = node.collectQC(buf);
          if (c.ok) {
            qcDoneThisView = true;
            const commits = node.commitCheck();
            if (commits.length) record({ kind: 'committed', view: m.view, blocks: commits.length });
            // 广播 QC：其他节点直接采纳（BFT 标准同步路径），不再各自集票
            broadcastGossip('qc', { view: m.view, qc: c.qc });
            node.onTimeout();
            resetView();
          }
        }
      } else if (m.kind === 'qc') {
        const q = m.qc;
        if (!q) return;
        if (node.verifyQC(q)) {
          if (!node.highestQC || Number(q.view) >= Number(node.highestQC.view)) {
            node.highestQC = q;
            node.qcByView.set(q.view, q);
            node.qcByBlockHash.set(q.blockHash, q);
            node.commitCheck();
          }
          // 视图对齐：落后于 QC 视图则推进，保证下一轮 parent 一致
          if (Number(q.view) >= node.view) {
            node.onTimeout();
            resetView();
          }
          // 追块触发：QC 视图超前本地已提交高度 ≥5 → 向 QC 来源请求缺失区块
          if (Number(q.view) - node.committedHeight >= 5 && Date.now() - lastBlockRequestAt > 5000) {
            lastBlockRequestAt = Date.now();
            client.send(m.from, { type: 'gossip', from: nodeId, kind: 'blockRequest', fromHeight: node.committedHeight, count: 200, reqId: 'br-' + Date.now() });
          }
        }
      } else if (m.kind === 'blockRequest') {
        // 对端：按请求高度发送已提交块序列（块对象 + 活 QC + 高度/前驱哈希）
        const out = [];
        for (let i = 0; i < node.committed.length; i += 1) {
          if (i < (m.fromHeight || 0)) continue;
          const b = node.committed[i];
          out.push({
            block: b,
            qc: node.qcByBlockHash.get(b.blockHash) || null,
            height: i,
            prevHash: i === 0 ? null : node.committed[i - 1].blockHash,
          });
          if (out.length >= (m.count || 200)) break;
        }
        // 空列表也回（让请求方知道链尾已到），不 silence
        client.send(m.from, { type: 'gossip', from: nodeId, kind: 'blockResponse', reqId: m.reqId, blocks: out, count: m.count || 200 });
      } else if (m.kind === 'blockResponse') {
        const n = handleBlockResponse(m);
        if (n) record({ kind: 'blocks-synced', count: n, height: node.committedHeight });
        if (m.blocks && m.blocks.length < (m.count || 200)) {
          record({ kind: 'chain-tail-reached', height: node.committedHeight });
          bootstrapped = true;
          resetView();
        }
      }
    } catch (e) {
      record({ kind: 'gossip-error', msg: String((e && e.message) || e) });
    }
  };
  const origOn = client.onEnvelope;
  client.onEnvelope((env) => { handle(env); gossipHandler(env); });
  // state 快照扩展自治字段
  const origSnap = snap;
  snap = function snapAuto() {
    const s = origSnap();
    s.autonomous = true;
    s.viewNow = node.view;
    s.events = events.slice(-20);
    return s;
  };
}
