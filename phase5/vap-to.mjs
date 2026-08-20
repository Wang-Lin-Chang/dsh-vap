// vap-to.mjs —— VAP Phase 5 锁步 QC 链共识内核（VAP-TO）
//
// 零第三方依赖，仅 node: 内置模块与相对路径 import。
// 复用（零改动，只 import）：
//   - ../vap-core.mjs               canonicalJson（规范化 JSON，键字典序递归排序）
//   - ../phase3/endorse-core.mjs    collectQC（2f+1 个体签名验签）/ detectDoubleSign / verifyDoubleSignEvidence
//
// 三个锁定（见 phase5/DESIGN.md 顶部裁决）：
//   ① commit 规则 = HotStuff 标准 3-chain（B 有 QC 且子、孙各有 QC → 提交 B）；
//   ② 分车道：窄车道（type=commit，需总序防双花）走共识；默认车道（报告/任务，幂等）走既有 nonce 去重；
//   ③ QC = 2f+1 个个体签名集合（不引入门限签名）。
//
// 诚实正名：锁步提交 / 视图切换 / equivocation 检测是全新未测代码，本阶段实验是第一次验证。

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../vap-core.mjs';
import { collectQC, detectDoubleSign } from '../phase3/endorse-core.mjs';
import { saveKey, loadKey } from '../key-store.mjs';
import { defaultLedgerDir } from '../config.mjs';

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

// 创世哨兵：无前置 QC 时，区块父指针指向该值。
export const GENESIS_HASH = 'GENESIS';

// ---------------------------------------------------------------------------
// 密钥规范化（局部助手，与 phase3/endorse-core.mjs 语义一致，不改复用模块）
// ---------------------------------------------------------------------------

function coercePublicKey(key) {
  if (key && typeof key === 'object' && typeof key.export === 'function') return key;
  if (typeof key === 'string') {
    const text = key.trim();
    if (text.startsWith('-----BEGIN')) return crypto.createPublicKey(text);
    return crypto.createPublicKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'spki' });
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return crypto.createPublicKey({ key: Buffer.from(key), format: 'der', type: 'spki' });
  }
  throw new Error('vap-to: unsupported public key value');
}

function coercePrivateKey(key) {
  if (key && typeof key === 'object' && typeof key.export === 'function') return key;
  if (typeof key === 'string') {
    const text = key.trim();
    if (text.startsWith('-----BEGIN')) return crypto.createPrivateKey(text);
    return crypto.createPrivateKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'pkcs8' });
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return crypto.createPrivateKey({ key: Buffer.from(key), format: 'der', type: 'pkcs8' });
  }
  throw new Error('vap-to: unsupported private key value');
}

function publicKeyToBase64(publicKey) {
  return coercePublicKey(publicKey).export({ type: 'spki', format: 'der' }).toString('base64');
}

function signString(message, privateKey) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), coercePrivateKey(privateKey)).toString('base64');
}

function verifyString(message, publicKey, sigB64) {
  try {
    if (typeof sigB64 !== 'string' || sigB64.length === 0) return false;
    return crypto.verify(
      null,
      Buffer.from(message, 'utf8'),
      coercePublicKey(publicKey),
      Buffer.from(sigB64, 'base64'),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 纯函数助手（导出供测试/实验复用）
// ---------------------------------------------------------------------------

function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

// 区块签名/哈希对象 = canonicalJson({ view, leader, parentHash, txs })。
function blockContent(proposal) {
  return {
    view: proposal.view,
    leader: proposal.leader,
    parentHash: proposal.parentHash,
    txs: proposal.txs || [],
  };
}

export function hashBlock(proposal) {
  return sha256hex(canonicalJson(blockContent(proposal)));
}

// leader = roster[view % n]；roster 为按 nodeId 升序排列的节点 id 数组。
export function leaderOf(view, rosterIds) {
  const n = rosterIds.length;
  return rosterIds[((Number(view) % n) + n) % n];
}

function sortTxs(txs) {
  const arr = Array.isArray(txs) ? txs.slice() : [];
  arr.sort((a, b) => {
    const ca = canonicalJson(a);
    const cb = canonicalJson(b);
    if (ca < cb) return -1;
    if (ca > cb) return 1;
    return 0;
  });
  return arr;
}

// 双花检测：同 (from, nonce) 出现两次（与已提交历史冲突、或提案内部重复）→ 返回理由。
function checkDoubleSpend(node, txs) {
  if (!Array.isArray(txs)) return 'safety: proposal.txs must be an array';
  const seen = new Set();
  for (const tx of txs) {
    if (!tx || typeof tx !== 'object') return 'safety: malformed tx';
    if (tx.type !== 'commit') return 'safety: default-lane tx (non-commit) must not be total-ordered';
    if (typeof tx.from !== 'string' || typeof tx.nonce !== 'string') return 'safety: commit tx needs from + nonce';
    const key = `${tx.from}:${tx.nonce}`;
    if (node.seenNonces.has(key)) return `double-spend: nonce '${key}' already committed`;
    if (seen.has(key)) return `double-spend: nonce '${key}' duplicated within proposal`;
    seen.add(key);
  }
  return null;
}

// ---------------------------------------------------------------------------
// 账本（append-only 哈希链）读写
// ---------------------------------------------------------------------------

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function appendLine(filePath, line) {
  ensureDir(path.dirname(filePath));
  fs.appendFileSync(filePath, `${line}\n`, 'utf8');
}

// 账本文件名白名单（M6）：安全 nodeId → 可读名 ledger-<nodeId>.jsonl；
// 不安全 nodeId → ledger-sha256-<sha256hex(nodeId)>.jsonl（不可控字符进不了路径）。
export const LEDGER_NODE_ID_PATTERN = /^[0-9a-zA-Z_-]{1,64}$/;

export function ledgerFileNameFor(nodeId) {
  const safe = typeof nodeId === 'string' && LEDGER_NODE_ID_PATTERN.test(nodeId);
  return safe ? `ledger-${nodeId}.jsonl` : `ledger-sha256-${sha256hex(String(nodeId))}.jsonl`;
}

function readLedgerLines(filePath) {
  let text;
  try {
    text = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }
  const out = [];
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    out.push(JSON.parse(t));
  }
  return out;
}

// ---------------------------------------------------------------------------
// createNode —— 共识节点
// ---------------------------------------------------------------------------

// createNode({ nodeId, keyPair, n, f, peers, now, randomBytes, ledgerDir, persistKeys, autoRestore })
//   nodeId      : 本节点 id（必须出现在 peers 里）
//   keyPair     : { publicKey, privateKey }（KeyObject / DER base64 / PEM）；缺省则现场生成
//   n           : roster 规模（= peers.length）
//   f           : 拜占庭容错上界；QC 门槛 = 2f+1
//   peers       : 全体节点 [{ nodeId, pubKey }]（pubKey 为 spki DER base64）
//   now         : 可注入时钟（返回 Date），测试用假时钟；缺省 () => new Date()
//   randomBytes : 可注入随机源；缺省 crypto.randomBytes
//   ledgerDir   : 账本落盘目录，缺省 os.tmpdir()/vap-ledger（M13，绝不默认源码树；
//                 安全 nodeId → ledger-<nodeId>.jsonl；越界 → ledger-sha256-<摘要>.jsonl）
//   persistKeys : true = 私钥落盘 root/keys（load→use→save，F3）
//   autoRestore : true = 启动即 restore()（从账本回放已提交前缀）
export function createNode({
  nodeId,
  keyPair,
  n,
  f,
  peers,
  now,
  randomBytes,
  ledgerDir,
  persistKeys = false,
  autoRestore = false,
} = {}) {
  if (!nodeId || typeof nodeId !== 'string') throw new Error('createNode: nodeId is required');
  if (!Number.isInteger(n) || n <= 0) throw new Error('createNode: n must be a positive integer');
  if (!Number.isInteger(f) || f < 0) throw new Error('createNode: f must be a non-negative integer');
  if (!Array.isArray(peers) || peers.length !== n) throw new Error(`createNode: peers must have length n=${n}`);
  if (2 * f + 1 > n) throw new Error(`createNode: 2f+1=${2 * f + 1} must be <= n=${n}`);

  const nowFn = typeof now === 'function' ? now : () => new Date();
  const rand = typeof randomBytes === 'function' ? randomBytes : crypto.randomBytes;
  // M13：账本目录默认 os.tmpdir()/vap-ledger，绝不默认源码树。
  const ledgerRoot = ledgerDir || defaultLedgerDir();

  let publicKey;
  let privateKey;
  if (keyPair && keyPair.publicKey && keyPair.privateKey) {
    publicKey = coercePublicKey(keyPair.publicKey);
    privateKey = coercePrivateKey(keyPair.privateKey);
  } else if (persistKeys) {
    // F3：无注入 keyPair 且开启 persistKeys → 先 loadKey；加载成功用持久身份，
    // 否则生成新钥并落盘。
    const loaded = loadKey(ledgerRoot, nodeId);
    if (loaded) {
      privateKey = loaded;
      publicKey = crypto.createPublicKey(loaded);
    } else {
      const generated = crypto.generateKeyPairSync('ed25519');
      publicKey = generated.publicKey;
      privateKey = generated.privateKey;
      saveKey(ledgerRoot, nodeId, privateKey);
    }
  } else {
    const generated = crypto.generateKeyPairSync('ed25519');
    publicKey = generated.publicKey;
    privateKey = generated.privateKey;
  }
  if (persistKeys) saveKey(ledgerRoot, nodeId, privateKey);
  const pubKey = publicKeyToBase64(publicKey);

  // roster：按 nodeId 升序，leader = roster[view % n]。
  const roster = peers
    .map((p) => ({ nodeId: p.nodeId, pubKey: p.pubKey }))
    .sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
  const peerMap = new Map(roster.map((p) => [p.nodeId, p.pubKey]));
  if (!peerMap.has(nodeId)) throw new Error('createNode: nodeId must be in peers');
  if (peerMap.get(nodeId) !== pubKey) throw new Error('createNode: self pubKey must match peers roster');

  const threshold = 2 * f + 1;
  // 安全（M6）：nodeId 参与账本文件名拼接。白名单内的 id 保留可读文件名；
  // 任何越界字符（'/'、'\'、'..'、超长等）一律改用 sha256 摘要文件名 ——
  // 文件名不可控则路径穿越无从下手，nodeId 本体仍逐行记录在账本内容里（见 commitBlock）。
  const ledgerFile = path.join(ledgerRoot, ledgerFileNameFor(nodeId));

  const node = {
    nodeId,
    pubKey,
    privateKey,
    publicKey,
    n,
    f,
    threshold,
    roster,
    peerMap,
    ledgerFile,
    ledgerRoot,
    nowFn,
    rand,

    // 轮次状态机状态
    view: 0,
    highestQC: null,
    votedViews: new Set(),
    blocks: new Map(),          // blockHash -> proposal
    qcByView: new Map(),        // view -> QC
    qcByBlockHash: new Map(),   // blockHash -> QC
    activeProposal: null,

    // 提交与账本状态
    committed: [],              // 已提交区块（按提交顺序）
    committedHashes: new Set(),
    committedHeight: 0,
    lastCommittedHash: GENESIS_HASH,
    seenNonces: new Set(),      // "from:nonce"（已提交窄车道 nonce）

    // 成员与 mempool
    expelled: new Set(),
    pendingTxs: [],
    pendingNonces: new Set(),

    // 时钟（可注入假时钟；超时用）
    lastActivityMs: nowFn().getTime(),
  };

  node.leaderOf = function leaderOfView(view) {
    return leaderOf(view, node.roster.map((r) => r.nodeId));
  };

  node.activeRoster = function activeRoster() {
    const map = new Map();
    for (const p of node.roster) {
      if (node.expelled.has(p.nodeId)) continue;
      map.set(p.nodeId, p.pubKey);
    }
    return map;
  };

  node.touch = function touch() {
    node.lastActivityMs = node.nowFn().getTime();
  };

  node.isTimedOut = function isTimedOut(timeoutMs) {
    return node.nowFn().getTime() - node.lastActivityMs > timeoutMs;
  };

  // 分车道入口：窄车道（type=commit）进 mempool；默认车道不在此列（走 nonce 去重）。
  node.submitTx = function submitTx(tx) {
    if (!tx || typeof tx !== 'object') return { ok: false, reason: 'submitTx: tx must be an object' };
    if (tx.type !== 'commit') {
      return { ok: false, reason: 'submitTx: default-lane tx is not total-ordered (use nonce dedup)' };
    }
    if (typeof tx.from !== 'string' || typeof tx.nonce !== 'string') {
      return { ok: false, reason: 'submitTx: commit tx needs from + nonce' };
    }
    const key = `${tx.from}:${tx.nonce}`;
    if (node.seenNonces.has(key)) return { ok: false, reason: `submitTx: double-spend nonce '${key}' already committed` };
    if (node.pendingNonces.has(key)) return { ok: false, reason: `submitTx: double-spend nonce '${key}' already pending` };
    node.pendingTxs.push(tx);
    node.pendingNonces.add(key);
    return { ok: true, tx };
  };

  // 打包窄车道交易（确定性排序），打包后清空 mempool。
  function packTxs() {
    const txs = sortTxs(node.pendingTxs);
    node.pendingTxs = [];
    node.pendingNonces.clear();
    return txs;
  }

  // 签名一个提案（供拜占庭场景构造：任意 parentHash / txs）。justify 置空。
  node.signProposal = function signProposal({ view, leader, parentHash, txs } = {}) {
    const proposal = { view, leader, parentHash, txs: sortTxs(txs || []), justify: null, sig: '' };
    proposal.blockHash = hashBlock(proposal);
    proposal.sig = signString(canonicalJson(blockContent(proposal)), privateKey);
    return proposal;
  };

  // propose(view)：leader 打包窄车道交易 + parentHash → 签名广播。
  node.propose = function propose(view) {
    const v = Number(view);
    if (!Number.isInteger(v) || v < 0) return { refused: true, reason: `propose: invalid view ${view}` };
    if (node.leaderOf(v) !== node.nodeId) {
      return { refused: true, reason: `propose: node ${node.nodeId} is not leader of view ${v}` };
    }
    if (v < node.view) return { refused: true, reason: `propose: view ${v} < current view ${node.view}` };

    const baseline = node.highestQC
      ? node.highestQC.blockHash
      : node.lastCommittedHash !== GENESIS_HASH
        ? node.lastCommittedHash
        : GENESIS_HASH;

    const proposal = {
      view: v,
      leader: node.nodeId,
      parentHash: baseline,
      txs: packTxs(),
      // 视图切换携带 highestQC；restore 回放的「已提交块锚点 QC」（restored:true，签名不在
      // 账本中）不可作为可验 justify 携带，否则对端 verifyQC 必失败 —— 置空，基线仍由
      // parentHash（= highestQC.blockHash）延续。
      justify: node.highestQC && node.highestQC.restored ? null : node.highestQC,
      sig: '',
    };
    proposal.blockHash = hashBlock(proposal);
    proposal.sig = signString(canonicalJson(blockContent(proposal)), privateKey);

    node.blocks.set(proposal.blockHash, proposal);
    node.activeProposal = proposal;
    node.view = Math.max(node.view, v);
    node.touch();
    return { proposal };
  };

  // 安全规则：只投扩展本地最高 QC 的提案（+ 双花在投票前拒 + 至少一次/视图）。
  node.safetyRule = function safetyRule(proposal) {
    if (!proposal || typeof proposal !== 'object') return { pass: false, reason: 'safety: malformed proposal' };
    const v = Number(proposal.view);
    if (!Number.isInteger(v) || v < 0) return { pass: false, reason: 'safety: invalid view' };
    if (proposal.leader !== node.leaderOf(v)) return { pass: false, reason: `safety: leader mismatch at view ${v}` };
    if (node.expelled.has(proposal.leader)) return { pass: false, reason: `safety: leader ${proposal.leader} expelled` };

    const contentStr = canonicalJson(blockContent(proposal));
    const leaderPub = node.peerMap.get(proposal.leader);
    if (!leaderPub || !verifyString(contentStr, leaderPub, proposal.sig)) {
      return { pass: false, reason: 'safety: invalid leader signature' };
    }
    if (proposal.blockHash !== sha256hex(contentStr)) {
      return { pass: false, reason: 'safety: blockHash mismatch' };
    }
    if (v < node.view) return { pass: false, reason: `safety: stale view ${v} < ${node.view}` };
    if (node.votedViews.has(v)) return { pass: false, reason: `safety: already voted in view ${v}` };

    // 携带的 highestQC（justify）若有效且不低，先采纳，再校验父指针（防安全倒退）。
    if (proposal.justify != null) {
      if (proposal.justify.blockHash !== proposal.parentHash) {
        return { pass: false, reason: 'safety: carried QC (justify) does not match parentHash' };
      }
      if (!node.verifyQC(proposal.justify)) {
        return { pass: false, reason: 'safety: invalid carried QC (justify)' };
      }
      if (!node.highestQC || Number(proposal.justify.view) >= Number(node.highestQC.view)) {
        node.highestQC = proposal.justify;
        node.qcByView.set(proposal.justify.view, proposal.justify);
        node.qcByBlockHash.set(proposal.justify.blockHash, proposal.justify);
      }
    }

    const baseline = node.highestQC
      ? node.highestQC.blockHash
      : node.lastCommittedHash !== GENESIS_HASH
        ? node.lastCommittedHash
        : GENESIS_HASH;
    if (proposal.parentHash !== baseline) {
      return {
        pass: false,
        reason: `safety: parentHash does not extend local highest QC (${baseline})`,
      };
    }

    const ds = checkDoubleSpend(node, proposal.txs);
    if (ds) return { pass: false, reason: ds };
    return { pass: true, reason: null };
  };

  // vote(proposal)：安全规则通过 → 对 (view, blockHash, parentHash) 签名投票。
  node.vote = function vote(proposal) {
    const check = node.safetyRule(proposal);
    if (!check.pass) return { voted: false, reason: check.reason };

    const v = Number(proposal.view);
    node.blocks.set(proposal.blockHash, proposal);
    node.activeProposal = proposal;
    node.votedViews.add(v);
    node.view = Math.max(node.view, v);
    node.touch();

    const voteTarget = { view: proposal.view, blockHash: proposal.blockHash, parentHash: proposal.parentHash };
    const sig = signString(canonicalJson(voteTarget), privateKey);
    return { voted: true, vote: { nodeId: node.nodeId, pubKey: node.pubKey, sig } };
  };

  // 重验一个 QC（复用 phase3 collectQC 的逐签验签 + 去重 + 数量达标；除名者不计入）。
  node.verifyQC = function verifyQC(qc) {
    if (!qc || typeof qc !== 'object' || !Array.isArray(qc.sigs)) return false;
    const res = collectQC({
      envelope: { view: qc.view, blockHash: qc.blockHash, parentHash: qc.parentHash },
      endorsements: qc.sigs,
      roster: node.activeRoster(),
      threshold: node.threshold,
    });
    return res.ok === true && res.kept >= node.threshold;
  };

  // collectQC(votes)：2f+1 个个体签名验签 → QC；达标则推进本地 highestQC。
  node.collectQC = function collectQCVotes(votes) {
    const p = node.activeProposal;
    if (!p) return { ok: false, reasons: ['collectQC: no active proposal (call propose or vote first)'] };
    const res = collectQC({
      envelope: { view: p.view, blockHash: p.blockHash, parentHash: p.parentHash },
      endorsements: Array.isArray(votes) ? votes : [],
      roster: node.activeRoster(),
      threshold: node.threshold,
    });
    if (!res.ok) return { ok: false, reasons: res.reasons, required: res.required, kept: res.kept };

    const qc = {
      view: p.view,
      blockHash: p.blockHash,
      parentHash: p.parentHash,
      sigs: res.qc.endorsements.map((e) => ({ nodeId: e.nodeId, pubKey: e.pubKey, sig: e.sig })),
      threshold: res.qc.threshold,
      rosterSize: res.qc.rosterSize,
    };
    node.highestQC = qc;
    node.qcByView.set(qc.view, qc);
    node.qcByBlockHash.set(qc.blockHash, qc);
    node.touch();
    return { ok: true, qc };
  };

  // 找"已认证子块"：父指针为 parentHash 且自身有 QC（跳过无 QC 的分叉块）。
  function findCertifiedChild(parentHash) {
    for (const [, blk] of node.blocks) {
      if (blk.parentHash === parentHash && node.qcByBlockHash.has(blk.blockHash)) return blk;
    }
    return null;
  }

  // 3-chain 提交：B 有 QC 且子、孙各有 QC → 提交 B（子/孙必须自身有 QC，防分叉块遮蔽）。
  node.commitCheck = function commitCheck() {
    const candidates = [];
    for (const [hash, blk] of node.blocks) {
      if (node.committedHashes.has(hash)) continue;
      if (!node.qcByBlockHash.get(hash)) continue; // B 有 QC
      const child = findCertifiedChild(hash);
      if (!child) continue; // 子有 QC
      const grandchild = findCertifiedChild(child.blockHash);
      if (!grandchild) continue; // 孙有 QC
      candidates.push(blk);
    }
    candidates.sort((a, b) => Number(a.view) - Number(b.view));
    const commits = [];
    for (const blk of candidates) {
      if (node.committedHashes.has(blk.blockHash)) continue;
      node.commitBlock(blk);
      commits.push(blk);
    }
    return commits;
  };

  // 提交一个区块：追加账本哈希链 + 登记 nonce。
  node.commitBlock = function commitBlock(blk) {
    const record = {
      height: node.committedHeight,
      // M6：文件名可能是 sha256 摘要，账本行内保留 nodeId 本体（谁的账本一目了然）。
      nodeId: node.nodeId,
      block: {
        view: blk.view,
        leader: blk.leader,
        parentHash: blk.parentHash,
        blockHash: blk.blockHash,
        txs: blk.txs || [],
        sig: blk.sig,
      },
      prevHash: node.lastCommittedHash,
    };
    node.committed.push(blk);
    node.committedHashes.add(blk.blockHash);
    node.committedHeight += 1;
    node.lastCommittedHash = blk.blockHash;
    for (const tx of blk.txs || []) {
      if (tx && tx.type === 'commit') node.seenNonces.add(`${tx.from}:${tx.nonce}`);
    }
    appendLine(node.ledgerFile, JSON.stringify(record));
    node.touch();
  };

  // 视图切换：v+1，携带本地 highestQC（防安全倒退）。
  node.onTimeout = function onTimeout() {
    const prevView = node.view;
    node.view = prevView + 1;
    node.touch();
    return { prevView, newView: node.view, carriedQC: node.highestQC };
  };

  // equivocation 检测：同 (view, leader) 两个冲突提案 → 双签证据（复用 phase3）→ 自动除名。
  node.detectEquivocation = function detectEquivocation(proposals) {
    if (!Array.isArray(proposals)) return [];
    const signatures = proposals.map((p) => ({
      nodeId: p.leader,
      pubKey: node.peerMap.get(p.leader),
      envelopeId: String(p.view),
      content: canonicalJson(blockContent(p)),
      sig: p.sig,
    }));
    const evidence = detectDoubleSign(signatures);
    for (const ev of evidence) {
      node.expel(ev.nodeId);
    }
    return evidence;
  };

  // 除名：加入 expelled 集合；此后其签名不再计入 QC（activeRoster 过滤）。
  node.expel = function expel(id) {
    if (typeof id !== 'string' || id.length === 0) return { expelled: null, expelledSet: [...node.expelled] };
    node.expelled.add(id);
    return { expelled: id, expelledSet: [...node.expelled] };
  };

  // 重启恢复：从账本读回已提交前缀，验证哈希链 + 区块哈希 + 签名；
  // 并回放重算 highestQC/qcByView/qcByBlockHash/blocks（M12，不猜 —— 只用账本行内
  // 已提交区块自身重算，未提交 QC 的签名不在账本中，故以「已提交区块」为粒度恢复）。
  node.restore = function restore() {
    const records = readLedgerLines(node.ledgerFile);
    const blocks = [];
    let prevHash = GENESIS_HASH;
    for (let i = 0; i < records.length; i++) {
      const rec = records[i];
      if (rec.height !== i) throw new Error(`restore: ledger height mismatch at index ${i}`);
      if (rec.prevHash !== prevHash) throw new Error(`restore: ledger chain broken at index ${i}`);
      const blk = rec.block;
      if (!blk || blk.blockHash !== hashBlock(blk)) throw new Error(`restore: blockHash mismatch at index ${i}`);
      const leaderPub = node.peerMap.get(blk.leader);
      if (!leaderPub || !verifyString(canonicalJson(blockContent(blk)), leaderPub, blk.sig)) {
        throw new Error(`restore: leader signature mismatch at index ${i}`);
      }
      blocks.push(blk);
      prevHash = blk.blockHash;
    }

    node.committed = [];
    node.committedHashes.clear();
    node.seenNonces.clear();
    // M12：votedViews 置空（诚实重投），mempool 丢弃（不可恢复的未提交交易）。
    node.votedViews.clear();
    node.pendingTxs = [];
    node.pendingNonces.clear();
    node.activeProposal = null;
    // M12：blocks / qcByView / qcByBlockHash / highestQC 从已提交前缀回放重算。
    node.blocks.clear();
    node.qcByView.clear();
    node.qcByBlockHash.clear();
    node.highestQC = null;
    for (const blk of blocks) {
      node.committed.push(blk);
      node.committedHashes.add(blk.blockHash);
      node.blocks.set(blk.blockHash, blk);
      // 已提交区块必有 QC（3-chain 提交规则保证），用账本内可重建的部分做回放锚点：
      // 签名集合不在账本中，故 sigs 置空（restored 标记）；仅用于恢复 highestQC/父指针延续。
      const qc = {
        view: blk.view,
        blockHash: blk.blockHash,
        parentHash: blk.parentHash,
        sigs: [],
        threshold: node.threshold,
        rosterSize: node.roster.length,
        restored: true,
      };
      node.qcByView.set(blk.view, qc);
      node.qcByBlockHash.set(blk.blockHash, qc);
      node.highestQC = qc;
      for (const tx of blk.txs || []) {
        if (tx && tx.type === 'commit') node.seenNonces.add(`${tx.from}:${tx.nonce}`);
      }
    }
    node.committedHeight = blocks.length;
    node.lastCommittedHash = blocks.length ? blocks[blocks.length - 1].blockHash : GENESIS_HASH;
    if (blocks.length) node.view = Number(blocks[blocks.length - 1].view) + 1;
    node.touch();
    return { restored: blocks.length, blockHashes: blocks.map((b) => b.blockHash) };
  };

  // health()：共识节点真实状态（M11）。
  node.health = function health() {
    return {
      nodeId: node.nodeId,
      height: node.committedHeight,
      view: node.view,
      committed: node.committed.length,
      rosterSize: node.roster.length,
      f: node.f,
      threshold: node.threshold,
      qcCount: node.qcByBlockHash.size,
      expelled: [...node.expelled].length,
    };
  };

  // 已提交前缀（用于一致性比对）。
  node.committedDigest = function committedDigest() {
    return node.committed.map((b) => ({
      view: b.view,
      leader: b.leader,
      parentHash: b.parentHash,
      blockHash: b.blockHash,
      txs: b.txs,
    }));
  };

  // M12：autoRestore = true → 启动即恢复（回放已提交前缀）。
  if (autoRestore) node.restore();

  return node;
}
