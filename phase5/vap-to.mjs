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
  // R3（生产级加固）：逐行 JSON.parse 必须容错——appendFileSync 非原子，崩溃可留半行；
  // 坏行（含尾部半行）跳过，绝不让「单行损坏」把 autoRestore 节点打成崩溃循环。
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      out.push(JSON.parse(t));
    } catch {
      // 跳过损坏行：从最近一致前缀继续（后续行的块哈希链会自然断在坏行处）
    }
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

  // QC 门槛（TLC 实测修正）：2f+1 仅在 n=3f+1 时与 ⌈2n/3⌉ 相等；n>3f+1（如 N=5/6）时
  // 2f+1 的诚实票下界过低，TLC 给出「同视图双 QC」（两个 QC 的诚实票互不相交）诚实反例。
  // 正确门槛 = max(2f+1, ⌈2n/3⌉)，保证任意两个 QC 的诚实票集合交集非空（quorum 交集论证成立）。
  const threshold = Math.max(2 * f + 1, Math.ceil((2 * n) / 3));
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
    childIndex: new Map(),      // P3：parentHash -> blockHash（已认证子索引，commitCheck O(B) 关键）
    activeProposal: null,
    lock: null,                // P2 lock-on-vote：{ blockHash, view }；null 等价锁创世

    // V4（第三层活性修复）view-change / new-view 消息状态：
    viewChanges: new Map(),     // nodeId -> Map(view -> { nodeId, view, highestQC })
    newViews: new Map(),        // view -> { view, anchorQC }（anchorQC 为 null = 创世锚）

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

  // 签名一个提案（供拜占庭场景构造：任意 parentHash / txs）。justify 默认为空，
  // 可显式传入父块 QC（第二层 Certified(parent) 前置的负控制用）。
  node.signProposal = function signProposal({ view, leader, parentHash, txs, justify = null } = {}) {
    const proposal = { view, leader, parentHash, txs: sortTxs(txs || []), justify, sig: '' };
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

    // baseline/最高-QC 扩展检查（V2 活性修复，PROOFS.md P1「扩展本地最高已认证区块」）：
    // 诚实节点对提案 P 投票的必要条件 = P.parentHash 沿 parent 链可达本地最高 QC 块
    // （isDescendant，允许相等 = 最高 QC 的扩展）；highestQC 为空且无已提交前缀时
    // baseline = 创世，此时仅允许 parent = GENESIS（isDescendant 对创世恒真，需显式等值特判）。
    const baseline = node.highestQC
      ? node.highestQC.blockHash
      : node.lastCommittedHash !== GENESIS_HASH
        ? node.lastCommittedHash
        : null; // 空基线（无最高 QC、无已提交前缀）→ 仅允许 parent = GENESIS
    if (baseline == null) {
      if (proposal.parentHash !== GENESIS_HASH) {
        return {
          pass: false,
          reason: 'safety: parentHash does not extend local highest QC (empty baseline, expect parent = GENESIS)',
        };
      }
    } else if (!node.isDescendant(proposal.parentHash, baseline)) {
      return {
        pass: false,
        reason: `safety: parentHash does not extend local highest QC (${baseline})`,
      };
    }

    // V3（第二层活性修复，Certified(parent) 前置）：父块必须已认证。
    // 收紧 baseline「扩展」语义：parentHash 沿链可达最高已认证块不再足够，parent 自身必须已获 QC
    // （= 提案携带父块 QC justify 的显式建模，与 TLA+ 的 ParentCertified(b)=Certified(parent[b]) 对齐）。
    // 判定：非创世父块，要么上方 justify 已验签并采纳进 qcByBlockHash，要么本地已持有该父块 QC
    // （qcByBlockHash，含 restore 回放的已提交块 QC）。消除 §4.2「父块=最高已认证块的未认证后代」
    // 反例：B1 获 QC 后投 parent=B2（B2 沿链可达 B1 但自身无 QC）的 B3 → B2 永无 QC → 无 3-chain。
    const parentCertified = proposal.parentHash === GENESIS_HASH || node.qcByBlockHash.has(proposal.parentHash);
    if (!parentCertified) {
      return {
        pass: false,
        reason: 'safety: parentHash is not certified (parent block has no QC; proposal must carry a valid justify QC for parent)',
      };
    }

    // P2（lock-on-vote）：提案必须扩展当前 lock（lock 为 null=创世则跳过）。
    // 用 parentHash 回溯（提案自身尚未入 blocks）：lock.blockHash 须是 parentHash 的祖先或相等。
    if (node.lock != null && !node.isDescendant(proposal.parentHash, node.lock.blockHash)) {
      return {
        pass: false,
        reason: `safety: proposal does not extend lock (${node.lock.blockHash})`,
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

    // P2（lock-on-vote）：投票成功即把 lock 推进到所投区块的父块。
    // 父块视图取携带 QC（justify = 父块 QC）的 view；无 justify 且非创世时查本地父块。
    if (proposal.parentHash === GENESIS_HASH) {
      node.lock = null; // 创世提案：父块即创世，lock 保持/置创世（null 等价）。
    } else {
      let parentView = null;
      if (proposal.justify != null) {
        parentView = proposal.justify.view;
      } else {
        const parentBlk = node.blocks.get(proposal.parentHash);
        if (parentBlk) parentView = parentBlk.view;
      }
      node.lock = { blockHash: proposal.parentHash, view: parentView };
    }

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
    indexCertifiedChild(node.blocks.get(qc.blockHash)); // P3：维护已认证子索引
    node.touch();
    return { ok: true, qc };
  };

  // P2（lock-on-vote）回溯 helper：判定 blockHash 是否扩展 ancestorHash（即 ancestorHash 在
  // blockHash 的祖先链上，含相等）。沿 blocks 的 parentHash 链回溯。
  // P5（生产级加固）：固定深度上限 1000 在长链下会把诚实提案误判「不扩展」→ 活性隐患。
  // 改为「祖先方向 view 严格递减」判环 + 步数上限 = blocks.size + 2（链长不可能超过块总数）。
  node.isDescendant = function isDescendant(blockHash, ancestorHash) {
    if (ancestorHash == null || ancestorHash === GENESIS_HASH) return true;
    if (blockHash === ancestorHash) return true;
    const ancestorBlk = node.blocks.get(ancestorHash);
    const ancestorView = ancestorBlk ? Number(ancestorBlk.view) : Number.POSITIVE_INFINITY;
    let cursor = blockHash;
    let prevView = Number.POSITIVE_INFINITY;
    let steps = 0;
    const maxSteps = node.blocks.size + 2;
    while (steps <= maxSteps) {
      if (cursor === ancestorHash) return true;
      if (cursor === GENESIS_HASH) return false;
      const blk = node.blocks.get(cursor);
      if (!blk) return false;
      const v = Number(blk.view);
      if (v < ancestorView) return false; // 已低于祖先 view：不可能再回溯到祖先
      if (v >= prevView) return false;    // 环保护：祖先方向 view 必须严格递减
      prevView = v;
      cursor = blk.parentHash;
      steps += 1;
    }
    return false; // 超过步数上限（块总数+2）视为不扩展——正常链长不可能触及
  };

  // P3（生产级加固）：已认证子索引。父块最多一个「已认证子」（同 view 唯一 leader 提案），
  // childIndex 由 collectQC 成功与 restore 回放时维护，把 commitCheck 的
  // findCertifiedChild 从 O(B) 全表扫描降为 O(1)，整函数 O(B²) → O(B)。
  function indexCertifiedChild(blk) {
    if (blk && blk.blockHash && blk.parentHash && node.qcByBlockHash.has(blk.blockHash)) {
      node.childIndex.set(blk.parentHash, blk.blockHash);
    }
  }

  // 找"已认证子块"：父指针为 parentHash 且自身有 QC（跳过无 QC 的分叉块）。
  function findCertifiedChild(parentHash) {
    const h = node.childIndex.get(parentHash);
    return h ? node.blocks.get(h) || null : null;
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
    // P4（生产级加固）：每 100 块落一次快照，restore 从快照前缀重建、跳过逐块验签。
    if (node.committedHeight % SNAPSHOT_EVERY === 0) writeSnapshot();
    node.touch();
  };

  // P4：周期快照 { v, height, lastCommittedHash, blocks }。信任域 = 本地磁盘（与账本同级，
  // 威胁模型 E0-E3 不覆盖磁盘，E4 物理接触不在威胁模型内）。restore 用快照时对块链
  // 重算 blockHash 校验链完整性（防快照内损坏），但跳过逐块 Ed25519 验签（O(L·验签) → O(L·哈希)）。
  const SNAPSHOT_EVERY = 100;
  function snapshotPath() {
    return `${node.ledgerFile}.snapshot.json`;
  }
  function writeSnapshot() {
    const snap = {
      v: 1,
      height: node.committedHeight,
      lastCommittedHash: node.lastCommittedHash,
      blocks: node.committed.map((b) => ({
        view: b.view, leader: b.leader, parentHash: b.parentHash,
        blockHash: b.blockHash, txs: b.txs || [], sig: b.sig,
      })),
    };
    const tmp = `${snapshotPath()}.tmp-${crypto.randomBytes(4).toString('hex')}`;
    try {
      fs.writeFileSync(tmp, `${JSON.stringify(snap)}\n`, 'utf8');
      fs.renameSync(tmp, snapshotPath());
    } catch {
      try { fs.unlinkSync(tmp); } catch { /* 尽力清理 */ }
      // 快照失败不影响提交（下次周期重试）
    }
  }
  function readSnapshot() {
    try {
      const snap = JSON.parse(fs.readFileSync(snapshotPath(), 'utf8'));
      if (!snap || snap.v !== 1 || !Number.isInteger(snap.height) || snap.height <= 0) return null;
      if (!Array.isArray(snap.blocks) || snap.blocks.length !== snap.height) return null;
      return snap;
    } catch {
      return null;
    }
  }

  // 视图切换（P4）：超时 → v+1，携带本地 highestQC（防安全倒退）。
  // V4（第三层活性修复）：扩展为 view-change 流程 —— 生成 view-change 消息
  // { nodeId, view, highestQC } 并登记本地 viewChanges（供新 leader 聚合）。
  // 返回保留既有 { prevView, newView, carriedQC } 字段（向后兼容），另增 viewChange。
  node.onTimeout = function onTimeout() {
    const prevView = node.view;
    node.view = prevView + 1;
    const vc = {
      nodeId: node.nodeId,
      view: node.view,
      highestQC: node.highestQC, // 本地最高 QC（无 QC 时 null = 创世锚）
    };
    if (!node.viewChanges.has(node.nodeId)) node.viewChanges.set(node.nodeId, new Map());
    node.viewChanges.get(node.nodeId).set(node.view, vc);
    node.touch();
    return { prevView, newView: node.view, carriedQC: node.highestQC, viewChange: vc };
  };

  // V4（第三层活性修复）view-change 收集：接收并校验其它节点的 view-change 消息
  // { nodeId, view, highestQC }。校验：nodeId 在 roster、view 为非负整数、
  // highestQC 为空或 verifyQC 通过（除名者拒收）。通过后登记进本地 viewChanges。
  node.receiveViewChange = function receiveViewChange(vc) {
    if (!vc || typeof vc !== 'object') return { ok: false, reason: 'receiveViewChange: malformed view-change' };
    if (typeof vc.nodeId !== 'string' || !node.peerMap.has(vc.nodeId)) {
      return { ok: false, reason: `receiveViewChange: unknown node ${vc.nodeId}` };
    }
    if (node.expelled.has(vc.nodeId)) {
      return { ok: false, reason: `receiveViewChange: node ${vc.nodeId} expelled` };
    }
    const v = Number(vc.view);
    if (!Number.isInteger(v) || v < 0) return { ok: false, reason: 'receiveViewChange: invalid view' };
    if (vc.highestQC != null && !node.verifyQC(vc.highestQC)) {
      return { ok: false, reason: 'receiveViewChange: invalid carried QC' };
    }
    if (!node.viewChanges.has(vc.nodeId)) node.viewChanges.set(vc.nodeId, new Map());
    node.viewChanges.get(vc.nodeId).set(v, vc);
    node.touch();
    return { ok: true };
  };

  // V4（第三层活性修复）new-view 聚合：收集 ≥ threshold 个（除名者除外的）节点对
  // targetView 的 view-change 消息，取其中 view 最高的 QC 作为锚（anchor）。
  // 返回 { ok, newView: { view, anchorQC }, collected } 或 { ok:false, reason, collected }。
  node.aggregateNewView = function aggregateNewView(targetView) {
    const v = Number(targetView);
    if (!Number.isInteger(v) || v < 0) return { ok: false, reason: 'aggregateNewView: invalid view', collected: 0 };
    let anchorQC = null;
    let seen = 0;
    for (const byView of node.viewChanges.values()) {
      const vc = byView.get(v);
      if (!vc) continue;
      if (node.expelled.has(vc.nodeId)) continue;
      seen += 1;
      if (vc.highestQC != null && (anchorQC == null || Number(vc.highestQC.view) > Number(anchorQC.view))) {
        anchorQC = vc.highestQC;
      }
    }
    if (seen < node.threshold) {
      return { ok: false, reason: `aggregateNewView: only ${seen}/${node.threshold} view-changes for view ${v}`, collected: seen };
    }
    const nv = { view: v, anchorQC }; // anchorQC 为 null = 创世锚（无任何 QC）
    node.newViews.set(v, nv);
    node.touch();
    return { ok: true, newView: nv, collected: seen };
  };

  // V4（第三层活性修复）采纳 new-view：校验 new-view 携带的锚 QC（anchorQC），
  // 若 ≥ 本地 highestQC 则采纳（推进 highestQC/qcByView/qcByBlockHash），否则拒。
  // 这是「诚实节点只接受携带 ≥ 本地最高 QC 的 new-view 提案」的落地。
  node.adoptNewView = function adoptNewView(nv) {
    if (!nv || typeof nv !== 'object') return { ok: false, reason: 'adoptNewView: malformed new-view' };
    const anchorQC = nv.anchorQC;
    if (anchorQC == null) return { ok: true, adopted: false }; // 创世锚：无可采纳 QC
    if (!node.verifyQC(anchorQC)) return { ok: false, reason: 'adoptNewView: invalid anchor QC' };
    if (node.highestQC && Number(anchorQC.view) < Number(node.highestQC.view)) {
      return { ok: false, reason: 'adoptNewView: anchor QC lower than local highestQC' };
    }
    node.highestQC = anchorQC;
    node.qcByView.set(anchorQC.view, anchorQC);
    node.qcByBlockHash.set(anchorQC.blockHash, anchorQC);
    node.touch();
    return { ok: true, adopted: true };
  };

  // V4（第三层活性修复）new-view 提案：leader 聚合 view-change → 采纳锚 → 以锚为父块
  // 提出 targetView 的 new-view 提案（proposal.parent = anchorQC.blockHash，justify = anchorQC）。
  // 复用现有 propose 的父指针延续：先 adoptNewView 把 highestQC 推进到锚，
  // 再 propose(targetView) 即锚定 parent = highestQC.blockHash 并携带 justify = 锚 QC。
  node.proposeNewView = function proposeNewView(targetView) {
    const v = Number(targetView);
    if (!Number.isInteger(v) || v < 0) return { refused: true, reason: `proposeNewView: invalid view ${targetView}` };
    if (node.leaderOf(v) !== node.nodeId) {
      return { refused: true, reason: `proposeNewView: node ${node.nodeId} is not leader of view ${v}` };
    }
    const agg = node.aggregateNewView(v);
    if (!agg.ok) return { refused: true, reason: agg.reason, collected: agg.collected };
    if (agg.newView.anchorQC != null) {
      const ad = node.adoptNewView(agg.newView);
      if (!ad.ok) return { refused: true, reason: `proposeNewView: ${ad.reason}` };
    }
    return node.propose(v);
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
  // R3（生产级加固）：校验失败不再 throw 打崩启动——截断到「最近一致前缀」并记录
  // truncatedAt，autoRestore 节点从一致位置继续服务，不再崩溃循环。
  node.restore = function restore() {
    const records = readLedgerLines(node.ledgerFile);
    const blocks = [];
    let prevHash = GENESIS_HASH;
    let truncatedAt = null;
    let snapUsed = false;

    // P4（生产级加固）：有有效快照时先用快照重建前缀——只重算哈希链完整性（不逐块验签），
    // 把重启回放从 O(L·验签) 降为 O(L·哈希)。快照损坏/链断则回退全量验签回放（不牺牲安全性）。
    const snap = readSnapshot();
    if (snap && snap.height <= records.length && snap.blocks.length === snap.height) {
      let snapOk = true;
      for (let i = 0; i < snap.blocks.length; i += 1) {
        const b = snap.blocks[i];
        try {
          const expectParent = i === 0 ? GENESIS_HASH : snap.blocks[i - 1].blockHash;
          if (!b || b.parentHash !== expectParent) { snapOk = false; break; }
          if (b.blockHash !== hashBlock(b)) { snapOk = false; break; }
          blocks.push(b);
        } catch { snapOk = false; break; }
      }
      if (snapOk && snap.lastCommittedHash === blocks[blocks.length - 1].blockHash) {
        snapUsed = true;
        prevHash = snap.lastCommittedHash;
      } else {
        blocks.length = 0; // 快照不可信：回退全量回放
      }
    }

    for (let i = blocks.length; i < records.length; i++) {
      const rec = records[i];
      let bad = false;
      try {
        if (!rec || rec.height !== i) { bad = true; }
        else if (rec.prevHash !== prevHash) { bad = true; }
        else {
          const blk = rec.block;
          if (!blk || blk.blockHash !== hashBlock(blk)) { bad = true; }
          else {
            const leaderPub = node.peerMap.get(blk.leader);
            if (!leaderPub || !verifyString(canonicalJson(blockContent(blk)), leaderPub, blk.sig)) bad = true;
            else {
              blocks.push(blk);
              prevHash = blk.blockHash;
            }
          }
        }
      } catch {
        bad = true; // 畸形块（深层嵌套等）触发 canonicalJson 等异常：视为损坏，截断
      }
      if (bad) {
        truncatedAt = i;
        break;
      }
    }
    node.lastRestoreError = truncatedAt === null
      ? null
      : `ledger invalid at index ${truncatedAt}; restored consistent prefix of ${blocks.length} blocks`;
    // R3（复验轮发现）：截断后必须把账本压缩为一致前缀（原子重写），
    // 否则后续新提交 append 在断裂行之后，重启再恢复时新块永久丢失。
    if (truncatedAt !== null) {
      try {
        const raw = fs.readFileSync(node.ledgerFile, 'utf8');
        const goodLines = raw.split('\n').filter((l) => {
          const t = l.trim();
          if (!t) return false;
          try { JSON.parse(t); return true; } catch { return false; }
        });
        const prefix = goodLines.slice(0, blocks.length);
        const tmp = `${node.ledgerFile}.compact-${crypto.randomBytes(4).toString('hex')}`;
        fs.writeFileSync(tmp, `${prefix.join('\n')}${prefix.length ? '\n' : ''}`, 'utf8');
        fs.renameSync(tmp, node.ledgerFile);
      } catch { /* 压缩失败不阻断恢复（下次启动再截断一次） */ }
    }

    node.committed = [];
    node.committedHashes.clear();
    node.seenNonces.clear();
    // M12：votedViews 置空（诚实重投），mempool 丢弃（不可恢复的未提交交易）。
    node.votedViews.clear();
    node.pendingTxs = [];
    node.pendingNonces.clear();
    node.activeProposal = null;
    // 锁不持久化：重启后 lock 从已提交前缀重建（置 null 诚实声明，等价锁创世）。
    node.lock = null;
    // M12：blocks / qcByView / qcByBlockHash / highestQC 从已提交前缀回放重算。
    node.blocks.clear();
    node.qcByView.clear();
    node.qcByBlockHash.clear();
    node.childIndex.clear(); // P3：回放重建索引
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
      indexCertifiedChild(blk); // P3：回放时重建已认证子索引
      node.highestQC = qc;
      for (const tx of blk.txs || []) {
        if (tx && tx.type === 'commit') node.seenNonces.add(`${tx.from}:${tx.nonce}`);
      }
    }
    node.committedHeight = blocks.length;
    node.lastCommittedHash = blocks.length ? blocks[blocks.length - 1].blockHash : GENESIS_HASH;
    if (blocks.length) node.view = Number(blocks[blocks.length - 1].view) + 1;
    node.touch();
    return { restored: blocks.length, truncatedAt, snapUsed, blockHashes: blocks.map((b) => b.blockHash) };
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
