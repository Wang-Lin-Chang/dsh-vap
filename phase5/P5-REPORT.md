# Phase 5 装置 —— 锁步 QC 链共识内核（VAP-TO）验收报告

> 立项问题：Phase 3 的 QC 只产"认可"不产"排序"；本阶段交付锁步 QC 链共识内核，把窄车道交易排成防双花的总序。
> 复用：信封/三闸/canonicalJson 复用 `vap-core.mjs`；QC 个体签名验签复用 `phase3/endorse-core.mjs`（`collectQC` / `detectDoubleSign`）——零改动，只 import。
> 诚实正名：锁步提交 / 视图切换 / equivocation 检测是**全新未测代码**，本阶段实验是第一次验证，不冒认"已实测"。

## 0. 多路独立推演与复核裁决记录（从 DESIGN.md 抄录）

三个锁定（收敛裁决）：

1. **commit 规则 = HotStuff 标准 3-chain**（B 有 QC 且子、孙各有 QC → 提交 B）——安全优先，最保守；
2. **分车道**：窄车道（资格凭证 / 惩罚证据，需总序防双花）走共识；默认车道（报告 / 任务，幂等）走既有去重 + 因果序；
3. **门限签名不引入**——QC = 2f+1 个个体签名集合（零依赖默认未被数据打破）。

复核裁决：

- **复核"门限签名"**：不引入门限签名，保持零第三方依赖，QC 用 2f+1 个个体签名验签（复用 phase3 `collectQC`）。
- **复核"已实测"**：锁步提交 / 视图切换 / equivocation 检测是全新未测代码，本阶段实验是第一次验证，不冒认。
- **复核"完全异步 + 拜占庭"**：部分同步假设内适用；完全异步 + 拜占庭 leader 可能活锁（异步 BA 是后续题，本阶段不做）。
- **复核"可防共谋"**：≥f+1 共谋可破安全（BFT 数学边界），只能检测不能阻止。

## 1. 交付物与运行方式

| 文件 | 职责 |
|---|---|
| `phase5/vap-to.mjs` | `createNode` 锁步 QC 链共识节点（轮次状态机 / 安全规则 / 2f+1 QC / 3-chain 提交 / 视图切换 / equivocation 自动除名 / append-only 哈希链账本 / 恢复 / 分车道） |
| `phase5/tests/vap-to.test.mjs` | node:test 单测（18 条：安全规则 / 3-chain 钉死 / QC 验签 / 除名 / 视图切换 / 双花拒绝 / 分车道 / 确定性 / 恢复） |
| `phase5/experiments/phase5-experiment.mjs` | T1-T6 六组实验，结构化 JSON 输出 |
| `phase5/experiments/phase5-results.json` | 本次实测的结构化结果（实验脚本自动写出） |

运行（在 dsh-vap/ 下）：

```
node --test                                      # 全绿：99 条（含本阶段 18 条）
node phase5/experiments/phase5-experiment.mjs    # T1-T6 + 结构化 JSON + 硬性自检
```

## 2. 核心设计实现

### 2.1 轮次状态机

- `view` 单调递增；`leader = view % n`（roster 按 nodeId 升序）；每轮 propose → vote → collectQC → commitCheck。
- `propose(view)`：leader 打包窄车道交易（`type=commit`）+ `parentHash`（本地最高 QC 区块 / 创世哨兵）+ `justify`（携带 highestQC）→ 签名广播。
- `vote(proposal)`：安全规则通过 → 对 `canonicalJson({view, blockHash, parentHash})` 签名投票。
- `collectQC(votes)`：2f+1 个个体签名验签（复用 phase3 `collectQC`）→ QC；达标推进本地 `highestQC`。
- `commitCheck()`：3-chain 规则（B 有 QC 且子、孙各有 QC → 提交 B；子 / 孙必须自身有 QC，防分叉块遮蔽）。

### 2.2 安全规则（vote 前置）

1. 结构合法 + view 合法 + `leader === view % n` + leader 未被除名；
2. leader 签名验签 + `blockHash` 一致性；
3. view 单调（不投过期 view）+ 每 view 至多一票（不投冲突提案）；
4. 携带的 highestQC（`justify`）有效且不低则先采纳（防安全倒退）；
5. **只投扩展本地最高 QC 的提案**（`parentHash === 本地最高区块`）；
6. **双花在投票前拒**（同 nonce 已提交 / 提案内重复 → 拒签，不进 QC）。

### 2.3 equivocation 检测 + 自动除名

- 同 `(view, leader)` 两个冲突提案 → 复用 phase3 `detectDoubleSign` 产出双签证据 `{ nodeId, sigA, sigB, contentA, contentB }`（第三方可验）→ `expel(nodeId)`。
- 除名后 `activeRoster()` 过滤该节点，其签名不再计入 QC。

### 2.4 分车道

- 窄车道 `type=commit` 走共识总序；默认车道（非 commit）不进总序（`submitTx` 拒绝、提案含非 commit 交易 → 安全规则拒绝）。

### 2.5 账本（append-only 哈希链）

- 每次提交追加一行 `{ height, block, prevHash }` 到 `phase5/ledger-<nodeId>.jsonl`；`prevHash` 链接前一已提交区块哈希。
- `restore()`：读回、验证高度递增 + 哈希链 + `blockHash` + leader 签名，恢复已提交前缀；账本被篡改即抛错。

## 3. 实验结果（本轮实测）

装置：n=4，f=1，QC 门槛 2f+1=3，commit 规则 HotStuff 3-chain。

| 实验 | 结果 | 判据 |
|---|---|---|
| **T1 正常收敛** | 10 轮 → 8 块提交，4 节点提交前缀逐字节一致 | `allNodesIdenticalPrefix=true` |
| **T2 崩溃容错** | kill view3 leader(n4) → 超时切 view4 → 新 leader 提交 block2，已提交前缀(block0)不回滚 | `prefixNotRolledBack=true` `newLeaderCommitted=true` |
| **T3 分叉注入** | 拜占庭 n4 双提案 P1/P2（各 2 票 <3）→ 无 QC → 1 条双签证据（第三方可验）→ 自动除名 n4；除名后 3 诚实节点签名继续成 QC，分叉 0 支提交 | `equivocationEvidenceCount=1` `autoExpelled=true` `branchesCommittedFromFork=0` |
| **T4 双花拒绝** | 同 nonce 第二笔在 mempool 层拒；塞进提案后 4 节点投票前拒（0 票，不进 QC） | `rejectedBeforeVote=true` |
| **T5 确定性重放** | 同密钥同输入跑两次 → 账本 1714 字节逐字节一致（sha256 相同） | `byteIdentical=true` |
| **T6 重启恢复** | 杀进程重启 → 恢复 4 块已提交前缀（哈希链验证通过）→ 继续 views 4-6 → 新提交块父指针 = 最后恢复块 | `recoveredIdentical=true` `extendedRecoveredPrefix=true` |

**结论：T1-T6 全部达标，`conclusion.allPass=true`。**

## 4. 验收标准对照（DESIGN §四）

| 验收项 | 结果 |
|---|---|
| T1-T6 全达标 | ✅ 六实验全达标（`allPass=true`） |
| 零第三方依赖 | ✅ 仅 node: 内置模块与相对路径 import |
| 复用模块零改动 | ✅ 未修改 `../vap-core.mjs`、`../phase3/endorse-core.mjs`（只 import） |
| 3-chain 提交规则单测钉死（2 链不提交、3 链才提交） | ✅ 单测 `3-chain commit: no commit with 2 QCs, commit at the 3rd QC` |
| equivocation 自动除名（除名后签名不计入） | ✅ 单测 `equivocation detection ... auto-expels` + `expelled node signature no longer counts toward QC` |
| 双花在投票前被拒（不进 QC） | ✅ 单测 + T4（0 票，`doubleSpendEnteredQc=false`） |
| 结构化 JSON | ✅ stdout + `phase5-results.json`（含 `conclusion` 段） |

## 5. 诚实边界（DESIGN §五）

1. 部分同步假设：信任域场景适用；完全异步 + 拜占庭 leader 可能活锁（异步 BA 是后续，本阶段不做）。
2. 静态 4 节点 roster（动态成员是 Phase 6）。
3. 无流水线 / 批量（吞吐 ≈ RTT×轮次，性能债显式标注）。
4. ≥f+1 共谋可破安全（BFT 数学边界），只能检测不能阻止。
5. 本机多进程 / 同进程模拟，跨机部署待 Phase 6 公网灰度。

## 6. 纪律自检

- 零第三方依赖：仅 node: 内置模块与相对路径 import，无 package.json、无 node_modules。
- 复用而非复制：`canonicalJson`（vap-core）、`collectQC` / `detectDoubleSign` / `verifyDoubleSignEvidence`（phase3）全部 import 复用，零改动。
- 不伪造实验结果：T1-T6 真实跑出，硬性自检失败即非零退出码（实测退出码 0）。
- 坏词清单：交付文件（vap-to.mjs / vap-to.test.mjs / phase5-experiment.mjs / P5-REPORT.md / progress-phase5.md）未出现禁用词。
- 3-chain 提交用"子 / 孙必须自身有 QC"的认证子块查找，单测钉死"无 QC 的分叉块不遮蔽认证链"。
