# baseline/最高-QC 扩展检查 —— 修复 VAP 锁步 QC 共识 TLC 活性缺口（进行记录）

> 目标：消除「诚实节点跳跃投票」EventuallyCommit 反例，且不破坏既有 7 条安全性质与全部测试。
> 接力机制：每轮追加本文件；下一轮先读本文件。

---

## 0. 最终结论（Round 1）

**baseline/最高-QC 扩展检查已设计并落地（实现 + TLA+ 双侧），7 条安全性质零回退、全部测试无回退；TLC 实证：**
- **安全回归 PASS**（7 不变式 + ViewProgress，完整穷举 "No error"）。
- **§5.2「跳跃投票」反例已消除**（TLC 不再在 34K 状态处复现，反例点后移至 86K）。
- **EventuallyCommit 仍 FAIL，但反例已升级为更深、更精确的缺口**，如实记录两条新反例并给出「还缺什么」：
  1. **稳定 leader 模型**：`父块 = 最高已认证块的『未认证后代』`仍可被投（父块无 QC 但沿链可达最高 QC）
     → 缺「**父块必须已认证（Certified(parent)）**」= 提案携带父块 QC（justify），即实现 `safetyRule`
     的 justify 校验在抽象模型 Propose 中被省略的那一处。
  2. **完全对抗模型**：`父块 = Genesis 的高视图块`仍可被投（空基线下 parent=Genesis 被放行）
     → 缺「**view-change/new-view 携带最高 QC 的消息协议 + 部分同步(GST)**」，这是 HotStuff 标准活性假设。

**结论：baseline 检查是活性修复的必要且正确的第一步（消除空基线跳跃投票），但不是充分条件；
完整活性需补「父块 Certified」与「new-view 携带最高 QC」两层协议机制。**

---

## 1. 设计决定：baseline/最高-QC 扩展检查

### 1.1 形式化一句话

**诚实节点 h 对提案块 b 投票的必要条件**（新增 Vote 前置 `BaselineOK`）：

```
HighestCertified ==
  IF \E b \in blocks : Certified(b)
  THEN CHOOSE b \in blocks : Certified(b) /\ \A q \in blocks : Certified(q) => viewOf[q] <= viewOf[b]
  ELSE Genesis

BaselineOK(h, b) ==
  \/ HighestCertified = Genesis /\ parent[b] = Genesis
  \/ HighestCertified /= Genesis /\ Extends(parent[b], HighestCertified)
```

即：**`parent[b]` 沿父链可达最高已认证块（= 最高 QC 的扩展，允许相等）；最高 QC 为空（= Genesis）时仅要求 `parent[b] = Genesis`。**

实现侧等价（phase5/vap-to.mjs）：`isDescendant(proposal.parentHash, baseline)`，
`baseline = highestQC.blockHash`（无 highestQC 且无已提交前缀时 `baseline = null`，仅允许 `parent = GENESIS`）。

> **建模选择（重要）**：`HighestCertified` 是**派生算子**（从全局 `votes` 算最高视图已认证块），
> 而非新增 per-node 变量 + AdoptQC 动作。理由：本 TLA 模型本就是共享状态的「超近似」抽象
> （TLA-REPORT.md §2.6，`Certified` 已从全局 `votes` 派生）；per-node `highestQC` 变量会让
> Block=3/MaxView=2 状态空间从 80K 膨胀到 327K（10min52s），而派生算子反降到 64K（2min22s）。
> 两者对反例结论一致，派生算子更契合既有抽象风格、代价更低。

### 1.2 为何消除「跳跃投票」反例

TLC-RESULTS.md §5.2 反例：链 `Genesis(0) → B3(1) → B1(2) → B2(3)`，诚实节点各自 ViewChange
到 view=3 后直接投 `B2@3`（跳过 B3、B1）⇒ 仅 B2 获 QC、B3/B1 永无 QC ⇒ 3-chain 永不成立。
根因：原 Vote 只有 `Extends(b, lock[h])`，**没有「父块必须扩展最高 QC」的 baseline 检查**。

新规则下：诚实节点 `HighestCertified = Genesis`（从未形成 QC），而 `B2` 的 `parent = B1 /= Genesis`
→ `BaselineOK` 不成立 → **拒投**。跳跃投票被消除（TLC 实证：反例点从 34K 状态后移到 86K 状态）。

### 1.3 为何不破坏 quorum 交集安全论证

`BaselineOK` 是 Vote 的**新增前置条件**：它只**削减诚实票的集合**（拒投部分提案），
**不新增任何票**、不改变 A2「同视图至多一票」、不改变 `Quorum = f+1` 计数。因此
L1（quorum 交集）→ L2（诚实交集）→ L3（同视图唯一 QC）→ 定理 T（无冲突提交）在
**更宽松的「超近似」模型**下已成立（TLA-REPORT.md §2.6、TLC-RESULTS.md 7 不变式 PASS）；
收紧诚实行为后，全称安全性质只可能更容易满足。**结论：baseline 检查是活性修复，不触碰安全边界。**

---

## 2. 实现 diff 要点

### 2.1 phase5/vap-to.mjs（`safetyRule`，约 L431-456）

- 原**等值检查** `proposal.parentHash !== baseline` → 升级为**扩展检查**
  `!node.isDescendant(proposal.parentHash, baseline)`（沿 parent 链可达，允许相等/后代）。
- 显式补「空基线」特例：`highestQC` 为空且无已提交前缀时 `baseline = null`，
  仅允许 `parent = GENESIS`（`isDescendant` 对创世恒真，故不能用它判空基线）。
- 拒投 reason：
  - 空基线：`safety: parentHash does not extend local highest QC (empty baseline, expect parent = GENESIS)`
  - 非空基线：`safety: parentHash does not extend local highest QC (${baseline})`
  - （保留 `parentHash` 子串，兼容既有测试 `r.reason.includes('parentHash')`。）

### 2.2 tlaplus/VAPConsensus.tla

- 新增派生算子 `HighestCertified`（最高视图已认证块，无 QC 时= Genesis）+ `BaselineOK(h, b)`（§1.1）。
- `Vote(h, b)` 前置增加 `BaselineOK(h, b)`（唯一语义改动，未增变量/未增动作）。
- 版本号 V1 → V2；注释如实标注剩余活性边界。

### 2.3 tlaplus/VAPConsensusLeader.tla

- 复用 VAPConsensus 的 Vote/BaselineOK（无独立改动）；头注释更新为「稳定 leader + baseline 检查」，
  并诚实标注剩余缺口（view-change 携带最高 QC）。

### 2.4 新增回归测试（phase5/tests/vap-to.test.mjs，+2 条）

1. `baseline 空基线：跳视图后拒投「父块无 QC」的高视图块（复现 TLC §5.2 跳跃投票反例）`
   —— 诚实节点跳视图 0→3、highestQC 仍为空；拜占庭 leader 提 view-3 块（父=无 QC 的 B1）
   → 拒投 + reason 含 `highest QC`/`empty baseline`；负控制：父=GENESIS 照常通过。
2. `baseline 扩展语义：父块为 highestQC 的严格后代也通过（旧等值检查会误拒）`
   —— 钉死「扩展」语义（严格后代也通过，非等值）。

---

## 3. 测试结果

### 3.1 node --test 全量（dsh-vap/）

| 运行 | 结果 |
|---|---|
| `node --test phase5/tests/vap-to.test.mjs` | **29 tests / 29 pass / 0 fail**（含新增 2 条） |
| `node --test`（全量，多次） | **256 tests / 252 pass / 1 fail / 3 skip** |

全量中唯一 `1 fail` = `phase7/_sym-test.mjs`（STUN NAT 对称性测试，向 Google 74.125.250.129 /
Cloudflare 发 UDP）：**与本次改动无关**（该文件不 import phase5/vap-to.mjs，`grep` 零命中）；
单测 `node --test phase7/_sym-test.mjs` 单独跑 **pass**（网络时序抖动导致全量并发下偶发超时）。
基线口径（251 pass/3 skip）之上净增 2 条新测试均通过；**无共识/安全测试回退**。

### 3.2 新增回归测试单独取证

见 §2.4；phase5 单测 29/29 全绿（其中含新增 2 条）。

---

## 4. TLC 服务器验证（腾讯云 ubuntu@101.42.23.246，TLC 2.19 / java 17）

改后 `VAPConsensus.tla`、`VAPConsensusLeader.tla` 已上传至 `/home/ubuntu/tlaplus/`，三跑实测：

| 运行 | 配置 | 结果 | 状态空间 / 耗时 |
|---|---|---|---|
| **安全回归** | `MC-N4-b3-v2.cfg` + `MC`（Block=3/MaxView=2） | **PASS** "Model checking completed. No error has been found."（7 不变式 + ViewProgress） | 64,260 distinct / 2min22s（原 80,820/95s） |
| **EventuallyCommit（稳定 leader）** | `MC-leader-b4-v3.cfg` + `VAPConsensusLeader` | **FAIL（新反例）** Temporal properties were violated | 86,522 distinct / 6min20s |
| **EventuallyCommit（完全对抗）** | `MC-commit-b4-v3.cfg` + `MC` | **FAIL（§5.1 反例）** Temporal properties were violated | 82,862 distinct / 3min09s |

### 4.1 安全回归：7 条安全性质零回退

Block=3/MaxView=2 完整穷举 "No error"；且状态空间 **64,260 < 原 80,820**（baseline 检查削减了
跳跃投票，投票组合减少），间接证明「只减票、不加票」。

### 4.2 稳定 leader 模型：§5.2 跳跃投票已消除，但出现「父块未认证后代」新反例

新反例轨迹（`run-v2-leader.log`）：
```
State 2: ProposeLeader B1@1（parent Genesis）
State 3: n2 投 B1@1
State 6: n1 投 B1@1          ⇒ B1 获 2 票 = QC（HighestCertified = B1）
State 4/5: ProposeLeader B2@2（parent B1）、B3@3（parent B2）
State 7: n3 投 B2@2          ⇒ B2 仅 1 票，无 QC
State 9/10: n1、n2 投 B3@3（parent B2，B2 沿链可达 B1 → BaselineOK 放行）⇒ B3 获 QC
State 11: Stuttering        ⇒ B2 永无 QC ⇒ 3-chain 永不成立 ⇒ 无提交
```
**机理**：baseline「扩展」语义允许 `parent = 最高已认证块的未认证后代`（B2 沿链可达 B1 但 B2 自身无 QC）。
**还缺**：`parent[b]` 必须**已认证** `Certified(parent[b])`——即提案携带父块 QC（justify）；这正是实现
`safetyRule` 的 justify 校验（vap-to.mjs L417-429）在抽象模型 Propose「parent 即延续的 QC 块」
（TLA-REPORT.md §2.5）中被省略、未显式建模的那一处。

### 4.3 完全对抗模型：§5.1「父块=Genesis」反例仍存

新反例轨迹（`run-v2-commit.log`）：
```
State 2/3: 拜占庭 leader Propose B1@3、B2@3（均 parent Genesis，同视图分叉）
State 4: n2 投 B1@3
State 5/6: n1、n3 投 B2@3   ⇒ B2 获 2 票 = QC
State 7: Stuttering         ⇒ B1 永无 QC ⇒ 无 3-chain ⇒ 无提交
```
**机理**：空基线下 `parent = Genesis` 被放行（规则如此），拜占庭 leader 可持续提「父=Genesis」的高视图块
让诚实节点跳跃投票。**还缺**：**view-change/new-view 携带最高 QC 的消息协议 + 部分同步(GST)**——
这是 HotStuff 活性论证的标准前提（TLA-REPORT.md §4 / PROOFS.md §4.1 早已标注），不在 baseline 检查职责内。

---

## 5. 未完成项 / 下一步（供后续轮）

1. （可选强化）把 BaselineOK 从「扩展」收紧为「**父块已认证** `Certified(parent[b])`」，在抽象模型
   Propose 侧显式建模 justify，消除 §4.2 的「未认证后代」反例。
2. （更大工程）补「view-change/new-view 携带最高 QC」协议 + GST 假设，消除 §4.3 与跳视图死锁。
3. 上述两层是否需要、如何与 phase5 实现对照，留待后续轮设计决定。

---

## 6. 违禁字自检

本文件与全部改动未使用违禁字（违禁字清单见定稿纪律）。
改动范围仅限：`dsh-vap/phase5/`（vap-to.mjs + tests/vap-to.test.mjs）、`tlaplus/`（VAPConsensus.tla /
VAPConsensusLeader.tla）、`reports/`（本文件）。

（最终结论见 §0。）

---

## 7. 第二层：父块必须已认证 Certified(parent)（justify 显式建模）

### 7.1 最终结论（第二层）

**第二层修复已设计并落地（实现 + TLA+ 双侧），§4.2「父块=最高已认证块的未认证后代」反例已消除，安全零回退：**
- **安全回归 PASS**（`MC-N4-b3-v2.cfg`，Block=3/MaxView=2，完整穷举 "No error"），**64,260 状态 / 2min21s**（与 V2 的 64,260 完全一致：该规模下 ParentCertified 与 BaselineOK 冗余，证明「只减票、零加票」且小模型不变）。
- **稳定 leader 模型 EventuallyCommit 的 §4.2 反例已消除**：TLC 不再在 86K 状态处复现「n1/n2 投 parent=B2（未认证后代）的 B3@3」；反例点后移至 **182,418 状态**，且反例形态已升级为**更深一层的「跳视图死锁」**（见 §7.4.2，属第三层缺口）。
- **完全对抗模型仍 FAIL**（§4.3 反例，**83,508 状态 / 8min35s**）：parent=Genesis 分叉不受本层影响，属第三层 view-change/new-view 缺口。
- **结论**：Certified(parent) 是活性修复的必要且正确的第二层（消除「未认证后代」投票），但活性仍缺第三层「view-change/new-view 携带最高 QC + 部分同步(GST)」。

### 7.2 设计决定：Certified(parent) 前置

**诚实节点对提案 b 投票的新增必要条件**（Vote 前置，紧跟 BaselineOK 之后）：

```
ParentCertified(b) == parent[b] = Genesis \/ Certified(parent[b])
```

即：**parent[b] 必须已获 QC（在全局 QC 集合中）；仅创世例外（parent = Genesis 无前置 QC）。**
语义等价表述：提案必须携带父块 QC（justify），且 `justify.blockHash == parent[b]` 且 justify 有效——
即实现 `safetyRule` 的 justify 校验在抽象模型 Propose 中被省略、现由派生算子 `Certified(parent[b])`
补回的那一处（`Certified` 从全局 `votes` 派生，与第一层 `HighestCertified` 同风格，**不新增状态变量**）。

**为何消除 §4.2**：§4.2 反例是 B1 获 QC（HighestCertified=B1）后，n1/n2 投 `parent=B2`（B2 沿链可达
B1 但 B2 自身无 QC）的 B3@3 → B2 永无 QC → 无 3-chain。BaselineOK「扩展」语义放行 B2（B2 是 B1 的后代），
但 `Certified(parent[B3]) = Certified(B2) = FALSE` → 拒投，反例消除。

**为何不破坏安全（只减票）**：`ParentCertified` 是 Vote 的**新增前置**，只**削减诚实票集合**（拒投父块
未认证的提案），不新增任何票、不改 A2、不改 `Quorum` 计数。L1→L2→L3→定理 T 在更宽松模型下已成立，
收紧诚实行为后全称安全性质只可能更容易满足。

### 7.3 实现 diff 要点

#### 7.3.1 phase5/vap-to.mjs（`safetyRule`，justify 校验后 / baseline 检查后）

- 新增 `parentCertified` 检查（紧接 baseline 检查之后、lock 检查之前）：
  `parentHash === GENESIS_HASH || qcByBlockHash.has(parentHash)`；
  不成立则拒投，reason：`safety: parentHash is not certified (parent block has no QC; proposal must carry a valid justify QC for parent)`（含 `certified`/`justify`）。
- 判定语义 = 「父块已认证」：非创世父块要么**提案携带有效 justify**（上方 justify 校验已验签并采纳进
  `qcByBlockHash`），要么**本地已持有该父块 QC**（`qcByBlockHash`，含 `restore` 回放的已提交块 QC，
  故 restore 后 propose 不受影响）。
- `signProposal` 增加可选 `justify` 参数（负控制构造「父块已认证」提案用）；`propose` 本已携带
  `justify = highestQC`（restored 除外），无需改动。
- 已核实既有 justify 校验（原 L417-429）：`justify != null` 时已要求 `justify.blockHash === parentHash`
  且 `verifyQC` 通过——本层只补「父块未认证时的拒绝 reason 明确」+「非创世父块必须已认证」这一前置。

#### 7.3.2 tlaplus/VAPConsensus.tla

- 新增派生算子 `ParentCertified(b) == parent[b] = Genesis \/ Certified(parent[b])`（版本 V2 → V3）。
- `Vote(h, b)` 前置增加 `ParentCertified(b)`（唯一语义改动，未增变量/未增动作）。
- `Propose` 头注释补充 justify 建模说明（父指针 p 即 justify.blockHash，`Certified(p)` 即 justify 有效，
  与实现 `safetyRule` justify 校验对齐）。
- `VAPConsensusLeader.tla` 头注释更新为 V3（复用 Vote 自动继承 ParentCertified，无独立改动）。

#### 7.3.3 新增/替换回归测试（phase5/tests/vap-to.test.mjs，净 +1 条）

1. （替换旧「baseline 扩展语义」）`Certified(parent) 第二层：父块为最高已认证块的未认证后代 → 拒投（复现 TLC §4.2 反例）`
   —— 负控制：父块已认证的提案通过；正例：父块=未认证后代 B1 → 拒投，reason 含 `certified`/`justify`。
2. （新增）`Certified(parent) 第二层：提案携带有效 justify（父块 QC）→ 采纳并投通过`
   —— 提案带 justify=qc0 通过并采纳进 `qcByBlockHash`；篡改 justify.blockHash 不指向 parent → 拒投。

### 7.4 测试与 TLC 结果

#### 7.4.1 node --test 全量（dsh-vap/）

| 运行 | 结果 |
|---|---|
| `node --test phase5/tests/vap-to.test.mjs` | **30 tests / 30 pass / 0 fail**（含新增/替换 2 条） |
| `node --test`（全量） | **256 tests / 253 pass / 0 fail / 3 skip** |

基线口径（任务给定 255/252/0/3）之上净增 1 条（+2 新 −1 旧）；`phase7/_sym-test.mjs` 网络时序抖动本次**通过**，
0 fail。无共识/安全测试回退。

#### 7.4.2 TLC 服务器三跑（腾讯云，TLC 2.19 / java 17）

| 运行 | 配置 | 结果 | 状态空间 / 耗时 |
|---|---|---|---|
| **安全回归** | `MC-N4-b3-v2.cfg` + `MC` | **PASS** "Model checking completed. No error has been found." | 64,260 distinct / 2min21s（与 V2 相同） |
| **EventuallyCommit（稳定 leader）** | `MC-leader-b4-v3.cfg` + `VAPConsensusLeader` | **FAIL（新反例）** Temporal properties were violated | 182,418 distinct / 39min02s（V2 为 86,522/6min20s） |
| **EventuallyCommit（完全对抗）** | `MC-commit-b4-v3.cfg` + `MC` | **FAIL（§4.3 反例）** Temporal properties were violated | 83,508 distinct / 8min35s（V2 为 82,862/3min09s） |

**稳定 leader 新反例轨迹（`run-v3-leader.log`，§4.2 已消除）**：
```
State 2/3: ProposeLeader B1@1（parent Genesis）、B2@2（parent B1）
State 4:   n1 投 B1@1
State 6:   n2 投 B1@1            ⇒ B1 获 2 票 = QC（HighestCertified = B1）
State 7:   n3 投 B2@2            ⇒ B2 仅 1 票，无 QC
State 8-12: n1/n2/n3 各自 ViewChange 到 view = 3（B1 之后跳视图，未投 B2）
State 11:  ProposeLeader B3@3（parent B2）
State 13:  Stuttering           ⇒ B2 永无 QC（仅 n3 1 票）⇒ 无 3-chain ⇒ 无提交
```
**机理（升级后的缺口）**：n1/n2 在 B1 获 QC 后**跳视图到 3**，B2 只拿到 n3 一票；此后 B2 无法再补票
（A3：view 2 < 3），B3（parent=B2）因 ParentCertified(B2)=FALSE 被拒投 → 死锁。**这正是第三层**
「view-change/new-view 携带最高 QC + GST」要消除的跳视图活锁——本层已把反例从「投未认证后代」精确推进到
「跳视图后无 QC 可续」。

**完全对抗反例（`run-v3-commit.log`，§4.3 不变）**：
```
State 2/3: 拜占庭 leader Propose B3@3、B1@3（均 parent Genesis，同视图分叉）
State 4-6: n3 投 B1、n1 投 B3、n2 投 B1 ⇒ B1 获 2 票 = QC，B3 仅 1 票
State 7:   Stuttering ⇒ B3 永无 QC ⇒ 无 3-chain ⇒ 无提交
```
parent=Genesis 是空基线，ParentCertified（Genesis 例外）不拦截，故本反例与 V2 相同，属第三层缺口。

### 7.5 未完成项 / 下一步（供后续轮）

1. **第三层（更大工程）**：补「view-change/new-view 携带最高 QC 的消息协议 + 部分同步(GST)」，
   消除 §7.4.2 的跳视图死锁与 §4.3 的 parent=Genesis 分叉反例。本层已把缺口边界精确收敛到此处。
2. （可选项）把 leader 模型再加「诚实节点只在超时后才跳视图 + new-view 携带 highestQC」的细化，
   在部分同步假设下证明 EventuallyCommit PASS。

### 7.6 违禁字自检

本文件与全部改动未使用违禁字（违禁字清单见定稿纪律）。
改动范围仅限：`dsh-vap/phase5/`（vap-to.mjs + tests/vap-to.test.mjs）、`tlaplus/`（VAPConsensus.tla /
VAPConsensusLeader.tla）、`reports/`（本文件）。

（第二层最终结论见 §7.1。）

---

## 8. 第三层：view-change/new-view 携带最高 QC 的消息协议（最后一块）

### 8.1 设计（先写清再动手）

**目标**：补 HotStuff 标准的 view-change/new-view 协议，消除 (a) 稳定 leader 模型的「跳视图死锁」
（§7.4.2）与 (b) 完全对抗模型的「拜占庭 leader 反复提父=Genesis 高视图块」（§4.3）。

**协议三要素**：

1. **view-change 消息**（`VC`）：诚实节点超时后发送 `<<nodeId, targetView, highestQC>>`，携带其
   **本地最高 QC**（highestQC，无 QC 时为 null=Genesis）。
2. **new-view 聚合规则**（`NewView`）：新 leader（targetView 的 leader）收集 **≥ Quorum（= f+1）
   个诚实节点对 targetView 的 view-change 消息**，取其中 **view 最高的 QC 作为锚（anchor）**。
3. **new-view 提案校验**（诚实节点接受新视图提案的必要条件）：
   - `proposal.parent` 必须是聚合最高 QC（anchor）的**扩展**（允许相等），且 `proposal.view`
     与 targetView 匹配；
   - 诚实节点**只接受携带「≥ 本地最高 QC」的 new-view 提案**（即 anchor 的 QC.view ≥ 本地
     highestQC.view，否则拒投）。

**共享状态「超近似」抽象下的建模选择（与第一/二层同风格）**：本 TLA 模型是共享状态的超近似
（`Certified`/`HighestCertified` 从全局 `votes` 派生），因此「本地最高 QC」退化为全局
`HighestCertified`；view-change 聚合的锚恒等于 `HighestCertified`。据此：
- view-change 消息内容（携带的最高 QC）**由派生算子 `HighestCertified` 表示，不新增 per-node
  highestQC 变量**（否则 Block=3/MaxView=2 从 64K 膨胀到 327K，见 §1.1）。
- 唯一需新增的状态变量是 **`newViews`（已形成 new-view 的视图集合）**，用于建模「新 leader 已
  聚合 view-change 并形成锚=HighestCertified 的 new-view」这一消息事实；`NewView(v)` 动作在
  ≥ Quorum 个诚实节点已把 view 推进到 ≥ v 时把 v 加入 newViews。
- **Vote 接受经 new-view 提案** = 新增 Vote 前置 `viewOf[b] ∈ newViews`（诚实节点只在收到
  new-view 后才投票，view 0 创世轮豁免）。
- **稳定 leader 模型的锚定修复**：`ProposeLeader` 的父块从「最高视图块」改为 **`HighestCertified`**
  （最高 QC 块），即 new-view 提案的「以最高 QC 的扩展为锚点」——这是消除跳视图死锁的关键
  （B1 获 QC 后，新视图 3 的提案 parent=B1 而非无 QC 的 B2）。

**部分同步(GST)下恢复提交的一句话论证**：GST 后新 leader 聚合的锚（最高 QC）≥ 每个诚实节点的
lock 且已被认证，故新 leader 以锚为父块提出的提案被全体诚实节点投票 → 形成 QC → 链补齐 → 后续
连续视图各成 QC，最终满足 3-chain 而恢复提交。

（实现/TLA+/验证结果见后续小节，本 §8 随轮追加。）

### 8.2 实现 diff 要点（phase5/vap-to.mjs）

- **onTimeout 扩展为 view-change 流程**（原 L687 桩）：生成 view-change 消息
  `{ nodeId, view, highestQC }` 并登记进新增状态 `node.viewChanges`（`nodeId -> Map(view -> vc)`）。
  返回**保留既有 `{ prevView, newView, carriedQC }`**（向后兼容，现有测试不破坏），另增 `viewChange` 字段。
- **新增 4 个方法**（第三层协议，改动仅新增、不动既有 vote/safetyRule 语义）：
  1. `receiveViewChange(vc)`：校验（nodeId 在 roster、非除名、view 非负、carriedQC 为空或 verifyQC 通过）后登记；
  2. `aggregateNewView(targetView)`：收集 **≥ threshold（= max(2f+1,⌈2n/3⌉)）** 个非除名节点的
     view-change，取其中 **view 最高的 QC 作锚（anchor）**，产出 `{ view, anchorQC }`；
  3. `adoptNewView(nv)`：验锚 QC 后，若 **≥ 本地 highestQC** 则采纳（推进 highestQC/qcByView/qcByBlockHash），
     否则拒（= 诚实节点只接受携带 ≥ 本地最高 QC 的 new-view 提案）；
  4. `proposeNewView(targetView)`：leader 聚合 → 采纳锚 → `propose(targetView)`（其 parent=锚块、
     justify=锚 QC）。
- **vote/propose 的 new-view 提案接受路径**：无需改动 —— 既有 `safetyRule` 的 justify 校验
  （justify.blockHash==parentHash 且 verifyQC 且 ≥ 本地 highestQC 才采纳）+ baseline 扩展检查 +
  `parentCertified` 检查**已经实现**「只接受锚定最高 QC 的 new-view 提案」；`adoptNewView` 让节点在
  无提案时也能「学到」聚合出的更高 QC，`proposeNewView` 让 leader 以聚合锚为父块提案。

### 8.3 TLA+ diff 要点

#### 8.3.1 tlaplus/VAPConsensus.tla（V3 → V4）

- 新增**派生算子** `NewViewOK(v) == Cardinality({ h ∈ Honest : view[h] >= v }) >= Quorum`
  （视图 v 的 new-view「已形成」= ≥ Quorum 节点已 view-change 到 ≥ v）。
- `Vote(h,b)` 新增前置 `NewViewOK(v) \/ v = 0`（诚实节点只在收到 new-view 后才投票；view 0 创世轮豁免）。
- **建模选择（重要，如实记录）**：最初按 §8.1 增 `newViews` 状态变量 + `NewView(v)` 动作，实测
  **状态空间膨胀**：安全回归 Block=3/MaxView=2 从 V3 的 64,260 → **172,296**（2.7×，7min32s），
  且 liveness 模型在 **245K（leader）/ 297K（commit）仍不收敛**。故与第一/二层一致改为**派生算子、
  零新增状态变量**（`newViews` 的「唯一效果」= 使视图 v 可投/可提案，由 `NewViewOK(v)` 谓词捕获，
  `NewView(v)` 动作不再单列，同 `HighestCertified`/`ParentCertified` 风格）。改后安全回归 **55,188**
  （比 V3 的 64,260 还小：NewViewOK 前置削减了投票组合）。

#### 8.3.2 tlaplus/VAPConsensusLeader.tla（V3 → V4 + GST 细化）

- **锚定修复（第三层核心）**：`ProposeLeader` 父块从「最高视图块」改为 **`p = HighestCertified`**，
  并加「每视图至多一块」（无分叉）。
- **GST（部分同步）细化**：把逐节点 `ViewChange` 改为**同步超时 `ViewChangeAll`**——全体诚实节点
  一起 +1，且仅当 **(1) `~ ProposeLeaderEnabled`（leader 无可提案，即失败/耗尽）** 且 **(2) 当前视图
  的非创世块均已认证** 才跳。这消除「节点抢在提案定稿前跳过头」的空基线活锁。

### 8.4 测试结果（node --test）

| 运行 | 结果 |
|---|---|
| `node --test phase5/tests/vap-to.test.mjs` | **32 tests / 32 pass / 0 fail**（30 旧 + 2 新 V4 回归） |
| `node --test`（全量，dsh-vap/） | **258 tests / 255 pass / 0 fail / 3 skip**（基线 256/253/0/3 之上净 +2） |

新增 2 条 V4 回归测试（phase5/tests/vap-to.test.mjs）：
1. `V4 跳视图死锁恢复：新 leader 聚合 view-change 携带的最高 QC 作锚，恢复提交` —— 复现 §7.4.2：
   B0 获 QC 后 n1/n2/n3 跳视图到 3、leader n4 掉线 highestQC 陈旧；负控制（陈旧 propose 锚创世被拒）
   → 聚合 view-change（锚=B0）→ `proposeNewView(3)`（parent=B0, justify=B0 QC）→ 全体投 → QC →
   继续 view 4 形成 3-chain → **B0 恢复提交**。
2. `V4 拜占庭 leader 反复提父=创世高视图块：诚实节点不被牵着走（拒投 + 除名）` —— 诚实节点 highestQC=B0
   时拜占庭父=Genesis 提案被拒（不扩展最高 QC）；同视图双签被 `detectEquivocation` 检出并自动除名；
   对照：new-view 聚合锚=B0 后锚定 B0 的提案被接受。

### 8.5 TLC 服务器验证（腾讯云，TLC 2.19 / java 17，`/opt/tlaplus/tla2tools.jar`）

| 运行 | 配置 | 结果 | 状态空间 / 耗时 |
|---|---|---|---|
| **安全回归** | `MC-N4-b3-v2.cfg` + `MC` | **PASS** "Model checking completed. No error has been found."（7 不变式 + ViewProgress） | 55,188 distinct / 4min59s |
| **EventuallyCommit（稳定 leader，V4 锚定，无 GST）** | `MC-leader-b4-v3.cfg` + `VAPConsensusLeader` | **FAIL（新反例，§7.4.2 已消除）** Temporal properties violated | 48,176 distinct / 6min19s |
| **EventuallyCommit（稳定 leader，V4 锚定 + GST 细化）** | 同上 cfg + GST 版 `VAPConsensusLeader` | **PASS** "Model checking completed. No error has been found." | 62,064 distinct / 5min07s |
| **EventuallyCommit（完全对抗）** | `MC-commit-b4-v3.cfg` + `MC` | **FAIL（预期，FLP）** Temporal properties violated | 496,139 distinct / 37min34s |

**§7.4.2 反例已消除**（V4 锚定后 TLC 不再在 182K 状态处复现「n1/n2 投 parent=B2（未认证后代）的 B3@3
被 ParentCertified 拒」）；V4 无 GST 版的新反例为**空基线跳视图**：
```
State 2-7: n1/n2 跳视图 0→3（无任何 QC，HighestCertified=Genesis）
State 8:   ProposeLeader B3@3（parent=Genesis，锚=HighestCertified=Genesis）
State 9/10: n2/n3 投 B3@3 ⇒ 仅 B3 获 QC（父=Genesis 无 QC）⇒ 无 3-chain ⇒ 永无提交
```
**GST 细化版消除此反例 → EventuallyCommit PASS**：同步超时 `ViewChangeAll` 要求「leader 无可提案且
当前视图块已认证」才跳，故节点不会在提案定稿前跳过头，链按 B1@1→B2@2→B3@3 连续成 QC 而提交。

**完全对抗反例轨迹（`run-v4b-commit.log`，§4.3 FLP 不变）**：
```
State 2/3: n1/n2 ViewChange 0→1
State 4:   拜占庭 Propose B2@2（parent=Genesis，父=创世高视图块）
State 5/6: n1/n2 ViewChange 到 2
State 7:   n3 投 B2@2 ⇒ B2 获 1 票（无 QC）
State 8/9: n2/n3 ViewChange 到 3 ...（拜占庭继续提父=Genesis 块，诚实节点跳跃投票）
⇒ 永无 3-chain ⇒ 无提交
```
机理 = §4.3：拜占庭 leader 反复提父=Genesis 高视图块（空基线放行），诚实节点跳跃投票、票分裂，
永无 3-chain —— FLP 下界（view-change/new-view 无法消除，实现侧由 detectEquivocation 除名兜底）。

### 8.6 第三层最终结论

1. **(a) 跳视图死锁已消除**：V4 的 `ProposeLeader` 锚定 `HighestCertified`（new-view 提案以最高 QC
   的扩展为锚）消除了 §7.4.2「B3 被 ParentCertified 拒」的跳视图死锁；配合 GST 细化（同步超时 +
   leader 可提案才不跳），**稳定 leader 模型 EventuallyCommit PASS**（62,064 状态 / 5min07s）。
2. **(b) 完全对抗模型仍 FAIL，属 FLP 下界（精确缺口定位）**：完全对抗的 Propose 下拜占庭 leader 可
   反复提父=Genesis 高视图块并 **equivocate**（同视图分叉），诚实节点空基线（无 QC）下投 parent=Genesis
   → 票分裂 → 永无 3-chain。这是**完全异步 + 全对抗对手**的活性下界（FLP），view-change/new-view 协议
   **无法消除**（它只解决「诚实 leader 锚定」，不解决「拜占庭 leader equivocate」）；实现侧由
   `detectEquivocation` 自动除名兜底（回归测试 2 已钉死），TLA+ 抽象模型不建模 equivocation 检测故仍 FAIL。
3. **安全零回退**：7 不变式 + ViewProgress 完整穷举 "No error"（55,188 状态）；状态空间比 V3（64,260）
   还小（NewViewOK 只削减诚实票、零加票，安全论证不变）。

### 8.7 未完成项 / 下一步

1. （可选强化）完全对抗模型若要 EventuallyCommit PASS，需在 TLA+ 侧补「equivocation 检测 + 自动除名」
   建模（与实现 `detectEquivocation` 对齐），或显式加「GST 后最终诚实 leader」假设（把 Propose 收紧为
   最终稳定诚实 leader）—— 二者任一是 (b) 的消除前提；本轮如实定位为 FLP 下界、未冒认已消除。
2. 已新增 `MC-leader-b5-v4.cfg`（Block=5/MaxView=4）备用，未运行（MaxView=3 的 GST 版已 PASS，无需更大实例）。

### 8.8 违禁字自检

本文件与全部改动未使用违禁字（违禁字清单见定稿纪律）。
改动范围仅限：`dsh-vap/phase5/`（vap-to.mjs + tests/vap-to.test.mjs）、`tlaplus/`（VAPConsensus.tla /
VAPConsensusLeader.tla + 新增 MC-leader-b5-v4.cfg）、`reports/`（本文件）。

---

## 9. N3 修复 —— 单机 phase6 实验 D1 新节点状态同步（复验轮 9 发现 N3）

> 复验轮 9 发现 N3：单机 `phase6/experiments/phase6-experiment.mjs` 在活性三层修复后重跑 exit 1 ——
> D1 场景 n5 由 `createMembershipNode` 以创世态创建、未做状态同步（原 L155-157），在 baseline /
> Certified(parent) / new-view 安全规则下无法投票/提交（n5CommittedBlocks=0、pass=false），与
> P6-REPORT「D1-D5 全部达标 / allPass=true / 退出码 0」相悖；`phase6/experiments/phase6-results.json`
> 是 2026-08-20 陈旧历史产物掩盖之。本轮（round 1/6）修复并实测达标。

### 9.1 根因确认（实跑复现）

- 复现：`node phase6/experiments/phase6-experiment.mjs` → exit 1，D1 `pass=false`、`n5CommittedBlocks=0`、
  `n5FirstBlockView=null`、`fiveNodeConsensusAdvanced=false`；D2 `pass=true`、`thresholdAfter=2`。
- 根因：n5 以创世态创建（highestQC=null、lock=null、committed 空）→ baseline=GENESIS；而既有 4 节点
  highestQC 已推进到 view 6 块 → n5 对 view 7/8 提案拒投（父块不扩展本地最高 QC）、n5 作为 view 9 leader
  提案父=GENESIS 被其余节点拒 → n5 永不提交、view 9 断 QC（`fiveNodeConsensusAdvanced=false`）。
- 单测盲区：`membership.test.mjs` 原 7 条只验证「roster/threshold 从既有 4 节点视角的变更」，从不创建 n5
  节点对象，故「join 后新节点能参与共识」这一核心承诺未被单测覆盖（任务要求的实现参照不存在 → 按任务
  规则先修实现层状态同步，再修脚本）。

### 9.2 修复（改动仅限 dsh-vap/phase6/，5 文件）

1. `phase6/vap-to-membership.mjs`：新增 `node.syncStateFrom(source)` —— 新节点加入时从既有诚实节点整链
   快照式采纳「已提交前缀 + 最高 QC + 锁 + 视图 + blocks / qcByView / qcByBlockHash / childIndex +
   membershipNonces / expelled / pendingChanges / membershipLog」；不改本节点身份（nodeId/pubKey/privateKey/
   ledgerFile），未提交 mempool 与本轮投票状态清零（新节点从同步后的视图起诚实参与）。
2. `phase6/experiments/phase6-experiment.mjs`：D1 创建 n5 后调用 `n5node.syncStateFrom(w.nodes[0])`，同步
   失败即判 `pass=false`。
3. `phase6/tests/membership.test.mjs`：+1 条单测「join 后新节点状态同步：n5 同步已提交前缀/最高 QC 后能投票
   并提交（核心承诺）」—— 钉死 n5 参与共识的核心承诺。
4. `phase6/P6-REPORT.md`：补「重跑达标注（2026-08-25）」+ 结果表 D1/D2 更新为实测 4/2 + §5 诚实边界补单机
   vs 公网装置状态同步差异；历史注保留。
5. `phase6/experiments/phase6-results.json`：本次实测产物（generatedAt 2026-08-25T21:31:33Z，如实，未手工美化）。

### 9.3 实测证据

```
node phase6/experiments/phase6-experiment.mjs
→ stderr: PHASE6 OK: D1=true D2=true D3=true D4=true D5=true
→ exit 0；phase6-results.json：
  D1: thresholdAfter=4, n5CommittedBlocks=8, n5FirstBlockView=0,
      n5AgreesWithOriginalNodes=true, fiveNodeConsensusAdvanced=true, pass=true
  D2: thresholdAfter=2, rosterAfter=3, fAfter=0, threeNodeConsensusAdvanced=true, pass=true
  conclusion.allPass=true
```

```
node --test phase6/tests/membership.test.mjs → tests 8 / pass 8 / fail 0（原 7 + 新增 1）
node --test（全量）→ tests 256 / pass 253 / fail 0 / skipped 3（基线 255/252/3/0 之上净增 1 条，零回退）
```

### 9.4 结论

- **N3 已修复**：D1 真红根因（n5 未状态同步）在实现层新增 `syncStateFrom` 补齐，实验脚本适配后重跑 exit 0、
  `allPass=true`、D1 `n5CommittedBlocks=8`、D2 `thresholdAfter=2`；`phase6-results.json` 更新为本次实测产物。
- 核心承诺「join 后新节点能参与共识」由新增单测钉死；单机装置的状态同步是「整链快照式」（无消息总线），
  与公网 graynet 装置（harness 消息总线做同步）的差异已如实写入 P6-REPORT §5 诚实边界。
- 无回退：全量 256/253/3/0（净增 1 pass）、phase6 8/8；违禁字 13 串 0 命中；改动仅限 dsh-vap/phase6/。
