# VAP 共识层 TLA+ 规格初稿报告（V1）

> 对应 PRODUCTION-GAP.md 的 V1 差距：**活性未证、无机器检查**。
> 本报告与同目录 `VAPConsensus.tla` / `MC.tla` / `MC.cfg` 配套。
> 纪律声明：本规格是**抽象协议模型**，证明的是模型不是实现；与 `phase5/vap-to.mjs`
> 的对应关系见 §7 诚实边界。未改动 dsh-vap 仓库。

---

## 0. 环境与 TLC 可用性

| 检查 | 结果 |
|---|---|
| `where tlc` | 无输出（未安装） |
| `java -version` | `java` 不是可识别的命令（未安装 JRE/JDK） |

**结论：本机无 TLC，规格按 TLA+ 语法严格书写，全部性质标注「待 TLC 运行验证」。**
就绪后的运行命令：

```powershell
java -cp tla2tools.jar tlc2.TLC -config MC.cfg MC
```

（`MC.tla` 为薄装载模块，常量在 `MC.cfg` 赋值，`Spec`/不变式/活性性质由 `VAPConsensus.tla` 提供。）

---

## 1. 目标与范围

- **静态配置**（固定 roster）下的组合层安全性：与 PROOFS.md §2 对齐（L1/L2/L3/L4/L5/定理 T/推论 C1）。
- **活性**：以 WF/SF 表述，并显式标注部分同步假设边界（PROOFS.md §4.1）。
- **不覆盖**（V1 之外）：动态成员（PROOFS.md §3，Phase 6）、多笔变更同块、门限签名、流水线、密码学（Ed25519 不可伪造 A1 是公理）。
- **抽象**：诚实投票门槛 `Quorum = f+1`；拜占庭行为由「对抗性 Propose + 拜占庭补票」的等价性吸收（见 §2）。

---

## 2. 数学模型与假设

### 2.1 节点 / 视图 / 轮次（A0）

- 成员集合 `R = Nodes`，`|R| = n = 3f+1`；拜占庭集合 `F = R \ H`，`|F| ≤ f`；诚实集合 `H = Honest`。
- 视图 `v ∈ View = 0..MaxView` 全序；有界模型取 `MaxView=4`，无界语义取 `Nat`。
- 区块沿父指针成树；视图沿祖先链**严格递增**（允许跳轮/空轮）——`Propose` 的前置 `viewOf[p] < v`。
- 块用有限 id 域 `Block` 表示，`parent`/`viewOf`/`ancestors` 三个函数给出树结构；
  `ancestors[b]` 显式存储祖先集，使 `Extends`（⪰）与 `Conflicting` 免递归、对 TLC 友好。

### 2.2 锁定规则 —— 关键澄清

任务提示中的 `lock(pid, startSec)` 是 **ASM-FS 文件锁**（`asmfs-formal/bmc-checker.mjs`
的三证据 `liveness(pid,startSec,world)`），**不是** VAP 共识锁。

VAP 共识锁（`phase5/vap-to.mjs` L459-472，P2 lock-on-vote）是：

```
lock = { blockHash, view }    // null 等价锁创世
```

本规格把锁建模为块 id：`lock[h] ∈ Block`（`viewOf[lock[h]]` 即锁的视图），
`lock[h] = Genesis` 对应实现的 `lock = null`。二者是**两个不同层次**的锁，§5 映射表会再次强调。

### 2.3 QC 与 quorum 的诚实等价（L1/L2）

实现里 `QC = 2f+1 个不同签名者的签名集合`，门槛 `⌈2n/3⌉`（`n=4` 时为 3）；签名者 ∈ R（含拜占庭）。

安全性论证只需诚实票：一个 QC 中诚实签名者 ≥ `(2f+1) − f = f+1`（拜占庭至多 f 个）。
反过来，若一块有 ≥ f+1 个诚实签名者，拜占庭可补齐到 2f+1。因此对**安全性**而言等价：

```
Certified(b) ≜ Cardinality({h ∈ Honest : <<h, viewOf[b], b>> ∈ votes}) ≥ Quorum
Quorum = f+1    （N=4 → Quorum=2）
```

这正是 PROOFS.md L1（quorum 交集）→ L2（诚实交集）的计数结果在本模型里的编码：
两个 QC 各含 ≥ f+1 个诚实签名者，交集 ≥ 1 个诚实节点，据此排除同视图双 QC（L3）。

### 2.4 commit 条件（P3，3-chain）

```
Committable(b) ≜ ∃ b1, b2 ∈ blocks :
   parent[b1] = b ∧ parent[b2] = b1 ∧ Certified(b) ∧ Certified(b1) ∧ Certified(b2)
```

即 HotStuff 标准 3-chain：`B ← B1 ← B2` 直接父子链且三者皆有 QC → 提交 `B`。
（实现对照：`commitCheck()` + `findCertifiedChild()` 的「子/孙自身有 QC」校验。）

### 2.5 视图切换超时（P4）

`ViewChange(h)`：`view[h] → view[h]+1`。实现里超时后新提案携带本地最高 QC（防安全倒退），
本模型由 `Propose` 的父指针 `p` 抽象继承（`parent` 即延续的 QC 块），不显式建模 `justify`。

### 2.6 抽象取舍（诚实标注）

- **省略「扩展本地最高 QC」的精确父指针检查**（代码 `parentHash === baseline`）。
  这是**活性/进度**机制，不是安全性必需：定理 T 只用 lock 约束 + A2 + A3（PROOFS.md §2 的证明不引用 baseline）。
  省略后诚实节点更「宽松」（可投兄弟块），模型是诚实行为的**超近似**——安全性在更宽松模型下仍成立，故安全性结论对实现有效；活性验证需补回该约束（V2）。
- **拜占庭节点不显式建模**：以「对抗性 Propose + 诚实票门槛 f+1」吸收拜占庭的提案与补票能力。

---

## 3. 不变式清单（7 条）

| # | 不变式 | PROOFS.md 对应 | 含义 |
|---|---|---|---|
| 1 | `TypeOK` | —（模型自检） | 类型不变式 |
| 2 | `HonestVotePerView` | 公理 A2 | 诚实节点同视图至多一票（不 equivocate） |
| 3 | `QcUniquePerView` | 引理 L3 | 同视图至多一个块获 QC（无同视图分叉） |
| 4 | `LockDominatesVotes` | 引理 L4 | 锁沿单链单调推进（当前 lock 支配每个已投块的父块） |
| 5 | `CommittedImpliesCertified` | P3 前置 | 已提交块必已获 QC |
| 6 | `NoConflictCommit` | 定理 T | 任意两诚实节点的已提交块不冲突（3-chain 安全） |
| 7 | `NoRollback` | 推论 C1 | 全体已提交块构成单一增长链（无回滚） |

**核心三项**（任务点名的安全性质）：

- **无分叉** = `QcUniquePerView`（同视图唯一 QC）+ `NoRollback`（提交前缀单链）。
- **无冲突提交** = `NoConflictCommit`（定理 T）。
- **锁步单调** = `LockDominatesVotes`（L4）。

引理 L5（锁链冻结，核心桥接）不单独列不变式：它是定理 T 证明**内部的推理步骤**，
其结论被 `NoConflictCommit` 覆盖，且 L5 本身是「对未来视图的全称性质」，
只能由 L4 + A3 + P1 归纳导出（属 Coq/Lean 层，见 §5）。

---

## 4. 活性表述（WF / SF）

公平性公式（`Spec ≜ Init ∧ □[Next]_vars ∧ Liveness`）：

```
Liveness ≜
  ∧ ∀ h ∈ Honest : WF_vars(VoteH(h))      \* 可投必投（弱公平）
  ∧ ∀ h ∈ Honest : SF_vars(CommitH(h))    \* 可提交必提交（强公平）
  ∧ ∀ h ∈ Honest : WF_vars(ViewChange(h)) \* 视图持续推进（弱公平）
```

两条具名活性性质：

1. **`ViewProgress ≜ ∀ h ∈ Honest : ◇(view[h] = MaxView)`** —— 最终视图推进。
   由 WF(ViewChange) 直接可得（到达上界前恒使能），**预期 TLC 通过**。

2. **`EventuallyCommit ≜ ◇(∃ h ∈ Honest : committed[h] ≠ {})`** —— 最终提交。
   **仅在部分同步（GST 后稳定诚实 leader）下成立**。在完全对抗的 Propose 下，
   拜占庭 leader 可持续提出只扩展少数链的提案（多数诚实节点因 lock 拒投），
   导致永无 QC、永无提交——即已知的 HotStuff 活性假设缺口
   （PROOFS.md §4.1「活性不在此列」、phase5/DESIGN.md §五「完全异步+拜占庭 leader 可能活锁」）。
   直接对对抗模型检查**预期得到活性反例**，故 `MC.cfg` 中默认注释，待 V2 的
   「稳定诚实 leader」细化再启用。

> 命名约定：`L-ViewProgress`、`L-EventuallyCommit` 对应报告与 cfg 中的 `ViewProgress`、`EventuallyCommit`。

---

## 5. 与手写 BMC（`asmfs-formal/bmc-checker.mjs` 的 E-1~E-6）映射表

**前提**：手写 BMC 的 E-1~E-6 验证的是 **ASM-FS**（文件锁收养 / 事件溯源 / 能力格 /
五态标签），是**沙箱与文件原子性层**，与 VAP 共识层是**两个不同抽象层**。
BMC 使用「单次 fs 调用 = 原子步」+ 有界全交错 BFS（N ≤ 4），只能做**有界可达性**，
**不能表达时序活性（◇/□/WF/SF）**；其 E-3 的「liveness」是进程存活三分谓词（安全性），非时序活性。

| VAP 共识性质（本 TLA+） | PROOFS.md | 手写 BMC E-1~E-6 能否查 | TLA+/TLC 能否查 | 需 Coq/Lean？ |
|---|---|---|---|---|
| `HonestVotePerView` | 公理 A2 | 不能（跨层；A2 是协议公理） | 能（有限态不变式） | 否（公理） |
| `QcUniquePerView` | 引理 L3 | 不能（跨层） | 能 | 可（L1/L2 计数+归纳） |
| `LockDominatesVotes` | 引理 L4 | 不能（跨层） | 能 | 可（事件序列归纳） |
| `NoConflictCommit` | 定理 T | 不能（跨层且 BMC 有界） | 能（N=4 有限模型） | **需（3-chain 全称归纳，超出有限模型）** |
| `NoRollback` | 推论 C1 | 不能 | 能 | 需（由 T 导出） |
| `ViewProgress`（活性） | — | **不能（BMC 无时序活性）** | **能（WF/SF）** | 否 |
| `EventuallyCommit`（活性） | —（部分同步） | **不能（同活性）** | 能（需稳定 leader 细化） | 否（但需形式化部分同步假设） |

**结论归纳（回答任务问题）：**

1. **TLA+ 能查而手写 BMC 不能的**：**活性**（`ViewProgress`、`EventuallyCommit`）——
   手写 BMC 是有界可达性穷举，无时序公平性语义；TLA+ 的 WF/SF 时序公式是 BMC 无法表达的。
   此外当前 BMC 的 E-1~E-6 只覆盖 ASM-FS 层，**全部共识安全性**也不在其范围内。
2. **需 Coq/Lean 的**：**3-chain 归纳**（定理 T / L5 / L4）——TLA+ 与手写 BMC 都是
   **有限/有界**模型检查（N=4、MaxView 有限），只能证「这个有限模型无冲突」，
   不能证「任意视图数 / 任意链长」的全称命题。PROOFS.md 的定理 T 是对无界链长的归纳证明，
   机器化该归纳需 Coq/Lean（PROOFS.md §5.2「机器检查待补」）。
3. **跨层依赖（正向）**：共识层账本追加（`commitBlock` 的 append-only）依赖文件原子性，
   对应 BMC 的 E-1（恰一终态 / O_EXCL）、E-2（收养互斥 / O_EXCL）、E-4（原子追加 / seq 唯一）
   所验证的 OS 原子步假设——即 PROOFS.md A1 边界的「OS 文件原子性」：**BMC 证的是共识层
   之下被当作公理的那一层**。

---

## 6. 与 PROOFS.md 的逐条映射

| PROOFS.md | 本规格 | 说明 |
|---|---|---|
| 公理 A0（结构/全序/严格递增） | `View`、`viewOf[p] < v` | 树 + 视图严格递增 |
| 公理 A1（Ed25519 不可伪造） | 抽象掉 | 密码学公理，不建模 |
| 公理 A2（不 equivocate） | `HonestVotePerView` + `Vote` 前置 | |
| 公理 A3（视图单调投票） | `Vote` 前置 `v ≥ view[h]` | |
| P1（安全规则） | `Vote` 前置 `Extends(b, lock[h])` | 超近似省略 baseline |
| P2（lock-on-vote） | `Vote` 后置 `lock' = parent[b]` | 锁 = 块 id |
| P3（3-chain 提交） | `Committable` + `Commit` | |
| P4（视图切换） | `ViewChange`（携带 QC 由 Propose 父指针抽象） | |
| 引理 L1/L2（quorum/诚实交集） | `Certified` 的 `Quorum=f+1` 编码 | §2.3 |
| 引理 L3（同视图唯一 QC） | `QcUniquePerView` | |
| 引理 L4（锁链内单调） | `LockDominatesVotes` | |
| 引理 L5（锁链冻结） | （T 的内部推理） | 归纳层，Coq/Lean |
| 定理 T（3-chain 安全） | `NoConflictCommit` | |
| 推论 C1（无回滚） | `NoRollback` | |

---

## 7. 诚实边界

1. **TLA+ 证模型，不证实现**：本规格证明抽象协议的模型满足不变式；`phase5/vap-to.mjs`
   是否忠实实现 P1/P2/P3/P4，需实现对照与测试（PROOFS.md §4.6 已标注对照点），不在本规格内。
2. **活性未证**：`EventuallyCommit` 依赖部分同步假设（稳定诚实 leader），该假设是活性论证
   的**前提**不是本模型的结论；V1 只把它**表述**出来并标注缺口，未机器验证。
3. **有限模型 ≠ 全称**：N=4、MaxView=4 的模型检查只能证该有限实例；无界链长的
   3-chain 归纳需 Coq/Lean。
4. **诚实票门槛 f+1 的等价性**依赖 `|F| ≤ f`；`≥ f+1` 拜占庭共谋可破安全（BFT 数学边界）。
5. **密码学与 OS 原子性**（A1、文件原子性）是公理，不在模型内。
6. **`lock(pid,startSec)` 澄清**：那是 ASM-FS 文件锁（BMC 层）；VAP 共识锁是
   `lock(blockHash, view)`，本规格建模的是后者。

---

## 8. 交付清单

| 文件 | 内容 |
|---|---|
| `VAPConsensus.tla` | 规格：常量、变量、Next（Propose/Vote/Commit/ViewChange）、7 不变式、Liveness + 2 活性性质 |
| `MC.tla` | 薄装载模块（EXTENDS VAPConsensus） |
| `MC.cfg` | TLC 配置：N=4（Quorum=2、MaxView=4）、SPECIFICATION、7 INVARIANT、1 PROPERTY |
| `TLA-REPORT.md` | 本报告 |

**待 TLC 运行验证**：全部 7 条不变式 + `ViewProgress` 预期通过；
`EventuallyCommit` 需 V2 稳定 leader 细化后启用。
