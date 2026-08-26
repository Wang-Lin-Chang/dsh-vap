---- MODULE VAPConsensus ----
\* VAP 锁步 QC 链共识（VAP-TO）TLA+ 规格初稿
\* -------------------------------------------------------------------------
\* 目标：把 PROOFS.md 的组合层安全性证明（L1/L2/L3/L4/L5/定理 T/推论 C1）与
\*       phase5/vap-to.mjs 的共识实现，提炼为可机器检查的 TLA+ 模型。
\* 层级：本文件是抽象协议模型，不证明 JS 实现（诚实边界见 TLA-REPORT.md §7）。
\* 版本：V4（2026-08-25）—— 三层活性修复全部落地：
\*       V2 baseline/最高-QC 扩展检查；V3「父块必须已认证 Certified(parent)」（提案携带父块 QC = justify 显式建模）；
\*       V4 view-change/new-view 携带最高 QC 的消息协议（view-change 消息携带本地最高 QC；new leader 聚合后
\*       以「最高 QC 的扩展」为新视图提案锚点）。
\*       建模选择（共享状态超近似，与第一/二层同风格）：本地最高 QC = 全局 HighestCertified（派生），
\*       故 view-change 消息内容不新增 per-node highestQC 变量（否则 Block=3/MaxView=2 从 64K 膨胀到
\*       327K，见 baseline-fix/PROGRESS.md §1.1）。new-view 的「已形成」同样由派生算子 NewViewOK(v) 表示
\*       （≥ Quorum 个诚实节点已把 view 推进到 ≥ v），不新增 newViews 状态变量 —— 实测新增该
\*       SUBSET View 变量会使 Block=3/MaxView=2 从 64K 膨胀到 172K、且 liveness 模型在 245K/297K
\*       状态仍不收敛（见 baseline-fix/PROGRESS.md 第三层），故与第一/二层一致采用派生算子、零新增状态变量。
\*       NewView(v) 动作的「唯一效果」（使视图 v 可投票/可提案）完全由派生谓词 NewViewOK(v) 捕获，
\*       故不再单列 NewView 动作（与 HighestCertified/ParentCertified 同风格）。Vote 新增前置
\*       NewViewOK(viewOf[b])（诚实节点只在 ≥ Quorum 节点已 view-change 到该视图后才投票；view 0 豁免）。
\* 状态：已由 TLC 2.19 实际运行验证（原稿 Unicode 运算符已规范化为 ASCII 等价形式）。
\*
\* 记号（与 PROOFS.md §1 对齐）：
\*   R        = Nodes            成员集合，|R| = n = 3f+1
\*   H        = Honest           诚实集合；F = R \ H 为拜占庭集合，|F| ≤ f
\*   QC       = Certified(b)     块 b 获得 ≥ Quorum 个诚实签名者（= f+1），
\*                               等价 ⌈2n/3⌉ 个签名者（拜占庭至多补 f 票，见报告 §2）
\*   lock     = lock[h]          诚实节点 h 的锁定块（P2 lock-on-vote）
\*   commit   = Committable      3-chain 提交条件（P3）
\*   baseline = HighestCertified 最高已认证块（baseline/最高-QC 扩展检查）

EXTENDS Naturals, FiniteSets, TLC

\* -------------------------------------------------------------------------
\* 模型常量（由 MC.cfg 赋值；语义见 TLA-REPORT.md §2）
\* -------------------------------------------------------------------------
CONSTANT Nodes      \* 全体成员集合 R（含诚实与拜占庭）
CONSTANT Honest     \* 诚实成员集合 H ⊆ R
CONSTANT Quorum     \* 诚实投票门槛 = f+1（QC = ⌈2n/3⌉ 签名者的诚实等价）
CONSTANT MaxView    \* 视图上界（有界模型；无界语义取 Nat）
CONSTANT Block      \* 有限块 id 域（含 Genesis）
CONSTANT Genesis    \* 创世块 id（Genesis ∈ Block）

View == 0..MaxView   \* 视图集合 v ∈ ℕ，全序（公理 A0）

\* -------------------------------------------------------------------------
\* 变量：链（blocks / parent / viewOf / ancestors）、票（votes）、锁（lock）、
\*       提交（committed）、视图（view）
\* -------------------------------------------------------------------------
VARIABLES blocks, parent, viewOf, ancestors, votes, lock, committed, view

vars == <<blocks, parent, viewOf, ancestors, votes, lock, committed, view>>

\* -------------------------------------------------------------------------
\* 派生算子
\* -------------------------------------------------------------------------

\* Extends(b, a)：块 b 扩展块 a（a 是 b 的祖先或 a = b）；即 PROOFS.md 的 ⪰ 关系。
Extends(b, a) == a \in ancestors[b]

\* Conflicting(b1, b2)：两块互不扩展（不在同一链上）。
Conflicting(b1, b2) == ~ (Extends(b1, b2) \/ Extends(b2, b1))

\* VotesFor(b)：投给块 b 的诚实节点集合（票按 viewOf[b] 键控）。
VotesFor(b) == { h \in Honest : <<h, viewOf[b], b>> \in votes }

\* Certified(b)：块 b 获得 QC（≥ Quorum 个诚实签名者；L1/L2 的诚实交集等价表述）。
Certified(b) == Cardinality(VotesFor(b)) >= Quorum

\* Committable(b)：3-chain 提交（P3）：存在直接父子链 B ← B1 ← B2 且三者皆有 QC。
\* A0 保证父指针链上视图严格递增，故 B1 为 B 的直接子块、B2 为 B1 的直接子块。
Committable(b) ==
  \E b1 \in blocks, b2 \in blocks :
    /\ parent[b1] = b
    /\ parent[b2] = b1
    /\ Certified(b)
    /\ Certified(b1)
    /\ Certified(b2)

\* -------------------------------------------------------------------------
\* baseline / 最高-QC 扩展检查（V2 活性修复，对应 PROOFS.md P1 的「扩展本地最高已认证区块」）
\* -------------------------------------------------------------------------
\* HighestCertified：已获得 QC 的块中视图最大者（无任何 QC 时退化为 Genesis）。
\* 由 L3（同视图唯一 QC）保证「最高视图已认证块」唯一，CHOOSE 良定义。
\* 注：本模型是共享状态的「超近似」抽象（TLA-REPORT.md §2.6），HighestCertified 即
\*     全局最高 QC 块，等价于实现的每节点 highestQC 在「节点已同步」后的值。
HighestCertified ==
  IF \E b \in blocks : Certified(b)
  THEN CHOOSE b \in blocks : Certified(b) /\ \A q \in blocks : Certified(q) => viewOf[q] <= viewOf[b]
  ELSE Genesis

\* BaselineOK：诚实节点对提案块 b 投票的必要条件 = parent[b] 沿父链可达最高已认证块
\* （= 最高 QC 的扩展，highestCertified \in ancestors[parent[b]]，允许相等）；
\* 最高 QC 为空（= Genesis）时仅要求 parent[b] = Genesis。
\* 理由：消除「跳跃投票」——诚实节点不得投父块未达最高 QC 的高视图块，否则中间块
\*       永无 QC、3-chain 永不成立（TLC-RESULTS.md §5 反例）。
\*       它只削减诚实票（不新增票），故不破坏 quorum 交集安全论证（L1/L2/L3/定理 T
\*       在更宽松的「超近似」模型下已成立，见 TLA-REPORT.md §2.6）。
BaselineOK(h, b) ==
  \/ HighestCertified = Genesis /\ parent[b] = Genesis
  \/ HighestCertified /= Genesis /\ Extends(parent[b], HighestCertified)

\* ParentCertified(b)：父块必须已认证（第二层活性修复，Certified(parent[b]) 前置）。
\* 收紧 BaselineOK 的「扩展」语义：parent[b] 沿链可达最高已认证块不再足够，
\* parent[b] 自身必须已获 QC —— 即提案携带父块 QC（justify）的显式建模；
\* 与实现 safetyRule 的 justify 校验（vap-to.mjs）对齐。创世例外：parent = Genesis
\* 无前置 QC（Genesis 视为平凡已认证）。
\* 理由：消除「父块 = 最高已认证块的未认证后代」反例（B1 获 QC 后，n1/n2 投 parent=B2、
\*       B2 沿链可达 B1 但 B2 自身无 QC 的 B3 → B2 永无 QC → 无 3-chain）。
\* 它只削减诚实票（不新增票），故不破坏 quorum 交集安全论证。
ParentCertified(b) == parent[b] = Genesis \/ Certified(parent[b])

\* -------------------------------------------------------------------------
\* view-change / new-view（V4 第三层活性修复，对应 PROOFS.md P4「视图切换携带最高 QC」）
\* -------------------------------------------------------------------------
\* NewViewOK(v)：视图 v 的 new-view 已形成 —— ≥ Quorum 个诚实节点已把本地 view 推进到 ≥ v
\* （即已发出针对 v 的 view-change 消息；消息携带的本地最高 QC 在本共享状态超近似下 = 全局
\* HighestCertified，由派生算子表示，不新增 per-node 状态变量）。
\* 聚合锚（anchor）恒 = HighestCertified：诚实节点各自携带「本地最高 QC」，超近似下全体一致，
\* 新 leader 取最高者 = 全局最高已认证块。
\* NewView(v) 动作的唯一效果（使视图 v 可投票/可提案）由此派生谓词捕获，不单列 NewView 动作
\*（与 HighestCertified/ParentCertified 派生风格一致，零新增状态变量）。
NewViewOK(v) == Cardinality({ h \in Honest : view[h] >= v }) >= Quorum

\* -------------------------------------------------------------------------
\* 初态
\* -------------------------------------------------------------------------
Init ==
  /\ blocks = {Genesis}
  /\ parent = [b \in Block |-> Genesis]
  /\ viewOf = [b \in Block |-> 0]
  /\ ancestors = [b \in Block |-> {Genesis}]
  /\ votes = {}
  /\ lock = [h \in Honest |-> Genesis]
  /\ committed = [h \in Honest |-> {}]
  /\ view = [h \in Honest |-> 0]

\* -------------------------------------------------------------------------
\* Next 动作：Propose / Vote / Commit / ViewChange
\* -------------------------------------------------------------------------

\* Propose(b, v, p)：领导者在视图 v 以父块 p 提出新块 b。
\* 拜占庭 leader 可任意提出（父指针任意、同视图可多块）→ 分叉在模型中可达，
\* 使 NoConflictCommit 不变式非空洞。诚实 leader 的约束折叠进 Vote 的 lock 检查。
\* justify（提案携带的父块 QC）在本共享状态「超近似」模型中由「父块 p 已认证」抽象表示：
\* p 即 justify.blockHash，Certified(p) 即 justify 有效（父块已获 QC，Certified 从全局 votes 派生）。
\* 拜占庭 leader 可提 parent 未认证的提案（无效 justify），由 Vote 前置 ParentCertified(b)
\* 判定 Certified(parent[b]) 拒投 —— 与实现 safetyRule 的 justify 校验对齐，不新增状态变量。
Propose(b, v, p) ==
  /\ b \in Block \ blocks
  /\ v \in View
  /\ p \in blocks
  /\ viewOf[p] < v            \* A0：视图沿祖先链严格递增
  /\ blocks' = blocks \cup {b}
  /\ parent' = [parent EXCEPT ![b] = p]
  /\ viewOf' = [viewOf EXCEPT ![b] = v]
  /\ ancestors' = [ancestors EXCEPT ![b] = ancestors[p] \cup {b}]
  /\ UNCHANGED <<votes, lock, committed, view>>

\* Vote(h, b)：诚实节点 h 投票给块 b。
\* P1 安全规则（扩展本地 lock + baseline/最高-QC 扩展检查）+ P2 投票即锁（lock 推进到父块）
\* + A2 不双签（同视图至多一票）+ A3 视图单调（不在旧视图投票）。
Vote(h, b) ==
  /\ h \in Honest
  /\ b \in blocks
  /\ LET v == viewOf[b] IN
      /\ v >= view[h]                                  \* A3：视图单调
      /\ ~ \E b2 \in blocks : <<h, v, b2>> \in votes       \* A2：不 equivocate
      /\ Extends(b, lock[h])                          \* P1：扩展本地 lock
      /\ BaselineOK(h, b)                             \* P1：baseline/最高-QC 扩展检查（V2）
      /\ ParentCertified(b)                           \* P1：父块已认证 Certified(parent)（V3）
      /\ NewViewOK(v) \/ v = 0                         \* V4：只接受经 new-view 的提案（view 0 创世轮豁免）
      /\ votes' = votes \cup {<<h, v, b>>}
      /\ lock' = [lock EXCEPT ![h] = parent[b]]       \* P2：投票即锁（推进到父块）
      /\ view' = [view EXCEPT ![h] = v]
      /\ UNCHANGED <<blocks, parent, viewOf, ancestors, committed>>

\* Commit(h, b)：诚实节点 h 提交满足 3-chain 的块 b（P3）。
Commit(h, b) ==
  /\ h \in Honest
  /\ b \in blocks
  /\ b \notin committed[h]
  /\ Committable(b)
  /\ committed' = [committed EXCEPT ![h] = committed[h] \cup {b}]
  /\ UNCHANGED <<blocks, parent, viewOf, ancestors, votes, lock, view>>

\* ViewChange(h)：超时 → 视图 +1（P4）。携带本地最高 QC（= HighestCertified，派生），
\* 在共享状态超近似下由 view[h] 推进 + HighestCertified 派生表示（即 view-change 消息，
\* 见 NewViewOK 注释；不新增 per-node highestQC 变量）。
ViewChange(h) ==
  /\ h \in Honest
  /\ view[h] < MaxView
  /\ view' = [view EXCEPT ![h] = view[h] + 1]
  /\ UNCHANGED <<blocks, parent, viewOf, ancestors, votes, lock, committed>>

Next ==
  \/ (\E b \in Block, v \in View, p \in Block : Propose(b, v, p))
  \/ (\E h \in Honest, b \in Block : Vote(h, b))
  \/ (\E h \in Honest, b \in Block : Commit(h, b))
  \/ (\E h \in Honest : ViewChange(h))

\* -------------------------------------------------------------------------
\* 安全性不变式（每条标注 PROOFS.md 公理/引理/定理）
\* -------------------------------------------------------------------------

\* 类型不变式（模型自检，非协议性质）。
TypeOK ==
  /\ blocks \subseteq Block
  /\ Genesis \in blocks
  /\ parent \in [Block -> Block]
  /\ viewOf \in [Block -> View]
  /\ ancestors \in [Block -> SUBSET Block]
  /\ votes \subseteq (Honest \X View \X Block)
  /\ lock \in [Honest -> Block]
  /\ committed \in [Honest -> SUBSET Block]
  /\ view \in [Honest -> View]
  /\ \A b \in blocks : parent[b] \in blocks
  /\ \A b \in blocks : ancestors[b] \subseteq blocks

\* 公理 A2（不 equivocate）：诚实节点同视图至多签一个块。
HonestVotePerView ==
  \A h \in Honest, v \in View :
    Cardinality({ b \in blocks : <<h, v, b>> \in votes }) <= 1

\* 引理 L3（同视图唯一 QC / 无同视图分叉）：任意视图至多一个块获得 QC。
QcUniquePerView ==
  \A v \in View :
    Cardinality({ b \in blocks : viewOf[b] = v /\ Certified(b) }) <= 1

\* 引理 L4（锁链内单调）：当前 lock 支配每个已投块的父块，
\* 即 lock 沿单一链单调推进、永不离开当前链。
LockDominatesVotes ==
  \A h \in Honest, b \in blocks :
    (<<h, viewOf[b], b>> \in votes) => Extends(lock[h], parent[b])

\* 提交前置（P3 的一部分）：已提交块必已获得 QC。
CommittedImpliesCertified ==
  \A h \in Honest : \A b \in committed[h] : Certified(b)

\* 定理 T（3-chain 安全性 / 无冲突提交）：任意两诚实节点的已提交块不冲突。
NoConflictCommit ==
  \A h1 \in Honest : \A h2 \in Honest : \A b1 \in committed[h1] : \A b2 \in committed[h2] :
    ~ Conflicting(b1, b2)

\* 推论 C1（无回滚）：全体已提交块构成单一增长链。
NoRollback ==
  \A b1 \in (UNION { committed[h] : h \in Honest }),
      b2 \in (UNION { committed[h] : h \in Honest }) :
    ~ Conflicting(b1, b2)

\* -------------------------------------------------------------------------
\* 活性（WF / SF）
\* -------------------------------------------------------------------------

\* 按诚实节点聚合的动作（供 WF/SF 引用）。
VoteH(h)   == \E b \in Block : Vote(h, b)
CommitH(h) == \E b \in Block : Commit(h, b)

\* 公平性：诚实动作按 WF（弱公平）/ SF（强公平）调度，不饿死。
\* 活性论证依赖部分同步假设（GST 后稳定诚实 leader）—— 这是活性论证的前提，
\* 不是本模型的结论（PROOFS.md §4.1、phase5/DESIGN.md §五）。
Liveness ==
  /\ \A h \in Honest : WF_vars(VoteH(h))
  /\ \A h \in Honest : SF_vars(CommitH(h))
  /\ \A h \in Honest : WF_vars(ViewChange(h))

Spec == Init /\ [][Next]_vars /\ Liveness

\* 活性性质 L-ViewProgress（最终视图推进）：每个诚实节点视图最终到达 MaxView。
\* 由 WF(ViewChange) 直接可得（ViewChange 在到达上界前恒使能）。
ViewProgress == \A h \in Honest : <>(view[h] = MaxView)

\* 活性性质 L-EventuallyCommit（最终提交）：最终至少一个诚实节点提交一块。
\* 诚实边界：仅在部分同步（稳定诚实 leader）下成立；在完全对抗的 Propose 下，
\* 拜占庭 leader 可持续提出被多数诚实节点拒投的提案（只扩展少数链），
\* 导致永无 QC、永无提交 —— 即 HotStuff 的活性假设缺口。
\* V2 已补 baseline 检查；V3 已补「父块必须已认证 Certified(parent)」；V4 已补
\*「view-change/new-view 携带最高 QC」的消息协议。完整活性仍依赖部分同步(GST)假设：
\* 完全对抗的 Propose 下，拜占庭 leader 可持续提出分叉（父=Genesis 高视图块）使诚实票分裂，
\* 永无 QC —— 这是 FLP 型活性下界（完全异步 + 全对抗对手），view-change/new-view 协议
\* 无法消除（见 baseline-fix/PROGRESS.md 第三层结论）；稳定 leader 模型下由 V4 锚定规则
\* 消除跳视图死锁（反例消解见第三层记录）。
EventuallyCommit == <>(\E h \in Honest : committed[h] /= {})

===============================================================================
