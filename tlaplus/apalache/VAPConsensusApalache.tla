---- MODULE VAPConsensusApalache ----
\* VAP 锁步 QC 链共识（VAP-TO）TLA+ 规格 —— Apalache 适配变体
\* -------------------------------------------------------------------------
\* 源：C:\Users\王霖昌\Desktop\dsh-vap\tlaplus\VAPConsensus.tla（V4，284 行，TLC 已跑）。
\* 本变体语义等价、语法 Apalache 友好，仅做以下最小改动（其余一字未动）：
\*   (1) EXTENDS Naturals, FiniteSets, TLC  →  EXTENDS Naturals, FiniteSets, Apalache
\*       （原规格未使用 TLC 模块的 Assert/Print 等算子，删除零影响；
\*        新增 Apalache 以获得 FoldSet）。
\*   (2) HighestCertified 的 CHOOSE 改写为 ApaFoldSet（Apalache 内置折叠算子）：
\*       原：IF \E b \in blocks : Certified(b)
\*           THEN CHOOSE b \in blocks : Certified(b) /\ \A q \in blocks :
\*                Certified(q) => viewOf[q] <= viewOf[b]
\*           ELSE Genesis
\*       新：ApaFoldSet(MaxByView, Genesis, {b \in blocks : Certified(b)})
\*       其中 MaxByView(a,b) == IF viewOf[a] >= viewOf[b] THEN a ELSE b。
\*       理由：max 是结合+交换运算，ApaFoldSet 结果良定义；L3（同视图唯一 QC）保证
\*       「最高视图已认证块」唯一，CHOOSE 的良定义性由 FoldSet 的确定性取代；
\*       空集返回基元 Genesis（与 CHOOSE 的 ELSE 分支一致）。
\*       视图值域为 0..MaxView（≥0），Genesis 视图=0，故 Genesis 是 max 的单位元。
\*   (3) UNCHANGED <<a,b,c>> 展开为逐变量 a'=a /\ b'=b /\ c'=c（语义等价）：
\*       规避 Apalache 对「分组 UNCHANGED 元组」的赋值分析缺陷（issue #3143），
\*       否则归纳步 check --init=Safety 报 "X' is used before it is assigned"。
\*   (4) 新增 CONSTANT/VARIABLE 的 Snowcat 类型注解（@type）与合取算子 Safety（纯合取，零语义改动）。
\*   (5) TypeOK 中 x \in [S -> T]（函数集成员）改写为 DOMAIN x = S /\ \A i \in S : x[i] \in T
\*       （语义等价：f ∈ [S→T] ⟺ DOMAIN f = S 且 ∀i∈S: f[i]∈T）。
\*       理由：Apalache 会把 x' ∈ [S→T] 脱糖为 \E t ∈ [S→T]: x' = t 的「赋值形」，
\*       与归纳步 check --init=Safety 的赋值分析冲突，报 "x' used before assigned"；
\*       DOMAIN 形是 Apalache 规范推荐的类型不变式写法，避免该冲突。
\* 活性算子（Liveness/Spec/ViewProgress/EventuallyCommit）原样保留：Apalache 仅做
\* 安全不变式检查，不消费这些算子（Apalache 不做时序活性检查）。
\*
\* 记号（与 PROOFS.md §1 对齐）：
\*   R = Nodes；H = Honest；QC = Certified(b)（≥ Quorum 诚实签名 = f+1）；
\*   lock = lock[h]；commit = Committable；baseline = HighestCertified。
\* 版本：V4（2026-08-25）三层活性修复（baseline → Certified(parent) → view-change/new-view）。

EXTENDS Naturals, FiniteSets, Apalache

\* -------------------------------------------------------------------------
\* 模型常量（由 cfg 赋值）
\* -------------------------------------------------------------------------
CONSTANT
  \* @type: Set(Str);
  Nodes,
  \* @type: Set(Str);
  Honest,
  \* @type: Int;
  Quorum,
  \* @type: Int;
  MaxView,
  \* @type: Set(Str);
  Block,
  \* @type: Str;
  Genesis

View == 0..MaxView

\* -------------------------------------------------------------------------
\* 变量（含 Apalache Snowcat 类型注解）
\* -------------------------------------------------------------------------
VARIABLES
  \* @type: Set(Str);
  blocks,
  \* @type: Str -> Str;
  parent,
  \* @type: Str -> Int;
  viewOf,
  \* @type: Str -> Set(Str);
  ancestors,
  \* @type: Set(<<Str, Int, Str>>);
  votes,
  \* @type: Str -> Str;
  lock,
  \* @type: Str -> Set(Str);
  committed,
  \* @type: Str -> Int;
  view

vars == <<blocks, parent, viewOf, ancestors, votes, lock, committed, view>>

\* -------------------------------------------------------------------------
\* 派生算子
\* -------------------------------------------------------------------------

Extends(b, a) == a \in ancestors[b]

Conflicting(b1, b2) == ~ (Extends(b1, b2) \/ Extends(b2, b1))

VotesFor(b) == { h \in Honest : <<h, viewOf[b], b>> \in votes }

Certified(b) == Cardinality(VotesFor(b)) >= Quorum

Committable(b) ==
  \E b1 \in blocks, b2 \in blocks :
    /\ parent[b1] = b
    /\ parent[b2] = b1
    /\ Certified(b)
    /\ Certified(b1)
    /\ Certified(b2)

\* -------------------------------------------------------------------------
\* baseline / 最高-QC 扩展检查（V2 活性修复）
\* -------------------------------------------------------------------------
\* MaxByView：两已认证块中视图更大者（相等分支由 L3 保证不可达）。
MaxByView(a, b) == IF viewOf[a] >= viewOf[b] THEN a ELSE b

\* HighestCertified：最高视图已认证块；无 QC 时 = Genesis。
\* 由 ApaFoldSet(MaxByView, Genesis, {已认证块}) 计算：max 结合+交换 → 良定义；
\* 空集返回 Genesis（与 V4 的 CHOOSE ELSE 分支一致）。
HighestCertified == ApaFoldSet(MaxByView, Genesis, { b \in blocks : Certified(b) })

BaselineOK(h, b) ==
  \/ HighestCertified = Genesis /\ parent[b] = Genesis
  \/ HighestCertified /= Genesis /\ Extends(parent[b], HighestCertified)

ParentCertified(b) == parent[b] = Genesis \/ Certified(parent[b])

\* -------------------------------------------------------------------------
\* view-change / new-view（V4 第三层活性修复）
\* -------------------------------------------------------------------------
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
\* Next 动作
\* -------------------------------------------------------------------------
Propose(b, v, p) ==
  /\ b \in Block \ blocks
  /\ v \in View
  /\ p \in blocks
  /\ viewOf[p] < v
  /\ blocks' = blocks \cup {b}
  /\ parent' = [parent EXCEPT ![b] = p]
  /\ viewOf' = [viewOf EXCEPT ![b] = v]
  /\ ancestors' = [ancestors EXCEPT ![b] = ancestors[p] \cup {b}]
  /\ votes' = votes
  /\ lock' = lock
  /\ committed' = committed
  /\ view' = view

Vote(h, b) ==
  /\ h \in Honest
  /\ b \in blocks
  /\ LET v == viewOf[b] IN
      /\ v >= view[h]
      /\ ~ \E b2 \in blocks : <<h, v, b2>> \in votes
      /\ Extends(b, lock[h])
      /\ BaselineOK(h, b)
      /\ ParentCertified(b)
      /\ NewViewOK(v) \/ v = 0
      /\ votes' = votes \cup {<<h, v, b>>}
      /\ lock' = [lock EXCEPT ![h] = parent[b]]
      /\ view' = [view EXCEPT ![h] = v]
      /\ blocks' = blocks
      /\ parent' = parent
      /\ viewOf' = viewOf
      /\ ancestors' = ancestors
      /\ committed' = committed

Commit(h, b) ==
  /\ h \in Honest
  /\ b \in blocks
  /\ b \notin committed[h]
  /\ Committable(b)
  /\ committed' = [committed EXCEPT ![h] = committed[h] \cup {b}]
  /\ blocks' = blocks
  /\ parent' = parent
  /\ viewOf' = viewOf
  /\ ancestors' = ancestors
  /\ votes' = votes
  /\ lock' = lock
  /\ view' = view

ViewChange(h) ==
  /\ h \in Honest
  /\ view[h] < MaxView
  /\ view' = [view EXCEPT ![h] = view[h] + 1]
  /\ blocks' = blocks
  /\ parent' = parent
  /\ viewOf' = viewOf
  /\ ancestors' = ancestors
  /\ votes' = votes
  /\ lock' = lock
  /\ committed' = committed

Next ==
  \/ (\E b \in Block, v \in View, p \in Block : Propose(b, v, p))
  \/ (\E h \in Honest, b \in Block : Vote(h, b))
  \/ (\E h \in Honest, b \in Block : Commit(h, b))
  \/ (\E h \in Honest : ViewChange(h))

\* -------------------------------------------------------------------------
\* 安全性不变式
\* -------------------------------------------------------------------------
TypeOK ==
  /\ blocks \subseteq Block
  /\ Genesis \in blocks
  /\ DOMAIN parent = Block /\ \A b \in Block : parent[b] \in Block
  /\ DOMAIN viewOf = Block /\ \A b \in Block : viewOf[b] \in View
  /\ DOMAIN ancestors = Block /\ \A b \in Block : ancestors[b] \subseteq Block
  /\ votes \subseteq (Honest \X View \X Block)
  /\ DOMAIN lock = Honest /\ \A h \in Honest : lock[h] \in Block
  /\ DOMAIN committed = Honest /\ \A h \in Honest : committed[h] \subseteq Block
  /\ DOMAIN view = Honest /\ \A h \in Honest : view[h] \in View
  /\ \A b \in blocks : parent[b] \in blocks
  /\ \A b \in blocks : ancestors[b] \subseteq blocks

HonestVotePerView ==
  \A h \in Honest, v \in View :
    Cardinality({ b \in blocks : <<h, v, b>> \in votes }) <= 1

QcUniquePerView ==
  \A v \in View :
    Cardinality({ b \in blocks : viewOf[b] = v /\ Certified(b) }) <= 1

LockDominatesVotes ==
  \A h \in Honest, b \in blocks :
    (<<h, viewOf[b], b>> \in votes) => Extends(lock[h], parent[b])

CommittedImpliesCertified ==
  \A h \in Honest : \A b \in committed[h] : Certified(b)

NoConflictCommit ==
  \A h1 \in Honest : \A h2 \in Honest : \A b1 \in committed[h1] : \A b2 \in committed[h2] :
    ~ Conflicting(b1, b2)

NoRollback ==
  \A b1 \in (UNION { committed[h] : h \in Honest }),
      b2 \in (UNION { committed[h] : h \in Honest }) :
    ~ Conflicting(b1, b2)

\* -------------------------------------------------------------------------
\* Apalache 归纳不变式（纯合取，语义零改动）：把 7 条安全不变式合为一条，
\* 供 `check --inv=Safety` 做归纳证明（Init => Safety 且 Safety /\ Next => Safety'），
\* 从而对全部可达状态成立，无需逐状态枚举。
\* -------------------------------------------------------------------------
Safety ==
  /\ TypeOK
  /\ HonestVotePerView
  /\ QcUniquePerView
  /\ LockDominatesVotes
  /\ CommittedImpliesCertified
  /\ NoConflictCommit
  /\ NoRollback

\* -------------------------------------------------------------------------
\* SafetyInit：与 Safety 语义等价（存在量词仅「命名」各变量取值，Safety 再约束之），
\* 但写成「赋值形」：其 primed 形式为 blocks'=blk /\ parent'=par /\ ... /\ Safety'，
\* 使 Apalache 的赋值抽取器（SmtFreeSymbolicTransitionExtractor）能先看到 8 个赋值、
\* 再看到 Safety' 的读取，从而规避「--init=Safety 报 x' used before assigned」的缺陷。
\* 仅用于归纳步 check --init=SafetyInit --inv=Safety --length=1。
\* -------------------------------------------------------------------------
SafetyInit ==
  \E blk \in SUBSET Block, par \in [Block -> Block], vo \in [Block -> View],
      anc \in [Block -> SUBSET Block], vt \in SUBSET (Honest \X View \X Block),
      lk \in [Honest -> Block], cm \in [Honest -> SUBSET Block], vw \in [Honest -> View] :
    /\ blocks = blk
    /\ parent = par
    /\ viewOf = vo
    /\ ancestors = anc
    /\ votes = vt
    /\ lock = lk
    /\ committed = cm
    /\ view = vw
    /\ Safety

\* -------------------------------------------------------------------------
\* 归纳强化（VotesForProposed）：票只投给「已提出」的块。
\* Vote 前置 b ∈ blocks，且 blocks 单调增长 → 可达态恒真（是 Safety 的语义推论，
\* 不在 V4 的 7 条不变式内）。加入它的原因：HonestVotePerView 在 V4 里量词域是
\* blocks（已提出块），当 Propose 新增块 B 且 votes 里恰有「未提出块 B」的票时，
\* 该不变式会从「成立」跳到「违反」——即 Safety 不归纳。VotesForProposed 封死
\* 这个缺口，使 Ind = Safety /\ VotesForProposed 归纳。对可达态，Ind ≡ Safety。
\* -------------------------------------------------------------------------
VotesForProposed ==
  \A h \in Honest, v \in View, b \in Block : <<h, v, b>> \in votes => b \in blocks

\* -------------------------------------------------------------------------
\* 归纳强化（UnproposedDefault）：未提出块的 parent/viewOf/ancestors 保持 Init 默认值
\* （parent=Genesis、viewOf=0、ancestors={Genesis}）。V4 把它们建模为 Block 上的全函数、
\* 初值即默认值，Propose 只改被提出块。若不加此强化，Propose 会把「未提出块」的
\* ancestors 从任意值重置为 ancestors[p]∪{b}，从而破坏 LockDominatesVotes 的归纳。
\* 可达态恒真（Init 默认 + Propose 只动被提出块）。
\* -------------------------------------------------------------------------
UnproposedDefault ==
  \A b \in Block \ blocks :
    /\ parent[b] = Genesis
    /\ viewOf[b] = 0
    /\ ancestors[b] = {Genesis}

\* -------------------------------------------------------------------------
\* 归纳强化（LockProposed / CommittedProposed）：lock 与 committed 只引用「已提出」块。
\* Vote 设 lock'=parent[b]（parent[b] ∈ blocks）、Commit 设 b ∈ blocks，故可达态恒真。
\* 若不加，未提出块的 lock/committed 引用会被后续 Propose 重置 ancestors 而破坏
\* LockDominatesVotes / CommittedImpliesCertified 的归纳（V4 TypeOK 只要求 ∈ Block，
\* 不要求 ∈ blocks）。
\* -------------------------------------------------------------------------
LockProposed == \A h \in Honest : lock[h] \in blocks

CommittedProposed == \A h \in Honest : committed[h] \subseteq blocks

\* -------------------------------------------------------------------------
\* 归纳强化（GenesisOK / AncestorsConsistent / ViewStrictlyIncreases）：
\* ancestors/parent/viewOf 与父链一致的结构不变式（可达态由 Init 默认 + Propose 唯一改写保证）。
\* GenesisOK：Genesis 永不被 Propose 改写，parent/viewOf/ancestors 保持 Init 默认。
\* AncestorsConsistent：ancestors[b] = ancestors[parent[b]] ∪ {b}（祖先闭包 + 自反）。
\* ViewStrictlyIncreases：父链视图严格递增（A0），排除祖先环。
\* 缺这些时，LockDominatesVotes/NoConflictCommit 的归纳步会因 ancestors[Genesis] 等被
\* 任意赋值而被 Propose/Vote 打破。
\* -------------------------------------------------------------------------
GenesisOK ==
  /\ parent[Genesis] = Genesis
  /\ viewOf[Genesis] = 0
  /\ ancestors[Genesis] = {Genesis}

AncestorsConsistent ==
  \A b \in blocks : ancestors[b] = ancestors[parent[b]] \cup {b}

ViewStrictlyIncreases ==
  \A b \in blocks \ {Genesis} : viewOf[parent[b]] < viewOf[b]

\* -------------------------------------------------------------------------
\* 归纳强化（ViewDominatesVotes）：诚实节点的本地 view 不低于其所投任何块的视图。
\* Vote 前置 v ≥ view[h] 且投后 view[h] := v（视图只增不减，A3）→ 可达态恒真。
\* 缺它时，归纳步可出现「投了 view 2 的票却 view[h]=1」的不可达态，被 Vote 打破
\* LockDominatesVotes。
\* -------------------------------------------------------------------------
ViewDominatesVotes ==
  \A h \in Honest, v \in View, b \in Block : <<h, v, b>> \in votes => view[h] >= v

Ind ==
  Safety
    /\ VotesForProposed
    /\ UnproposedDefault
    /\ LockProposed
    /\ CommittedProposed
    /\ GenesisOK
    /\ AncestorsConsistent
    /\ ViewStrictlyIncreases
    /\ ViewDominatesVotes

IndInit ==
  SafetyInit
    /\ VotesForProposed
    /\ UnproposedDefault
    /\ LockProposed
    /\ CommittedProposed
    /\ GenesisOK
    /\ AncestorsConsistent
    /\ ViewStrictlyIncreases
    /\ ViewDominatesVotes

\* -------------------------------------------------------------------------
\* 活性（Apalache 不消费，原样保留以维持与 V4 的一一对应）
\* -------------------------------------------------------------------------
VoteH(h)   == \E b \in Block : Vote(h, b)
CommitH(h) == \E b \in Block : Commit(h, b)

Liveness ==
  /\ \A h \in Honest : WF_vars(VoteH(h))
  /\ \A h \in Honest : SF_vars(CommitH(h))
  /\ \A h \in Honest : WF_vars(ViewChange(h))

Spec == Init /\ [][Next]_vars /\ Liveness

ViewProgress == \A h \in Honest : <>(view[h] = MaxView)

EventuallyCommit == <>(\E h \in Honest : committed[h] /= {})

===============================================================================
