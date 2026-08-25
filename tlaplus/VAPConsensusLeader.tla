---- MODULE VAPConsensusLeader ----
\* V4 细化（活性演示用）：稳定诚实 leader + GST（部分同步）理想化 + view-change/new-view 锚定。
\* -------------------------------------------------------------------------
\* 目的：演示 TLA-REPORT.md §4 所述「稳定诚实 leader / 部分同步(GST)」假设补齐后，
\*       EventuallyCommit 活性从 FAIL 恢复为 PASS。
\* V2 修复：复用 Vote 的 BaselineOK（baseline/最高-QC 扩展检查）。
\* V3 修复：复用 Vote 的 ParentCertified（父块必须已认证 Certified(parent)）。
\* V4 修复（第三层）：ProposeLeader 的父块 = HighestCertified（最高 QC 块），即 new-view 提案
\*       以「最高 QC 的扩展」为锚点 —— 消除跳视图死锁（B1 获 QC 后，新视图提案 parent = B1
\*       而非无 QC 的 B2）。
\* GST 理想化（本模块）：把 ViewChange 细化为「同步超时 ViewChangeAll」——全体诚实节点一起
\*       跳视图，且仅当当前视图的非创世块均已认证（或无块）才跳。这消除「节点抢在提案定稿前
\*       跳视图」的空基线活锁（第三层记录里 MaxView=3 的残缺口），对应 GST 下「诚实 leader 提案
\*       及时、节点不跳过头」的假设。
\* 诚实边界：这是「稳定 leader + 无 equivocation + baseline + 父块已认证 + new-view 锚定 + GST
\*       同步超时」的理想化；完全对抗模型下仍 FAIL（FLP 下界，见 baseline-fix/PROGRESS.md 第三层）。
\* 本模块 EXTENDS VAPConsensus，复用其 Init/Vote/Commit/不变式；仅重定义 Propose/ViewChange/公平性。

EXTENDS VAPConsensus

\* new-view 锚定提案：父块 = 最高已认证块（HighestCertified），目标视图 v = 全体节点当前视图
\*（GST 同步，view 全同步故 \A h : v = view[h] 良定义），每视图至多一块（无分叉）。
ProposeLeader(b, v, p) ==
  /\ b \in Block \ blocks
  /\ p = HighestCertified                     \* V4：以最高 QC 的扩展为锚（而非最高视图块）
  /\ v \in View
  /\ \A h \in Honest : v = view[h]            \* GST：目标视图 = 全体节点当前视图
  /\ viewOf[p] < v                            \* A0：视图沿祖先链严格递增
  /\ ~ \E q \in blocks : viewOf[q] = v        \* 每视图至多一块（无分叉/无浪费）
  /\ blocks' = blocks \cup {b}
  /\ parent' = [parent EXCEPT ![b] = p]
  /\ viewOf' = [viewOf EXCEPT ![b] = v]
  /\ ancestors' = [ancestors EXCEPT ![b] = ancestors[p] \cup {b}]
  /\ UNCHANGED <<votes, lock, committed, view>>

\* ProposeLeaderEnabled：leader 在当前（同步）视图 v 仍有可提的块（父块 = HighestCertified、
\* v = 全体节点当前视图、viewOf[HighestCertified] < v、当前视图尚无块）。GST 下若 leader 仍可
\* 提案则节点不应超时跳视图（leader 提案及时），仅当 leader 无可提案（失败/耗尽）才超时。
ProposeLeaderEnabled ==
  \E b \in Block, v \in View :
    /\ b \in Block \ blocks
    /\ \A h \in Honest : v = view[h]
    /\ viewOf[HighestCertified] < v
    /\ ~ \E q \in blocks : viewOf[q] = v

\* ViewChangeAll：GST 同步超时 —— 全体诚实节点一起跳视图 +1；仅当 (1) leader 无可提案
\* （ProposeLeader 不可使能）且 (2) 当前视图的所有非创世块均已认证（或无块）才跳，
\* 防止「提案未定稿前跳走 / 跳过头」的空基线活锁。
ViewChangeAll ==
  /\ \A h \in Honest : view[h] < MaxView
  /\ ~ ProposeLeaderEnabled
  /\ \A h \in Honest : \A b \in blocks : (viewOf[b] = view[h] /\ b /= Genesis) => Certified(b)
  /\ view' = [h \in Honest |-> view[h] + 1]
  /\ UNCHANGED <<blocks, parent, viewOf, ancestors, votes, lock, committed>>

NextLeader ==
  \/ (\E b \in Block, v \in View, p \in Block : ProposeLeader(b, v, p))
  \/ (\E h \in Honest, b \in Block : Vote(h, b))
  \/ (\E h \in Honest, b \in Block : Commit(h, b))
  \/ ViewChangeAll

\* leader 提案的弱公平（稳定期 leader 终将被调度提案）。
ProposeLeaderH == \E b \in Block, v \in View, p \in Block : ProposeLeader(b, v, p)

\* 公平性：诚实投票/提交 + 同步超时 + leader 提案弱公平。
\*（不复用 VAPConsensus 的 Liveness——其中 WF(ViewChange(h)) 按逐节点跳视图，与本模块的
\*  ViewChangeAll 不同；此处按 GST 同步超时重定义。）
LivenessLeader ==
  /\ \A h \in Honest : WF_vars(VoteH(h))
  /\ \A h \in Honest : SF_vars(CommitH(h))
  /\ WF_vars(ViewChangeAll)
  /\ WF_vars(ProposeLeaderH)

SpecLeader == Init /\ [][NextLeader]_vars /\ LivenessLeader

===============================================================================
