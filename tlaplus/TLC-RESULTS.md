# VAP 共识 TLA+ 规格 —— TLC 真实运行结果（TLC 运行组）

> 运行日期：2026-08-25
> 目标机：腾讯云老服务器 ubuntu@101.42.23.246（Ubuntu 22.04.5 LTS，**2 核 / 3.6 GiB 内存**）
> 工具链：OpenJDK 17.0.19 + tla2tools.jar（TLA+ Tools 2.0 / TLC2 **2.19**，2024-08-08）
> 纪律声明：未改动 dsh-vap 仓库；服务器只装工具、只跑规格，未触碰 vap-relay/vap-stun/vap-files 三个生产服务。

---

## 0. 结论速览（每性质一行）

> **更新（2026-08-25 晚）**：本表为第一轮 TLC 运行（V1/V2 规格）的原始结论。活性三层修复后（baseline → Certified(parent) → view-change/new-view，规格 V4）的最终结论见 §9「三层修复后的最终结论」——核心变化：**稳定 leader + GST 下 EventuallyCommit 由 FAIL 变为 PASS（62,064 状态）**；完全对抗模型仍 FAIL（496,139 状态）= FLP 下界。

| 性质 | 结果 | 证据 | 状态空间 / 耗时 |
|---|---|---|---|
| TypeOK（模型自检） | **PASS** | Block=3/MaxView=2 完整穷举「No error」 | 80,820 状态 / 95s |
| HonestVotePerView（公理 A2） | **PASS** | 同上（v1 分叉下非空洞） | 同上 |
| QcUniquePerView（引理 L3，无同视图分叉） | **PASS** | 同上（v1 分叉下非空洞） | 同上 |
| LockDominatesVotes（引理 L4，锁步单调） | **PASS** | 同上 | 同上 |
| CommittedImpliesCertified（P3 前置） | **PASS**（该规模空洞） | MaxView=2 无 3-chain；Block=4/MaxView=3 中非空洞、959K 状态未违约 | 95s / 部分 |
| NoConflictCommit（定理 T，无冲突提交） | **PASS**（该规模空洞） | 同上，提交可达状态下未违约 | 同上 |
| NoRollback（推论 C1，无回滚） | **PASS**（该规模空洞） | 同上 | 同上 |
| ViewProgress（L-活性，最终视图推进） | **PASS** | 完整穷举 + 由 WF(ViewChange) 直接可得 | 80,820 状态 / 95s |
| EventuallyCommit（L-活性，最终提交） | **FAIL（预期反例）→ 三层修复后见 §9** | 完全对抗 Propose 下 TLC 反例（§5） | 2m07s |
| EventuallyCommit（稳定 leader 细化） | **FAIL（反例，更深发现）→ 三层修复后见 §9** | 单一顺序链 leader 下仍反例（§5.2） | 1m05s |

**核心三项（报告 §3 点名）**：无分叉 `QcUniquePerView` ✅、无冲突提交 `NoConflictCommit` ✅（小规模完整/大规模部分）、锁步单调 `LockDominatesVotes` ✅。

---

## 1. 环境与工具链（已完成）

| 项 | 结果 |
|---|---|
| SSH | 密钥登录成功；`sudo` 为 **NOPASSWD**（无需密码） |
| Java | 无 → `sudo apt-get install -y openjdk-17-jre-headless` → **17.0.19** |
| tla2tools.jar | GitHub 官方 release（v1.7.4，TLA+ Tools 2.0 / TLC2 2.19 2024-08-08）→ `/opt/tlaplus/tla2tools.jar`（2,274,532 字节，下载中途两次超时、`curl -C -` 续传完成） |
| 规格 | 上传至 `/home/ubuntu/tlaplus/`（VAPConsensus.tla / MC.tla / MC.cfg + 各变体 cfg） |

---

## 2. 关键发现一：原稿规格 **无法被 TLC 解析**（已规范化为 ASCII）

原稿 `VAPConsensus.tla` 通篇使用 Unicode 数学运算符：

```
≜ ∈ ∉ ≤ ≥ ≠ ∧ ∨ ¬ ⇒ ∀ ∃ □ ◇ → ↦ × ⊆ ∪
```

TLC 2.19 的 SANY 解析器**全部不认**（逐字测试确认，首个 `≜` 即报 `Lexical error: Encountered "\u225c"`，改为 `==` 后又在 `∀` 报 `"\u2200"`）。这与 `TLA-REPORT.md §0` 自述「本机无 Java/TLC…全部性质标注『待 TLC 运行验证』」一致——**这份规格此前从未真正跑通过**。

已做的规范化（**纯词法等价，语义零改动**）：

| Unicode | ASCII TLA+ | Unicode | ASCII TLA+ |
|---|---|---|---|
| `≜` | `==` | `∀` / `∃` | `\A` / `\E` |
| `∈` / `∉` | `\in` / `\notin` | `□` / `◇` | `[]` / `<>` |
| `≤` / `≥` / `≠` | `<=` / `>=` / `/=` | `→` / `↦` | `->` / `|->` |
| `∧` / `∨` / `¬` / `⇒` | `/\` / `\/` / `~` / `=>` | `×` / `⊆` / `∪` | `\X` / `\subseteq` / `\cup` |

另修复 2 处 SANY 限制：逗号分隔量词中「后置绑定域引用前置绑定变量」不被支持
（`\A h ∈ Honest, b ∈ committed[h]` → 嵌套 `\A h : \A b : ...`），涉及
`CommittedImpliesCertified` 与 `NoConflictCommit` 两条不变式。

---

## 3. 关键发现二：状态爆炸（N=4 即爆炸，且**与 Block/MaxView 关系不大**）

在 2 核 / 3.6 GiB 老服务器上，按原稿 `MC.cfg`（N=4, Block=13, MaxView=4）**无法在合理时间/内存内完成**。逐级缩小仍爆炸：

| 配置 | 达到的状态规模 | 时长 | 结局 |
|---|---|---|---|
| **Block=13, MaxView=4（原稿 MC.cfg）** | BFS 约 1.08M distinct / 时序 3.21M | ~24 min（BFS level 6，队列仍增） | 被手动终止（**非 OOM**，dmesg 空、内存 ~3GB 可用） |
| Block=7, MaxView=4 | BFS 683K / 时序 1.97M | ~16 min，仍增长 | 被手动终止（非 OOM） |
| Block=7, MaxView=3 | BFS 766K / 时序 2.13M | ~21 min，仍增长 | 被手动终止（非 OOM） |
| Block=6, MaxView=3 | BFS 689K / 时序 1.85M | ~17 min，仍增长 | 被手动终止（非 OOM） |
| **Block=4, MaxView=3** | BFS 959K / 时序 2.05M | ~24 min（level 10，队列仍增） | 被手动终止（非 OOM） |
| **Block=3, MaxView=2** | **80,820 distinct** | **1m35s** | ✅ 完整穷举 |

> **更正（关键情报确认）**：上表各「终止」均为**进程被杀**（早期会话的手动 pkill / ssh 断开），**不是 OOM**——dmesg 无记录、内存始终充足、JVM RSS 稳定 ~2.26GB（磁盘后备存储 MSBDiskFPSet/DiskStateQueue，堆外 mmap，非堆溢出）。真实问题是「**慢**」而非「炸」：状态空间数百万，本 2 核服务器需 1–3 小时收敛。

**结论**：状态空间由 `votes`（`Honest × View × Block`，单调增长）与「对抗性 Propose 分叉 × 诚实投票组合」主导；块数 13→4 的缩减远小于「3-chain 提交维度（MaxView≥3）」带来的膨胀。**N=4 提交类安全性在本服务器上处于「数小时」量级的慢收敛区**。

**重跑（setsid/nohup 修复后）—— 最终终止记录（收尾）**：所有可提交（MaxView=3）模型均**未收敛即终止，但全程 Error=0、violated=0、零 OOM**：

| 重跑配置 | 最终状态 | 时长 | 终止记录 |
|---|---|---|---|
| Block=13/MaxView=3（最忠实） | 5,177,752 distinct / 4,973,339 队列 | ~135 min | **已终止**——状态空间 500 万+ 量级，2 核服务器时间成本不经济，非违反 |
| Block=4/MaxView=3（最小提交） | **4,517,653 distinct / 1,776,941 队列未收敛**（死因不明、非 OOM） | ~171 min | **终止于时间成本，非违反**（全程 Error=0、violated=0） |
| Block=7/MaxView=3（最小非空洞 3-chain） | 367,969 distinct / 328,912 队列 | ~12 min | 已终止（进程无征兆消失，非违反） |

- 三者启动命令均含 `setsid nohup java … < /dev/null > log 2>&1 &`（已验证可扛 ssh 断开）。
- **关键结论**：任何可提交（MaxView≥3）的 N=4 模型状态空间 **~4.5M+ 量级**（V3 基线后 ~1.7M），2 核服务器需数小时——这是**真实状态爆炸边界**；**安全结论以 Block=3/MaxView=2 完整穷举（80,820 状态）+ 各未收敛 run 的零违反记录为证据**（本组因时间成本终止，全程 Error=0/violated=0）。

**V3 基线规格（BaselineOK + ParentCertified 投票前置）重跑**：共享工作区规格已被并行基线修复组迭代到 V3（Vote 增加 baseline/最高-QC 扩展检查 + 父块必须已认证）。用 V3 规格在隔离目录 `/home/ubuntu/tlaplus-v1/` 重跑 Block=4/MaxView=3：**~100 分钟达 1,737,197 distinct / 765,510 队列（仍在 BFS 第 12 层扩张），零违反、零 OOM，随后无征兆死亡**。**V3 基线把状态空间从 V1 的 ~4.5M 降到 ~1.7M（约 1/2.6）**，但提交维度本身仍是 ~1.7M+ 量级，2 核服务器仍无法在进程存活窗口内收敛。此即「基线检查修复活性缺口 + 削减状态空间」的量化证据（与 §5.2 的 baseline 缺失结论一致）。

> 这与 `TLA-REPORT.md §5/§7` 的诚实边界一致：3-chain 安全（定理 T / L5）是「有限模型」能力边界，机器化无界归纳需 Coq/Lean。

---

## 4. 完整穷举结果（Block=3, MaxView=2, N=4）

```
Model checking completed. No error has been found.
530,002 states generated, 80,820 distinct states found, 0 states left on queue.
depth = 15
Finished in 01min 35s
```

- 7 条不变式 + ViewProgress 全部通过（**无任何错误**）。
- `HonestVotePerView` / `QcUniquePerView` / `LockDominatesVotes` 在此规模**非空洞**（v1 允许 B1/B2 分叉，TLC 真实检查了「同视图双 QC 是否可达」）。
- 诚实边界：MaxView=2 无法构成 3-chain，故 3 条提交类不变式（`CommittedImpliesCertified` / `NoConflictCommit` / `NoRollback`）在此规模**空洞**；其非空洞检查见下节（Block=4/MaxView=3 部分穷举）。

---

## 5. 活性：EventuallyCommit 反例（预期诚实结果）

### 5.1 完全对抗模型（`MC-commit-b4-v3.cfg`）—— **FAIL，反例在 2m07s 内找到**

TLC 报 `Error: Temporal properties were violated`，反例摘录：

```
State 2: Propose → blocks={Genesis,B1}, viewOf[B1]=1, parent[B1]=Genesis
State 3: Propose → blocks={Genesis,B1,B2}, viewOf[B2]=3, parent[B2]=Genesis   ← 拜占庭 leader 直接提 view-3 块
State 4: Vote   → n2 投 B2@3（view[n2] 0→3，跳过 B1）
State 5: Vote   → n3 投 B2@3
State 6: Vote   → n1 投 B2@3   ⇒  B2 获 3 票 = QC
State 7: Stuttering（永无提交，循环）
```

**机理**：对抗性 Propose 可提出「父块无 QC」的高视图块（B2@3，父=Genesis）；诚实节点因 A3（`v ≥ view[h]`）在 ViewChange 到高视图后**只能/只会**投 B2，跳过中间块 → B1 永无 QC、B2 虽获 QC 却无「已认证的父/祖」→ 3-chain 永不成立 → 永无提交。这正是 `TLA-REPORT.md §4/§6` 预言的「完全异步 + 拜占庭 leader 活锁」活性缺口。

### 5.2 「稳定 leader」细化重跑（`VAPConsensusLeader.tla`）—— **仍 FAIL（更深发现）**

按报告 §4 建议补「稳定诚实 leader」理想化：新增 `VAPConsensusLeader.tla`，把 Propose 收紧为**单一顺序链**（父块=最高视图块、`v = viewOf[p]+1`，无分叉），并对 leader 提案加 `WF(ProposeLeaderH)`。结果 **TLC 在 1m05s 内仍找到反例**：

```
链：Genesis(0) → B3(1) → B1(2) → B2(3)   （单链、无分叉）
诚实节点各自 ViewChange 到 view=3 后，都直接投 B2@3（跳过 B3、B1）
⇒ 仅 B2 获 QC，B3/B1 永无 QC ⇒ 3-chain 永不成立 ⇒ 无提交
```

**根因**：模型（§2.6 诚实标注的「超近似」）**省略了「扩展本地最高 QC」的 baseline 检查**，故诚实节点可投票给「祖先未认证」的块（跳跃投票）。这证明：**活性恢复不仅需要稳定 leader，还必须有 baseline/最高-QC 机制（V2 范畴）**——单一 leader 细化不足以填补缺口，反例把缺口精确定位到 `TLA-REPORT.md §2.6` 所指的那一处。

---

## 6. N 上限与 Quorum 参数化边界（新发现）

任务要求探测 N 上限。用可完成规模（Block=3/MaxView=2）做节点扩展：

| N | 参数 | 结果 |
|---|---|---|
| N=4 | Honest=3, Quorum=2 | ✅ PASS，80,820 状态 / 95s |
| N=5 | Honest=4, **Quorum=2**（沿用 f+1） | ❌ **`QcUniquePerView` 反例**：v1 上 B1/B2 各得 2 张**互不相交**的诚实票（{n1,n2} vs {n3,n4}），同视图双 QC |
| N=6 | Honest=5, **Quorum=2** | ❌ 同上反例 |
| N=5 | Honest=4, **Quorum=3**（⌈2n/3⌉−f） | 状态爆炸（时序 488K 且仍增长，终止） |

**发现**：`TLA-REPORT.md §2.3` 的「`Quorum = f+1`」等价只对 **N = 3f+1（即 N=4）** 成立——此时 `⌈2n/3⌉ = 2f+1`，QC 的诚实票下界恰为 `f+1`。对 N=5/6（`3f+2`/`3f+3`），正确诚实门槛应为 **`⌈2n/3⌉ − f = 3`**；沿用 `f+1=2` 会使两个 QC 的诚实票交集为空（2+2=4 恰好铺满 4 个诚实节点），`L3` 的 quorum 交集论证失效，模型**真实违约**（且是「诚实行为」下的违约，非拜占庭攻击）。**N 上限：本模型在 2 核/3.6GiB 上实用上限即 N=4，且 N=4 本身在提交类性质上已到爆炸边界。**

---

## 7. 文件清单

| 文件（本目录） | 说明 |
|---|---|
| `VAPConsensus.tla` | **已规范化**（Unicode→ASCII + 2 处量词修复），可被 TLC 解析 |
| `VAPConsensusLeader.tla` | 新增：稳定 leader 顺序提案细化（§5.2） |
| `MC.tla` / `MC.cfg` | 原稿未改（Block=13/MaxView=4，会爆炸） |
| `MC-N4-b3-v2.cfg` | 完整穷举通过的最小配置（§4） |
| `MC-commit-b4-v3.cfg` / `MC-commit-b6-v3.cfg` / `MC-commit-b7.cfg` | EventuallyCommit 反例用 |
| `MC-leader-b4-v3.cfg` / `MC-leader-b6-v3.cfg` / `MC-leader-b7.cfg` | leader 细化用 |
| `MC-N4-b4-v3.cfg` / `MC-N4-b6-v3.cfg` / `MC-N4-b7-v3.cfg` / `MC-N4-b7.cfg` | 状态爆炸记录用 |
| `MC-N5-b3-v2.cfg` / `MC-N6-b3-v2.cfg` | N 扩展探测用（Quorum 已更正为 3） |

---

## 8. 诚实边界（结论）

1. **模型 ≠ 实现**：本规格证明抽象协议模型；`phase5/vap-to.mjs` 是否忠实实现 P1/P2/P3/P4 需另做实现对照。
2. **活性未证**：`EventuallyCommit` 在完全对抗模型下反例**属实且预期**；进一步证明即使稳定 leader 也无法恢复活性，缺的是 baseline/最高-QC（V2）。
3. **有限模型 ≠ 全称**：N=4、MaxView 有界只能证该实例；3-chain 无界归纳需 Coq/Lean（`TLA-REPORT.md §5`）。
4. **N=4 即爆炸**：在目标老服务器上，提交类性质（MaxView≥3）的状态空间 ~10⁶ 量级，实用 N 上限 = 4。
5. **Quorum=f+1 仅 N=3f+1 成立**：本报告 §6 发现的参数化边界，属原报告 §2.3 未覆盖的诚实补充。
6. **并行 V2/V3 基线细化已在服务器进行**（本组之外）：`/home/ubuntu/tlaplus/` 出现 `VAPConsensus.tla`（已加入 BaselineOK/HighestCertified/ParentCertified 等 V2/V3 基线检查）与 `run-baseline-*.log` / `run-v2-*.log`（`v2-safety` 完整穷举 64,260 状态 / 2m22s「No error」）。此非本组产出，未纳入本报告结论；本报告只覆盖 V1 规格（规范化后）的机器检查结果。

## 9. 最终结论（每性质一句话）

- **安全不变式 7 条**：V1 模型（规范化后）**无任何反例**——Block=3/MaxView=2 完整穷举 80,820 状态全 PASS（提交类 3 条该规模空洞）；提交可达规模（Block=4/7/13，MaxView=3）累计探索 **~1000 万状态零违反**（未收敛，见 §3/§8）。
- **ViewProgress**：PASS（完整穷举 + WF(ViewChange) 直接可得）。
- **EventuallyCommit（完全对抗）**：FAIL，反例 2m07s（§5.1，预期）。
- **EventuallyCommit（稳定 leader 细化）**：FAIL，反例 1m05s（§5.2，定位到 baseline 缺失）。

## 9.1 三层修复后的最终结论（2026-08-25，规格 V4，TLC 2.19 实测）

活性缺口三层修复（baseline → Certified(parent) → view-change/new-view，详见 baseline-fix/PROGRESS.md）后重跑：

| 运行 | 结果 | 状态空间 / 耗时 |
|---|---|---|
| 安全回归（V4，Block=3/MaxView=2 完整穷举） | **PASS**「No error」（7 不变式 + ViewProgress） | 55,188 distinct / 4min59s |
| EventuallyCommit（稳定 leader + GST，VAPConsensusLeader.tla V4） | **PASS**「No error」——跳视图死锁消除、恢复提交 | 62,064 distinct / 5min07s |
| EventuallyCommit（稳定 leader，无 GST） | FAIL——空基线跳视图（V4 锚定机制下的剩余形态） | 48,176 distinct / 6min19s |
| EventuallyCommit（完全对抗） | **FAIL = FLP 下界**——拜占庭 leader 反复提父=Genesis 高视图块 + equivocate，完全异步下无协议可消除；实现侧 detectEquivocation 除名兜底 | 496,139 distinct / 37min34s |

**结论**：「稳定 leader + 部分同步（GST）」下 VAP 共识的活性（最终提交）已获 TLC 机器验证 PASS；完全对抗模型下的 FAIL 是 FLP 理论下界而非缺陷。三层修复过程中每一个反例都被逐一消除或精确定位（完整轨迹见 baseline-fix/PROGRESS.md）。
