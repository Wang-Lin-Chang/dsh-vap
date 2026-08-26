# VAP 共识 TLA+ 规格 —— Apalache 符号模型检查结果（结果：提交模型归纳证毕 PASS）

> 运行日期：2026-08-26
> 目标机：腾讯云老服务器 ubuntu@101.42.23.246（Ubuntu 22.04.5 LTS，**2 核 / 3.6 GiB 内存**，8 GiB swap）
> 工具链：**Apalache 0.62.1**（GitHub release apalache-mc，sha256 `93fef2f3…` 校验一致）+ OpenJDK 21.0.11 + Z3 4.8.12
> 对照基线：TLC 2.19（`/opt/tlaplus/tla2tools.jar`，见 `dsh-vap/tlaplus/TLC-RESULTS.md`）
> 纪律声明：未改动 dsh-vap 仓库与 tlaplus 目录内任何原始规格；适配变体放 `/home/ubuntu/apalache-work/` 与本目录。

---

## 0. 结论速览（一句话）

**结果**：用 Apalache 符号归纳法，把 TLC 无法收敛的 **N=4 提交维度模型（Block=4/MaxView=3，TLC 下 4,517,653 distinct 未收敛）跑成归纳证毕——7 条安全不变式全部 PASS，全程 ~33 秒（归纳步 28.3s + 基础步 4.8s），零状态枚举、零爆炸。**

| 模型 | TLC（显式枚举） | Apalache（符号归纳） |
|---|---|---|
| Block=3/MaxView=2（最小） | 55,188 distinct / 4min59s 完整穷举 PASS | 归纳步 13.9s + 基础步 4.6s，**NoError** |
| **Block=4/MaxView=3（提交维度）** | **4,517,653 distinct 未收敛（171min，零违反）** | 归纳步 28.3s + 基础步 4.8s，**NoError（完整穷举等价）** |

---

## 1. 环境安装（步骤 1，已完成）

| 项 | 结果 |
|---|---|
| Apalache | `apalache-mc-0.62.1.tgz`（192,000,903 B）→ `/opt/apalache`；`bin/apalache-mc version` → **0.62.1** |
| 下载通道 | GitHub release 直连被 GFW 阻断（`SSL_read: unexpected eof`）；改走镜像 `gh-proxy.com` 前缀一次成功，sha256 `93fef2f381d30465eff906a2d6afa3358cb2c9adf6a8aad3bec0ded4f45432bb` 与官方一致 |
| Java | 0.62.1 的 jar 编译目标为 class 61（Java 21），原机 java17 报 `UnsupportedClassVersionError` → `apt-get install openjdk-21-jre-headless` → 21.0.11（update-alternatives 自动切默认） |
| Z3 | Apalache 0.62.1 不自带 z3 → `apt-get install z3` → 4.8.12（满足 ≥4.8.7 要求） |
| 内存 | 启动器默认 `-Xmx4096m` 超本机 3.6GiB，运行统一 `JVM_ARGS='-Xmx2g'` 留内存给 Z3 子进程 |

---

## 2. 规格适配 Apalache 语法子集（步骤 2）

源规格 `VAPConsensus.tla`（V4）无法直接喂 Apalache，逐项最小改动如下（语义等价，差异如实标注）：

| # | 原写法 | 适配后 | 理由 |
|---|---|---|---|
| 1 | `EXTENDS Naturals, FiniteSets, TLC` | `EXTENDS Naturals, FiniteSets, Apalache` | 原规格未用 TLC 的 Assert/Print；需 `Apalache` 获得 `ApaFoldSet` |
| 2 | `HighestCertified` 用 `CHOOSE b ∈ blocks : Certified(b) ∧ ∀q…viewOf[q]≤viewOf[b]` | `ApaFoldSet(MaxByView, Genesis, {b ∈ blocks : Certified(b)})`，`MaxByView(a,b)≜IF viewOf[a]≥viewOf[b] THEN a ELSE b` | Apalache 不支持带任意谓词的 CHOOSE；max 是结合+交换运算，`ApaFoldSet` 结果良定义；空集返回基元 Genesis（与 CHOOSE 的 ELSE 分支一致） |
| 3 | `UNCHANGED <<a,b,c>>` | 逐变量 `a'=a ∧ b'=b ∧ c'=c` | 规避 Apalache 对「分组 UNCHANGED 元组」的赋值分析缺陷（issue #3143） |
| 4 | 无类型注解 | CONSTANT/VARIABLE 加 `\* @type: …;`（Snowcat） | `votes={}` 空集初值无法推断元素类型 |
| 5 | `parent ∈ [Block→Block]` 等函数集成员 | `DOMAIN parent = Block ∧ ∀b∈Block : parent[b] ∈ Block` | Apalache 把 `x'∈[S→T]` 脱糖成 `∃t∈[S→T]: x'=t` 的「赋值形」，与归纳步赋值分析冲突 |
| 6 | （新增）`Safety`/`SafetyInit`/`Ind`/`IndInit` 算子 | 见 §3 | 纯合取/存在量词命名，零语义改动，仅为归纳证明服务 |

**关键点**：`HighestCertified`（唯一 CHOOSE 点）经 `ApaFoldSet` 重写后，其余 284 行规格（动作/7 条不变式/活性算子）语义零改动，逐字保留。

---

## 3. 归纳证明方法与 8 条归纳强化（核心工程）

Apalache 不做 TLC 式显式枚举，而是**符号归纳**：证明 `Ind` 是归纳不变式，即

- **基础步** `Init ⇒ Ind`：`check --init=Init --inv=Ind --length=0`
- **归纳步** `Ind ∧ Next ⇒ Ind'`：`check --init=IndInit --inv=Ind --length=1`

两者皆 `NoError` ⇒ `Ind` 对**全部可达状态**成立（无界，与 TLC 穷举等价），故 `Safety`（7 条原不变式之合取）对全部可达状态成立。

**首次试跑发现 `Safety` 本身不归纳**（Apalache 找到反例：HonestVotePerView 因「票可指向未提出块」被 Propose 打破）。逐条加入以下 **8 条归纳强化**后闭合（每条都是「可达态恒真」的结构/类型补全，非协议新性质）：

| 强化 | 定义 | 封死的缺口 |
|---|---|---|
| VotesForProposed | 票只投已提出块：`<<h,v,b>>∈votes ⇒ b∈blocks` | HonestVotePerView 量词域是 blocks，未提出块的票会打破它 |
| UnproposedDefault | 未提出块保持 Init 默认 `parent=Genesis/viewOf=0/ancestors={Genesis}` | Propose 重置未提出块 ancestors，打破 LockDominatesVotes |
| LockProposed | `lock[h] ∈ blocks` | 未提出块作 lock 被 Propose 重置 ancestors |
| CommittedProposed | `committed[h] ⊆ blocks` | 未提出块入 committed 使 CommittedImpliesCertified 假 |
| GenesisOK | `parent[Genesis]=Genesis / viewOf[Genesis]=0 / ancestors[Genesis]={Genesis}` | ancestors[Genesis] 被任意赋值引入「Genesis 的假祖先」 |
| AncestorsConsistent | `ancestors[b] = ancestors[parent[b]] ∪ {b}` | 祖先闭包不自洽，Extends 关系失稳 |
| ViewStrictlyIncreases | 父链视图严格递增（A0，Genesis 除外） | 祖先环/视图不回退 |
| ViewDominatesVotes | `<<h,v,b>>∈votes ⇒ view[h] ≥ v`（A3 视图单调） | 「投了 view2 却 view=1」的不可达态 |

> 这 8 条**不改变**原 7 条安全不变式的语义：它们仅是把「Init 默认 + 动作前置条件」蕴含的、原 TypeOK 未写全的跨变量一致性补进归纳不变式。这是标准做法（安全性质通常不归纳，需加强）；`Ind ⇒ Safety` 由构造平凡成立。

---

## 4. 两个模型的 Apalache 结果（步骤 3）

全部命令 `cd /home/ubuntu/apalache-work && JVM_ARGS='-Xmx2g' apalache-mc check --config=<cfg> <flags> VAPConsensusApalache.tla`，`setsid nohup` 后台跑。

### 4.1 Block=3/MaxView=2（最小模型，交叉验证 TLC 55,188）

| 检查 | 命令 | 结果 | 耗时 |
|---|---|---|---|
| 基础步 | `--init=Init --inv=Ind --length=0` | **NoError** | 4.6s |
| 归纳步 | `--init=IndInit --inv=Ind --length=1` | **NoError** | 13.9s |

### 4.2 Block=4/MaxView=3（提交维度模型，TLC 未收敛的那个）

| 检查 | 命令 | 结果 | 耗时 |
|---|---|---|---|
| 基础步 | `--init=Init --inv=Ind --length=0` | **NoError** | 4.8s |
| **归纳步** | `--init=IndInit --inv=Ind --length=1` | **NoError** | **28.3s** |

完整日志存于本目录 `run-apalache-*.log`（四条均 `EXITCODE: OK`、`The outcome is: NoError`）。

---

## 5. 与 TLC 的交叉验证结论（步骤 4a）

1. **规格等价**：适配仅改 `EXTENDS`、`HighestCertified` 的 CHOOSE→ApaFoldSet、`UNCHANGED`→显式赋值、TypeOK 的 DOMAIN 形、加类型注解（§2 逐项）。动作与 7 条安全不变式的逻辑结构未变；`HighestCertified` 的 max 语义在「max 结合+交换 + L3 唯一」下与 CHOOSE 良定义等价。
2. **最小模型**：TLC 完整穷举 **55,188 distinct「No error」**（`run-v4b-safety.log`：`367195 states generated, 55188 distinct states found, 0 states left on queue; Model checking completed. No error has been found.`）；Apalache 归纳证明 Safety 对全部可达态成立 → **结论一致**。
3. **提交模型**：TLC 在 **4,517,653 distinct / 1,776,941 队列**处未收敛终止（`run-b4-v3.log`，171min，全程 Error=0/violated=0，非违反）；Apalache 归纳步 **28.3s NoError** → **首次给出该模型的完整安全结论**（TLC 只到「未收敛且零违反」，Apalache 到「归纳证毕」）。

---

## 6. 最终结论

- **结果**：N=4 提交维度模型（Block=4/MaxView=3）在 TLC 下 4,517,653 distinct 未收敛，Apalache 以符号归纳在 **~33 秒**内证毕 7 条安全不变式（TypeOK/HonestVotePerView/QcUniquePerView/LockDominatesVotes/CommittedImpliesCertified/NoConflictCommit/NoRollback）对全部可达状态成立，**零状态枚举、零内存爆炸**。
- **符号方法对本模型的边界**：Apalache 不检查时序活性（`<>`/WF/SF），故 `ViewProgress`/`EventuallyCommit`（活性）仍由 TLC 负责（其 §9.1 三层修复后结论不变）；本组只覆盖安全不变式（这正是状态爆炸的源头，也是本任务「攻破边界」的靶点）。
- **诚实边界（不变）**：这是 N=4、MaxView≤3 的有限模型机器证明，不替代无界归纳（Coq/Lean）。

---

## 7. 文件清单

| 文件（本目录 /home/ubuntu/apalache-work/） | 说明 |
|---|---|
| `VAPConsensusApalache.tla` | Apalache 适配变体（语义等价，§2 改动 + §3 归纳算子与强化） |
| `MC-N4-b3-v2-apalache.cfg` / `MC-N4-b4-v3-apalache.cfg` | 与 TLC 同参数的 Apalache 配置（仅 CONSTANT/INIT/NEXT/INVARIANT） |
| `run-apalache-b3v2-indinit.log` / `run-apalache-b3v2-indnext.log` | 最小模型基础步/归纳步日志（NoError） |
| `run-apalache-b4v3-indinit.log` / `run-apalache-b4v3-indnext.log` | **提交模型基础步/归纳步日志（NoError，归纳证毕证据）** |
