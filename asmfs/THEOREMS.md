# ASM-FS 形式化定理集（机器可检查证明）

> 本文档给出 ASM-FS 协议（智能体状态机即文件系统）六个组合层性质的机器可检查证明。
> 证明引擎：`bmc-checker.mjs`（零第三方依赖的有界模型检查器，全交错穷举）。
> **spec 驱动**：检查器启动时用 `fs` 读取 `specs/E-1~E-6.json`，每个定理的状态机参数、断言目标、预期状态空间大小全部取自对应 spec 的 `model` 字段；spec 缺失 / 非法 JSON / id 不符 / 缺 `model` ⇒ 明确报错退出（拒绝硬编码自证）。定理结果中的预期状态空间大小（13/55/217、36、32 等）由 spec 声明并**运行时自检**。
> 复跑：`node bmc-checker.mjs`（全部）或 `node bmc-checker.mjs E-4`（单条）。
> 所有定理标注有限域边界——**有界穷举是组合证明，不是全称证明**；边界之外不声称。

---

## 记号与公理

### 抽象状态

任务对象 X 由五元组描述：

```
X = (S, L, E, D, Q)
  S ∈ {⊥, running, stopping, orphaned, adopted, done}   主状态标记
  L ∈ {⊥} ∪ {(pid, startSec)}                            锁内容
  E ∈ {⊥} ∪ ℤ                                            退出码
  D ∈ {0, 1}                                              done 文件存在位
  Q = [(seq₁, e₁), …]                                     事件序列
```

### 原子步假设（模型粒度）

每个文件系统调用视为一个原子步。以下两条是**公理**（操作系统保证，非本模型所证）：

- **A1（O_EXCL 独占创建）**：`open(path, O_CREAT|O_EXCL)` 在任意并发进程集上至多一个成功；
- **A2（rename 原子重命名）**：`rename(tmp, path)` 原子完成；读者只能观察到旧内容或新内容，无中间态。

### liveness 判定（三证据存活性）

```
liveness(pid, now) ∈ {alive, dead, pid_reused}
  dead        ⇔  pid ∉ OS(now)
  pid_reused  ⇔  pid ∈ OS(now) ∧ startSec 有定义 ∧ startSec(pid) ≠ L.startSec
  alive       ⇔  pid ∈ OS(now) ∧ (startSec = ⊥ ∨ startSec(pid) = L.startSec)
```

adopt 判定 ⟺ liveness = alive；settle 判定 ⟺ liveness ∈ {dead, pid_reused}。
orphan 标记与收养判定是同一次扫描的两个出口，不存在先后两阶段的时序假设。

---

## 定理

### E-1 恰一终态（Exactly-once finalization）

**陈述**：对同一任务的 N 个并发 finalize（含与 observe 的任意交错），可观察终态满足：(i) `state/done` 恰好被创建一次；(ii) 退出码由 `exit.txt` 唯一决定，不因交错而改变。

**前提**：单任务单执行模式；结论覆盖"可观察终态 done + 退出码"，不含尸检报告原子性（写尸检为最后写者胜，见 E-REPORT 诚实边界）。

**证明**：N ∈ {2,3,4} 全交错穷举（去重状态 13/55/217，由 spec 声明并经状态空间自检确认与实跑一致），断言 doneWins = 1 且退出码单值。✓

**边界**：N ≤ 4；单任务。

---

### E-2 收养互斥（Adoption mutual exclusion）

**陈述**：N 个并发 adopt 竞争同一孤儿任务，恰好一个赢家（adoptWins = 1），终态 adopted 且锁内容唯一。

**证明**：由 A1（O_EXCL 认领锁）与 A2（状态标记原子落盘）组合导出；N ∈ {2,3,4} 全交错穷举验证。✓

**边界**：N ≤ 4。

---

### E-3 三证据健全性（Liveness trichotomy soundness）

**陈述**：liveness 是全函数三分（alive/dead/pid_reused），且：
- pid 存活但 startSec 不匹配 ⇒ pid_reused ⇒ 拒绝收养（防 PID 复用）；
- startSec = ⊥ 时退化为二证据（pid 存活即 alive）——退化前提显式声明，不隐藏。

**证明**：pid ∈ {0,1,2} × startSec ∈ {⊥,100,200} × alive ∈ {false,true} × liveSec ∈ {100,200} 全枚举 36 例（由 spec 声明并经例数自检确认）：liveness 三分唯一且正确（三分支映射由 spec 显式断言，alive=>owner-alive、dead=>win、pid_reused=>reject）；pid_reused 分支在 N ∈ {2,3,4} 并发收养下全部拒绝（0 赢家）。✓

**边界**：有限 pid/startSec 域；Windows 语义（startSec 来自进程启动时间查询）。

---

### E-4 事件溯源追加性（Append-only sequence uniqueness）

**陈述**：事件序列的 seq 编号唯一且历史无损。

**证伪记录**：朴素模型（seq = readdirSync().length + 1，读与写两步非原子）在 N=2 并发下存在反例——两个进程读出同一 seq，后写覆盖先写（seq 冲突 [1,1]）。反例路径可重放：
`A.readSeq → B.readSeq → A.writeEvent → B.writeEvent`。

**修复**：单步原子追加（每事件一次原子写），N ∈ {2,3,4} 全交错穷举全绿。✓

**意义**：本定理以"先证伪、后修复、再转正"的方式完成——检查器首先作为证伪器暴露真实竞态，修复后同一断言转正。这使"证明"成为可回归的机器义务，而非一次性陈述。

**边界**：N ≤ 4；修复语义假设单步写原子（对应实现变更：每事件 O_EXCL 文件或单 O_APPEND 日志）。

---

### E-5 能力格保序嵌入（Capability order-preserving embedding）

**陈述**：模式链 read-only ≤ workspace-write ≤ danger-full-access（许可度升序）下，deny 集单调不增：
`deny(read-only) ⊇ deny(workspace-write) ⊇ deny(danger-full-access)`；
等价地 allow 集单调不减。该映射为单射嵌入（三个 deny 集两两互异）但**非满射**（存在非任何模式 deny 集的子集），故为**保序嵌入而非同构**。

**证明**：能力原语域 9 项 × 模式 3 项全枚举；严格单调链成立；三 deny 集互异；构造非模式 deny 子集（如 {write} 单独）证非满射。✓

**边界**：有限能力域 {read,stat,write,create,delete,rename,staticCall,execute,net}；OS ACL 语义为公理（装置 EXP-5 为经验锚）。

---

### E-6 五态优先级唯一标签（Priority-unique observable label）

**陈述**：observe 是目录结构的全函数，按优先级 done > running > stopping > adopted > orphaned 对任意标记组合输出唯一标签。

**说明**：规范中"任一时刻恰有一个主标记"在实现字面不成立（unlink→rename 存在零标记窗口、done 不被清除、多标记可共存）。**真定理是"优先级决定唯一可观察标签"，不是"唯一文件"**。

**证明**：2⁵ = 32 个标记子集（含空集）穷举（32 由 spec 声明并经子集数自检确认）：observe 全部唯一且等于最高优先级标记；优先级序由 spec 声明并与模型优先级自检一致。✓

**边界**：有限标记集（5 态）。

---

## 附录：复跑方式

```bash
node bmc-checker.mjs             # 全部 6 条（spec 驱动，读 specs/E-*.json）
node bmc-checker.mjs E-4         # 单条（含证伪反例 + 修复版对照）
node bmc-checker.mjs --specs-dir <dir>   # 指定 spec 目录（测试用）
```

每条定理的规约（陈述/前提/公理/装置锚/边界）与**验证参数（`model`：N 范围、actor 脚本、初始状态、断言目标、预期状态空间、deny 集、优先级序）**都在 `specs/E-*.json`。
每台装置的结果与诚实边界在 `E-REPORT.md`。

## 诚实边界（总）

1. 有界穷举（N ≤ 4、有限状态空间）是**组合证明**，不是全称证明；N > 4 与无限域不声称。**N ≤ 4 是人为交付上限，不是计算墙**：`asmfs-audit/probe-n5n6.mjs` 实测 N=5/6/8 完全可行（E-1 N=8 约 942ms、E-2 N=8 约 2ms、E-4fixed N=8 约 3.0s），默认仍以 N≤4 交付以保持与既有装置口径一致；
2. A1/A2（O_EXCL、rename 原子）是操作系统保证的公理，非本模型所证；
3. 抽象模型 ≠ 真实实现：跨进程时序、OS 竞态窗口、平台 ACL 细节不在模型内——差距由装置号（EXP-*/B-*/D-*）锚定；
4. 不声称"证明了实现"——本定理集证明的是抽象模型的组合性质，实现与模型的一致性由装置测试保障。
