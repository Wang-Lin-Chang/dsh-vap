# ASM-FS 有界模型检查器 验收报告

> 生成方式：`node bmc-checker.mjs` 实跑结果（spec 驱动：每个定理的参数/断言/预期状态空间取自 `specs/E-*.json` 的 `model` 字段并运行时自检）。
> 结论：6/6 定理通过（E-4 按证伪优先纪律：先输出可重放反例，再给出修复版全绿）。

## 总览

| 定理 | 结果 | 边界声明（有界穷举） |
|---|---|---|
| E-1 恰一终态 | PASS | N ∈ {2,3,4}，每进程 2 步 |
| E-2 收养互斥 | PASS | N ∈ {2,3,4}，每进程 1 步 |
| E-3 三证据健全性 | PASS | 36 例域枚举（pid × startSec × alive × liveSec = 3×3×2×2）+ 三分支 + N ∈ {2,3,4} 并发全拒绝 |
| E-4 事件 seq 唯一（证伪优先） | PASS（先反例后修复） | 证伪 N=2；修复 N ∈ {2,3,4} |
| E-5 能力格保序嵌入 | PASS | 9 原语 × 3 模式全枚举 |
| E-6 五态优先级唯一标签 | PASS | 2^5 = 32 个标记子集（含空集）穷举 |

## 逐条结果

### E-1 恰一终态

- 断言：任意交错下 done 标记恰写一次、退出码单值不覆盖；幂等第二次 finalize 一律 no-op。
- 结果：N=2/3/4 全交错穷举全绿。
- 反例：无。
- 边界：N ∈ {2,3,4}，每进程脚本长度 2；状态空间有限。

### E-2 收养互斥

- 断言：N 并发 adopt 同一孤儿，恰一赢家，终态 adopted 且锁唯一。
- 结果：N=2/3/4 全交错穷举全绿。
- 反例：无。
- 边界：N ∈ {2,3,4}，每进程脚本长度 1。

### E-3 三证据健全性

- 断言：(1) liveness 三分全函数（36 例域枚举 = pid × startSec × alive × liveSec，⊥ 退化为二证据）；(2) 三分支映射 alive=>owner-alive、dead=>win、pid_reused=>reject；(3) 复用态 N 并发 adopter 全拒绝。
- 结果：全绿。
- 反例：无。
- 边界：pid ∈ {0,1,2}，startSec ∈ {⊥,100,200}，alive ∈ {false,true}，liveSec ∈ {100,200}，复用态 N ∈ {2,3,4}。

### E-4 事件 seq 唯一（证伪优先）

- 证伪阶段（朴素模型 seq=length+1 两步非原子，N=2）：
  - **反例（可重放）**：`[A.readSeq → B.readSeq → A.writeEvent(ev-0) → B.writeEvent(ev-1)]`，
    两事件 seq 均为 1，冲突 `[1,1]`。replay 复现 `seq=[1,1]`，复检一致。
- 修复阶段（单步原子追加）：N=2/3/4 全交错全绿，seq 严格唯一。
- 边界：证伪 N=2；修复 N ∈ {2,3,4}；事件数 ≤ 4。

### E-5 能力格保序嵌入

- 断言：read-only ≤ workspace-write ≤ danger-full-access 下 deny 集严格单调不增
  （deny(read-only) ⊇ deny(workspace-write) ⊇ deny(danger-full-access)）；嵌入单射非满射（非同构）。
- 结果：全绿。
- 边界：能力原语域 9 项 × 模式 3 项全枚举。

### E-6 五态优先级唯一标签

- 断言：observe 优先级（done>running>stopping>adopted>orphaned）对 32 个子集 + 空集输出唯一标签；
  多标记共存仍唯一（修正“恰一主标记”虚假不变量）。
- 结果：全绿。
- 边界：2^5 = 32 个标记子集（含空集）穷举。

## spec 驱动与负控制（V1 修复记录）

- 检查器启动时 `fs.readFileSync` 按 `E-1..E-6` 顺序读取 `specs/*.json`；每个 spec 的 `model` 字段是该定理验证的**唯一参数来源**（`nRange`、actor 脚本模板、`initial` 初始态、`assertion` 断言目标、`expected` 预期状态空间大小、`denyOf` deny 集、`priority` 优先级序等）。
- 缺失 spec / 非法 JSON / id 不符 / 缺 `model` ⇒ 明确报错并退出码 2（不再 6/6 空跑自证）。
- 改坏 spec 断言/参数 ⇒ 对应定理 FAIL（退出码 1）。负控制实测：

| 变异 | 结果 |
|---|---|
| E-1 `model.expected.nodes` 217→999 | E-1 FAIL：状态空间自检 `实跑 217 ≠ spec 预期 999` |
| E-1 `model.assertion.doneWinsTarget` 1→2 | E-1 FAIL：`终态 doneWins=1（应为 2）` |
| E-6 `model.priority` 重排 | E-6 FAIL：`优先级自检 … 一致 = FAIL` |
| E-4 `model.naive.expectedConflictSeq` [1,1]→[2,2] | E-4 FAIL：`反例 seq 自检：实跑 [1,1] 与 spec 预期 [2,2] = 不一致` |
| E-5 `model.denyOf` 破坏严格单调 | E-5 FAIL：`保序链 … = false` + `逐原语单调性 FAIL` |

## N≤4 是人为上限（诚实记录）

`asmfs-audit/probe-n5n6.mjs` 实测（同一模型仅上推 N，本机 node v25.8.1）：

| 模型 | N=5 | N=6 | N=8 |
|---|---|---|---|
| E-1（每进程 2 步 finalize） | 811 态 / 14.6ms | 2917 态 / 68.0ms | 34993 态 / 942ms |
| E-2（每进程 1 步 adopt） | 81 态 / 0.35ms | 193 态 / 0.30ms | 1025 态 / 2.0ms |
| E-4fixed（每进程 1 步 event） | 326 态 / 0.69ms | 1957 态 / 4.1ms | 109601 态 / 3044ms |

结论：**N≤4 是人为交付上限，非计算墙；N=5/6/8 实测完全可行**（所有 N 均 found=false，性质在更大 N 下仍成立）。默认交付仍维持 N≤4 边界以保持与既有文档/装置的对照口径；如需上推，改 spec 的 `model.nRange` 与 `model.expected` 即可，检查器会自检新 N 的状态空间（改错 `expected` 会立即 FAIL，见上表负控制）。

## 诚实边界（写死）

1. **有界穷举 ≠ 全称证明**：所有结论限于标注的有限域（N ≤ 4、状态空间有限、有限原语域），不构成对任意 N 或无限域的证明。
2. **公理边界**：O_EXCL 独占创建、tmp+rename 原子重命名、进程存活查询为**公理**（OS 保证，代码外假设），不在模型内证明；模型只证其上的组合性质。
3. **模型-实现差距**：OS 竞态窗口、ACL 细节、跨进程语义不在模型内；差距本身标注装置锚（EXP-3/B-01、EXP-2/B-04、L383-385、EXP-5、L222-231）。
4. **不冒认“证明了实现”**：本报告只证抽象模型的组合性质，不对任何具体实现的可执行正确性作全称断言。

## 复现

```bash
node bmc-checker.mjs                 # 全部 6 条（人话 + 结构化 JSON；spec 驱动）
node bmc-checker.mjs E-4             # 单条
node bmc-checker.mjs --json          # 纯 JSON
node bmc-checker.mjs --specs-dir <dir>   # 指定 spec 目录（测试/负控制用）
```
