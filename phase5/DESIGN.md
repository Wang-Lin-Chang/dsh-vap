# VAP Phase 5 设计：锁步 QC 链共识内核（VAP-TO）

> 多路独立推演 + 复核后的收敛裁决。三个锁定：
> ① commit 规则 = HotStuff 标准 3-chain（B 有 QC 且子、孙各有 QC → 提交 B）——安全优先，最保守；
> ② 分车道：窄车道（资格凭证/惩罚证据，需总序防双花）走共识；默认车道（报告/任务，幂等）走既有去重+因果序；
> ③ 门限签名不引入——QC = 2f+1 个个体签名集合（零依赖默认未被数据打破）。
> 诚实正名：锁步提交/视图切换/equivocation 检测是**全新未测代码**，本阶段的实验是第一次验证——不冒认"已实测"。

## 一、内核组件

1. **轮次状态机**：view v 单调递增；leader = v mod N；每轮 propose → vote → QC → 3-chain 判定 commit；
2. **QC 链**：QC = { view, parentHash, blockHash, sigs: 2f+1 个个体签名 }；父指针成链；
3. **3-chain 提交**：B 有 QC、B 的子有 QC、B 的孙有 QC → 提交 B（HotStuff 标准）；
4. **安全规则**：只对扩展本地最高 QC 的提案投票；
5. **视图切换**：超时（本地单调时钟）→ v+1 → 新 leader，携带本地最高 QC（防安全倒退）；
6. **equivocation 检测**：同 (view, leader) 两个冲突提案 → 双签证据（两签名+两内容，密码学铁证）→ **自动除名**（可验证，军法闸自动触发）；
7. **分车道**：信封 type=commit 走总序；其余走既有 nonce 去重（默认车道不受共识影响）；
8. **账本**：append-only 哈希链落盘，重启恢复。

## 二、实验（experiments/phase5-experiment.mjs，n=4 f=1）

- **T1 正常收敛**：4 节点连续 10 轮 → 全节点提交前缀逐字节一致；
- **T2 崩溃容错**：kill 当前 leader → 视图切换 → 新 leader 在超时后提交，已提交前缀不回滚；
- **T3 分叉注入**：拜占庭 leader 对 2 节点发 P1、对 2 节点发 P2 → 至多一支 commit + equivocation 证据产出 + 作恶者自动除名；
- **T4 双花拒绝**：同 nonce 两交易 → 第二笔被安全规则拒绝；
- **T5 确定性重放**：同输入脚本跑两次 → 账本逐字节一致；
- **T6 重启恢复**：杀进程重启 → 从磁盘恢复已提交前缀继续推进。

## 三、交付物

1. `dsh-vap/phase5/vap-to.mjs`——锁步 QC 链内核（零第三方依赖，复用 vap-core 信封/三闸/nonce、phase3 QC 验签）；
2. `dsh-vap/phase5/tests/vap-to.test.mjs`——状态机/安全规则/3-chain/视图切换/equivocation 单测；
3. `dsh-vap/phase5/experiments/phase5-experiment.mjs`——T1-T6；
4. `dsh-vap/phase5/P5-REPORT.md`——含多路独立推演结论与复核裁决记录。

## 四、验收标准

1. T1-T6 全达标；2. 零第三方依赖；3. 复用模块零改动；
4. 3-chain 提交规则有单测钉死（2 链不提交、3 链才提交）；
5. equivocation 自动除名（除名后其签名不再被计入 QC）；
6. 双花在投票前被拒（不进 QC）；7. 结构化 JSON。

## 五、诚实边界

- 部分同步假设：信任域场景适用；完全异步+拜占庭 leader 可能活锁（异步 BA 是后续，本阶段不做）；
- 静态 4 节点 roster（动态成员是 Phase 6）；
- 无流水线/批量（吞吐 ≈ RTT×轮次，性能债显式标注）；
- ≥f+1 共谋可破安全（BFT 数学边界），只能检测不能阻止；
- 本机多进程模拟，跨机部署待 Phase 6 公网灰度。
