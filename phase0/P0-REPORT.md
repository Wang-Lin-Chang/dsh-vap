# Phase 0 装置 —— 伪造成本模型与验收报告

> 立项问题：在否决 PoW/PoS/PoP 后，身份稀缺性还有没有第三条路？
> 假设：**伪造 1000 个裸公钥零成本；伪造 1 个"有可验证历史"的公钥不可行（除非真干活）——历史成本杠杆存在。**
> 本装置只验证此假设；自举问题（谁当审计者）诚实标注为下一阶段缺口。

## 1. 交付物与运行方式

| 文件 | 职责 |
|---|---|
| `phase0/history-forge.mjs` | 铸币机：任务 / 求解 / 重放验证 / 多路独立审计 / 凭证铸造与验证 / 三种伪造变体 |
| `phase0/experiments/phase0-experiment.mjs` | 四组实验（P0-1..P0-4），结构化 JSON 输出 |
| `phase0/experiments/phase0-results.json` | 本次实测的结构化结果（实验脚本自动写出） |

运行：`node phase0/experiments/phase0-experiment.mjs`（在 dsh-vap/ 下）。

## 2. 核心设计实现

### 2.1 可验证任务（sha256 链）

```
h0 = sha256(seed)
h_{i+1} = sha256(h_i || ':' || i)，i = 0 .. difficulty-1
solution = 最终哈希（hex）
```

- **单向**：无法跳过 difficulty 次迭代直接得到解（sha256 原像不可逆）。
- **确定性**：任何人重算得同一解（实测同 seed 两次求解逐字节一致）。
- **实现口径说明**：链式迭代采用 brief 明确写出的 `sha256(prev + ':' + i)`（含冒号分隔）；DESIGN §一的 `h_i || i` 为简写。二者在"内部一致"下等价成立——本装置 solve / verify / 审计三方用同一公式，确定性与重放验证均不受影响。

示例（确定性基准）：`solveTask(makeTask('demo-seed', 5))` = `0ab6f11899990e1638d00cb08aed8687529c9a1482275cc264613c60c6478426`。

### 2.2 凭证三要素与多路独立审计

```
credential = {
  work:     { seed, difficulty },      # 可验证任务
  solution: hex,                        # 唯一正确解
  auditors: [ { id, sig } × 3 ],        # 3 路独立审计签名（各持独立 Ed25519 密钥，互不共享）
  ts:       ISO8601,
  forgedBy: null | { kind }             # 伪造路径留痕（装置内；真实攻击者不会自我标注）
}
```

- **审计**：每个审计者独立重算 solution，通过后才对 `canonicalJson({ work:{seed,difficulty}, solution })` 签名。签名绑定 work+solution——篡改 seed / difficulty / solution 任一字段，验签必失败。
- **验证三道闸**（`verifyCredential`）：
  1. 重算 solution 与凭证一致（不信凭证自带的 solution）；
  2. 逐路验签（对 work+solution 的 Ed25519 签名）；
  3. 审计者互异（id 全不同且非空）。
  三闸全过才返回 true。

## 3. 实验结果（本轮实测）

### P0-1 裸身份基线

1000 个裸 Ed25519 密钥对总耗时 **35.93ms**，单身份 **0.0359ms**（预期 <1ms，达标）。

### P0-2 伪造拦截（必须 100%）

三种伪造各 100 个，合计 300 个伪造件，**拒绝率 100%**（300/300）：

| 伪造类型 | 拦截闸 | 样例拒绝原因 |
|---|---|---|
| randomSolution（编造 solution） | 重算闸 | `solution recomputation mismatch`（且因签名绑定 solution，验签同步失败） |
| fakeSig（伪造审计签名） | 验签闸 | `auditor '…' signature invalid (not bound to work+solution)` |
| duplicateAuditor（审计者重复） | 互异闸 | `auditors not distinct (duplicate or missing auditor id)` |

### P0-3 诚实成本曲线

| difficulty | solve 单次耗时 | 完成 1 凭证耗时（含 3 路审计重算+签名） |
|---|---|---|
| 1000 | 2.78ms | 6.58ms |
| 10000 | 19.95ms | 50.43ms |
| 100000 | 142.95ms | 460.73ms |

成本随 difficulty 线性增长（哈希链 O(difficulty)），稀缺性可由难度参数调节。

### P0-4 杠杆结论

- **C_bare = 0.0359ms**（单裸身份）。
- **C_honest = 6.58ms**（difficulty=1000 的 1 凭证）。
- **杠杆比 C_honest / C_bare ≈ 183**（difficulty=1000 时）。
- **伪造拦截率 = 100%**，确定性自检通过，绑定性自检（篡改 seed/difficulty/solution/sig 任一必被拒）全部通过。

**判定：历史稀缺性杠杆成立。** 身份的价值 = 其可验证历史的深度；稀缺性 = 可调工作成本 + 不可伪造的多路审计链。

## 4. 伪造成本模型（三个量）

| 量 | 定义 | 实测 |
|---|---|---|
| C_bare | 生成 1 个裸身份的耗时 | 0.0359ms（零成本基线） |
| C_forge | 伪造 1 个有历史凭证：跳过工作编造 solution / 伪造审计签名 / 审计者重复 | **不可行**——重放验证 100% 拒绝，唯一出路是真干活 |
| C_honest | 真实完成 1 个凭证：difficulty 次哈希 + 3 路审计 | 6.58ms（difficulty=1000），随难度可调 |

**结论判据**：C_forge 被验证门 100% 拦截，且 C_honest 可调（difficulty 1000/10000/100000 递增），故"历史稀缺性杠杆"成立。

## 5. 验收标准对照

| 验收项 | 结果 |
|---|---|
| 实验跑通，P0-2 拒绝率 100% | ✅ 300/300 全拒 |
| 零第三方依赖 | ✅ 仅 node:crypto / node:fs / node:path 与相对路径 import |
| 确定性（同 seed 同解） | ✅ 独立两次求解逐字节一致 |
| 验证重算 solution（不信自报） | ✅ `verifyCredential` 第一步即重算比对 |
| 审计签名绑定 work+solution | ✅ 篡改 seed/difficulty/solution/sig 任一，验签/重算必失败 |
| 输出结构化 JSON 且含 costModel 结论段 | ✅ `P0_4.costModel` 含 C_bare/C_forge/C_honest + conclusion |

## 6. 诚实边界（Phase 0 之后的缺口）

1. **自举问题未解决**：审计者自身身份如何建立。装置内 3 个审计者密钥是预设的（`createAuditors` 当场生成并注入验证方）；"谁有资格当审计者、审计者如何被信任"是 Phase 0 之后的最大缺口。
2. **难度↔信任映射未定义**：难度可调 = 工作成本可调 = 稀缺性可调，但"历史深度"与"信任"的映射（多少凭证、多深历史才算可信）尚未定义。
3. **概念验证，非生产系统**：单机进程内运行；审计者密钥传递、跨机共享、审计者共谋/串通、重放与时间戳信任等均未纳入本装置范围。
4. **C_honest 含审计重算**：本装置审计者各自重算 solution（O(difficulty)），故 1 凭证总成本 ≈ (1 + 审计者数) 次求解 + 审计签名；这与 DESIGN"各自重算再签名"一致，代价是诚实成本随审计者数线性放大（换取不可伪造性）。
