# Phase 0.5 装置 —— 审计者信任引导（自举问题）与验收报告

> 立项问题：Phase 0 的审计者是预设密钥。公网上审计者从哪来？若审计者身份免费，
> 攻击者自己造审计者给自己发凭证（自我背书），历史稀缺性崩塌。
> 假设：**审计者资格链（资格 = 持有更早代际凭证）+ 审计留痕（放水可追责）使自我背书不可行、放水可追责。**
> 唯一不可消除的中心化假设：创世锚（诚实标注）。

## 1. 交付物与运行方式

| 文件 | 职责 |
|---|---|
| `phase0.5/bootstrap-forge.mjs` | 自举装置：创世锚 / 凭证代际签发 / 自引用禁止 / 代际链验证 / 审计留痕 / 独立复核抽查 / 放水变体 |
| `phase0.5/experiments/phase05-experiment.mjs` | A-E 五组实验，结构化 JSON 输出 |
| `phase0.5/experiments/phase05-results.json` | 本次实测的结构化结果（实验脚本自动写出） |
| `phase0.5/trails-d/`、`phase0.5/trails-e/` | 审计留痕文件（D/E 实验自动写出） |

运行：`node phase0.5/experiments/phase05-experiment.mjs`（在 dsh-vap/ 下）。

复用 `phase0/history-forge.mjs` 的 `makeTask / solveTask / verifySolution / createAuditors / canonicalJson`
（相对路径 import，不复制代码）。零第三方依赖：仅 node:crypto / node:fs / node:path。

## 2. 核心设计实现（四原语）

### 2.1 创世锚（Genesis Anchor）

- `createGenesisAnchor()` 复用 `createAuditors(1)` 在装置内生成 1 个 Ed25519 审计者，id 固定为
  `genesis-anchor`，标记 `role: 'genesis'`。
- 只签 gen-0 凭证；这是自举的信任种子，是唯一中心化假设（对应创世块、面对面签名的角色）。
- 诚实标注：创世锚密钥每次运行在装置内重新生成一次，其身份 `genesis-anchor` 是约定的锚点。

### 2.2 凭证代际（Credential Generation）

```
gen-0 凭证：由创世锚审计签名
gen-1 凭证：由"持有 ≥1 个 gen-0 凭证的节点"审计签名
gen-k 凭证：由"持有 ≥1 个 gen-(k-1) 凭证的节点"审计签名
```

凭证结构 = phase0 结构 + `{ generation, holder, prior }`（另加派生字段 `credentialId`）：

```
credential = {
  work:     { seed, difficulty },
  solution: hex,
  auditors: [ { id, sig } × n ],       # 签名绑定 generation+holder+work+solution
  generation: int,
  holder:    string,                    # 持有者 id
  prior:     [ { auditorId, credentialId, credential } ] | null,  # 资格证明引用（内嵌全量凭证）
  credentialId: string,                 # 派生 = 核心内容 sha256 前 24 位
  ts, forgedBy
}
```

- **签名对象** = `canonicalJson({ generation, holder, work:{seed,difficulty}, solution })`，
  因此篡改 generation / holder / seed / difficulty / solution 任一字段验签必失败。
- **签发**（`issueCredential`）：
  - `generation=0`：auditors 必须含创世锚（非创世锚无 gen-0 资格，一并拒绝）；
  - `generation≥1`：每个审计者必须出示自己持有的 gen-(generation-1) 凭证，验签 + 重放验证 +
    全链验证（ctx 提供时回验到创世锚）通过才算有资格；缺资格 → 拒绝并给 `reasons`；
  - **自引用禁止**：审计者 id 与持有者 id 相同 → 拒绝（自我背书）。
- **代际链验证**（`verifyCredentialChain(cred, ctx)`）：① 重算 solution ② 审计者互异 ③ 自引用禁止
  ④ generation=0 验创世锚签名 / generation≥1 递归验证每个审计者资格凭证自身链并验签，沿链回验到创世锚。
  `ctx = { genesis: {id, publicKey}, keys: Map<id,publicKey>, credentials: Map<id,credential> }`。
  返回 `{ pass, reasons, chain }`，`chain` 为 DFS 前序，末端即创世锚根。

### 2.3 审计留痕（Audit Trail）

- `signAuditTrail(auditor, cred)` 把 `{ auditorId, credentialId, generation, ts }` 追加到
  `trail-<auditorId>.jsonl`；trail 公开可查（文件即消息）。
- 放水定义：审计者签名了"重放验证不通过"的凭证。

### 2.4 独立复核抽查（Audit Quality Check）

- `auditQuality(trailPath, verifyFn, { sampleRatio, seed })` 用确定性伪随机抽样（mulberry32）抽查
  trail 中的凭证，对每条抽样调用 `verifyFn(entry)` 重放验证，返回
  `{ total, checked, passed, failed, failRate, evidence, sampledCredentialIds }`。
- 放水证据 = 失败凭证（credentialId）+ 签名者 id（auditorId）+ 失败原因。

### 2.5 放水变体

- `forgeLaxSign(qualifiedAuditor, fakeCred)`：模拟合格审计者故意放水——不对 solution 重算即用真私钥
  签名。签名本身验签能过，但 solution 是错的，`verifyCredentialChain` 在重放闸拦截。

## 3. 实验结果（本轮实测）

### A 合法代际链（gen-0..2 + 延伸 gen-3）

创世锚签 gen-0 → gen-0 持有者审计 gen-1 → gen-1 持有者审计 gen-2 → gen-2 持有者审计 gen-3，
**4 张凭证全部验签 + 重放通过**，且每条链都回验到创世锚根：

| 凭证 | 验签+重放 | 回验到创世锚 | 链深（代际序列） |
|---|---|---|---|
| gen-0 | ✅ | ✅ | 1（[0]） |
| gen-1 | ✅ | ✅ | 2（[1,0]） |
| gen-2 | ✅ | ✅ | 3（[2,1,0]） |
| gen-3 | ✅ | ✅ | 4（[3,2,1,0]） |

### B 自我背书攻击（100% 拒）

| 攻击向量 | 尝试 | 拒绝 | 拒绝率 | 拒绝原因 |
|---|---|---|---|---|
| 自造 3 个"审计者"（无凭证）签 gen-1 | 100 | 100 | **100%** | `qualification missing`（资格不足） |
| 审计者 == 持有者（自我背书） | 100 | 100 | **100%** | `self-endorsement forbidden` |

### C 跨代伪造攻击（100% 拒）

| 攻击向量 | 尝试 | 拒绝 | 拒绝率 | 拦截闸 |
|---|---|---|---|---|
| 编造解（假 gen-0 冒充资格） | 100 | 100 | **100%** | 重放闸：`solution fabricated` |
| 伪造签名（真干活但假创世锚签名） | 100 | 100 | **100%** | 验签闸：`genesis signature invalid` |
| 跳代（合法 gen-0 直接签 gen-2） | 100 | 100 | **100%** | 代际闸：`generation 0 != required 1` |

### D 放水攻击与追责（证据链完整）

合格审计者（持合法 gen-0）故意放水签一个解错误的 gen-1 凭证：

- 验证门抓出：`solution recomputation mismatch`（重放失败）；
- trail 留痕可追责：`trail-<auditorId>.jsonl` 记录 `{ auditorId, credentialId, generation, ts }`；
- `auditQuality` 抽查该 trail（sampleRatio=1）→ failRate=1，证据 = `{ auditorId, credentialId, reasons }`；
- **追责证据链完整**：谁签的（审计者 id）、签了什么（credentialId）、验证为何失败（解重算不符）。

### E 独立复核抽查（检出率可度量）

100 张 gen-1 凭证中混入 20 张放水件，复核者抽查 20%（20 张）：

| 指标 | 值 | 含义 |
|---|---|---|
| 抽样数 | 20 | 20% × 100 |
| 样本内放水件 | 4 | 抽样命中的坏凭证 |
| 检出坏凭证 | 4 | 4/4 全部抓出 |
| **检出率（样本内）** | **1.0** | 抽查到的放水件无一漏网 |
| 全集召回（检出/总放水件） | 0.2 | 受 20% 抽样上限约束 |
| **误伤率** | **0** | 好凭证无一被误判（验证是确定性的） |

## 4. 结论判据对照（DESIGN §三）

| 判据 | 结果 |
|---|---|
| 自我背书不可行：B/C 攻击拒绝率 100% | ✅ B 两向量 100% 拒、C 三向量 100% 拒 |
| 放水可追责：D 证据链完整 | ✅ 谁签的 / 签了什么 / 为何失败，三要素齐备 |
| 独立复核抽查有效：E 检出率 > 0 且误伤率可度量 | ✅ 检出率 1.0、误伤率 0 |
| 自举成立：除创世锚外无中心化假设，代际链可延伸 | ✅ 测到 gen-3，全链回验到创世锚 |

**判定：自举成立。** 除创世锚这一诚实标注的信任种子外，其余信任由代际凭证链 + 审计留痕 +
独立复核抽查推导；自我背书与跨代伪造被验证门 100% 拦截，放水可追责。

## 5. 验收标准对照（brief 硬性）

| 验收项 | 结果 |
|---|---|
| A 链成立（gen-0..2 全过）、B/C 拒绝率 100%、D 证据链完整、E 检出率可度量 | ✅ 全部达标 |
| 零第三方依赖 | ✅ 仅 node:crypto / node:fs / node:path 与相对路径 import |
| 凭证验证重算 solution（不信自报） | ✅ `verifyCredentialChain` 第一步重算比对 |
| 审计签名绑定 work+solution+generation+holder | ✅ 签名对象含四者，篡改任一验签失败 |
| 自我背书（审计者=持有者）与跨代伪造（无资格签高职凭证）必拒 | ✅ 100% |
| 代际链验证可回验到创世锚 | ✅ chain 末端即创世锚根 |
| 结构化 JSON 含 bootstrapConclusion 段 | ✅ `bootstrapConclusion.bootstrapHolds=true` |

## 6. 诚实边界（DESIGN §四）

1. **创世锚是中心化起点**（不可消除，只能诚实标注）：所有 gen-0 凭证都回到这一把预设密钥；
   若创世锚自身被攻破或滥签，全链信任随之失效——本装置只诚实标注，不解决创世锚的信任来源。
2. **审计质量抽查是概率性保障，不是完备证明**：E 中全集召回受 20% 抽样上限约束（0.2），
   未抽查到的放水件不在此次覆盖内；抽查是"提高放水被发现的期望成本"，不是"必然发现"。
3. **装置是概念验证，非生产系统**：单机进程内运行；密钥与 trail 文件靠文件系统共享；
   审计者共谋/串通、时间戳信任、网络传播、跨机共享均未纳入本装置范围。
4. **代际深度与信任的映射未定义**：持有 gen-k 凭证能"多可信"、多少代才算可信，尚未定义；
   本装置只证明"资格链可无限延伸 + 伪造必拒"，不给出信任打分函数。
5. **复核者自身的信任同样递归**（复核者的复核者……）：装置内的复核者是预设的，标注为开放问题。
6. **`credentialId` 是内容哈希**（generation+holder+work+solution），不同审计者签同一核心内容会碰撞；
   实验内每个凭证 seed 唯一，碰撞不出现；生产系统需纳入签名者集合或随机 nonce 才能严格唯一。

## 7. 纪律自检

- 零第三方依赖：仅 node:crypto / node:fs / node:path 与相对路径 import，无 package.json、无 node_modules。
- 复用而非复制：`makeTask / solveTask / verifySolution / createAuditors / canonicalJson` 全部 `import` 自 `phase0/history-forge.mjs`。
- 不伪造实验结果：A-E 全部真实跑出，结果写入 `phase05-results.json`；硬性自检失败即非零退出码。
- 坏词清单：交付文件（bootstrap-forge.mjs / phase05-experiment.mjs / 本报告）未出现禁用词。
