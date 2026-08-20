# Phase 6 装置 —— 动态成员 + 军法上链（VAP-TO 扩展）验收报告

> 立项问题：Phase 5 的 roster 是静态 4 节点；本阶段让成员可进出、密钥可轮换、军法成为共识级规则。
> 复用（零改动，只 import）：`phase5/vap-to.mjs`（锁步 QC 链内核）、`vap-core.mjs`（canonicalJson / makeLaws）、
> `phase3/endorse-core.mjs`（collectQC / detectDoubleSign / verifyDoubleSignEvidence / quorumThreshold）、
> `phase0.5/bootstrap-forge.mjs`（verifyCredentialChain / credentialIdOf）。
> 诚实正名：动态成员 / 军法谓词 / h+2 调度是**全新未测代码**，本阶段实验是第一次验证；公网灰度是清单不是实测。

## 0. 设计裁决（从 DESIGN.md 抄录）

1. 成员变更走窄车道 `type=membership`，提交于高度 h → **h+2 生效**（roster 切换、f 重算 `f=floor((n-1)/3)`）。
2. equivocation 双签证据 = 密码学铁证：slash 交易上链 → 作恶者签名**从提交高度起立即不计入**，roster 表变更延迟 2 块。
3. 军法（laws）作为投票前谓词：不满足的信封提案 0 票（诚实节点拒投），不进 QC。
4. 复用零改动：4 个复用模块均只 import，不修改文件。

## 1. 交付物与运行方式

| 文件 | 职责 |
|---|---|
| `phase6/vap-to-membership.mjs` | `createMembershipNode`（proposeJoin / endorseJoin / rotateKey / expelByEquivocation / detectEquivocation / wrapEnvelope / checkLaws / checkMembershipTx / applyMembership / applyDueChanges + 实例级 safetyRule / submitTx / commitBlock / propose / vote / signProposal 扩展） |
| `phase6/tests/membership.test.mjs` | node:test 单测 7 条 |
| `phase6/experiments/phase6-experiment.mjs` | D1-D5 实验，结构化 JSON（stdout + `phase6-results.json`） |
| `phase6/DEPLOYMENT.md` | D6 公网灰度部署清单（诚实标注未实测） |
| `phase6/P6-REPORT.md` | 本报告 |

运行（在 dsh-vap/ 下）：

```
node --test                                      # 全绿：106 条（含本阶段 7 条）
node phase6/experiments/phase6-experiment.mjs    # D1-D5 + 结构化 JSON + 硬性自检（退出码 0）
```

## 2. 核心设计实现

### 2.1 动态 roster（复用 phase5 实例，不改文件）

- `createMembershipNode` 内部调用 phase5 `createNode`，在返回实例上扩展成员变更与军法谓词。
- 动态 roster 复用 phase5 的 `node.roster`（成员表数组）+ `node.expelled`（立即除名集）；`activeRoster()` 过滤 expelled。
- `leaderOf` 用 roster 表（延迟期内被除名者仍在表内，其提案会被安全规则拒，靠视图切换跳过）。
- 每次 roster 表变更重算 `n / f / threshold`。

### 2.2 成员变更（窄车道 type=membership）

- `proposeJoin`：资格凭证回验（`verifyCredentialChain`）→ 打包 join 交易（含 `selfSig` 证明 pubKey 归属）。
- `endorseJoin`：现有成员回验资格凭证 + selfSig + 未重复后签名背书；投票前谓词要求 2/3 背书（`quorumThreshold(n)`）。
- `rotateKey`：旧钥签变更交易 → h+2 新钥生效（生效时换 peerMap 与本节点私钥）。
- `expelByEquivocation`：验证双签证据 → 打包 slash 交易；commitBlock 提交 slash 时立即 `expelled.add`，h+2 掉表。
- `detectEquivocation`：复用 phase3 `detectDoubleSign` 只产证据（不立即除名，除名走 slash 上链）。

### 2.3 军法上链（laws as consensus predicates）

- `checkLaws(subject)`：对信封形态 subject 逐条判定（SIG_REQUIRED / BOUNDARY_VALID / SUMMARY_BOUND / EVIDENCE_L2A / FROM_KNOWN + NO_EQUIVOCATION），reject 级失败 → 投票前拒。
- `checkMembershipTx(tx)`：membership 交易的投票前谓词（no-equivocation + op 专属：join 资格/背书、rotate 旧钥、slash 证据、expel 自签、report 信封军法）。
- `wrapEnvelope`：把信封包成 `op=report` 窄车道交易，接受军法投票前裁决（invalid 信封 0 票）。

### 2.4 延迟生效（h+2）

- commitBlock 提交 membership 交易时 `scheduleMembership(tx, height)`，`activateHeight = height + 2`。
- `applyDueChanges`：`committedHeight >= activateHeight` 时落 roster 并重算 f / threshold。
- 除名特殊：slash/expel 提交瞬间 `expelled.add`（签名立即不计入），roster 表变更仍在 h+2。

### 2.5 密钥轮换后的签名入口

- phase5 的 `propose/vote/signProposal` 内部用构造期闭包私钥（不可替换），故在实例层用可替换的 `node.privateKey` 重实现这三个签名入口，使轮换后本节点用新钥签名。

## 3. 实验结果（本轮实测）

装置：n=4 起，f=floor((n-1)/3)，QC 门槛 2f+1，commit 规则 HotStuff 3-chain。

| 实验 | 结果 | 判据 |
|---|---|---|
| **D1 加入生效** | 资格凭证 + 3/4 背书 → join 提交 → h+2 后 roster=5（f=1, threshold=3）→ 新节点 n5 上链后与原有节点提交前缀一致、5 节点继续推进 | `rosterAfter=5` `n5Agrees=true` `fiveNodeConsensusAdvanced=true` |
| **D2 除名生效** | n4 双签 → 证据（第三方可验）→ slash 上链 → 签名立即不计入（n1+n2+n4 只剩 2 <3）→ h+2 后 roster=3（f=0, threshold=1）→ 3 节点继续推进 | `expelledImmediately=true` `signatureExcludedImmediately=true` `rosterAfter=3` |
| **D3 密钥轮换** | 旧钥签变更交易 → h+2 新钥生效 → 旧钥签名被拒、新钥签名有效 | `newKeyActive=true` `oldKeyRejected=true` `newKeyAccepted=true` |
| **D4 军法上链** | invalid 信封（summary 120 >100）→ 投票前 0 票不进 QC；同一背书者 equivocation → slash 证据上链 → 自动除名 + h+2 掉表 | `invalidEnvelopeZeroVotes=true` `slashCommitted=true` `autoExpelled=true` |
| **D5 延迟窗口** | join 提交后、生效前旧 roster 照常推进（窗口块 4 票成 QC，无中断），随后切 5 继续推进 | `windowVotes=4` `windowQc=true` `rosterAfterWindow=5` |

**结论：D1-D5 全部达标，`conclusion.allPass=true`，退出码 0。**

## 4. 验收标准对照（DESIGN §五 / brief §验收）

| 验收项 | 结果 |
|---|---|
| D1-D5 全达标 | ✅ 结构化 JSON `allPass=true` |
| 零第三方依赖 | ✅ 仅 node: 内置模块与相对路径 import |
| 复用模块零改动 | ✅ 未修改 vap-core / phase3 / phase0.5 / phase5（只 import） |
| 除名后签名立即不计入（延迟只作用于 roster 表） | ✅ 单测 + D2（slash 提交瞬间 expelled，roster 掉表在 h+2） |
| 军法投票前拒（0 票有测试） | ✅ 单测 `laws as vote-before predicate` + `join with insufficient endorsement` + D4 |
| 延迟窗口无中断推进（有测试） | ✅ 单测 `delay window advances without interruption` + D5 |
| 结构化 JSON + 灰度清单文档 | ✅ `phase6-results.json` + `DEPLOYMENT.md`（诚实标注未实测） |

## 5. 诚实边界

1. **公网灰度是清单不是实测**：DEPLOYMENT.md 全部 [未实测]；跨机延迟/丢包/分区行为未验证。
2. **动态成员在大网络未覆盖**：reconfiguration 风暴、双 roster 过渡未处理——小规模信任域简化版。
3. **军法只上链"可判定"部分**：模糊部分（诚实边界的主观判断）留审计层，不进共识。
4. **部分同步假设**：完全异步 + 拜占庭 leader 可能活锁（异步 BA 是后续题）。
5. **≥f+1 共谋**：BFT 数学边界，只能检测不能阻止。
6. **restore 不回放成员变更**：本阶段账本恢复（phase5 `restore`）回放已提交前缀，但不重建动态 roster / membership nonce（实验走内存态，未跨重启回放成员历史）。
7. **延迟生效定义**：变更交易提交于高度 h → 其所在块(h)与后一块(h+1)仍按旧 roster 推进（共 2 块窗口），第 h+2 块起用新 roster（与 DESIGN "h+2 生效" 一致）。

## 6. 纪律自检

- 零第三方依赖：无 package.json、无 node_modules。
- 复用而非复制：canonicalJson/makeLaws（vap-core）、collectQC/detectDoubleSign/verifyDoubleSignEvidence/quorumThreshold（phase3）、verifyCredentialChain/credentialIdOf（phase0.5）、createNode/leaderOf/hashBlock/GENESIS_HASH（phase5）全部 import 复用，零改动。
- 不伪造实验结果：D1-D5 真实跑出，硬性自检失败即非零退出码（实测退出码 0）。
- 坏词清单：交付文件未出现禁用词。
- 信封军法谓词的 SIG_REQUIRED 在共识层以本地 `verifyEnvelopeSig`（同 vap-core 展平签名对象语义）重实现，未改 vap-core。
