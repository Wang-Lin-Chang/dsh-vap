# Phase 3 装置 —— 分布式 2/3 背书（信任聚合）验收报告

> 立项问题：把单点 2/3 门限签名升级为真正的分布式多节点背书（Quorum Certificate, QC）。
> 衔接：背书者资格复用 Phase 0.5 凭证代际链；信封与三闸复用 vap-core 零改动。
> 正名：单点门限签名 ≠ 分布式背书——本阶段交付的是分布式多节点背书，不冒认。

## 1. 交付物与运行方式

| 文件 | 职责 |
|---|---|
| `phase3/endorse-core.mjs` | `endorse` / `collectQC` / `verifyQC` / `detectDoubleSign` / `verifyDoubleSignEvidence` / `quorumThreshold` |
| `phase3/tests/endorse-core.test.mjs` | node:test 单测（13 条，gateVerify 注入真实 vap-core verify） |
| `phase3/experiments/phase3-experiment.mjs` | E1-E6 六组实验，结构化 JSON 输出 |
| `phase3/experiments/phase3-results.json` | 本次实测的结构化结果（实验脚本自动写出） |

运行（在 dsh-vap/ 下）：

```
node --test                                  # 全绿：73 条（含本阶段 13 条）
node phase3/experiments/phase3-experiment.mjs  # E1-E6 + 结构化 JSON + 硬性自检
```

## 2. 核心设计实现

### 2.1 背书协议三件套

```
Envelope（vap-core 既有）→ 过三闸（验证门先行）
Endorsement = { nodeId, pubKey, sig }   # sig = Ed25519(私钥, canonicalJson(envelope))
QuorumCertificate(QC) = { envelope, endorsements:[...], rosterSize, threshold: ceil(2n/3) }
```

### 2.2 endorse —— 外部有效性谓词 + 资格门 + 签名

- **外部有效性谓词**：先跑 `gateVerify`（注入 vap-core 的真实 `verify`，三道闸真实重放）。不过三闸 → 返回 `{ refused: true, reason, gateResult }`，拒绝背书并留痕。
- **资格门**：背书者必须持有资格凭证（`endorser.credential`）。无凭证 → 抛错（诚实路径拒绝无资格者）。
- **签名**：对 `canonicalJson(envelope)` 用 Ed25519 签名（与 vap-core 的信封验签相互独立，背书绑定整封信封）。

### 2.3 collectQC —— 聚合（去重 + 逐签验签 + 数量）

- 按 nodeId 去重（保留首个）；逐签验签（对 roster 权威公钥，防密钥替换）；有效背书数 ≥ threshold。
- 达标 → `{ ok: true, qc }`；不足 → `{ ok: false, reasons }`（诚实停摆）。

### 2.4 verifyQC —— 五闸全量验证

1. 每个背书签名有效（对 roster 权威公钥验签）；
2. 签名者互异；
3. 有效背书数 ≥ `ceil(2n/3)`（n 按 roster 重新推算，不信 QC 自报的 threshold）；
4. 信封过三闸（`gateVerify` 注入 vap-core 的 `verify`，真实调用，不 mock，不信任背书者声称）；
5. 资格链验证（每个背书者的资格凭证沿代际链回验到创世锚，复用 phase0.5 `verifyCredentialChain`）。

返回 `{ pass, reasons, detail }`。

### 2.5 detectDoubleSign —— 双签冲突证据

- 同一 nodeId 对同一 envelopeId 的**不同内容**签名 → 冲突证据 `{ nodeId, envelopeId, pubKey, sigA, sigB, contentA, contentB }`。
- `verifyDoubleSignEvidence(evidence)`：第三方仅凭公钥即可验 `contentA ≠ contentB` 且两签名均有效——冲突自证，无需信任任何声称。

## 3. 实验结果（本轮实测）

装置：创世锚（phase0.5）+ 4 个持 gen-0 凭证的合格背书者（n1..n4），rosterSize=4，threshold=ceil(8/3)=3，f=floor(3/3)=1。

| 实验 | 结果 | 判据 |
|---|---|---|
| **E1 正常背书** | QC 成立（3/4 签，verifyQC pass） | `qcHolds=true` |
| **E2 拜占庭拒签** | 1 节点拒签，剩余 3 签 ≥3，QC 仍成立（f=1 容错） | `quorumHeldDespiteRefusal=true` |
| **E3 伪造背书** | 伪造签名被 collectQC 丢弃（3 真签名保留）；塞进 QC 后 verifyQC 拒绝 | `forgedRejected=true` |
| **E4 双签检测** | 1 节点对同 id 不同内容双签 → 1 条冲突证据，第三方可验 | `evidenceVerifiable=true` |
| **E5 资格不足** | 无 gen 凭证节点 endorse 抛错；手工签名塞入后 verifyQC 不计入（effective=2<3）诚实失败 | `unqualifiedNotCounted=true` |
| **E6 外部有效性** | 伪签名信封 → 4 个合格背书者全部拒签 → 拿不到 2/3（verifyQC ④ 三闸重放拦截） | `noQuorum=true` |

**结论：E1-E6 全部达标，`endorseConclusion.allPass=true`。**

## 4. 验收标准对照（DESIGN §六）

| 验收项 | 结果 |
|---|---|
| E1 QC 成立、E2 f=1 容错、E3 拒绝、E4 证据可验、E5 不计入、E6 拿不到 2/3 | ✅ 六实验全达标 |
| 零第三方依赖 | ✅ 仅 node:crypto / node:fs / node:os / node:path 与相对路径 import |
| vap-core / phase0.5 零改动（只 import 复用） | ✅ 未修改 `../vap-core.mjs`、`../phase0.5/bootstrap-forge.mjs`、`../phase0/history-forge.mjs` |
| QC 验证重放三闸（不信任背书者声称） | ✅ `verifyQC` ④ 调用注入的 vap-core `verify`，真实三闸；单测含"④ 三闸重放拒绝"用例 |
| 双签证据任何第三方可验 | ✅ `verifyDoubleSignEvidence` 仅凭公钥验 `contentA≠contentB` + 两签有效 |
| 结构化 JSON 输出 | ✅ stdout + `phase3-results.json`（含 endorseConclusion 段） |

## 5. 诚实边界（DESIGN §七）

1. roster 是静态的（装置内预设 4 节点）——动态成员是 Phase 6 的题。
2. 背书者资格链的 gen-k 深度与 roster 的对应关系（多少 gen 算合格）装置内固定（k=0 起），公网参数未定。
3. 网络层（P2P 洪泛背书请求）在装置内以内存调用模拟——真实 UDP 洪泛背书是 Phase 4 的题。
4. QC 不产总序（两个 QC 可并存分叉）——共识是 Phase 5 的题，本阶段只有"认可"，没有"排序"。
5. `>2n/3` 恶意时系统无法区分（诚实标注：不是防，是数学边界）。

## 6. 纪律自检

- 零第三方依赖：仅 node: 内置模块与相对路径 import，无任何 npm 依赖。
- 复用而非复制：`canonicalJson` 自 vap-core、`verifyCredentialChain` 自 phase0.5、`makeTask` 自 phase0，全部 import 复用，零改动。
- 不伪造实验结果：E1-E6 真实跑出，硬性自检失败即非零退出码（实测退出码 0）。
- 坏词清单：交付文件（endorse-core.mjs / endorse-core.test.mjs / phase3-experiment.mjs / P3-REPORT.md / progress-phase3.md）未出现禁用词。
- E4 的"同 id 不同内容"信封夹具在实验脚本内镜像 vap-core §1 签名对象构造，并用 `gateVerify(envB).pass` 自验正确性——不修改 vap-core，仅装置内夹具代码。
