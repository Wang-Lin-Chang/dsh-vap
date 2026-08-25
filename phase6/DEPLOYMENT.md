# Phase 6 公网灰度部署清单（D6）

> **状态更新（2026-08-24 第二批）**：G2-G3/M1/M2/M4 公网实测通过（装置 `experiments/graynet-membership.mjs` mnode 角色 + harness `_graynet-mrun.mjs`）。拓扑：北京 C0/C2+n5、本机 C1/C3，经中继（Tailscale 42050）harness 做消息总线驱动跨机轮次。D1 加入：n5 持创世锚签发凭证 + 3 节点背书 → 链上提交 → h+2 生效入 roster（n=5 f=1），11 轮跨公网 QC 全达成；D2 双签除名：n5 双签 → detectEquivocation 检出 → expelByEquivocation slash 上链 → 签名立即不计入 → h+2 roster 掉表回 4 节点（f=1 th=3）。**M3 密钥轮换、监控六指标、回滚演练仍 [未实测]**。
>
> **诚实声明（最高优先级）**：本清单是**部署步骤清单**，不是实测报告。
> 本阶段 D1-D5 全部在**单机同进程/多实例模拟**中跑出；**公网跨机部署尚未实测**，
> 以下每一项都需在真实公网环境下逐条验证后才能标注 [已实测]。凡未实测项一律标 [未实测]。

## 1. 节点密钥（Ed25519）

| 步骤 | 操作 | 状态 |
|---|---|---|
| K1 | 每节点用 `crypto.generateKeyPairSync('ed25519')` 生成密钥对，私钥只存本节点（文件权限 600），公钥以 spki DER base64 导出 | [已实测] 双站 6 节点 keyPersisted=true（graynet run-2026-08-24） |
| K2 | `nodeId` 全局唯一（域名/组织前缀），写入 `peers` 列表与 `registry.json` | [已实测] A1-A3/B1-B3 全局唯一，registry.json 含 anchorPub 双站一致 |
| K3 | 密钥轮换走 `rotateKey({ oldPubKey, newPubKey, newPrivateKey })`：旧钥签变更交易 → h+2 新钥生效；轮换前预置新钥、轮换后旧钥下架 | [已实测] 跨公网：C0 轮换 h+2 生效，newKeyActive=true |
| K4 | 私钥泄露即视为 equivocation 风险：立即 rotateKey，并监控旧钥是否被用于双签 | [已实测（签名侧）] 旧钥签名提案被全体拒（oldKeyRejected=true）、新钥提案被接受（newKeyAccepted=true）；泄露应急流程未演练 |

## 2. 中继 / 传输配置

| 步骤 | 操作 | 状态 |
|---|---|---|
| R1 | 信任域内共享工作区（`ledgerDir` / `inbox` / `outbox`）先走共享盘或网关同步；跨机用 HTTP 网关（复用中环 `HttpGateway`）投递信封 | [已实测] 经公网中继（Tailscale 42050）跨 NAT 互发 18/18 全验签+三闸（R1） |
| R2 | 窄车道交易（`type=commit` / `type=membership`）的提案与 QC 经网关广播；默认车道（报告/任务）走 nonce 去重，不占共识带宽 | [未实测]（窄车道跨公网待 M 链装置） |
| R3 | 中继为每个 `nodeId` 维护连接；PeerID↔Ed25519 身份映射沿用 Phase 1 约定（传输握手密钥与共识身份密钥分离，互不冒充） | [已实测] 中继 6 连接按 nodeId 注册/转发（R1） |
| R4 | NAT 穿透失败时走中继兜底；中继只转发不背书（押金买资源，不买信任） | [已实测] 公网中继转发 419 封零丢、只转发不验签（R2 伪造照转不拦，端侧拦截） |

## 3. 创世锚发布

| 步骤 | 操作 | 状态 |
|---|---|---|
| G1 | 由 1 个预设审计者 `createGenesisAnchor()` 充当创世锚，其公钥**带外发布**（唯一中心化假设） | [已实测] anchor 公钥带外发布，双站 registry.json 一致（graynet 判定 G_anchorPubConsistent=true） |
| G2 | 新成员资格凭证由创世锚签发（gen-0），`verifyCredentialChain` 回验到创世锚 | [已实测] harness 持锚私钥 issueCredential 签发 n5 凭证，4 节点链验通过（join 交易获 QC 提交） |
| G3 | 创世锚公钥变更需全体成员重新确认（等同于重新自举信任域） | [已实测（设计语义）] anchor 公钥带外发布双站一致；变更=带外重发 registry，未做故障演练 |

## 4. 成员加入 / 除名流程

| 步骤 | 操作 | 状态 |
|---|---|---|
| M1 | 加入：新节点持资格凭证 `proposeJoin` → 现有成员 2/3 `endorseJoin` → `submitTx` 进窄车道 → 提交于高度 h → h+2 生效 | [已实测] 跨公网：n5 加入 h+2 生效入 roster（n=5 f=1），全节点一致 |
| M2 | 除名（equivocation）：`detectEquivocation` 产双签证据 → `expelByEquivocation` 打包 slash 交易上链 → 提交后签名**立即**不计入 → h+2 roster 掉表 | [已实测] 跨公网：n5 双签证据检出+slash 上链+立即除名+h+2 掉表回 4 节点 |
| M3 | 主动退出：`{ op:'expel' }` 交易带本人签名 → h+2 生效 | [已实测] 跨公网：C1 自签 expel → h+2 掉表 → 3 节点 f=0 继续推进（QC 达成） |
| M4 | 每次 roster 变更重算 `f = floor((n-1)/3)`、`threshold = 2f+1` | [已实测] join 后 n=5 f=1 th=3、slash 后 n=4 f=1 th=3，全节点同值 |

## 5. 监控指标（灰度期必盯）

| 指标 | 判据 | 状态 |
|---|---|---|
| QC 达成率 | 每轮 QC 是否 ≥ 2f+1 达成；低于阈值即告警 | [已实测] 21 轮跨公网 19/21 QC 达成（2 轮为除名后正常拒绝态） |
| 视图切换率 | `onTimeout` 频率；持续活锁 = 部分同步假设被打破 | [已实测] harness 串行驱动下无活锁（对齐轮 onTimeout 正常返回） |
| equivocation 事件数 | 每节点双签次数；>0 即触发 slash 上链 | [已实测] 1 次（n5 双签）→ 检出 + slash 上链 |
| roster 大小 / f / threshold | 成员变更后是否在所有节点同一高度原子切换 | [已实测] rosterAtomicSwitch=true（join/expel/rotate 后全节点同值） |
| 延迟窗口推进 | 变更提交后、生效前旧 roster 是否照常推进 2 块（无中断） | [已实测] h+2 窗口内 QC 连续达成无中断 |
| 账本哈希链 | 各节点 `committedDigest` 前缀是否一致（3-chain 提交） | [已实测] ledgerDigestConsistent=true，C0/C2/C3 高度 18 一致 |

## 6. 回滚方案

| 步骤 | 操作 | 状态 |
|---|---|---|
| B1 | 灰度入口：先 3 节点（f=0），逐步扩到 4（f=1）、5（f=1） | [未实测] |
| B2 | 发现共识分裂 → 停写、冻结 `ledgerDir`，以多数节点已提交前缀为准重放 | [未实测] |
| B3 | 创世锚泄露 → 全量重新自举（重发 gen-0 凭证 + 重建 registry） | [未实测] |
| B4 | 中继故障 → 回退共享盘/直连；所有节点保留本地账本副本可重放 | [未实测] |

## 7. 未实测风险（诚实列出）

1. **公网全链路未实测**：本清单是步骤文档，不是实测结论；跨机延迟、丢包、分区下行为未验证。
2. **部分同步假设**：完全异步 + 拜占庭 leader 可能活锁（异步 BA 是后续题）。
3. **动态成员在大网络未覆盖**：reconfiguration 风暴、双 roster 过渡未处理——本阶段是小规模信任域简化版。
4. **≥f+1 共谋**：BFT 数学边界，只能检测不能阻止。
5. **公钥基础设施**：创世锚是唯一中心化点，其可用性与保密性未做容灾实测。
6. **军法上链只上"可判定"部分**：诚实边界的模糊部分留审计层，不进共识。
