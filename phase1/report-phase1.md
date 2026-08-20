# Phase 1 传输抽象 + 选型 + 身份绑定 —— 验收报告

> 立项：外环路线的 Phase 1。三个交付：① 传输 SPI 抽象（零依赖）② 身份绑定规范（解决 MAJOR-5）
> ③ 传输选型报告（先决策后实现）。原则：抽象先行，libp2p 等外部依赖接入放到 Phase 2，
> 本阶段只定接口、定身份、定选型。

## 1. 交付物与运行方式

| 文件 | 职责 |
|---|---|
| `phase1/transport-spi.mjs` | 传输 SPI：createFileTransport / createHttpTransport / transportConformance |
| `phase1/IDENTITY.md` | 身份绑定规范（四条决策 + 违规必拒） |
| `phase1/SELECTION.md` | 选型报告（libp2p / 自研 / HTTP 网格） |
| `phase1/tests/transport-spi.test.mjs` | SPI 无损 + 身份绑定违规 + conformance 诊断（10 用例） |
| `phase1/experiments/phase1-experiment.mjs` | SPI 上重跑中环四场景 + 身份冒充拦截，结构化 JSON |

运行（在 dsh-vap/ 下）：
- `node --test` —— 全量单测；
- `node phase1/experiments/phase1-experiment.mjs` —— 实验装置。

复用 `vap-transport.mjs`（FileTransport/HttpGateway/HttpClient）与 `vap-core.mjs`（createVapNode/
createBrain/verify/canonicalJson）——**只包装与复用，不复制其逻辑**。零第三方依赖：仅 node: 内置模块。

## 2. 核心设计实现

### 2.1 Transport SPI（transport-spi.mjs）

统一形状：`{ name, capabilities, send, recv, peers, close }`。

- `createFileTransport({ root })` 包装 FileTransport：`send`=原子写 outbox、`recv`=读未投递信封
  （复用 FileTransport.read，支持 `{ after }` 游标）、`peers`=恒空、`close`=no-op，行为与 v0 完全一致。
- `createHttpTransport({ port, root, peers, baseUrl, laws })` 包装 HttpGateway（服务器）+ HttpClient
  （拨号客户端）：`send`=POST /envelopes 到 baseUrl（复用 HttpClient.post，202/409/400 语义不变）、
  `recv`=读 root/inbox-http 入站信封、`peers`=对端列表、`health`=透传网关计数、`start`/`close` 起停网关。
  网关/客户端内部逻辑一行未改，HttpTransport 只是壳。
- `transportConformance(t)` 返回 `{ ok, missing, diagnostics }`：检查 name（非空字符串）、
  capabilities（数组且位合法）、send/recv/peers/close（函数），并报“声明能力却缺方法”“未知能力位”诊断。

### 2.2 身份绑定（IDENTITY.md，解决 MAJOR-5）

四条决策：

1. VAP Ed25519 是唯一协议身份（from.pubKey/凭证/声誉/registry.json 全绑定它）；
2. 传输层密钥（如未来 libp2p PeerID）仅作握手密钥，不进任何协议签名/凭证/信誉语义；
3. 双层密钥映射表节点本地维护，映射本身进协议层审计（防中间人冒充）；
4. 违规检测：协议身份 ≠ 信封签名者 → 验证门必拒。

违规判据落在三道闸第①道（身份闸）：签名对象含 `from.pubKey` 自身，验证门用 `from.pubKey` 去验
`sig`，因此传输层密钥无法签出“通过受害者公钥验签”的伪造信封，冒充必被身份闸 reject。

### 2.3 选型（SELECTION.md）

**现阶段 HTTP 网格（已实测）为主力；libp2p 为 Phase 2 候选（按 IDENTITY.md 绑定，PeerID 仅握手）；
自研 NAT 穿透否决（对称 NAT/CGNAT 打洞是陷阱，不重造轮子）。身份绑定规范先行。**

## 3. 实验结果（本轮实测）

### S1 链转发（A→B→C）

节点 X 经 SPI `send` 到 A，网关 peers 链式转发，信封达 C；C 验签 pass、脑进程入账：
`postStatus=202, reachedC=true, verifyPass=true, credited=true`。

### S2 伪造拦截

无签名信封经链送达 C，验证门身份闸拦截（SIG_REQUIRED）：
`postStatus=202, reachedC=true, verifyPass=false, intercepted=true`。

### S3 重放 409

同一信封第二次 `send` 被拒且不落盘：
`firstStatus=202, secondStatus=409, secondError="replay rejected", inboxCount=1`。

### S4 环路终止（A↔B）

互连环内 relayed + nonce 双兜底，转发终止：
`relayedA=1, relayedB=1, inboxA=1, inboxB=1, terminated=true`。

### I1 身份绑定攻击

攻击者（传输层持有者）用自己密钥签名、`from` 冒充受害者协议身份：
`keysDiffer=true, fromClaimsVictim=true, verdictPass=false, identityGatePass=false,
identityReason="signature verification failed", intercepted=true`。

### 汇总

```json
{ "spiLossless": true, "identityBindingHolds": true, "allPass": true }
```

退出码 0。

## 4. 验收标准对照（brief 硬性）

| 验收项 | 结果 |
|---|---|
| `node --test` 全绿，旧 45 个一个不破 | ✅ 55 pass / 0 fail（旧 45 + 新 10） |
| 零第三方依赖 | ✅ 仅 node: 内置模块 + 相对路径；libp2p 只出现在 SELECTION.md 文档 |
| 旧行为零变化（网关/客户端内部一行不改） | ✅ vap-core.mjs / vap-transport.mjs 未动，SPI 只包装复用 |
| 身份绑定测试钉死（传输层密钥冒充协议身份必拒） | ✅ 单测 + 实验 I1 均断言必拒 |
| 实验结构化输出 | ✅ spiLossless / identityBindingHolds / allPass |

## 5. 诚实边界

1. **libp2p 未接入**：本阶段零依赖，不安装不 import；DCUtR/中继/gossipsub 是外部项目成熟事实，
   本项目要到 Phase 2 才接入并实测。决策 3 的双层密钥映射表落盘与协议层审计记录是 Phase 2 落地项，
   当前仅作规则约定。
2. **“HTTP 网格为主力”只对信任域/小规模联邦成立**：公网大规模下的 NAT 可达性、push/洪泛需求
   未在 HTTP 网格实测，属 Phase 2（LAN P2P）与 Phase 4（NAT 穿透 + 中继兜底）范围。
3. **本规范不解决“传输层握手密钥本身如何被信任”**（libp2p 连接建立时的对端真实性），只保证协议身份
   的唯一性不受传输层密钥影响。
4. **Ed25519 验签只证明“消息出自持有私钥者”**，不防节点签自己的谎言——那是军法闸与交叉复核的职责，
   不在身份绑定范围。
5. **实验为单机进程内本地回环**：多网关共进程、文件系统共享，非跨机公网。

## 6. 纪律自检

- 零第三方依赖：仅 node:fs / node:path / node:http / node:crypto 与相对路径 import，无 package.json、无 node_modules。
- 复用而非复制：FileTransport/HttpGateway/HttpClient 全部 import 自 vap-transport.mjs，信封/验签/验证门逻辑未在 SPI 模块内重写。
- 不伪造实验结果：四场景 + 身份攻击全部真实跑出，硬性自检失败即非零退出码。
- 坏词清单：全部交付文件未出现禁用词。
