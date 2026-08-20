# VAP v0.2 —— 可验证智能体交互协议（Verifiable Agent Protocol）

> **EN** — VAP (Verifiable Agent Protocol) is a trust-domain multi-agent interaction protocol:
> any Node.js agent that installs this plugin and enters the same trust domain (a shared
> workspace) can claim tasks, submit ≤100-char reports, be adjudicated by a three-gate
> verification gate, and be adopted on crash. Zero third-party dependencies.
>
> 插件形态的信任域内多智能体交互协议。任何 Node.js 智能体安装本插件后，
> 进入同一信任域（共享工作区），即可：领任务、交百字战报、被验证门裁决、崩溃被收养。
>
> 设计来源：dsh-mesh/megamesh（文件即消息、5 函数契约、军法）、dsh-witness（三证据收养、
> tampered 判决）、dsh-anchor（不信自报）、dsh-arena（证人制、验证门、诚实边界）。

## 0. 定位与不越界声明（v0 诚实边界）／ Positioning & Honest Boundaries

> **EN** — v0 is a small trust-domain protocol (single-machine shared filesystem; extensible to a
> shared disk / HTTP gateway, but public internet is untested). It is not Byzantine consensus, not
> public P2P. Ed25519 only proves "the message came from whoever holds the private key".

- **v0 是信任域协议**：单机共享文件系统（同一信任域内可扩展到共享盘 / HTTP 网关，
  公网未实测不声称）。
- **不是拜占庭共识、不是公网 P2P**：Ed25519 签名只保证"消息出自持有私钥的节点"，
  不防节点自己签自己的谎言（谎言的裁决是验证门与交叉复核的职责）。
- **防重放已实现（v0.2）**：信封含 nonce，签名对象绑定 nonce；传输层/裁决层用
  seen-nonces 一次性认领（重复 → 409/拒绝入账）。非法 nonce 形状 → 400。
- **零第三方依赖**：仅 node: 内置模块（crypto Ed25519、fs、path、node:test、node:http 等）。

## 1. 信封（Envelope）——节点间唯一的消息形态／ Envelope

```json
{
  "v": 1,
  "id": "evt-<16位小写hex>",
  "nonce": "<16位小写hex>",
  "ts": "<ISO8601>",
  "from": { "nodeId": "scout-01", "pubKey": "<base64 Ed25519 公钥>" },
  "to": "brain" | "all" | "<nodeId>",
  "sig": "<base64 Ed25519 签名>",
  "claim": { "type": "task|report|query|verdict", "body": { } },
  "evidence": {
    "devices": ["E01"],          // 实验装置编号（可验证域必填）
    "bills": { },                // 账单（模型调用计数等，可为空对象）
    "digest": "sha256:<hex>"     // 全文冷引用摘要（全文存本节点，不上报）
  },
  "boundary": "L2a" | "L1" | "L0",
  "report": {
    "summary": "≤100 字结构化战报",
    "keyNumbers": [ ],
    "request": "给脑进程的请求，可为空"
  }
}
```

**签名规范**：sig = Ed25519(私钥, canonical JSON of {v,id,ts,nonce,from.nodeId,from.pubKey,to,claim,evidence,boundary,report})。
canonical JSON = 键按字典序、无空白、字符串不转义多余字符（按 JS JSON.stringify 输出为约定基准）。
`nonce` 纳入签名对象：签名绑定 nonce，防重放不能靠「签名后追加字段」蒙混（v0.2 已实现，见 vap-core.mjs signPayload）。

## 2. 五函数契约（任何框架的节点只是协议的一个实现）／ Five-Function Contract

对齐 megamesh adapter-spec（LangGraph/CrewAI 已真库实测）：

| 函数 | 语义 | 文件协议 | 状态 |
|---|---|---|---|
| `claimTask` | 领任务（O_EXCL 租约） | `inbox/task-N.json` + `task-N.lock`（内容 nodeId:pid:startSec） | 已落地 |
| `doWork` | 干活（本节点自治） | 工作产物存本节点 `agents/<id>/`，不上报 | 桩（写 work.jsonl 条目） |
| `heartbeat` | 心跳（租约 touch） | 更新 lock mtime 与内容 | 已落地 |
| `respondExpand` | 字段级展开（细粒度信息按需取） | 瞬态区交换，不入快照 | 桩（读 `expand-resps/`） |
| `report` | 交战报（必须过验证门） | `outbox/evt-*.json` → 脑进程/接收方验三道闸 | 已落地（send 的命名别名） |

> **EN** — three of five are fully implemented (claimTask / heartbeat / report); doWork and
> respondExpand are stubs (see vap-core.mjs createVapNode) pending the real executor.

## 3. 验证门（接收方，三道闸，全过才入账）／ Three-Gate Verification

```
接收信封 → ① 身份闸：Ed25519 验签（失败 = reject + tampered 记录）
        → ② 军法闸：规则是数据（laws.json），逐条判定（失败 = reject）
        → ③ 诚实边界闸：boundary=L2a 的 claim 必须带 evidence.devices 非空（失败 = reject 并建议降级 L0）
        → 入账（done/ 或 consensus/）
```

**军法规则文件 laws.json（规则是数据，升级=改文件不改代码）**：

```json
{
  "rules": [
    { "id": "SIG_REQUIRED",   "check": "sig 验签通过",                    "severity": "reject" },
    { "id": "BOUNDARY_VALID", "check": "boundary ∈ {L2a,L1,L0}",          "severity": "reject" },
    { "id": "SUMMARY_BOUND",  "check": "report.summary 字符数 ≤ 100",      "severity": "reject" },
    { "id": "EVIDENCE_L2A",   "check": "boundary=L2a ⇒ evidence.devices 非空", "severity": "reject" },
    { "id": "FROM_KNOWN",     "check": "from.nodeId 在登记册或首封自注册",  "severity": "warn" }
  ]
}
```

## 4. 目录布局（battlefield = 信任域工作区）／ Directory Layout

```
battlefield/
├── inbox/            # 任务队列（文件即消息）
├── outbox/           # 战报信封（evt-*.json + evt-*.verdict）
├── laws.json         # 军法规则（数据）
├── registry.json     # 节点登记册（nodeId → pubKey）
├── done/             # 完成区（任务+结果+EXIT 记录）
├── dead-letter/      # 崩溃现场（三证据收养）
├── agents/<nodeId>/  # 每节点独立日志/全文档案/证据
├── expand-resps/     # 字段级展开瞬态区（respondExpand 读侧，不入快照）
└── seen-nonces/      # nonce 一次性认领标记（防重放）
```

## 5. 与既有仓库的关系（不重复造轮子）／ Provenance

| 能力 | 来源 | VAP 用法 |
|---|---|---|
| 文件即消息/租约/收养 | dsh-mesh/megamesh 内核 | 原样继承（同三证据） |
| 5 函数契约 | megamesh adapter-spec | 原样继承 |
| 战报协议（百字+冷引用） | megamesh E02/E04 | envelope.report + evidence.digest |
| 签名+背书 | megamesh E38（Ed25519） | 信封 sig 字段 |
| 证人制/验证门/诚实边界 | dsh-arena | 三道闸 + boundary 字段 |
| 尸检/tampered | dsh-witness | 收养判定与留痕 |

## 6. 中环与外环能力（v0.2 已并入）／ Middle Ring & Outer Ring

> **EN** — v0.2 folds in the middle ring (transport) and outer ring (identity / trust / ordering /
> governance) as separate phases, each with its own experiment device and report.

| 层 | 能力 | 装置/实现 |
|---|---|---|
| 身份层 | Ed25519 信封 + nonce 防重放 + 行为历史稀缺性 | Phase 0 / 0.5（bootstrap-forge.mjs） |
| 信任层 | 验证门三闸 + 资格链自举 + 分布式 2/3 QC | Phase 3 / 6（endorse-core.mjs） |
| 顺序层 | 锁步 QC 链共识（总序/防分叉/防双花） | Phase 5（vap-to.mjs） |
| 传输层 | 文件 / HTTP 网关 / UDP P2P / 中继跨 NAT | Phase 1 / 2 / 4（vap-transport.mjs、lan-peer.mjs、relay-server.mjs） |
| 治理层 | 动态成员 + 军法上链 + slash 自动除名 | Phase 6（vap-to-membership.mjs） |

- **中环（传输）**：HTTP 网关（createHttpGateway，验签前置 + nonce 防重放 409/400）、
  LAN P2P（createLanPeer，组播发现 + 洪泛 + 身份绑定，仅 IPv4 组播）、中继（createRelayServer）。
- **外环（身份/信任/顺序/治理）**：Phase 0 行为历史稀缺性、Phase 0.5 自举、Phase 3 分布式
  2/3 背书、Phase 5 锁步 QC 共识、Phase 6 动态成员 + 军法上链。
- 每个 phase 有独立 `DESIGN.md` / `*-REPORT.md` / `experiments/`，见各 phase 目录。

## 7. 已知缺口（诚实列出，不冒认）／ Known Gaps

- nonce 防重放已落地（传输层 + 裁决层 seen-nonces）；但 seen-nonces 无过期回收策略（长期运行会增长）。
- 单机文件系统为主 → 跨机需要共享盘 / 网关 / 中继；公网灰度未实测（见 phase6/DEPLOYMENT.md）。
- 无拜占庭共识的全网形态 → 恶意节点可签自己的谎言（验证门拦格式，交叉复核拦内容）；
  外环共识（Phase 5/6）在 n=3f+1 下容忍 f 个拜占庭节点，≥f+1 共谋即越界（数学边界）。
- 信封未压缩 → 大 payload 应走 evidence.digest 冷引用（已约定，未强制）。
- doWork / respondExpand 为桩：真实执行器与瞬态区写入端是下一阶段题。

## 8. v0 验收标准（跑通 = 全部满足）／ Acceptance

1. 两个异构节点（原生节点 + 模拟框架节点）在同一战场互动：领任务→干活→交战报→脑进程入账；
2. 伪造声明拦截对照：无签名 / 坏边界 / 超长战报 / L2a 无证据 四种伪造全部被验证门 reject；
3. 崩溃收养：节点被强杀后，其三证据现场被收养，任务重派完成；
4. 全部单测 `node --test` 通过；零第三方依赖；军法规则升级无需改代码（改 laws.json 生效）。
