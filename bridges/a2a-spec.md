# VAP ↔ A2A 桥接规格（bridges/a2a-spec.md）

> A2A = Agent2Agent 协议（agent card + JSON-RPC 2.0 任务 + SSE 流式事件）。
> 本文档定义 VAP 能力到 A2A 的映射，以及本仓库已实现/未实现的边界。
> 配套实现：`bridges/a2a-card.mjs`（生成 `.well-known/agent.json`）。

## 一、Agent Card 字段映射

`.well-known/agent.json`（由 `a2a-card.mjs` 生成）字段与 VAP 概念的对应：

| A2A 字段 | VAP 来源 | 说明 |
|---|---|---|
| `name` | `nodeId` | 节点身份（默认 `vap-agent`，可用 `--name` 覆盖） |
| `description` | 协议定位 | 可验证报告 / 三闸裁决 / 崩溃收养 |
| `url` | 网关/节点 URL | 默认 `http://127.0.0.1/`，可 `--url` 覆盖 |
| `version` | `package.json.version` | 默认 `0.2.0` |
| `capabilities.streaming` | — | **false**（SSE 流式未实现，诚实标注） |
| `capabilities.pushNotifications` | — | false（无推送） |
| `capabilities.stateTransitionHistory` | — | false（无任务状态迁移历史） |
| `vapCapabilities` | vap-spec.md §6 | 五层能力映射（身份/信任/顺序/传输/治理） |
| `skills[]` | 五函数契约 | claimTask / doWork / heartbeat / respondExpand / report / vap_verify |

## 二、JSON-RPC 任务生命周期 → 信封映射

A2A 的任务状态机：`submitted → working → input-required → completed/failed/canceled/rejected`。
VAP 用「文件即消息」表达同一生命周期：

| A2A 方法 / 状态 | VAP 等价物 | 文件协议 |
|---|---|---|
| `tasks/send`（提交任务） | 脑进程/中继投递任务 | `inbox/task-N.json` |
| `working` | `claimTask`（O_EXCL 租约） | `inbox/task-N.lock`（nodeId:pid:startSec） |
| `working`（续租） | `heartbeat` | 更新 lock mtime 与内容 |
| `completed` | `report` 信封过三闸 | `outbox/evt-*.json` → `done/` |
| `tasks/get`（查询） | `respondExpand(taskId, field)` 或读 `done/` | `expand-resps/`、`done/<taskId>.json` |
| `tasks/cancel` | `complete` 以非 EXIT 结果收尾 / 释放租约 | `done/<taskId>.json`、删除 lock |

## 三、流式事件 → respondExpand 对接

A2A 用 SSE 推送 `TaskStatusUpdateEvent` / `TaskArtifactUpdateEvent`（任务状态/产物增量）。
VAP 以「字段级按需展开」替代全量流式推送：

- A2A 客户端无需订阅整条 SSE 流，而是按需 `respondExpand(taskId, field)` 拉取单个字段响应；
- 字段响应存放在瞬态交换区 `expand-resps/`（不入快照）；
- 缺失字段返回 `null`，由客户端自行决定轮询或降级。

## 四、诚实边界（未实现项，不冒认）

- **完整 A2A 任务状态机未实现**：`submitted/input-required/failed/canceled/rejected`
  等状态迁移、`tasks/sendSubscribe`、`tasks/cancel`、SSE 事件流均未落地；
  本仓库只交付 agent card 生成器与 MCP 侧的 `vap_verify` 验证工具。
- `doWork` / `respondExpand` 在 vap-core 内为桩（见 vap-spec.md §2），A2A 对接先复用桩契约。
- A2A 认证（如 API key / OAuth）未实现；VAP 的信任来自 Ed25519 信封签名与验证门，不经 A2A 认证层。
