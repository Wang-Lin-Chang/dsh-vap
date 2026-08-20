# VAP 中环 v0 —— 设计说明与验收报告

## 1. Transport 接口形状

统一 Transport 形状为 `{ send, read, markDelivered, countUndelivered }`，`createFileTransport` 是它的文件系统实现：

| 方法 | 语义 | 文件协议 |
|---|---|---|
| `send(envelope)` | 把已构造的信封原子写入出站队列，返回信封 | `outbox/evt-<id>.json`（tmp+rename） |
| `read({ after })` | 读未投递信封数组（按文件名排序，排除 `.delivered` 标记） | 扫 `outbox/evt-*.json` |
| `markDelivered(id)` | 投递后标记，避免重复投递 | `outbox/evt-<id>.delivered` |
| `countUndelivered()` | 未投递计数（供 health） | — |

信封**构造**不在此层：仍复用 `vap-core` 的 `createVapNode.send`（Ed25519 签名 + 信封字段组装）。传输层只搬运已构造的信封，验证门也仍由 `vap-core` 的 `node.verify` / `createBrain.consume` 执行——信封、签名、三闸逻辑零改动复用。

## 2. 网关协议（node:http，仅回环）

`createHttpGateway({ port, root, laws?, maxBodyBytes?, log? })`：

| 路由 | 语义 | 响应 |
|---|---|---|
| `POST /envelopes` | 接收远端信封 → 原子写 `inbox-http/evt-<id>.json`（网关只搬运不裁决） | 202 `{ ok, envelopeId }`；400（非法 JSON/缺 id）；413（超限）；500（写失败） |
| `GET /envelopes?after=<id>` | 出站：返回 outbox 未投递信封数组，投递后标 `.delivered` | 200 信封数组 |
| `GET /health` | 状态计数（`envelopesIn`=inbox-http 信封数，`envelopesOut`=outbox 未投递数） | 200 `{ ok, envelopesIn, envelopesOut }` |

- `start()` 返回实际端口，`port=0` 时由系统自动分配；`stop()` 关闭服务并释放端口。
- 请求体上限默认 1MB（`maxBodyBytes` 可配）：content-length 快速拦截 + 边读边计数两条路径，超出返回 413。
- `after` 为信封文件名（`evt-<id>`，不含 `.json`）的字典序游标；真正的去重依赖 `.delivered` 标记（游标为渐进消费的辅助）。
- 网关日志只写状态（`status=202 id=...` / `status=413 too-large`），不写信封全文。

## 3. 客户端（node:http）

`createHttpClient({ baseUrl })`：

- `post(envelope)` → `{ status, ok, envelopeId?, error? }`（202 即 ok，非 2xx 返回 status+error，网络异常抛错）。
- `poll({ after })` → 信封数组（未投递）；非 200 抛错。

## 4. 验收对照（brief-ring 硬性标准）

1. **`node --test` 全绿**：35/35（v0 的 17 个一个不破 + 中环 18 个新增全过）。
2. **零第三方依赖**：三件交付文件 import 仅 `node:http`/`node:fs`/`node:path`/`node:crypto`/`node:test`/`node:assert`/`node:os`/`node:net` 与相对路径；真 HTTP 本地回环，非 mock。
3. **信封/验签/验证门零改动复用 vap-core**：`vap-core.mjs` 未修改（信封构造用 `createVapNode.send`，三闸用 `node.verify`/`createBrain.consume`，签名/验签全部复用）；因此无「改 vap-core 的理由」需要说明。
4. **跨节点实验跑通**：`node experiments/vap-http-experiment.mjs` 真信封入账（pass=true + done 落盘）、伪信封拦截（pass=false + reasons 含 `SIG_REQUIRED`）。
5. **原子写 tmp+rename**：传输层 `atomicWrite` 全部 tmp+rename；**1MB 上限 413**：content-length 与流式计数两条路径均 413。

## 5. 已知缺口（诚实列出，不冒认）

- 网关是「搬运不裁决」的 store-and-forward：验证仍在接收方脑进程做（符合 brief 的「验证门语义不变」，但网关本身不预验证）。
- `after` 游标按文件名（信封 id）字典序，而信封 id 是随机 hex、非单调——渐进消费主要靠 `.delivered` 标记去重；若需按时间顺序的游标，需给信封加单调序号（属下一步）。
- `poll()` 返回「全部未投递信封」，不按 `to` 字段过滤（客户端无自身 nodeId，收件过滤由接收方裁决侧完成）。
- 无重放防护（nonce），与 vap-spec §6 一致，为既有已知缺口。
- `laws?` 仅在缺 `laws.json` 时落一份供下游 verify 用同一规则；网关不在入站时裁决。

## 6. 纪律自检

- 三件交付文件未出现坏词清单禁用词；UTF-8 中文文件均用文件编辑工具写入。
- 无 npm 依赖、无 package.json 新增字段。
- 每个断言对应 brief-ring 一条要求；跨节点实验以退出码报告判定，不伪造通过。

## 7. 结论

三件交付物（`vap-transport.mjs`、`tests/vap-transport.test.mjs`、`experiments/vap-http-experiment.mjs`）完成；`node --test` 35/35 全绿、v0 的 17 个测试一个不破；跨节点实验真入账/伪拦截实测通过；满足 brief-ring 全部硬性验收标准与纪律约束。
