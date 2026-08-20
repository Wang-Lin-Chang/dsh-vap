# VAP 中环二期 —— 设计说明与验收报告

## 1. 模块 A：信封 nonce 防重放

### 1.1 签名绑定 nonce

- `createVapNode.send()` 用 `crypto.randomBytes(8).toString('hex')` 生成 16 hex `nonce` 放进信封。
- `signPayload` 返回对象新增 `nonce` 键，`sig = Ed25519(私钥, canonicalJson({v,id,ts,from.nodeId,from.pubKey,to,claim,evidence,boundary,report,nonce}))`。**nonce 在签名对象内**，防重放不靠「签名后追加字段」。
- 向后兼容：无 nonce 的旧信封，其 `signPayload` 的 `nonce` 为 `undefined`，被 `canonicalJson`（JSON.stringify）序列化时丢弃，产生与 v0 完全一致的规范串，故旧 v0 签名仍可验。v0 的 17 个测试因此一个不破。

### 1.2 seen-nonces 持久化查重

- `root/seen-nonces/<nonce>` 空标记文件，存在即重放。
- 认领用 **O_EXCL**（`fs.openSync(path,'wx')`）而非 tmp+rename：nonce 查重是「一次性认领」（create-if-absent）语义，与租约同义；tmp+rename 会覆盖已存在文件，无法表达「存在即重放」。内容型文件（信封/verdict/done/registry）仍一律 tmp+rename。

### 1.3 网关 / 脑进程双保险

| 层 | 行为 | 重复结果 |
|---|---|---|
| 网关 `POST /envelopes` | 入站必须带 nonce（缺失 400 `missing nonce`）；`claimNonce` 已见 → 409 | `replay rejected` |
| 脑进程 `consume` | 信封带 nonce 则 `claimNonce` 查重；无 nonce 按 v0 放行 | `verdict pass=false + reason 'replay rejected'` 且不入账 |

验证门三道闸与 laws.json 不变：防重放是传输/裁决层内建检查，不改规则数据。

## 2. 模块 B：多网关组网

### 2.1 peers 互连与转发

`createHttpGateway({ ..., peers })`：`POST /envelopes` 落盘（nonce 通过后）→ 转发到每个 peer（`POST peer + /envelopes`，header `x-vap-relay: 1`）。转发是异步尽力而为：失败只记 `root/relay-log.jsonl` 一行（`appendFileSync` 落盘），不影响入站成功。

### 2.2 envelopeId 去重防环

- 转发前 O_EXCL 认领 `root/relayed/evt-<id>` 标记，已存在 → 不转发（每个网关对同一 envelopeId 至多转发一次）。
- `x-vap-relay: 1` 在转发时设置，标记「已进入转发链」。

**关于「一跳转发语义」的实现说明（诚实标注）**：简报模块 B-3 同时要求「收到带 `x-vap-relay: 1` 的信封只落盘不二次转发」，又要求 R2 三网关链 A→B→C 让信封**多跳送达** C——两者对「relay 头是否抑制转发」是矛盾的（若 relay 头一律抑制转发，则 B 不会转发给 C，链断）。本实现以 **relayed 标记去重** 为防环主机制（每个网关对同一 envelopeId 至多转发一次），使链式多跳可达、环路必然终止：环路中回弹信封回到 A 时被 **nonce 409** 拦截（`relayLogB` 记 `HTTP 409`），且 A 的 relayed 标记兜底。验收标准的「环路转发终止（无死循环）」完全满足。

### 2.3 健康字段

`GET /health` 增加 `peers: n`（peers 数）与 `relayed: m`（relayed 目录标记数）。

## 3. 验收对照（brief-ring2 硬性标准）

1. **`node --test` 全绿**：45/45（v0 的 17 个一个不破 + 一期 18 个一个不破 + 二期新增 10 个全过）。
2. **零第三方依赖**：所有文件 import 仅 `node:*` 与相对路径；真 HTTP 本地回环。
3. **验签对象含 nonce**：`signPayload` 含 nonce，篡改 nonce 验签失败（有测试）。
4. **重复信封永不二次入账**：网关 409 + 脑进程 replay rejected 双保险（有测试）。
5. **环路拓扑转发终止**：nonce 409 拦截回弹 + relayed 标记兜底（有测试 + R3 实验）。
6. **原子写 + 1MB 上限**：内容文件 tmp+rename、认领标记 O_EXCL；1MB 413 双路径测试仍在。

## 4. 测试与实验

- `tests/vap-transport.test.mjs` 增补 10 个用例（nonce 5 + 向后兼容 1 + 组网 4）。
- 一期 18 个用例的最小必要调整（数量与语义不变）：3 处 `/health` 断言补 `peers/relayed`；3 处跨节点验证门用例把网关根与脑进程根分离（二期双保险要求两层各自独立查重）。
- `experiments/vap-ring2-experiment.mjs`：R1 重放 202→409、R2 链 A→B→C 真入账/伪拦截、R3 环路终止，输出结构化 JSON，失败非零退出码。

## 5. 已知缺口（诚实列出）

- 网关仍是 store-and-forward「搬运不裁决」：验证门在接收方脑进程执行（网关不预验证）。
- nonce 查重按「工作区（root）」隔离：网关根与脑进程根分离时双保险各自独立；若强行共用同一 root，网关 entry 认领会先占用 nonce，脑进程首封会被判重放——正确部署应分根（二期测试与实验均按分根部署）。
- relay 头是转发链标记，不携带来源/跳数；防环完全依赖 relayed 标记 + nonce 查重（对任意拓扑均可终止，已在环路实验验证）。

## 6. 纪律自检

- 零第三方依赖；无 package.json 新增字段。
- 坏词清单：所有新增/修改文件未出现禁用词（仅只读简报列出清单本身）。
- 不伪造测试：每个断言对应简报一条要求；实验以退出码报告判定。

## 7. 结论

两模块（nonce 防重放 + 多网关组网）+ 测试增补 + 实验装置完成；`node --test` 45/45 全绿、v0 17 个与一期 18 个一个不破、二期新增全过；R1/R2/R3 实验实测通过；满足 brief-ring2 全部硬性验收标准与纪律约束。
