# Phase 4 —— 跨 NAT 第一步（中继模式）验收报告

> 立项问题：让信封跨越 NAT 边界。策略：**中继优先（relay-first）**——先走中继让跨 NAT 通信成立，
> 打洞（STUN/DCUtR）与 libp2p 的取舍做成决策文档（NAT-PUNCHING-DECISION.md）。
> 核心自我质疑：零依赖是纪律还是教条？本阶段用「中继模式全自研 + 决策文档有根据」来回答。

## 1. 交付物与运行方式

| 文件 | 职责 |
|---|---|
| `phase4/relay-server.mjs` | `createRelayServer({ port })` → `{ start, stop, stats }`；TCP 注册/转发/度量/同名顶替 |
| `phase4/relay-client.mjs` | `createRelayClient({ host, port, nodeId, pubKey })` → `{ connect, send, onEnvelope, close, connected }`；指数退避重连（上限 30s） |
| `phase4/tests/relay.test.mjs` | node:test 单测（8 条）：注册/转发/顶替/重连/度量/篡改必拒/行协议 |
| `phase4/experiments/phase4-experiment.mjs` | R1-R4 实测装置，结构化 JSON 输出 + `phase4-results.json` |
| `phase4/NAT-PUNCHING-DECISION.md` | 三方案对比 + 决策 + 零依赖强默认非教条 |
| `phase4/P4-REPORT.md` | 本文档 |

运行（在 dsh-vap/ 下）：

```
node --test                                        # 全绿：81 条（含本阶段 8 条）
node phase4/experiments/phase4-experiment.mjs      # R1-R4 + 结构化 JSON + 硬性自检
```

## 2. 核心设计实现

### 2.1 relay-server.mjs（中继，node:net）

- **行协议**：4 字节大端长度前缀 + JSON（`encodeFrame` / `createFrameDecoder`，处理半包与粘包）。
- **注册**：`{ type:'register', nodeId, pubKey }` → 维护 nodeId→socket 表；同名重复注册 → 后注册者顶替旧连接（旧连接断开）。
- **转发**：`{ type:'relay', to, envelope }` → 查表**原样字节**转发（写回同一 frame，不重新序列化）；**只转发不验签不解密**。
- **度量**：`stats() → { connections, totalBytes, forwardedBytes, forwarded, registered, replacements, dropped, uptimeMs }`（R4 数据源）。
- 可选 `drop` 钩子：仅实验装置用于模拟审查丢弃（默认 null = 永不丢弃）。

### 2.2 relay-client.mjs（客户端）

- `connect()` 上线即注册；`send(to, envelope)` 写 length-prefixed relay 帧；`onEnvelope(cb)` 收信封回调；`close()` 关闭；`connected()` 状态。
- **断线重连**：指数退避 `1s→2s→4s→8s→16s→上限 30s`（`backoffDelayMs` 纯函数），重连成功后重置退避并重新注册。
- 收信封后走 vap-core 三闸由接收方复用（实验装置内 `verify`），客户端只搬运与收发。

## 3. 实验结果（本轮实测，本机回环 127.0.0.1）

### R1 跨「网段」通信

两组各 3 节点（A1-A3 / B1-B3）只经中继可达（不直连），互发 18 封真信封 → **全部验签 + 三闸通过**（`r1_allPass=true`，6/6 节点在线，18/18 收到）。

### R2 伪造经中继

无签名伪造信封经中继转发 → 对端三闸拦截（`identity: signature verification failed`，rejected，不入账）。中继无感知，照常转发（`relayForwardedForged=true`）。

### R3 审查检测

中继选择性丢弃节点 A 的 1 封消息（drop 钩子）→ 节点 B 对账：发送确认 2 vs 到达确认 1 → **detected=true + 证据**（missing 列表 + 结论）。诚实标注：只可检测不可防止。

### R4 无激励基线（单机模拟，中继与客户端同进程）

| 并发连接 | 每连接封数 | 总转发 | 转发字节 | 耗时 | CPU(ms) | RSS 增量 | 字节/s | 封/s |
|---|---|---|---|---|---|---|---|---|
| 50 | 10 | 500 | 281,200 | 0.45s | 485 | +3.4MB | 623,503 | 1,109 |
| 200 | 10 | 2,000 | 1,130,700 | 1.77s | 1,703 | +6.9MB | 638,814 | 1,130 |
| 500 | 10 | 5,000 | 2,831,700 | 4.54s | 4,203 | +13.1MB | 623,173 | 1,100 |

结构见 `phase4/experiments/phase4-results.json`。

## 4. 验收标准对照（DESIGN §五）

| 验收项 | 结果 |
|---|---|
| R1 全部验签三闸过 | ✅ `r1_allPass=true`（18/18） |
| R2 拦截 | ✅ `r2_intercepted=true`（rejected 不入账） |
| R3 审查可检测（证据链完整） | ✅ `r3_detected=true`（expected 2 → got 1 + missing 证据） |
| R4 基线数据产出 | ✅ 50/200/500 三档表（CPU/内存/字节） |
| 零第三方依赖 | ✅ 仅 node: 内置模块与相对路径 import |
| vap-core 零改动 | ✅ 未修改 `../vap-core.mjs`，只 import `createVapNode` 复用 |
| 中继篡改信封 → 对端必拒 | ✅ 单测「中继篡改信封 → 对端三闸拒绝」+ R2 |
| 断线 5s 内重连 | ✅ 单测实测 1.05s 重连 + `backoffDelayMs` 上限 30s |
| 结构化 JSON | ✅ stdout + `phase4-results.json` |

## 5. 诚实边界（DESIGN §六）

1. 中继是中心化点：只见明文（JSON）、不可伪造（改内容验签必败）、可选择性丢弃——信任边界 = 「不可信但不可作恶」，作恶（审查/丢包）可被检测（R3）但不可防止。
2. 打洞未做（决策见 NAT-PUNCHING-DECISION.md）；libp2p 未引入（决策文档说明触发条件）。
3. 本机回环测试，真实跨 NAT 实测待公网环境。
4. 无激励基线是单机模拟（中继与客户端同进程，CPU/内存含客户端开销），公网带宽成本另算。
5. 同名顶替是诚实标注的「后注册者顶替」，防顶替（如公钥绑定鉴权）是后续题。

## 6. 纪律自检

- 零第三方依赖：仅 node:net / node:crypto / node:fs / node:os / node:path / node:url 与相对路径 import，无 package.json、无 node_modules。
- 复用而非复制：信封构造与三闸判定全部复用 vap-core 的 `createVapNode.verify`，中继/客户端只搬运与收发，不复制任何判定逻辑。
- 不伪造实验结果：R1-R4 真实跑出，硬性自检失败即非零退出码（实测 node 退出码 0）。
- 坏词清单：交付文件（relay-server.mjs / relay-client.mjs / relay.test.mjs / phase4-experiment.mjs / 本文档 / NAT-PUNCHING-DECISION.md / progress-phase4.md）未出现禁用词。
