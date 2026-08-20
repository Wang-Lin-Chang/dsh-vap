# VAP Phase 2 LAN P2P 闭环 —— 实现与实测报告

> 契约依据：`phase2/brief.md`、`phase2/DESIGN.md`、项目根 `vap-spec.md` §1/§3、`phase1/IDENTITY.md`。
> 原则：信封、签名、验证门三闸全部复用 `vap-core.mjs`（零改动，只 import）；P2P 只是新传输，
> 只「搬运与转发」，不复制任何信封构造 / 验签 / 军法 / 诚实边界判定逻辑。

## 一、交付物

| 文件 | 内容 |
|---|---|
| `phase2/lan-peer.mjs` | `createLanPeer`（node:dgram UDP 组播发现 + 信封洪泛 + messageId 去重防环 + TTL 上限 + 身份绑定） |
| `phase2/tests/lan-peer.test.mjs` | 5 个 node:test 用例（发现 / 投递 / 去重 / TTL / 身份绑定，本机回环短超时） |
| `phase2/experiments/phase2-experiment.mjs` | P2-1..P2-4 独立可运行，结构化 JSON 输出 |
| `phase2/P2-REPORT.md` | 本文档 |

## 二、设计说明（`lan-peer.mjs`）

### 2.1 双 socket 结构

- **单播 socket**（`node:dgram` udp4，绑定本节点 `port`）：信封洪泛的收发通道。
- **组播 socket**（udp4，`reuseAddr`，绑定 `multicast.port`）：announce 的收发通道，加入组
  `239.255.42.99`（可用 `multicast` 参数覆盖，测试用回环）。

默认组播地址 `239.255.42.99:42666`；`mcastInterface` 默认 `127.0.0.1`（本机回环），跨机可覆盖。

### 2.2 节点发现（mDNS 简化版）

- `start()` 后每 3s 组播一条 `{ type:'announce', nodeId, pubKey, port, ts }`（join 后立即首播加速发现）。
- 收到 announce → 更新 peer 表 `{ nodeId → { pubKey, addr, port, lastSeen } }`（`addr` 取 rinfo 源地址，
  `port` 取对端单播端口）；**10s 未见剔除**（1s 周期检查）。
- 节点协议身份 = VAP Ed25519 公钥（复用 `vap-core` 的 `createVapNode` 从同一 `keyPair` 派生）。

### 2.3 信封洪泛（floodsub 语义）+ 防环防风暴

- `sendEnvelope(envelope, ttl=8)`：包装 `{ type:'flood', ttl, srcNodeId, envelope }` 单播给所有已知 peer；
  源头也把 messageId 登记进 seen（防自己发的不再二次投递/转发）。
- 收到 flood 的消息处理顺序（brief 规定的顺序）：

  1. **messageId 去重**：`messageId = envelope.id`，已在 seen → 丢弃（不投递、不转发）；否则登记进 seen；
  2. **身份绑定检查**：信封 `from.pubKey` 必须与 announce 登记的 pubKey 一致，不一致 → 拒收
     `reason='identity mismatch'`，不投递、不转发；
  3. **三闸验证**（零改动复用 `vap-core` 的 `verify`）：不过 → 拒收（`onReject` 回调），不转发；
  4. **送达回调** `onEnvelope`：去重 + 身份绑定 + 三闸全过后才送达；
  5. **TTL 递减转发**：`TTL>1` 才转发给其他 peer（`TTL-1`），不发回上游（`srcNodeId`）、不发给自己。

- **防环**：seen 集合按 messageId 去重，同一 id 永不二次投递/转发。
- **防风暴**：TTL 上限 8；转发排除上游（不沿来路回发）。
- **seen 清理**：内存 Set/Map，60s 超时清理（1s 周期）。

### 2.4 API 形状

```
createLanPeer({ port, nodeId, keyPair, multicast, host, mcastInterface, discover, root, now })
  → start() / stop()
  → sendEnvelope(envelope, ttl?) / broadcast(envelope, ttl?)
  → onEnvelope(cb) / onReject(cb) / addPeer(info) / peers() / stats()
  → ready（绑定+组播加入完成的 Promise）、pubKey、port、nodeId
```

- `addPeer({ nodeId, pubKey, addr, port })`：手动注入 peer，供确定性拓扑（环状 P2-4、链式 TTL 测试）。
- `discover=false`：关闭组播发现，只用手动 peer 表（环状拓扑用）。
- `onReject(cb)`：到达但被拒（身份绑定不一致 / 三闸不过）时回调，供实验统计「receivedButRejected」。
- `stats()`：`{ sent, received, delivered, forwarded, rejected, deduped, identityRejected }` 传输计数。

## 三、实测结果（本机回环，`node phase2/experiments/phase2-experiment.mjs`）

```
p2_1_received4of4 = true    // 5 节点全互连，节点 1 发真信封，其余 4 节点收到且三闸全过
p2_2_noReplay      = true    // 重放同一信封，其余节点 receivedCount 不增（去重）
p2_3_intercepted   = true    // 节点 5 洪泛无签名信封，到达但三闸拦截（receivedButRejected，且不送达）
p2_4_bounded       = true    // 5 节点环，每节点至多 1 次、转发 4 次 ≤ 边数 5
allPass            = true    // 退出码 0
```

- **P2-1**：`got4of4=true`、`allGatesPass=true`、每节点投递 `[1,1,1,1]`（节点 2..5 各 1 次）。
- **P2-2**：重放前后 `[1,1,1,1] → [1,1,1,1]`，`noReplay=true`（去重计数 deduped 落在各节点 stats）。
- **P2-3**：无签名伪造每节点 `perNodeRejected=[1,1,1,1]`、`forgedNotDelivered=true`（拦截率 100%）。
- **P2-4**：环状 5 节点，源节点 0 次、其余 4 节点各恰 1 次（`perNode=[0,1,1,1,1]`），
  总转发 `4 ≤ 5`（边数），无爆炸。

## 四、验收自检（对照硬性标准）

1. **P2-1 4/4 收且过、P2-2 零重放、P2-3 100% 拦截、P2-4 每节点恰 1 次** ✅（见 §三结构化输出）。
   - 「每节点恰收 1 次」的诚实表述：源节点 0 次（自己发出不重复投递），其余 4 节点各恰 1 次，
     没有任何节点收到重复副本（`eachAtMostOnce=true`）。
2. **零第三方依赖** ✅：`lan-peer.mjs` 仅 `node:dgram/node:crypto/node:fs/os/path` + 相对路径 import
   `../vap-core.mjs`；无 package.json、无 node_modules。
3. **vap-core 零改动** ✅：只 import `createVapNode`/`makeLaws`；全量 `node --test` 60 通过 / 0 失败
   （旧 55 个一个不破 + 新增 5 个）。
4. **身份绑定** ✅：单测「身份绑定」断言 `reason='identity mismatch'`、不送达、`identityRejected=1`；
   并附对照——该伪造信封若走纯三闸会放行（攻击者自签自 claim），证明身份绑定是独立一闸。
5. **结构化 JSON 输出** ✅：`p2_1_received4of4 / p2_2_noReplay / p2_3_intercepted / p2_4_bounded / allPass`。

## 五、诚实边界（DESIGN §七）

- **UDP 无可靠投递**：丢包不重传。LAN 闭环验证正确性；可靠投递是后续层的题。
- **组播在部分网络环境被禁用**：实验在本机回环（`127.0.0.1` 组播回环）完成，跨机实测未做（标注待做）。
- **mDNS 简化版非标准 mDNS**：不实现 SRV/TXT 记录，仅供 VAP 节点发现。
- **seen 集合内存态**：节点重启后去重失效；持久化去重是后续题，nonce 层仍兜底防重放入账。
- **身份绑定的前提**：announce 先于信封到达才可对照（peer 表已有该 nodeId）。信封早于 announce 到达时
  无法对照登记公钥，此时仅三闸验签兜底（`FROM_KNOWN` 为 warn 语义）。这是「发现 + 洪泛」异步时序的
  固有窗口，已在 `lan-peer.mjs` 注释与本节显式列出，不冒认为已消灭。
- **nodeId 可被冒名登记**：攻击者可宣布「nodeId=X, pubKey=自己的公钥」。本阶段身份绑定只保证
  「同一 nodeId 的 announce 公钥与信封签名者公钥一致」，不解决 nodeId 抢注/声誉问题（那是声誉层的题，
  协议身份唯一凭证仍是 `from.pubKey` 的 Ed25519 验签，见 `phase1/IDENTITY.md`）。

## 六、测试覆盖（`node phase2/tests/lan-peer.test.mjs` → 5 通过）

| 用例 | 断言要点 |
|---|---|
| 发现 | 两节点 5s 内互相发现，登记公钥/端口与对端一致 |
| 洪泛投递 | A 发 → B 收到且三闸验签通过，信封往返无损 |
| 去重 | 同 id 二次到达不触发回调，`deduped=1` |
| TTL 递减 | TTL=1 不转发（C 收不到）；TTL=2 转发一跳（C 收到） |
| 身份绑定 | 公钥不一致 → `reason='identity mismatch'`、不送达、`identityRejected=1`，并附三闸放行对照 |
