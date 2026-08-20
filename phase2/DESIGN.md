# VAP Phase 2 设计：LAN P2P 闭环（零依赖自研）

> 立项：外环 Phase 2。同一局域网内不经 HTTP 的端到端 P2P：节点发现 + 信封洪泛 + 防环防重放。
> 选型决策（已定）：零依赖自研（node:dgram UDP 组播 + UDP 洪泛）。libp2p 推迟到 Phase 4（NAT 穿透才是它的主场）。
> 原则：信封、签名、验证门三闸全部复用 vap-core，零改动——P2P 只是新传输。

## 一、节点发现（mDNS 简化版）

- UDP 组播：`239.255.42.99:42666`（或广播 255.255.255.255；本机多进程测试用组播回环）；
- announce：节点周期性发送 `{ type:'announce', nodeId, pubKey, port, ts }`（3 秒间隔）；
- peer 表：收到 announce 即更新 `{ nodeId → { pubKey, addr, port, lastSeen } }`，10 秒未见剔除；
- 节点身份 = VAP Ed25519 公钥（复用 vap-core 的 createVapNode 生成的密钥对）——身份绑定规范（Phase 1 IDENTITY.md）在 P2P 层同样生效。

## 二、信封洪泛（floodsub 语义）

- 发送：信封序列化 → UDP 单播给所有已知 peer（或组播洪泛）；信封带 TTL 字段（洪泛层包装，不改信封本体——包装 `{ ttl, envelope }`）；
- 转发：收到 → messageId（=信封 id）未见 → 存入 seen 集合 → TTL>1 则转发给其他 peer（TTL-1）；
- 防环：seen 集合按 messageId 去重（同一 id 永不二次转发）；
- 防风暴：TTL 上限（默认 8）；
- seen 集合：内存 Set + 定期清理（超时 60s）。

## 三、验证门（零改动复用）

节点收到信封后走 vap-core 的 verify（三闸）——P2P 层不信任传输，只信任验证门。

## 四、实验（experiments/phase2-experiment.mjs，本机多端口模拟多节点）

- **P2-1 一发四收**：5 节点（不同端口），节点 1 发真信封 → 其余 4 节点收到且验签+三闸通过；
- **P2-2 重放**：同一信封再次洪泛 → seen 去重（不二次投递/转发）；
- **P2-3 伪造**：伪造信封（无签名）洪泛 → 到达节点但三闸拦截（不入账）；
- **P2-4 风暴防护**：5 节点全互连（环路拓扑），信封洪泛 → 每个节点恰好收到 1 次（去重），转发次数有界（≤ 边数），无爆炸。

## 五、交付物

1. `dsh-vap/phase2/lan-peer.mjs`——createLanPeer({ port, nodeId, keyPair, multicast? })：start/stop/sendEnvelope/broadcast/onEnvelope/peers()；
2. `dsh-vap/phase2/tests/lan-peer.test.mjs`——发现/洪泛/去重/TTL 单测（本机回环，短超时）；
3. `dsh-vap/phase2/experiments/phase2-experiment.mjs`——P2-1..P2-4；
4. `dsh-vap/phase2/P2-REPORT.md`。

## 六、验收标准

1. P2-1：4/4 收到且验证通过；P2-2：重放 0 次二次投递；P2-3：拦截率 100%；P2-4：每节点收到恰好 1 次、转发有界；
2. 零第三方依赖（node:dgram/node:crypto/node:fs）；
3. vap-core 零改动；
4. 身份绑定：announce 的 pubKey 与信封签名者不一致 → 拒绝（peer 表与信封身份对照）；
5. 结构化 JSON 输出。

## 七、诚实边界

- UDP 无可靠投递（丢包不重传）——LAN 闭环验证正确性，可靠投递是后续层的题；
- 组播在部分网络环境被交换机禁用——实验在本机回环完成，跨机实测标注待做；
- mDNS 简化版非标准 mDNS（不实现 SRV/TXT 记录），仅供 VAP 节点发现；
- seen 集合内存态——节点重启后去重失效（持久化去重是后续题，nonce 层仍兜底防重放入账）。
