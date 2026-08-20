# VAP Phase 1 设计：传输抽象 + 选型 + 身份绑定

> 立项：外环路线的 Phase 1。三个交付：①传输 SPI 抽象（零依赖）②身份绑定规范（解决 MAJOR-5 双重身份漏洞）③传输选型报告（不引入依赖，先决策后实现）。
> 原则：抽象先行——libp2p 等外部依赖的接入放在 Phase 2，本阶段只定接口、定身份、定选型。

## 一、Transport SPI（零依赖抽象）

```js
// 所有传输实现必须满足的形状
transport = {
  name: 'http' | 'file' | (future: 'libp2p'),
  capabilities: ['dial'|'send'|'recv'|'peers'],   // 能力位：实现按能力声明
  send(envelope),          // 出站（实现决定落盘/HTTP/未来 P2P）
  recv(),                  // 入站拉取
  peers(),                 // 已知对端（可为空）
  close(),
}
```

- FileTransport：现 v0 行为（outbox/inbox 文件）；
- HttpTransport：包装已实测 HttpGateway/HttpClient——**行为零变化，只换壳**；
- 验收装置：中环全部回归用例（链转发/伪造拦截/重放 409/环路终止）在 SPI 上重跑全绿 = 抽象无损。

## 二、身份绑定规范（IDENTITY.md）

**决策（解决 MAJOR-5）：**

1. **VAP Ed25519 是唯一协议身份**——信封 from.pubKey、审计凭证、声誉记录全部绑定它；
2. **传输层密钥（如未来 libp2p PeerID）仅作握手密钥**——只用于建立连接，不出现在任何协议签名/凭证/信誉语义里；
3. 双层密钥的映射表由节点本地维护（protocolKey ↔ transportKey），**映射本身进协议层审计**（防中间人冒充）；
4. 违规检测：任何"协议身份 ≠ 信封签名者"的消息，验证门必拒（现有三闸已覆盖，Phase 1 加显式测试钉死）。

## 三、选型报告（SELECTION.md，只决策不引入依赖）

| 方案 | 优势 | 代价 | VAP 决策 |
|---|---|---|---|
| libp2p | DCUtR 打洞/中继/gossipsub 被 IPFS+以太坊2.0 真实流量磨过 | 第三方依赖、PeerID 身份体系需映射 | Phase 2 接入候选（按 IDENTITY.md 绑定）|
| 自研 NAT 穿透 | 零依赖、完全掌控 | 对称 NAT/CGNAT 无法简单打洞——陷阱 | 否决（不重造轮子）|
| HTTP 网格扩展 | 已实测、零依赖、网关升级 mesh 即可 | request-response 不适合 push/洪泛 | 现阶段主力（Phase 1-2 过渡）|

结论：**现阶段 HTTP 网格（已实测）为主力，libp2p 为 Phase 2 候选，自研否决。身份绑定规范先行。**

## 四、交付物

1. `dsh-vap/phase1/transport-spi.mjs`——SPI 定义 + createFileTransport/createHttpTransport（包装既有实现）；
2. `dsh-vap/phase1/IDENTITY.md`——身份绑定规范；
3. `dsh-vap/phase1/SELECTION.md`——选型报告；
4. `dsh-vap/phase1/tests/transport-spi.test.mjs`——SPI 无损回归（中环用例）+ 身份绑定违规检测测试；
5. `dsh-vap/phase1/experiments/phase1-experiment.mjs`——SPI 上重跑中环三实验 + 身份绑定攻击拦截。

## 五、验收标准

1. `node --test` 全绿（旧 45 个不破 + 新增）；
2. SPI 无损：中环全部行为在 HttpTransport 上重现；
3. 身份绑定：传输层密钥冒充协议身份 → 验证门必拒（有测试钉死）；
4. 零第三方依赖（libp2p 只出现在 SELECTION.md 文档里，不安装）；
5. 结构化实验输出。
