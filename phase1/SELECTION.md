# Phase 1 传输选型报告（SELECTION.md）

> 立项问题：中环之后，外环要上公网。libp2p / 自研 NAT 穿透 / HTTP 网格三条路，先决策后实现。
> 本阶段（Phase 1）只定接口、定身份、定选型，**不引入任何第三方依赖**；libp2p 只在此文档提名，
> 不安装、不 import。
> 契约依据：`phase1/DESIGN.md` §三、项目根 `ROADMAP-OUTER.md`（传输层维度）。

## 一、候选方案对比

| 方案 | 优势 | 代价 | VAP 决策 |
|---|---|---|---|
| libp2p | DCUtR 打洞、中继、gossipsub 被 IPFS 与以太坊 2.0 的真实流量打磨过；模块化、生态成熟 | 第三方依赖（与“零依赖”红线冲突）；引入 PeerID 第二套身份体系，需按 IDENTITY.md 做映射与审计 | **Phase 2 接入候选**（按 IDENTITY.md 绑定：协议身份永远用 VAP Ed25519，PeerID 仅作握手密钥） |
| 自研 NAT 穿透 | 零依赖、完全掌控；与现有文件即消息心智一致 | 对称 NAT / CGNAT 无法简单打洞，是已知陷阱；等于重造 libp2p 已磨过的轮子 | **否决**（不重造轮子） |
| HTTP 网格扩展 | 已实测（中环 HttpGateway/HttpClient 真本地回环）；零依赖；网关升级 mesh 即可 | request-response 形态不适合 push / 洪泛；公网大规模下的可达性有限 | **现阶段主力**（Phase 1–2 过渡） |

## 二、决策与理由

1. **现阶段主力 = HTTP 网格（已实测）**。
   - 证据：`vap-transport.mjs` 的 HttpGateway/HttpClient 已跑通入站/出站/链转发/防重放 409/防环，
     28 个中环单测全绿；Phase 1 的 SPI 无损回归将同样全绿。
   - 代价可控：request-response 不适配 push/洪泛的问题，用“网关 peers 异步尽力转发”补一半；
     真正的洪泛留给 libp2p 的 gossipsub（Phase 2）。
2. **libp2p = Phase 2 接入候选**，但**必须先定身份绑定**再进 Phase 2。
   - 这是 MAJOR-5 的硬性前提：PeerID ↔ VAP Ed25519 映射方案未定前，不引入 libp2p。
   - 接入时严格执行 IDENTITY.md：PeerID 只作握手密钥，不出现在协议签名/凭证/信誉语义。
3. **自研 NAT 穿透否决**。对称 NAT/CGNAT 打洞是公认陷阱，自研的收益（零依赖）远小于
   成本（重造 libp2p 已磨过的轮子且大概率打不通）。

## 三、结论

**现阶段 HTTP 网格（已实测）为主力，libp2p 为 Phase 2 候选（按 IDENTITY.md 绑定），自研否决。
身份绑定规范先行。**

## 四、Phase 1 落地动作（对应交付物）

| 动作 | 交付物 |
|---|---|
| 把 HTTP 网格抽象成统一 SPI 形状 | `transport-spi.mjs`（createFileTransport / createHttpTransport / transportConformance） |
| 身份绑定规范（MAJOR-5 前提） | `IDENTITY.md` 四决策 + 违规必拒 |
| SPI 无损回归 + 身份冒充拦截 | `tests/transport-spi.test.mjs`、`experiments/phase1-experiment.mjs` |

## 五、诚实边界

- 本报告是**文献/实测推演的选型决策**，不声称 libp2p 的 DCUtR/gossipsub 已在本项目实测——
  它们是外部项目的成熟事实，本项目要到 Phase 2 才接入并实测。
- “HTTP 网格为主力”只对**信任域/小规模联邦**成立；公网大规模下的 NAT 可达性、push/洪泛
  需求未在 HTTP 网格上实测，属 Phase 4（NAT 穿透 + 中继兜底）与 Phase 2（LAN P2P）范围。
- 自研否决不排除未来复用部分自研思路（如文件即消息的入站/出站语义），只是否掉“自研 NAT 穿透”。
