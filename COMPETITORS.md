# VAP 竞争格局调研报告

> 调研日期：2026-08-20 ｜ 方法：agent-reach 开源生态多轮检索
> 结论：**竞争者真实存在（微软/Google/W3C 都在场），但我们的差异化清晰可守。**

## 一、竞争者全景（按与 VAP 的距离排序）

| 项目 | 背景 | 做什么 | 与 VAP 的关系 |
|---|---|---|---|
| MCP | Anthropic | agent↔工具/资源接入 | 正交（我们不做工具接入）|
| A2A | Google（已入 Agentic AI Foundation）| agent↔agent 任务委托 | 竞争维度：agent 间消息，但信任模型=相信对方输出 |
| ACP | Zed/IBM | agent↔客户端 | 正交 |
| ANP / Agora / UCP | 社区/联盟 | agent 身份（DID）/寻址/路由 | 竞争维度：身份层；已有 arxiv 安全威胁建模论文 |
| **微软 IATP** | microsoft/agent-governance-toolkit | agent 间信任协议 + agent-mesh + CSA ATF 治理集成 | **最强竞争者**（组织级、治理全家桶）|
| **PIC Standard** | 社区（fossunited）| Provenance & Intent Contracts（来源与意图契约，fail-closed evidence）| **理念最接近 dsh-anchor**（意图预承诺+对账）|
| **VACT-P** | mindify-ai | Verifiable Agent Coordination and Transaction Protocol | 名字同款，验证 agent 协调与交易 |
| ratify-protocol | identities-ai（Go）| agent 凭据验证 | 竞争维度：验证层 |
| W3C agent-identity 组 | W3C | 讨论"Trust Accumulation for Agent Credentials" | **与我们 Phase 0 同题**（行为历史/信任累积），但仍处邮件列表讨论阶段 |

## 二、竞争者的共同盲区（我们的机会）

1. **全是"规范+参考实现"，没有"实测纪律"**：没有一家像 VAP 这样每个声称带实验装置编号+对照组（106 测试 + 11 装置）。PIC/IATP/VACT-P 的 README 里找不到"实验账本"。
2. **信任锚 = 身份/证书，不是行为历史**：IATP 用 DID/证书链；W3C 在**讨论**信任累积但无落地。VAP 的 Phase 0/0.5 是**已实测**的行为历史稀缺性 + 资格链自举（伪造 300/300 拦截、杠杆 127 倍）。
3. **验证 = 格式/证书验证，不是交叉审计**：PIC 的 fail-closed evidence 是意图对账（VAP 的 dsh-anchor 早已实测且理念一致）；**没有一家做多路独立审计+独立复核轮的交叉复核（交叉审计）**。
4. **崩溃模型缺失**：没有一家做"文件即消息+三证据收养"的崩溃隔离（megamesh 39 装置独有：kill -9 后 40/40 完成、杀主席换脑 1641ms）。
5. **共识层空缺或中心化**：IATP 的 mesh 偏治理服务（微软云语境）；VAP 是零依赖自研锁步 QC 链（总序/防分叉/防双花/动态成员全部实测）。

## 三、VAP 的真实优势（可守的差异化）

1. **实测纪律**：106 测试 + 11 装置 + 对照组 + 诚实边界——竞争者抄不走，因为实验数据要一台一台跑；
2. **行为历史稀缺性**：W3C 还在邮件列表讨论，VAP 已装置实测；
3. **崩溃收养**：megamesh 独有；
4. **交叉审计原语**：唯一把"独立复核轮"做成协议组件的；
5. **零依赖自研共识**：从信封到锁步 QC 全链零第三方依赖。

## 四、VAP 的弱点（诚实）

1. 生态位：微软/Google/Anthropic 有分发渠道，VAP 0 star；
2. 成熟度：组织级维护 vs 个人项目；
3. 命名：VACT-P 已占"Verifiable Agent"词组——公开时需差异化命名或定位措辞。

## 五、定位建议

**竞争者在做"规范"，VAP 在做"实测的信任机器"。** 对外定位一句话：
"不是又一套 agent 协议规范，而是一套**每个能力都带实验装置编号与对照组的可验证信任栈**——规范可以抄，实测记录抄不走。"
