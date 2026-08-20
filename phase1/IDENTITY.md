# Phase 1 身份绑定规范（IDENTITY.md）

> 立项问题：MAJOR-5——libp2p 双重身份漏洞未决却首推。若传输层 PeerID 与协议层 VAP
> Ed25519 两套身份并存而映射未定，攻击者可在传输层持有一把密钥、在协议层冒用另一身份，
> 中间人冒充与声誉张冠李戴都无从拦截。
> 本文件把身份绑定定为四条决策，并说明违规如何在验证门三道闸内被必拒。
> 契约依据：`phase1/DESIGN.md` §二、项目根 `vap-spec.md` §1/§3、`vap-core.mjs` 的 `runGates`。

## 一、四条决策（不可变）

1. **VAP Ed25519 是唯一协议身份**。
   信封 `from.pubKey`、审计凭证、声誉记录、登记册 `registry.json`（nodeId → pubKey）全部
   绑定这一把协议密钥。协议内不存在第二套身份来源；`from.nodeId` 只是可读代号，
   其真实性完全由 `from.pubKey` 的验签结果背书。

2. **传输层密钥（如未来 libp2p PeerID）仅作握手密钥**。
   传输层密钥只用于建立/维持连接（拨号、握手、链路加密），**绝不**出现在任何协议签名、
   凭证、信誉、审计语义里。传输层“是谁在连我”与协议层“这封信是谁签的”是两件事。

3. **双层密钥映射表由节点本地维护，映射本身进协议层审计**。
   每个节点本地维护 `protocolKey ↔ transportKey` 映射；该映射作为可验证记录进入协议层
   （例如一条经协议身份签名的绑定记录），供对端交叉核验，防中间人在握手阶段偷换传输密钥。
   Phase 1 只定此规则，不实现映射落盘（libp2p 尚未接入，见 SELECTION.md）。

4. **违规检测：协议身份 ≠ 信封签名者 → 验证门必拒**。
   任何“信封声称的 `from.pubKey` 与实际签名所用私钥不匹配”的消息，验证门三道闸的身份闸
   必拒。该判定已由现有 `vap-core.mjs` 的 `verifyEnvelopeSignature` 覆盖；Phase 1 增加显式
   测试与实验，把“传输层密钥冒充协议身份必拒”钉死，防止未来接入 libp2p 时回归。

## 二、违规如何被检测（三道闸第①道）

`vap-core.mjs` 的验证门身份闸做的是确定性判据：

```
验证门身份闸：
  pubKey = envelope.from.pubKey          // 声称的协议身份
  sig    = envelope.sig                  // 实际签名
  校验 = Ed25519Verify(pubKey, canonicalJson(签名对象), sig)
  校验失败 → identity.pass = false → 整封 reject
```

关键点：签名对象 `{ v, id, ts, from.nodeId, from.pubKey, to, claim, evidence, boundary, report, nonce }`
**包含 `from.pubKey` 自身**。因此：

- 攻击者用**自己的传输层密钥**给“声称 `from.pubKey = 受害者`”的信封签名时，签名覆盖的
  `from.pubKey` 是受害者公钥；验证门用受害者公钥去验攻击者的签名 → 必然失败 → reject。
- 攻击者无法“签出”一个能通过受害者公钥验签的伪造信封——除非拿到受害者私钥（那就等于
  握有协议身份本身，已超出“冒充”范畴）。

结论：**传输层密钥永远无法冒充协议身份**，因为协议身份的唯一凭证是 `from.pubKey` 的
Ed25519 验签，而验签只认与 `from.pubKey` 配对的私钥。

## 三、与现有验证门的关系（为何“已覆盖”）

| 闸 | 职责 | 对身份绑定的作用 |
|---|---|---|
| ① 身份闸 | Ed25519 验签（`verifyEnvelopeSignature`） | 直接执行决策 4 的判据 |
| ② 军法闸 | `SIG_REQUIRED`（severity=reject）复用身份闸结果 | 把“验签失败”固化为军法 reject 原因 |
| ③ 诚实边界闸 | L2a 必须 evidence.devices 非空 | 与身份绑定正交，不重复 |

军法规则 `SIG_REQUIRED` 与身份闸共用同一验签结果（`vap-core.mjs` `runGates` 的
`effectiveCtx.sigValid`），保证“验签失败”不会因规则升级而漏判。

## 四、Phase 1 的钉死手段（可复现）

1. **单测**：`phase1/tests/transport-spi.test.mjs` 的“身份绑定”用例——构造
   `from.pubKey = 受害者` 而 `sig` 由攻击者（传输层持有者）密钥签名的信封，断言
   `verify(...).pass === false` 且 `gates.identity.pass === false`。
2. **实验**：`phase1/experiments/phase1-experiment.mjs` 的 I1——同一攻击在 SPI 上重放，
   结构化输出 `identityBindingHolds=true/false`。

## 五、诚实边界

- Phase 1 **不实现** libp2p、不实现 PeerID，决策 3 的映射表落盘与协议层审计记录是 Phase 2
  接入候选时的落地项（当前仅作规则约定）。
- 本规范不解决“传输层握手密钥本身如何被信任”的问题（即 libp2p 连接建立时的对端真实性问题），
  只保证：**无论传输层如何，协议身份的唯一性不受传输层密钥影响**。
- Ed25519 验签只能证明“消息出自持有私钥者”，不能证明“该持有者没在签自己的谎言”——后者是
  验证门军法闸与交叉复核的职责，不在身份绑定范围。
