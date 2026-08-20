# VAP Phase 3 设计：分布式 2/3 背书（信任聚合）

> 立项：把 E38 的单点 2/3 门限签名升级为真正的分布式多节点背书（Quorum Certificate）。
> 衔接：背书者资格复用 Phase 0.5 凭证代际链；网络层复用 Phase 2 lan-peer；信封与三闸复用 vap-core 零改动。
> 正名（路线图 MAJOR-3 处理）：E38 是单点门限签名，本阶段交付的是分布式多节点背书——不冒认。

## 一、背书协议三件套

```
Envelope（vap-core 既有）→ 过三闸（验证门先行）
Endorsement = { nodeId, pubKey, sig }   # sig = Ed25519(私钥, canonicalJson(envelope))
QuorumCertificate(QC) = {
  envelope,
  endorsements: [ Endorsement × m ],
  rosterSize,          # 背书者总数 n
  threshold: ceil(2n/3)
}
```

## 二、规则

1. **资格**：背书者必须持有 gen-k 凭证（k 由 roster 约定，装置内 k=0 起）——复用 phase0.5 的凭证资格链（验签+重放验证通过才算有资格）；
2. **外部有效性谓词**：背书者只对"过三闸"的信封签名（不过三闸 → 拒签并留痕）；
3. **QC 成立**：去重后的有效背书数 ≥ ceil(2n/3)；
4. **双签检测**：同一背书者对同一信封 id 的**不同内容**签名 → 冲突证据留痕（两种内容 + 两个签名并排，任何第三方可验）；
5. **verifyQC**：逐签验签 + 签名者互异 + 数量达标 + 信封过三闸 + 资格链验证。

## 三、拜占庭容错语义（诚实标注）

- f = floor((n−1)/3)：≤f 个拜占庭背书者（拒签/伪造/双签）时，QC 仍能成立或诚实停摆；
- >2n/3 恶意 → 系统无法区分（诚实标注：不是防，是数学边界）。

## 四、实验（experiments/phase3-experiment.mjs）

- **E1 正常背书**：4 节点 roster，3 个有资格节点签名 → QC 成立；
- **E2 拜占庭拒签**：1 节点拒签（f=1）→ 剩余 3 签 ≥3（ceil(8/3)=3）→ QC 仍成立；
- **E3 伪造背书**：伪造签名混入 → verifyQC 拒绝；
- **E4 双签检测**：1 节点对冲突内容双签 → 冲突证据留痕且可验；
- **E5 资格不足**：无 gen 凭证节点签名 → 不计入、QC 不足时诚实失败；
- **E6 外部有效性**：不诚实信封（伪签名）→ 有资格背书者全部拒签 → 拿不到 2/3。

## 五、交付物

1. `dsh-vap/phase3/endorse-core.mjs`——endorse()/collectQC()/verifyQC()/detectDoubleSign()（零第三方依赖，复用 phase0.5 资格链）；
2. `dsh-vap/phase3/tests/endorse-core.test.mjs`——QC 聚合/验签/资格/双签单测；
3. `dsh-vap/phase3/experiments/phase3-experiment.mjs`——E1-E6；
4. `dsh-vap/phase3/P3-REPORT.md`。

## 六、验收标准

1. E1 QC 成立、E2 f=1 容错、E3 拒绝、E4 证据可验、E5 不计入、E6 拿不到 2/3；
2. 零第三方依赖；vap-core/phase0.5 零改动（只 import 复用）；
3. QC 验证必须重放验证信封三闸（不信任背书者声称）；
4. 双签证据任何第三方可验（证据 = 两签名 + 两内容）；
5. 结构化 JSON 输出。

## 七、诚实边界

- roster 是静态的（装置内预设 4 节点）——动态成员是 Phase 6 的题；
- 背书者资格链的 gen-k 深度与 roster 的对应关系（多少 gen 算合格）装置内固定，公网参数未定；
- 网络层（P2P 洪泛背书请求）在装置内以内存调用模拟——真实 UDP 洪泛背书是 Phase 4 的题；
- QC 不产总序（两个 QC 可并存分叉）——共识是 Phase 5 的题，本阶段只有"认可"，没有"排序"。
