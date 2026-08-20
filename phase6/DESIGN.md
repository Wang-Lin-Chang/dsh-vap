# VAP Phase 6 设计：动态成员 + 军法上链（收官）

> 立项：外环最后一块拼图。Phase 5 的 roster 是静态 4 节点；Phase 6 让成员可进出、密钥可轮换、军法成为共识级规则。
> 设计约束继承 Phase 5 交叉审计推演结论：延迟生效保持 2/3 交集；equivocation=密码学铁证=自动除名；窄车道走总序。

## 一、成员变更（membership change）

### 三种变更类型（窄车道交易 type=membership）

1. **加入（join）**：新节点提交资格凭证（gen-k，回验到创世锚）+ 现有成员 2/3 背书 → 生效；
2. **除名（expel）**：来源两途——equivocation 双签证据（自动）或主动退出（自愿）；证据本身是密码学铁证；
3. **密钥轮换（rotate）**：id 不变、pubKey 换新——变更交易带旧钥签名 + 新钥声明。

### 延迟生效（核心安全机制）

- 变更交易提交于高度 h → **h+2 生效**（延迟 2 块）：
  - 生效前：旧 roster 照常推进（交集保证）；
  - 生效时点：所有节点在同一高度原子切换 roster；
  - 新 roster 的 f 重算：f' = floor((n'−1)/3)。
- 除名特殊：equivocation 证据提交后，作恶者**立即**失去投票权（其签名从提交高度起不计入），roster 表更新延迟 2 块（防反射攻击的窗口由"签名不计入"封死）。

## 二、军法上链（laws as consensus predicates）

- laws.json 的可判定规则（SIG_REQUIRED / BOUNDARY_VALID / SUMMARY_BOUND / EVIDENCE_L2A / FROM_KNOWN + no-equivocation）成为**投票前谓词**：不满足的信封提案 0 票（诚实节点拒投）；
- **slash 证据上链**：背书者 equivocation → 双签证据作为窄车道交易上链 → 自动除名 + 留痕可审计；
- 不可判定规则（诚实边界的模糊部分）不进共识，留审计层（诚实标注：军法上链只上"可判定"部分）。

## 三、实验（experiments/phase6-experiment.mjs，n=4 起）

- **D1 加入生效**：新节点持资格凭证申请 → 2/3 背书 → 提交 → h+2 后 roster=5 → 5 节点共识继续推进；
- **D2 除名生效**：节点作恶（equivocation）→ 双签证据上链 → 其签名立即不计入 → h+2 后 roster=3 → 3 节点（f=0）继续推进；
- **D3 密钥轮换**：节点换 pubKey（旧钥签变更交易）→ h+2 后新钥生效 → 旧钥签名被拒、新钥签名有效；
- **D4 军法上链**：invalid 信封提案 → 投票前 0 票不进 QC + 若提案者是背书者且 equivocation → slash 证据上链除名；
- **D5 延迟生效窗口**：变更提交后、生效前，旧 roster 照常推进 2 块（无中断）；
- **D6 灰度清单**：`DEPLOYMENT.md`——公网部署步骤清单（节点密钥、中继配置、创世锚发布、监控指标、回滚方案），**诚实标注：全部本机模拟，公网未实测**。

## 四、交付物

1. `dsh-vap/phase6/vap-to-membership.mjs`——扩展 vap-to.mjs 的成员变更与军法谓词（复用零改动）；
2. `dsh-vap/phase6/tests/membership.test.mjs`；
3. `dsh-vap/phase6/experiments/phase6-experiment.mjs`——D1-D5；
4. `dsh-vap/phase6/DEPLOYMENT.md`——D6 灰度清单；
5. `dsh-vap/phase6/P6-REPORT.md`。

## 五、验收标准

1. D1-D5 全达标；2. 零第三方依赖；3. 复用模块零改动；
4. 除名后签名立即不计入（延迟只作用于 roster 表）；
5. 军法投票前拒（0 票有测试）；
6. 延迟生效窗口内旧 roster 无中断推进（有测试）；
7. 结构化 JSON + 灰度清单文档。

## 六、诚实边界

- 公网灰度是清单不是实测（D6 文档级）；
- 动态成员在大型网络的复杂性（reconfiguration 风暴、双 roster 过渡）未覆盖——小规模信任域简化版；
- 军法只上链"可判定"部分，模糊部分留审计层；
- ≥f+1 共谋边界同 Phase 5。
