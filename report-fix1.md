# 修复批次 1（安全歼灭战）—— 验收报告

依据：`fix-batch1-brief.md`（批次 1 = F1/F2/F6/F7 + M1-M7）与 `FIXLIST.md`。
工作区 `dsh-vap/`；Node v25.8.1；零第三方依赖（仅 `node:` 内置模块 + 相对 import）。

## 0. 验收结论

| 硬性验收 | 结果 |
|---|---|
| 全量测试全绿、现有 106 个一个不破 | ✅ `node --test` → **tests 125 / pass 125 / fail 0**（旧 106/106 + 新增 19/19） |
| 新增 `security-regression.test.mjs` 覆盖全部修复点 | ✅ `tests/security-regression.test.mjs` 19 条，F1/F2/F6/F7/M1-M7 每项至少 1 条 |
| 零第三方依赖保持 | ✅ 无 `package.json`、无 `node_modules`；全库 import 仅 `node:` 与相对路径 |
| 坏词清单保持 | ✅ 交付代码/测试/文档零命中（仅各 brief 自述清单处命中，与 `ACCEPTANCE.md` 一致） |
| 实验装置未被修复打坏（额外自检） | ✅ 11 个实验全部 `exit 0`、`allPass: true` |

## 1. 逐项修复证据

### F1 nonce 路径穿越 DoS

- `vap-core.mjs:40` `NONCE_PATTERN=/^[0-9a-f]{16}$/` + `isValidNonce`；`vap-core.mjs:217` `claimNonce` 首行即白名单，
  非法 nonce **直接 `return false`**（不 `ensureDir`、不 `openSync`）；`nonceSeen` 同样前置校验。
- `vap-transport.mjs:372-384` nonce 形状非法 → 400 `bad nonce`；`vap-transport.mjs:399-409` `claimNonce` 包 try/catch，
  异常 → 400 `bad nonce`（网关不崩）。
- 攻击面消除：单个 `POST` 带 `nonce='../../../etc/passwd'` 曾能让服务端在任意路径落文件；现在文件系统一次都不被触碰。
- 测试：`security-regression.test.mjs` 第 1、2 条（10 种越界 nonce 全拒 + `seen-nonces` 目录都不创建；网关 400 后仍能正常收合法信封）。

### F2 HTTP 网关 host 参数

- `vap-transport.mjs:223` `host = '127.0.0.1'`（安全默认不变）；`vap-transport.mjs:439` `s.listen(port, host, …)`。
- `vap-transport.mjs:327` `handle()` 的 URL base 用实际 host（`hostForUrl` 把 `0.0.0.0`/`::`/`*` 映射为回环、IPv6 加方括号）；
  `vap-transport.mjs:467` 新增 `gateway.baseUrl`。
- `phase1/transport-spi.mjs:100-130` `createHttpTransport({ host, … })` 原样透传，并暴露 `host` / `baseUrl`。
- 测试：第 6、7 条（默认仍 `127.0.0.1`；`host:'0.0.0.0'` + `port:0` 绑定成功、回环拨号 202、`baseUrl` 正确；SPI 透传）。

### F6 slash 证据 pubKey 绑定（嫁祸漏洞）

- `phase3/endorse-core.mjs:457` 新增 `verifyDoubleSignEvidenceBound(evidence, expectedPubKey)`：
  在原 `verifyDoubleSignEvidence` 之上要求**证据签名公钥 === 期望公钥**；比较前两侧统一规范化为 spki DER base64
  （KeyObject / PEM / base64 三种写法等价），任一侧不可解析则退回严格字符串相等。
- `phase6/vap-to-membership.mjs:460-478` slash 分支：取 `node.peerMap.get(tx.nodeId)`（roster 注册公钥），
  不在 roster → reject；绑定失败 → reject（`phase6:474` 明确区分"证据不可验"与"公钥未绑定"）。
- `phase6/vap-to-membership.mjs:601-612` `expelByEquivocation` 举报入口同样先绑定再打包。
- 攻击面消除：攻击者用自己的密钥造一份**真实可验**的双签证据、把 `evidence.nodeId` 写成无辜者即可除名无辜者；现在必被拒。
- 测试：第 8、9 条（嫁祸证据自身 `verifyDoubleSignEvidence===true` 但判定 reject 且理由指明公钥未绑定；
  真作恶者证据仍 `pass:true` —— 证明修复没有把真除名打死）。

### F7 endorsements 类型守卫 + 判定链路异常边界

- `phase6:405-413` `endorsements` 存在但非数组 → reject（旧代码 `for (const e of tx.endorsements || [])` 对数字直接抛
  `TypeError: is not iterable`，一笔畸形交易可崩掉全部诚实节点）；`phase6:417-421` join 要求 endorsements 为数组。
- `phase6:206-218` credential 结构守卫：非对象或缺 `.work` → reject；`phase6:193-204` `joinSubjectOf` 的 `credentialIdOf` 包 try/catch。
- 异常边界：`checkLaws`（`phase6:316-328`）、`checkMembershipTx`（`phase6:388-399`）、`safetyRule`（`phase6:689-697`）、
  `vote`（`phase6:823-839`）全部包 try/catch —— 异常一律 `pass:false` / `voted:false`，绝不外抛。
- 测试：第 10、11、12 条（4 种非数组 endorsements 全部 `doesNotThrow` + reject；`safetyRule→vote` 对含畸形交易的
  已签名提案只拒投；`null/42/'x'/[]` 进 `checkLaws`/`checkMembershipTx` 只判拒；credential 缺 work → reject 不抛）。

### M1 envelope.id 路径穿越

- `vap-transport.mjs:28` `ENVELOPE_ID_PATTERN=/^evt-[0-9a-f]{16}$/`（`strictEnvelopeId` 默认 true）；
  `vap-transport.mjs:30` 兼容模式 `SAFE_NAME_PATTERN=/^[0-9A-Za-z._-]{1,128}$/` 且禁 `..`。
- `vap-transport.mjs:385-391` 不合白名单 → 400 `bad envelope id`（**两种模式都杜绝路径穿越**，差别只是是否允许自定义 id）。
- 测试：第 3、4 条（`../../evil`、`evt-XYZ` 等 6 种 → 400，上层目录无 `evil.json`、`inbox-http` 为空；
  兼容模式允许 `evt-legacy-id` 但仍拒 `../../evil`）。

### M2 rotate 新钥校验

- `phase6:448-453` rotate 分支 try/catch `coercePublicKey(tx.newPubKey)` → 失败 reject（`not a usable public key`）。
- `phase6:557-566` `rotateKey` 发起侧同样校验（不给共识层递非法钥）。
- `phase6:258-286` `applyRosterChange` 兜底：h+2 生效时若新钥不可解析则跳过本次轮换并记
  `membershipLog{kind:'rejected'}`，不抛异常炸掉生效流程。
- 测试：第 13 条（`'not-a-key'`/`'AAAA'`/`''` 发起被拒；手工绕过 `rotateKey` 的非法 rotate 交易判定被拒；合法新钥仍可轮换）。

### M3 relay 注册白名单 + 顶替认证 + 帧限速

- `phase4/relay-server.mjs:31` `NODE_ID_PATTERN=/^[0-9a-zA-Z_-]{1,64}$/`；`:156-163` 非法 nodeId 拒绝注册（计
  `rejectedRegistrations`，不进转发表）。
- `:164-176` 顶替认证：`requireTakeoverAuth`（默认 true）下同名顶替必须携带与旧注册者一致的 pubKey，
  不匹配 → `rejectedTakeovers += 1` 且**旧连接保持在表内**（知道 nodeId 不再能抢别人的信封）。
- `:28` `DEFAULT_MAX_FRAMES_PER_SEC=1000`；`:141-153` 每连接 1 秒滑动窗口计数，超限 `rateLimited += 1` + `socket.destroy()`。
- 转发表结构由 `nodeId → socket` 改为 `nodeId → { socket, pubKey }`（`registry()` 返回值形状不变）。
- 测试：第 14、15、16 条（5 种越界 nodeId 全拒且 `registry()` 为空；顶替被拒后信封仍到旧连接、攻击者零截获、
  携带正确 pubKey 的重连仍可顶替；`maxFramesPerSec:5` 下 40 帧洪泛 → 断连且 `rateLimited>=1`）。

### M4 consume 仅 pass 登记

- `vap-core.mjs:632` `if (result.pass && from && from.nodeId && from.pubKey) writeRegistryEntry(...)`。
- 攻击面消除：旧代码对**任何**信封（含验签失败/军法拒绝的伪造件）都写 `registry.json`，攻击者可用必被拒的信封
  污染登记册（此后 `FROM_KNOWN` 对其恒真）。
- `vap-core.mjs:375-383` `writeRegistryEntry` 保持"读→合并→单次 atomicWrite"，并标注 `TODO(M4-并发)`（多进程写侧互斥属批次 2）。
- 测试：第 17 条（坏边界信封与无签名伪造件都不创建 `registry.json`；通过的信封照常首封自注册）。

### M5 heartbeat/complete taskId 白名单

- `vap-core.mjs:41` `TASK_ID_PATTERN=/^[0-9a-zA-Z_-]{1,64}$/`；`:539` `heartbeat`、`:551` `complete` 非法即抛；
  `:388-391` `lockPathFor` 内层再校验（任何调用路径都过闸）；`claimTask`/`adoptIn` 跳过畸形 taskId。
- 测试：第 18 条（6 种越界 taskId `heartbeat`/`complete` 均抛 `invalid taskId`、上层目录无 `evil.lock`/`evil.json`；
  合法 taskId 认领→心跳→完成全流程仍通）。

### M6 ledgerFile nodeId 安全

- `phase5/vap-to.mjs:157` 新增 `ledgerFileNameFor(nodeId)`：白名单内 → `ledger-<nodeId>.jsonl`（旧行为兼容），
  越界 → `ledger-sha256-<sha256hex(nodeId)>.jsonl`；`:226` 构造期使用。
  取 FIXLIST M6 的"sha256 文件名**或**白名单"两者并用：不可控字符永远进不了路径，同时不破坏既有可读账本命名。
- `phase5/vap-to.mjs:496` 账本记录行内新增 `nodeId` 字段（文件名是摘要时仍能认出账本归属）。
- 测试：第 19 条（`nodeId='../evil'` → `path.dirname(ledgerFile)===ledgerDir`、basename 为摘要名、
  3-chain 提交后账本行 `nodeId==='../evil'`、`ledgerDir` 内只有摘要文件、上层目录无 `evil.jsonl`）。

### M7 网关对端认证（验签前置）

- `vap-core.mjs:131` `verifyEnvelopeSignature` 改为导出（网关复用同一份验签逻辑，不复制信封判定）。
- `vap-transport.mjs:392-398` `requireInboundSignature`（默认 true）下入站信封先验 Ed25519 签名，
  失败 → 403 `signature verification failed`；**在 `claimNonce` 之前**，故验签失败既不落盘也不消耗 nonce。
- 语义边界（诚实标注）：网关只验身份闸的签名，不跑军法闸与诚实边界闸 —— "网关只搬运不裁决军法"不变。
- 测试：第 5 条（无签名 → 403、篡改内容 → 403、`inbox-http` 为空、`seen-nonces` 无该 nonce；原封仍 202 落盘）。

## 2. 为保留旧测试语义所做的最小调整（诚实标注）

修复后的安全默认与 4 条旧测试钉住的旧（不安全）语义直接冲突：不安全语义正是本批要歼灭的对象，
故采取"**安全默认 + 旧用例显式声明兼容模式**"，旧用例断言一字未改、数量不变（106 条全在、全绿）：

| 文件 | 用例 | 调整（仅构造参数） |
|---|---|---|
| `tests/vap-transport.test.mjs:403` | 跨节点验证门：无签名伪造经 HTTP 被三闸拦截 | `requireInboundSignature:false` |
| `tests/vap-transport.test.mjs:640` | 组网：同 envelopeId 不重复转发（手工 id `evt-dup`、无签名） | `strictEnvelopeId:false, requireInboundSignature:false`（两端网关） |
| `phase1/tests/transport-spi.test.mjs:203` | Http SPI：无签名伪造经 SPI 被三闸拦截 | `requireInboundSignature:false` |
| `phase4/tests/relay.test.mjs:177` | 同名 nodeId 重复注册 → 后注册者顶替 | `requireTakeoverAuth:false` |

对应实验装置同步：`experiments/vap-ring2-experiment.mjs` R2、`phase1/experiments/phase1-experiment.mjs` S2。
兼容模式并非"关掉安全"：兼容模式下 `SAFE_NAME_PATTERN` 仍禁 `/`、`\`、`..`，路径穿越在任何模式下都不成立。
安全默认（403 / 严格 id / 顶替认证）由 `tests/security-regression.test.mjs` 正面钉死。

## 3. 实测记录

```
node --test           → tests 125 / suites 0 / pass 125 / fail 0
（其中 tests/security-regression.test.mjs：19 / 19 pass）
11 个实验装置          → 全部 exit 0，allPass: true
第三方依赖             → package.json 0 个、node_modules 0 个、非 node:/非相对 import 0 处
坏词清单               → 交付代码/测试/本报告 0 命中
```

## 4. 诚实边界与遗留

1. M4 并发：`registry.json` 仍是读-改-写，多进程并发写可能后写覆盖先写（已标 `TODO(M4-并发)`，写侧互斥属批次 2）。
2. M7 只做签名前置，不做静态 peer 白名单/双向认证 —— "网关只搬运不裁决军法"语义按简报保留；
   更强的对端认证（mTLS / 静态 peer 名单）未在本批范围内。
3. M3 顶替认证是"pubKey 相等"级别的绑定（对照旧注册者自称的 pubKey），不是挑战-应答证明持私钥；
   真正的持钥证明需要中继侧签名挑战，属后续批次。
4. M6 采用"白名单 + 摘要"混合命名：已有可读账本文件名不变，只对越界 nodeId 改摘要名。
5. 批次 1 之外（F3 私钥落盘、F4 README、F5 LICENSE、M8-M24）未动，按 FIXLIST 批次计划推进。
