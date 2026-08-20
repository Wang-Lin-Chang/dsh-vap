# VAP v0 插件核心 —— 设计说明与验收报告

## 1. 模块划分

单文件 `vap-core.mjs`，按职责分为六块（零第三方依赖，仅 node: 内置模块）：

| 区块 | 职责 | 对应 spec |
|---|---|---|
| 常量与默认军法 | `constants`、`DEFAULT_LAWS`（5 条规则） | §3 |
| `canonicalJson` | 键按字典序递归排序、无空白的规范化 JSON | §1 签名规范 |
| Ed25519 信封 | `signPayload` / 验签 / 密钥转 base64（SPKI DER） | §1 |
| 军法判定器 | `LAW_CHECKERS` 按 rule.id 分发，severity 由规则数据决定 | §3 |
| 节点 `createVapNode` | register / send / verify / claimTask / heartbeat / complete / adopt | §2、§4 |
| 脑进程 `createBrain` | consume（三道闸 + verdict + done）/ adopt | §2、§3 |

## 2. 关键判定规则实现

- **签名**：`sig = Ed25519(私钥, canonicalJson({v,id,ts,from.nodeId,from.pubKey,to,claim,evidence,boundary,report}))`。`from` 展平为带点键（`from.nodeId` / `from.pubKey`），不含 sig 自身，与 brief 纪律 4 一致。验签用信封内 `from.pubKey`（SPKI DER 的 base64）重建公钥。
- **三道闸**（`runGates`）：
  - ① 身份闸：Ed25519 验签，失败即 `reject` + tampered 语义（记录 `identity.reason`）。
  - ② 军法闸：读 `root/laws.json`（缺失则回退 `makeLaws()`），逐条走 `LAW_CHECKERS[rule.id]`；`severity === 'reject'` 的失败才导致闸失败，`warn`（FROM_KNOWN）不拦账。
  - ③ 诚实边界闸：`boundary === 'L2a'` 且 `evidence.devices` 为空时失败，并建议降级 `L0`。
  - 三闸全过才 `pass`；`SIG_REQUIRED` 军法规则复用身份闸的验签结果，避免重复验签。
- **规则是数据**：`makeLaws(overrides)` 对 `DEFAULT_LAWS` 做按 id 合并（可改 severity / 增删规则），判定随 `laws.json` 变化而无需改代码（测试用「SUMMARY_BOUND 降为 warn」验证）。
- **租约**：`claimTask` 用 `fs.openSync(lock, 'wx')`（O_EXCL）抢锁，锁内容 `nodeId:pid:startSec`；`heartbeat` 更新内容并 `utimesSync` 触 mtime。
- **三证据收养**：`adopt` 扫描 `dead-letter/task-*.lock`，逐条判：
  1. pid 死（`process.kill(pid, 0)` 抛 ESRCH 即死，EPERM 视为存活）；
  2. startSec 比对（`now - startSec > LEASE_TIMEOUT_SEC`，内容超时）；
  3. 租约超时（`now - lock.mtimeMs > LEASE_TIMEOUT_MS`）。
  三证据齐备才把任务重派回 `inbox/` 并清理死现场。

## 3. 验收对照（spec §7）

1. **异构节点互动**：`createVapNode` 节点 + `createBrain` 脑进程在同一工作区互动（send → outbox → consume → done），租约测试用两个节点竞争同一任务，印证「5 函数契约是框架无关的协议实现」。
2. **四种伪造拦截**：无签名、坏边界、超长战报、L2a 无证据 四类伪造在单测中全部被验证门 reject（对应 4 个用例）。
3. **崩溃收养**：死现场（pid 不存在 + startSec/mtime 超时）三证据齐备后被 `adopt` 重派成功；存活或未超时则拒收养（2 个用例）。
4. **单测全绿 + 零依赖 + 规则可升级**：`node --test` 17/17 通过；无 package.json、无 node_modules；`makeLaws(overrides)` 改 laws.json 后判定随之变化（1 个用例）。

## 4. 已知缺口（诚实列出，不冒认）

- 无 nonce → 防重放未做（spec §6 已声明为已知缺口）。
- 单机共享文件系统 → 跨机需共享盘/网关，未实测不声称。
- Ed25519 只保证「消息出自持私钥节点」，不防节点签自己的谎言；内容裁决交给验证门与后续交叉复核。
- 信封未压缩，大 payload 依赖 `evidence.digest` 冷引用（已约定，未强制）。

## 5. 纪律自检

- 零第三方依赖：仅 node: 内置模块与相对路径 import。
- 原子写一律 tmp+rename；锁一律 O_EXCL。
- 每处失败路径返回明确原因；reject 的 verdict 带 `reasons` 数组（含身份闸/军法闸/边界闸逐条原因）。
- 交付文件未出现坏词清单中的禁用词。

## 6. 结论

三件交付物（`vap-core.mjs`、`laws.json`、`tests/vap-core.test.mjs`）完成，`node --test` 全绿，满足 spec §1-§7 与 brief 全部纪律约束。
