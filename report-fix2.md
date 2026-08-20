# 修复批次 2（部署歼灭战）—— 完成报告

工作区 `dsh-vap/`；依据 `fix-batch2-brief.md` + `FIXLIST.md`。
结论：F3 + M8-M13 全部完成，验收硬性指标全绿。

---

## 验收对照

### 1. 全量测试全绿（旧 125 一个不破）

- `node --test` → **tests 147 / pass 147 / fail 0**（旧 125 + 新增 22）。
- 11 个实验装置全部 `exit 0`：`phase5` T1-T6 全 true、`phase6` 全 true，
  根目录 3 个 + phase0/0.5/1/2/3/4 各 1 个均 exit 0。

### 2. 新增 tests/deploy-regression.test.mjs

22 条，逐条覆盖：

| 覆盖点 | 测试 |
|---|---|
| key-store 存取/加载/chmod | `F3 key-store：saveKey 落盘 PKCS8、loadKey 读回等价、无文件返回 null`；`safeNodeId 使用 sha256 摘要` |
| persistKeys + rotate 新钥落盘 | `createVapNode persistKeys`；`createNode persistKeys`；`createMembershipNode rotateKey 生效后新私钥落盘` |
| config env 覆盖 | `M8 loadConfig：JSON 合并 + VAP_* env 覆盖`；`默认值含 tmpdir`；`createHttpGateway config 覆盖` |
| logger 轮转 | `M9 logger：JSON line 格式 + 1MB 轮转为 .1（只保留一代）` |
| bin 信号优雅退出 | `M10 vap-relay/gateway/node 可启动并优雅退出（exit 0）`；`process-guard uncaughtException 兜底 exit 1` |
| health 真实状态 | `M11 gateway health 可写探测+errors/lastError/积压`；`relay health+旁路 /health`；`vap-to health()` |
| phase5/6 restore 补全 | `M12 phase5 restore QC 回放+votedViews 置空+mempool 丢弃`；`phase6 restore 成员状态回放（重启后除名者签名仍不计入、membership nonce 仍去重）`；`autoRestore` |
| ledgerDir 默认 tmpdir | `M13 createNode 缺省 ledgerDir 落 tmpdir`；`signAuditTrail 缺省 trailDir 落 tmpdir` |

### 3. 三个 bin 独立启动并优雅退出

`bin/vap-relay.mjs` / `bin/vap-gateway.mjs` / `bin/vap-node.mjs` 均可独立启动
（打印 `... listening ...`）并优雅退出（exit 0）。deploy 测试内真实 `spawn` → 等待就绪 →
优雅退出 → 断言 exit 0。

### 4. 零第三方依赖 + 坏词清单

- `package.json` 无 `dependencies`/`devDependencies`，无 `node_modules`；
  全库 import 仅 `node:` 与相对路径（grep 核验）。
- 词检规范（仓库禁用词清单）在交付代码/注释/测试/文档零命中（grep 核验）。

---

## 逐项实现证据（文件 / 行 / 测试）

### F3 私钥落盘与加载

- **`key-store.mjs`（新，零依赖）**
  - `safeNodeId`（L18）= `sha256hex(nodeId)`，防路径穿越（呼应 M6）。
  - `saveKey`（L32）：`root/keys/<safeNodeId>.key` 写 PKCS8 PEM；原子写后
    `fs.chmodSync(file, 0o600)`（Windows no-op，注释标注）。
  - `loadKey`（L62）：读文件 `crypto.createPrivateKey` 重建 KeyObject；无文件/损坏返回 null。
  - 测试：`F3 key-store` 两条（存取等价、越界 nodeId 不越出 keys 目录）。
- **`vap-core.mjs` L464-500**：`createVapNode` 增 `persistKeys`；缺 keyPair 且 persistKeys →
  `loadKey` 命中用持久身份，否则生成并 `saveKey`；注入 keyPair 也落盘。
  测试：`F3 createVapNode persistKeys`。
- **`phase5/vap-to.mjs` L202-239**：`createNode` 增 `persistKeys`（load→use→save）。
  测试：`F3 createNode persistKeys`。
- **`phase6/vap-to-membership.mjs` L176-183 + L291**：`createMembershipNode` 透传 persistKeys；
  `applyRosterChange` 换钥生效时 `saveKey` 新私钥（原子切换）。
  测试：`F3 createMembershipNode rotateKey 生效后新私钥落盘`。

### M8 配置外部化

- **`config.mjs`（新）**
  - `defaultConfig()`：gatewayHost/gatewayPort/relayHost/relayPort/multicastAddr/multicastPort/
    multicastInterface/ledgerDir/trailDir/timeouts。
  - `loadConfig({path,env})`（L85）：JSON 合并 + `VAP_*` env 覆盖（数值/布尔强制转换，
    键映射 `VAP_GATEWAY_HOST` 等，timeout 走 `VAP_PEER_FORWARD_MS`）。
  - `defaultLedgerDir()`/`defaultTrailDir()` = `os.tmpdir()` 下。
- **`vap-transport.mjs` L221-243**：`createHttpGateway` 增 `config` 参数覆盖 host/port 默认值。
  测试：`M8 loadConfig` 两条 + `M8 createHttpGateway config 覆盖`。

### M9 日志体系

- **`logger.mjs`（新）**
  - `createLogger({file,level,component,maxBytes})`（L29）：JSON line `{ts,level,component,msg}`
    + extra 合并；file 超 1MB 轮转 `<file>.1`（只保留一代，再超覆盖 .1）；
    无 file 时 error 级 `console.error`；`silentLogger`（L90）。
- **`vap-transport.mjs` L226-241**：网关 `log` 默认空操作改为接 `silentLogger`（error 级静默
  console.error），`emitLog` 统一路由；relay/gateway/node bin 关键路径接 `createLogger`。
  测试：`M9 logger 轮转`。

### M10 进程管理

- **`package.json`（新）**：name=vap / version=0.2.0 / type=module / engines node>=18 /
  bin（vap-relay/vap-gateway/vap-node）/ scripts（test/relay/gateway/node）。测试：`M10 package.json`。
- **`bin/process-guard.mjs`（新，L33）**：`installProcessGuards({logger,onStop})` →
  SIGINT/SIGTERM 顺序 stop/close 后 `exit 0`；`uncaughtException`/`unhandledRejection` 记日志 `exit 1`；
  stdin `shutdown` 一行 = Windows 等价优雅退出通道。
- **`bin/vap-relay.mjs`**：组装 `createRelayServer`（config+logger+startHealth+信号兜底）。
- **`bin/vap-gateway.mjs`**：组装 `createHttpGateway`（config+logger+信号兜底）。
- **`bin/vap-node.mjs`**：组装 `createMembershipNode`（persistKeys+ledgerDir+autoRestore）
  + 旁路 `/health` + 信号兜底。
  测试：三 bin 启动/优雅退出（exit 0）+ `process-guard uncaughtException 兜底 exit 1`。

### M11 监控

- **`vap-transport.mjs` L259-309**：`health({detail})` ok = 目录可写探测（真实状态，不再恒 true）；
  detail 增 `errors`/`lastError`/`inboxBacklog`/`outboxBacklog`；错误路径 `recordError` 计数。
  测试：`M11 gateway health`。
- **`phase4/relay-server.mjs` L132-147 + L247-283**：`health()`（connections/totalBytes/
  forwardedBytes/forwarded/errors/uptimeMs）+ 旁路 HTTP `/health`（node:http 仅回环，
  `healthPort` 可选，默认 null 不启用，不破坏旧 relay 测试）。
  测试：`M11 relay health + 旁路 /health`。
- **`phase5/vap-to.mjs` L646-656** + **`phase6/vap-to-membership.mjs` L949-962**：
  `createNode`/`createMembershipNode` 增 `health()`：height/view/committed/rosterSize/f/threshold/
  qcCount/expelled。测试：`M11 vap-to createNode health()`。

### M12 restore 补全

- **`phase5/vap-to.mjs` L585-644**：`restore()` 补回放 ——
  - `blocks`/`qcByView`/`qcByBlockHash`/`highestQC` 从账本已提交前缀重算（`restored:true` 锚点，
    QC 签名不在账本中，不猜不伪造）；
  - `votedViews` 置空（诚实重投）；`pendingTxs`/`pendingNonces`/`activeProposal` 丢弃（mempool 丢弃）；
  - L371 `propose` 不把 `restored` 锚点当可验 justify 携带（否则对端 verifyQC 必失败），
    基线仍由 parentHash（= highestQC.blockHash）延续。
  测试：`M12 phase5 restore`；phase5 实验 T6 重启恢复继续推进仍 true。
- **`phase6/vap-to-membership.mjs` L879-946**：重写 `restore()`（`baseRestore` + `replayMembership`）——
  - 从 `node.committed`（已校验前缀）回放 `membershipNonces`/`expelled`/`pendingChanges`
    （按 activateHeight）/`membershipLog`；
  - `applyReplayRosterChange` 重建 roster/peerMap/n/f/threshold（rotate 更新 pubKey，不重建私钥）。
  - L176-177/L964：`createNode`/`createMembershipNode` 增 `autoRestore`（启动即恢复）。
  测试：`M12 phase6 restore`（重启后除名者签名仍不计入 + membership nonce 仍去重）、
  `M12 autoRestore`。

### M13 ledgerDir/TRAIL_DIR 默认

- **`phase5/vap-to.mjs` L217/L254**：`ledgerRoot = ledgerDir || defaultLedgerDir()`
  （`os.tmpdir()/vap-ledger`），绝不默认源码树。测试：`M13 createNode 缺省 ledgerDir 落 tmpdir`。
- **`phase0.5/bootstrap-forge.mjs` L38/L42**：`TRAIL_DIR = defaultTrailDir()`
  （`os.tmpdir()/vap-trails`），移除 `__dirname` 默认。测试：`M13 signAuditTrail 缺省 trailDir 落 tmpdir`。

---

## 平台边界说明（诚实标注，非缺陷）

- Windows 上 `child.kill('SIGTERM')` 走 `TerminateProcess`（硬杀），不触发 JS 信号处理器
  （Node 平台限制，已实测：`code=null signal=SIGTERM`）。bin 仍按 M10 安装
  SIGINT/SIGTERM/uncaughtException/unhandledRejection 处理器（POSIX 下 exit 0 / exit 1 生效），
  并额外提供 stdin `shutdown` 一行作为 Windows 等价优雅退出通道；deploy 测试据此在 Windows
  上验证 exit 0（POSIX 走 SIGTERM）。

## 交付物清单

新增：`key-store.mjs`、`config.mjs`、`logger.mjs`、`package.json`、
`bin/process-guard.mjs`、`bin/vap-relay.mjs`、`bin/vap-gateway.mjs`、`bin/vap-node.mjs`、
`tests/deploy-regression.test.mjs`、`progress-fix2.md`、`report-fix2.md`。
修改：`vap-core.mjs`、`vap-transport.mjs`、`phase4/relay-server.mjs`、
`phase5/vap-to.mjs`、`phase6/vap-to-membership.mjs`、`phase0.5/bootstrap-forge.mjs`。
