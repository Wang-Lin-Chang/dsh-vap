# 用户验收精修批次（CLI 体验）—— 完成报告

工作区 `dsh-vap/`；依据 `polish-brief.md`（用户验收 8 个问题中的 7 个：问题 1/2/3/4/5/6/7，MCP 桥免修）。

一句话：把「能跑」补成「用得顺手」——四个 CLI 一套参数规矩（`--help` exit 0 / 未知参数 exit 2）、
新增 `vap-send` 让人一条命令发出第一封可验证信封并读懂裁决、README 改成照抄能走通的端到端体验流。

## 验收对照（硬性 5 条）

### 1. 全量测试保持全绿（旧 157 一条不破）+ 新增 cli.test.mjs 全过

- 起点基线：`node --test` → tests 157 / pass 157 / fail 0。
- 终局：`node --test` → **tests 198 / pass 198 / fail 0**（157 + 新增 41，Node v25.8.1）。
- 单跑：`node --test tests/cli.test.mjs` → 41/41 通过。
- 未改任何既有测试文件：旧 `deploy-regression` 对三 bin 的契约（stdout 含 `listening`、
  Windows stdin `shutdown` 优雅退出码 0、`--port 0` / `--node-id` / `--ledger-dir` / `--health-port`
  继续可用）原样成立——统一参数解析只增不减，首行就绪信号格式保留。

### 2. `--help` 三 bin + vap-send 全部 exit 0 且输出用法；未知参数 exit 2

实测（`node bin/<cli>.mjs --help; $LASTEXITCODE`）：

| CLI | `--help` | `-h` | 未知参数 `--nope` |
|---|---|---|---|
| `vap-gateway.mjs` | exit 0，用法到 stdout | exit 0 | exit 2，stderr 报 `unknown option '--nope'` |
| `vap-relay.mjs` | exit 0 | exit 0 | exit 2 |
| `vap-node.mjs` | exit 0 | exit 0 | exit 2 |
| `vap-send.mjs` | exit 0 | exit 0 | exit 2 |

帮助内容含：程序名 + 一句话说明、`用法 / Usage`、`参数 / Options`（含默认值）、
`示例 / Examples`、`说明 / Notes`。另有 exit 2 的其余入口：缺值（`--port` 后无值）、
非数字（`--port abc`）、位置参数（`vap-send hello`）、缺 `--summary`、
`--boundary L2a` 无证据、坏 `--key`、`--gateway` 带路径 / `https://`、`--summary` 超 100 字。
测试固化在 `tests/cli.test.mjs`（含 stdout 为空、stderr 提示 `--help` 的断言）。

### 3. vap-send 端到端三种结果的人话输出

| 场景 | 命令 | 输出（首行） | exit |
|---|---|---|---|
| 真信封 202 | `--to brain --summary "hello vap" --gateway http://127.0.0.1:3081` | `✓ 已投递 envelopeId=evt-d4826a4f50e697f8 网关已接收（HTTP 202 Accepted）` | 0 |
| 伪签名 403 | `--from-file badsig.json` | `✗ 拒绝: 签名无效（网关返回 HTTP 403 signature verification failed）` | 1 |
| 格式错 400 | `--from-file nononce.json` | `✗ 拒绝: 格式错（网关返回 HTTP 400 missing nonce）` | 1 |
| 重放 409 | 同一封 `--from-file` 投两次 | `✗ 拒绝: 重放拦截（网关返回 HTTP 409 replay rejected）` | 1 |
| 网关未启动 | `--gateway http://127.0.0.1:<空端口>` | `✗ 连不上网关: http://127.0.0.1:<port>（ECONNREFUSED）` | 1 |

每种失败都附两行可执行建议，例如 ECONNREFUSED：
`为什么 : 目标端口没有服务在监听（网关没起，或端口写错了）` /
`怎么办 : 另开一个终端先起网关：node bin/vap-gateway.mjs --port 3081`，并告知信封已落盘可
`--from-file` 重发。成功输出除 envelopeId 外还回显 from/to/boundary/summary/gateway、
本地三闸预检结论与「看裁决」下一步命令。

### 4. README 体验流逐条实测可跑

`README.md` / `README.zh-CN.md` 的 6 步全部照抄执行过（详表见 `progress-polish.md`）：
`node --version` → v25.8.1；`node bin/vap-gateway.mjs --port 3081` → `✓ … listening` + 四行提示；
`node bin/vap-send.mjs --to brain --summary "hello vap" --gateway http://127.0.0.1:3081` → 202 exit 0；
`curl http://127.0.0.1:3081/health` → `{"ok":true,"envelopesIn":1,…}`（计数 +1）；`node --test` → 198 全绿。
CLI 表里的 L2a、`--dry-run`、`--from-file`、`vap-node --port 3083`、`vap-relay --port 3082` 也逐条跑过。
第 1 步 `git clone` 是简报授权的占位 URL（`Wang-Lin-Chang/dsh-vap`），本机 `git ls-remote` 无网络返回，
发布时替换——这一条是唯一未能实测的命令，照实标注。

### 5. 零第三方依赖；坏词清单保持

- `package.json` 无 dependencies/devDependencies；新增 `bin/vap-send.mjs` 只 import
  `node:fs`/`node:http`/`node:os`/`node:path`/`node:crypto` + `../vap-core.mjs` + `./process-guard.mjs`。
- 坏词清单改为自动化核验（`tests/cli.test.mjs`，清单以 `\u` 码点书写以免检查器自身命中），
  覆盖四个 CLI、双语 README、`progress-polish.md`、`report-polish.md`：零命中。

## 逐项实现证据

### ① 三 bin 统一参数解析（问题 2/4/5/6）

- `bin/process-guard.mjs`：新增 `parseCliArgs(argv, spec)`（选项声明式解析：`--flag value`、
  `--flag=value`、布尔开关、number 类型转换；未知参数/缺值/非数字/位置参数各给明确 error）、
  `renderHelp(spec)`（对齐的参数表 + 示例 + 说明）、`cliArgs(spec)`（帮助→stdout+exit 0、
  错误→stderr+exit 2）、`dialHost()`（`0.0.0.0`/`::` 映射为可拨号 `127.0.0.1`）。
  旧宽松 `parseArgs` 保留导出，兼容任何旧引用。
- 三个 bin 各声明自己的 SPEC：统一 `--host` / `--port` / `--config` / `--log-file` / `--log-level`；
  `vap-relay` 保留 `--health-port`；`vap-node` 保留 `--node-id` / `--ledger-dir` / `--health-port`
  并让 `--port` 等价 `--health-port`（三 bin 都认 `--port`）。
- 启动输出（首行仍是 `listening` 就绪信号，其后为提示）：

```text
✓ vap-gateway listening http=127.0.0.1:3081
  health    : http://127.0.0.1:3081/health
  envelopes : POST http://127.0.0.1:3081/envelopes （GET 同址拉取未投递信封）
  data      : <root>
  next      : send envelopes via POST /envelopes — node bin/vap-send.mjs --to brain --summary "hello vap" --gateway http://127.0.0.1:3081
              详见 README §Quick start / 快速开始
```

`vap-node` 提示 health 地址 + 账本目录 + `curl /health` 下一步；`vap-relay` 提示 health 地址 +
「节点以 TCP 连到 host:port 注册后即可经中继互发信封」。

### ② bin/vap-send.mjs（问题 7，核心诚意件）

流程：`--key` PKCS8 PEM 或 key-store 持久钥（`--root`，重启同一身份）→
`createVapNode().send()` 构造签名信封（nonce 随机、签名绑定 nonce）→ 本地跑一遍验证门三闸预检 →
`POST <gateway>/envelopes` → 人话裁决。

- 诚实边界处理：不给 `--evidence` 时自动降级 `L0` 并说明原因；显式 `--boundary L2a` 而
  `evidence.devices` 为空时直接 exit 2 并给两条出路（加证据 / 改 L0）——不让用户到下游才被拒。
- `--summary` 超 `constants.SUMMARY_BOUND`（100）字提前拦（军法 SUMMARY_BOUND 会 reject）。
- `--from-file <json>` 直接发已有信封（供脚本与重放试验）；`--dry-run` 只构造并打印信封 JSON；
  `--timeout <ms>` 控制投递超时；`--request` / `--claim-type` / `--from` / `--to` 补齐字段。
- 状态码解释表：202 / 400 / 403 / 409 / 413 / 404 / 500 + 网络错 ECONNREFUSED / ENOTFOUND /
  ETIMEDOUT / ECONNRESET，各带「为什么 + 怎么办」。

### ③ tests/cli.test.mjs（41 条）

覆盖：四 CLI 的 help/-h（exit 0、stdout 含用法、stderr 空）；四 CLI 未知参数（exit 2、stdout 空）；
缺值/非数字/位置参数/各类 vap-send 用法错（exit 2）；三 bin 启动提示行与优雅退出码 0；
vap-send 端到端 202（含网关 `inbox-http/` 落盘文件名与输出 envelopeId 一致性核对）、L2a、
自动降级 L0、403 伪签名（且不落盘）、400 缺 nonce、409 重放、ECONNREFUSED、`--dry-run` 不发网络、
`--key` 身份一致；`parseCliArgs`/`renderHelp`/`dialHost` 单元；package.json 与 README 版本一致性；
坏词清单。

### ④ README 精修（问题 1/3/4）

- Quick start → 「端到端在约两分钟内走完」6 步：获取代码（git clone 占位 URL / 下载 zip）、
  `node --version`（Node.js 22+）、终端 A 起网关 `--port 3081`、终端 B `vap-send` 发信、
  `curl /health` 看裁决、`node --test`。附真实输出样例（网关提示块 + vap-send 成功块 + health JSON）。
- 新增「怎么读裁决」表：202/403/400/409/ECONNREFUSED/exit 2 六行，含含义与退出码。
- 新增「CLI 命令表」：四个命令 + 作用 + 可照抄示例；`vap-send` 全参数列举 + L2a / `--dry-run` /
  `--from-file` 三个进阶示例；三服务入口的公共参数与 `VAP_*` 环境变量。
- 端口策略按简报选后者：**默认保持随机（0）**，文档所有示例显式 `--port`（3081/3082/3083），
  并把「默认 0 = 系统分配」这一事实写清楚。
- 版本统一：README 双语写 Node.js 22+，`package.json` `engines.node` 同步为 `>=22`
  （原 README 写 22+ 而 engines 写 `>=18` 的自相矛盾已消除，并由测试固化）。
- 目录结构补 `bin/` 的 `vap-send`、`tests/` 的 `cli`。

### ⑤ 文案统一

成功 `✓`、失败 `✗`、附属信息缩进两格、下一步统一 `next :`；帮助与结果走 stdout，
错误走 stderr（`✗ <name>: <error>` + `提示：node <entry> --help 查看完整用法`）。
四个 CLI 与 README 同一套记号。

## 交付物清单

| 文件 | 状态 | 说明 |
|---|---|---|
| `bin/process-guard.mjs` | 改 | `parseCliArgs` / `renderHelp` / `cliArgs` / `dialHost`（旧 `parseArgs` 保留） |
| `bin/vap-gateway.mjs` | 改 | SPEC + cliArgs + 启动提示（health/envelopes/data/next） |
| `bin/vap-relay.mjs` | 改 | SPEC + cliArgs + 启动提示 |
| `bin/vap-node.mjs` | 改 | SPEC + cliArgs（`--port` 等价 `--health-port`、`--host` 可控 health 绑定）+ 启动提示 |
| `bin/vap-send.mjs` | 新 | 发信封 CLI（密钥/构造/预检/投递/人话裁决/`--from-file`/`--dry-run`） |
| `tests/cli.test.mjs` | 新 | 41 条 CLI 体验回归 |
| `README.md` / `README.zh-CN.md` | 改 | 端到端体验流 + 裁决表 + CLI 命令表 + 版本统一 |
| `package.json` | 改 | `engines.node >=22`、`bin.vap-send`、`scripts.send` |
| `CHANGELOG.md` | 改 | 新增「未发布 —— 用户验收精修批次（CLI 体验）」 |
| `progress-polish.md` | 新 | 迭代记录（起点核对 / 逐项实现 / 测试 / README 实测表 / 自检） |
| `report-polish.md` | 新 | 本报告 |

## 诚实标注（非缺陷）

- `git clone` 的仓库地址是简报授权的占位 URL，本机无网络无法实测，发布时替换。
- `vap-send` 只支持 `http://` 网关（走 `node:http`）；`https://` 显式 exit 2 并说明，不假装支持。
- 网关只验签（403）与格式/重放（400/409）；军法与诚实边界的完整裁决在下游，
  故 vap-send 增加了本地三闸预检并在输出里区分「网关已接收」与「下游裁决」。
- Windows 上 `child.kill('SIGTERM')` 是硬杀，测试与文档统一用 stdin `shutdown` 一行验证优雅退出。
