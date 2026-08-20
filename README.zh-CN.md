# VAP — 可验证智能体交互协议（Verifiable Agent Protocol）

> 可验证智能体交互协议——一台**实测的信任机器**。任何 Node.js 智能体安装本插件后，
> 进入同一信任域（共享工作区），即可：领任务、交百字战报、被验证门裁决、崩溃被收养。
> 零第三方依赖（仅 `node:` 内置模块）。

English: [README.md](./README.md)。协议规范：[vap-spec.md](./vap-spec.md)。

## 能力总览

每个能力都带实验装置编号与对照组。

| 层 | 能力 | 装置号 |
|---|---|---|
| **身份层** | Ed25519 信封 + nonce 防重放 + 行为历史稀缺性 | E01/E02/E03、P0-1..P0-4、P05 |
| **信任层** | 验证门三闸 + 资格链自举 + 分布式 2/3 QC | E02、P3、D1-D5 |
| **顺序层** | 锁步 QC 链共识（总序 / 防分叉 / 防双花） | T1-T6 |
| **传输层** | 文件 / HTTP 网关 / UDP P2P / 中继跨 NAT | P2-1..P2-4、R1-R4 |
| **治理层** | 动态成员 + 军法上链 + slash 自动除名 | D1-D5 |

## 快速开始 —— 两分钟走完端到端

环境要求：**Node.js 22+**（`package.json` 的 `engines.node` 声明 `>= 22`）。零第三方依赖，无需 install。

```bash
# 1. 获取代码
git clone https://github.com/Wang-Lin-Chang/dsh-vap.git   # 或下载 zip 解压
cd dsh-vap

# 2. 确认 Node.js 版本（22 或更新）
node --version

# 3. 终端 A —— 用固定端口起 HTTP 网关
node bin/vap-gateway.mjs --port 3081

# 4. 终端 B —— 发出第一封可验证信封
node bin/vap-send.mjs --to brain --summary "hello vap" --gateway http://127.0.0.1:3081

# 5. 看裁决 —— vap-send 直接讲结果；网关计数可复核
curl http://127.0.0.1:3081/health

# 6. 跑测试
node --test
```

第 3 步不会把你丢在一个空提示符前，它会告诉你下一步做什么：

```text
✓ vap-gateway listening http=127.0.0.1:3081
  health    : http://127.0.0.1:3081/health
  envelopes : POST http://127.0.0.1:3081/envelopes （GET 同址拉取未投递信封）
  next      : send envelopes via POST /envelopes — node bin/vap-send.mjs --to brain --summary "hello vap" --gateway http://127.0.0.1:3081
```

第 4 步把裁决讲成人话（退出码 `0`）：

```text
✓ 已投递 envelopeId=evt-a2d6aa6ab72547f3 网关已接收（HTTP 202 Accepted）
  boundary : L0（未给 --evidence，按诚实边界降级；加 --evidence '{"devices":["E01"]}' 才能声明 L2a）
  本地三闸 : pass（身份 ✓ / 军法 ✓ / 诚实边界 ✓）
  裁决     : 网关验签通过并落盘 inbox-http/（军法与诚实边界由下游裁决）
  next     : 看网关计数 → curl http://127.0.0.1:3081/health   （envelopesIn 会 +1）
```

第 5 步是网关自己的计数：`{"ok":true,"envelopesIn":1,"envelopesOut":0,"peers":0,"relayed":0}`。

### 怎么读裁决

| `vap-send` 输出 | HTTP | 含义 | 退出码 |
|---|---|---|---|
| `✓ 已投递 … 网关已接收` | 202 | 验签通过，信封落盘 `inbox-http/` | 0 |
| `✗ 拒绝: 签名无效` | 403 | `sig` 与 `from.pubKey` 不是同一身份，或信封签名后被改动 | 1 |
| `✗ 拒绝: 格式错` | 400 | 缺 / 畸形 `nonce` 或 `envelope.id`，或请求体不是合法 JSON | 1 |
| `✗ 拒绝: 重放拦截` | 409 | 该 `nonce` 已被记账——防重放生效 | 1 |
| `✗ 连不上网关 … ECONNREFUSED` | — | 该端口上没有网关在监听（先起网关） | 1 |
| `✗ vap-send: unknown option …` | — | 用法错（未知参数 / 缺值 / `--boundary` 非法） | 2 |

每种拒绝都会附 `为什么` 与 `怎么办` 两行：失败不只告诉你哪里错，还告诉你下一步怎么做。

## CLI 命令表

四个入口共用同一套参数解析：`--help` 打印用法到 stdout 并 exit `0`；未知参数（或缺值 / 非数字）
把错误打到 stderr 并 exit `2`。错误一律走 stderr，帮助与结果走 stdout。

| 命令 | 作用 | 示例 |
|---|---|---|
| `bin/vap-send.mjs` | 构造 + 签名 + 投递一封信封，并把裁决讲成人话 | `node bin/vap-send.mjs --to brain --summary "hello vap" --gateway http://127.0.0.1:3081` |
| `bin/vap-gateway.mjs` | HTTP 网关：`POST/GET /envelopes` + `/health` | `node bin/vap-gateway.mjs --port 3081` |
| `bin/vap-node.mjs` | 共识节点（锁步 QC 链 + 动态成员）带 `/health` | `node bin/vap-node.mjs --node-id brain --port 3083` |
| `bin/vap-relay.mjs` | 中继：TCP 注册 + 跨 NAT 转发 | `node bin/vap-relay.mjs --port 3082` |

`vap-send` 参数：`--to <nodeId>`、`--summary <text>`（≤ 100 字）、`--gateway <url>`、
`--from <nodeId>`、`--claim-type <type>`、`--boundary <L2a|L1|L0>`、`--evidence <json>`、
`--request <text>`、`--key <keyFile>`、`--root <dir>`、`--from-file <json>`、`--timeout <ms>`、
`--dry-run`。两种常用写法：

```bash
# 声明最强边界 L2a —— 它要求 evidence.devices 非空
node bin/vap-send.mjs --to brain --summary "巡检完成" --boundary L2a \
  --evidence '{"devices":["E01"]}' --gateway http://127.0.0.1:3081

# 只看信封长什么样（不发），或让脚本重发一封已落盘的信封
node bin/vap-send.mjs --to brain --summary "hello" --dry-run
node bin/vap-send.mjs --from-file ./evt-a2d6aa6ab72547f3.json --gateway http://127.0.0.1:3081
```

三个服务入口都支持 `--host <ip>`、`--port <n>`、`--config <path>`（JSON 配置，见 `config.mjs`）、
`--log-file`、`--log-level`，以及 `VAP_*` 环境变量覆盖；`vap-node` 另有 `--node-id <id>` 与
`--ledger-dir <dir>`。**默认端口是 0（由系统分配）**——上面的示例一律显式写 `--port`，
省得你去找随机端口。日志走结构化 logger（`logger.mjs`）；SIGINT/SIGTERM（以及 Windows 的
`stdin shutdown` 一行）触发优雅退出，退出码 0。设置 `VAP_LANG=zh` 或 `VAP_LANG=en` 可强制
CLI 输出语言——逃生舱，覆盖控制台码页自动检测（在 Windows 控制台里 CLI 会把 `cp936` 自愈为 UTF-8）。

## 测试方式

```bash
node --test
```

测试覆盖内环（信封 / 三闸 / 租约 / 收养）、中环（HTTP 网关 / nonce 防重放 409-400 / 组网 /
防环）、CLI 体验（`tests/cli.test.mjs`：help exit 0、未知参数 exit 2、`vap-send` 的
202/403/400/409 与网关未启动路径）与外环各 Phase。`node --test` 必须全绿。

## 目录结构

```
vap-core.mjs          # 内环：信封、三闸、租约、收养、五函数契约
vap-transport.mjs     # 中环：file/HTTP 传输、网关、nonce 防重放
vap-spec.md           # 协议规范（双语，v0.2）
config.mjs            # JSON + VAP_* env 配置层
logger.mjs            # 结构化 JSON-line 日志 + 轮转
key-store.mjs         # PKCS8 私钥落盘（chmod 600）
bin/                  # vap-send（发信封 CLI）/ vap-relay / vap-gateway / vap-node + 进程兜底
bridges/              # MCP 服务（mcp-server.mjs）+ A2A 卡片/规格（a2a-*.mjs/.md）
tests/                # 回归套件（core / transport / security / deploy / bridge / cli）
phase0/ … phase6/     # 外环各 Phase：DESIGN + REPORT + experiments
experiments/          # v0 / http / ring2 实测装置
```

## 诚实边界

- **小规模信任域**：按单机共享文件系统设计（可扩展到共享盘 / HTTP 网关）；**公网未实测**
  （见 `phase6/DEPLOYMENT.md`）。
- **不是公网规模的拜占庭共识**：Ed25519 只证明"消息出自持有私钥的节点"。外环共识
  （Phase 5/6）在 `n = 3f+1` 下容忍 `f` 个拜占庭节点，**≥ f+1 节点共谋**即越过数学边界。
- **`doWork` / `respondExpand` 为桩**（见 `vap-spec.md` §2）：真实执行器是下一阶段题。
- **仅支持 IPv4 组播**：LAN P2P（`phase2/lan-peer.mjs`）对 IPv6 组播字面量显式拒绝。

## 各 Phase 链接

| Phase | 设计 | 报告 |
|---|---|---|
| Phase 0（行为历史稀缺性） | [DESIGN](phase0/DESIGN.md) | [P0-REPORT](phase0/P0-REPORT.md) |
| Phase 0.5（审计者自举） | [DESIGN](phase0.5/DESIGN.md) | [P05-REPORT](phase0.5/P05-REPORT.md) |
| Phase 1（传输抽象 SPI） | [DESIGN](phase1/DESIGN.md) | [report-phase1](phase1/report-phase1.md) |
| Phase 2（LAN P2P） | [DESIGN](phase2/DESIGN.md) | [P2-REPORT](phase2/P2-REPORT.md) |
| Phase 3（分布式 2/3 背书） | [DESIGN](phase3/DESIGN.md) | [P3-REPORT](phase3/P3-REPORT.md) |
| Phase 4（NAT 穿透 + 中继） | [DESIGN](phase4/DESIGN.md) | [P4-REPORT](phase4/P4-REPORT.md) |
| Phase 5（锁步 QC 共识） | [DESIGN](phase5/DESIGN.md) | [P5-REPORT](phase5/P5-REPORT.md) |
| Phase 6（动态成员 + 军法上链） | [DESIGN](phase6/DESIGN.md) | [P6-REPORT](phase6/P6-REPORT.md) |

## License

[Apache-2.0](./LICENSE)
