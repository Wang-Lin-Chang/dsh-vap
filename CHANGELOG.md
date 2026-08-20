# Changelog

本项目版本遵循「内环 / 中环 / 外环」的能力推进节奏；所有能力都带实验装置编号与对照组。

## [未发布] —— 用户验收精修批次（CLI 体验）

依据 `polish-brief.md`：把「能跑」补成「用得顺手」。

- 统一参数解析（`bin/process-guard.mjs` 的 `parseCliArgs` / `renderHelp` / `cliArgs`）：
  四个 CLI 共用一套行为——`--help`/`-h` 打印用法到 stdout 并 exit 0；未知参数、缺值、
  非数字取值把错误打到 stderr 并 exit 2（不再静默忽略后挂住）。
- 三个服务入口统一支持 `--host` / `--port` / `--config`（`vap-node` 另有 `--node-id`、
  `--port` 等价 `--health-port`），启动输出补 health 地址、数据目录与「下一步」提示行。
- 新增 `bin/vap-send.mjs`：一条命令完成「取密钥 → 构造签名信封 → 本地三闸预检 → POST 网关
  → 人话裁决」；202/400/403/409/413 与 ECONNREFUSED 各给「为什么 + 怎么办」；
  支持 `--from-file`、`--dry-run`、`--key`、`--evidence`（无证据自动降级 L0）。
- 新增 `tests/cli.test.mjs`（41 条）：help exit 0、未知参数 exit 2、端到端 202/403/400/409、
  网关未启动友好报错、启动提示行、参数解析单元、版本与坏词一致性。
- README 双语改为端到端体验流（获取代码 / Node.js 22+ / 固定端口 3081 / 发信 / 看裁决 / 跑测试）
  + CLI 命令表；`package.json` 的 `engines.node` 同步为 `>=22`，新增 `vap-send` bin 与 `send` script。

## [0.2.0] - 2026-08-20

外环六 Phase 全部并入 + 开源前安全修复批次 1/2。

### 外环（身份 / 信任 / 顺序 / 传输 / 治理）

- Phase 0：行为历史稀缺性（伪造成本模型，P0-1..P0-4）。
- Phase 0.5：审计者信任引导（创世锚 + 资格链 + 放水追责）。
- Phase 1：传输抽象 SPI（spiLossless + 身份绑定）。
- Phase 2：LAN P2P（UDP 组播发现 + 洪泛 + 三闸不破，P2-1..P2-4）。
- Phase 3：分布式 2/3 背书（QC，E38 升级版）。
- Phase 4：NAT 穿透 + 中继兜底 + 无激励基线实测。
- Phase 5：锁步 QC 链共识（总序 / 防分叉 / 防双花，T1-T6）。
- Phase 6：动态成员 + 军法上链 + slash 自动除名（D1-D5）。

### 安全修复批次 1（F1/F2/F6/F7/M1-M7）

- F1 nonce 白名单（路径穿越 DoS）、F2 网关 host 参数（跨机可达）。
- F6 slash 证据 pubKey 绑定（嫁祸除名）、F7 endorsements 类型守卫。
- M1 envelope.id 白名单、M2 rotate 新钥校验、M3 relay 注册认证+限速、
  M4 consume 仅 pass 登记、M5 taskId 白名单、M6 ledgerFile 摘要文件名、
  M7 网关验签前置（403）。

### 部署修复批次 2（F3/M8-M13）

- F3 私钥落盘（PKCS8 + chmod 600 + 启动加载）。
- M8 配置外部化（JSON + VAP_* env）、M9 结构化日志 + 轮转、
  M10 进程管理（bin + 信号兜底）、M11 真实 /health、
  M12 restore 补全（QC 回放 + 成员状态回放）、M13 数据目录默认 os.tmpdir()。

## [0.1.0] - 2026-08-19

内环 + 中环：插件核心与传输。

- 内环：Ed25519 信封、验证门三闸（身份/军法/诚实边界）、O_EXCL 租约、三证据收养。
- 中环：HTTP 网关（file/HTTP 可插拔传输）、nonce 防重放（409/400）、多网关组网防环。
