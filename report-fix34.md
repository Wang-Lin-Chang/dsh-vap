# 修复批次 3+4（包装与接口歼灭战）—— 完成报告

工作区 `dsh-vap/`；依据 `fix-batch34-brief.md` + `FIXLIST.md`。
结论：批次 3（F4/F5/M14-M16/M21-M24）+ 批次 4（M17-M20）全部完成，验收硬性指标全绿。

---

## 验收对照

### 1. 全量测试全绿（旧 147 一个不破）

- `node --test` → **tests 157 / pass 157 / fail 0**（旧 147 + 新增 10）。
- `phase2/experiments/phase2-experiment.mjs` 重跑 `allPass: true`（组播默认改动未破坏发现用例）。

### 2. 新增 tests/bridge-regression.test.mjs

10 条，逐条覆盖：

| 覆盖点 | 测试 |
|---|---|
| MCP 握手 | `M19 MCP 握手：initialize 返回 protocolVersion/capabilities/serverInfo` |
| MCP tools/list + tools/call 全链 | `M19 MCP tools/list + tools/call(vap_verify) 全链：真信封过闸、坏边界被军法拦`（含通知无响应、未知工具 isError） |
| MCP 缺参健壮 | `M19 MCP tools/call 参数缺 envelope → isError 且不崩` |
| report 桩 | `M18 report：send 的命名别名——写 outbox 且语义一致` |
| doWork 桩 | `M18 doWork：创建 agents/<nodeId>/ 目录并记录 work.jsonl 条目` |
| respondExpand 桩 | `M18 respondExpand：从 expand-resps/ 读字段响应，无则 null` |
| a2a-card 字段 | `M20 a2a-card：生成 agent.json 字段映射（name/url/capabilities/skills）` |
| a2a-card 可运行 | `M20 a2a-card：可独立运行并输出可解析 JSON` |
| IPv6 拒绝 | `M23 IPv6 组播字面量显式拒绝（仅支持 IPv4 组播）` |
| 组播默认 | `M17 组播默认出接口：不传 mcastInterface 仍可启动到 ready` |

### 3. README 双语 / LICENSE / CHANGELOG / package engines+os 齐备

- `README.md`（英文）+ `README.zh-CN.md`（中文）：定位、五层能力表（装置号）、快速开始、
  测试、目录结构、诚实边界、各 phase 链接。
- `LICENSE`：Apache-2.0 全文。
- `CHANGELOG.md`：v0.1.0（内环+中环）→ v0.2.0（外环六 Phase + 安全修复批次 1/2）。
- `package.json`：`engines.node >=18`、`os: [win32,darwin,linux]`、`version 0.2.0`、
  `license Apache-2.0`（win32 主开发、darwin/linux 未实测在 README 诚实边界标注）。

### 4. 零第三方依赖 + 坏词清单

- `package.json` 无 dependencies/devDependencies、无 `node_modules`；新增/修改模块
  import 仅 `node:` 与相对路径（grep 核验）。
- 词检规范（仓库禁用词清单）在交付文件零命中（grep 核验）。

---

## 逐项实现证据（文件 / 要点）

### F4 双语 README

- **`README.md`（新）** / **`README.zh-CN.md`（新）**：一段话定位（实测的信任机器）、
  五层能力总览表（身份/信任/顺序/传输/治理，每层带装置号 E01-E03/P0-P4/P05/P2-P4/R1-R4/T1-T6/D1-D5）、
  快速开始 3 命令（`node bin/vap-gateway.mjs` → `node bin/vap-node.mjs`）、`node --test`、
  目录结构、诚实边界段（小规模信任域 / 公网未实测 / ≥f+1 共谋边界 / doWork+respondExpand 为桩 /
  仅 IPv4 组播）、各 phase DESIGN/REPORT 链接表。

### F5 LICENSE

- **`LICENSE`（新）**：Apache License 2.0 全文（含 TERMS AND CONDITIONS + APPENDIX）。

### M14/M15 spec 同步 + 双语

- **`vap-spec.md`**：§1 信封 JSON 增 `nonce`、签名对象增 nonce；§0 防重放改为「已实现（v0.2）」；
  §6 新增「中环与外环能力」表（五层 + 装置/实现文件）；§7 已知缺口更新（nonce 已落地、
  seen-nonces 无回收策略、公网未实测、≥f+1 共谋边界、doWork/respondExpand 为桩）；
  §2 五函数表增「状态」列（claimTask/heartbeat/report 已落地；doWork/respondExpand 桩）；
  关键段加英文摘要（EN 标题段）。

### M16/M24 package + CHANGELOG

- **`package.json`**：增 `os: ["win32","darwin","linux"]`（engines/version/license 批次 2 已有）。
- **`CHANGELOG.md`（新）**：0.1.0（内环+中环）→ 0.2.0（外环六 Phase + 安全批次 1/2 逐项）。

### M21 原子写回退注释

- **`vap-core.mjs` atomicWrite**：回退分支加 M21 诚实注释（Windows unlink+rename 非原子窗口 +
  无写侧互斥，多写者并发为已知缺口，引用 writeRegistryEntry 的 TODO(M4-并发)）。

### M22 isPidAlive 注释

- **`vap-core.mjs` isPidAlive**：加 M22 跨平台注释（kill(pid,0) ESRCH/EPERM 语义、
  Windows 语义弱化、PID 复用误判；收养判定叠加 startSec/mtime 三证据齐备，不单信 PID）。

### M23 IPv6 显式拒绝

- **`phase2/lan-peer.mjs` normalizeMulticast**：字符串形态（含冒号）与对象形态
  （addr 含冒号）IPv6 组播字面量均显式抛 `仅支持 IPv4 组播`；IPv4 形态照常。
  测试：`M23 IPv6 组播字面量显式拒绝`。

### M17 组播默认出接口

- **`phase2/lan-peer.mjs`**：`mcastInterface` 默认 `'127.0.0.1'` → `undefined`（OS 默认出接口）。
- **`config.mjs`**：`multicastInterface` 默认 `''`（未显式指定 = OS 出接口）。
- **`phase2/tests/lan-peer.test.mjs`** 发现用例、**`phase2/experiments/phase2-experiment.mjs`** mesh：
  显式传 `mcastInterface: '127.0.0.1'`。
  测试：`M17 组播默认出接口`；phase2 实验重跑 `allPass: true`。

### M18 五函数契约补桩

- **`vap-core.mjs` createVapNode** 新增三个方法：
  - `report(envelope)`：send 的命名别名，写 `outbox/evt-<id>.json`，返回信封；
  - `doWork(task, workDir?)`：桩，创建 `root/agents/<nodeId>/` 并 append `work.jsonl` 条目；
  - `respondExpand(taskId, field)`：桩，读 `root/expand-resps/<taskId>.json` 字段，无则 null
    （TODO 瞬态区语义）。
- **`vap-spec.md` §2**：表格标注三落地（claimTask/heartbeat/report）两桩（doWork/respondExpand）。
  测试：`M18 report/doWork/respondExpand` 三条。

### M19 MCP 桥（最小可运行）

- **`bridges/mcp-server.mjs`（新，零依赖）**：stdio 换行分隔 JSON-RPC 2.0（node:readline）；
  initialize → protocolVersion/capabilities/serverInfo；tools/list → 1 工具 `vap_verify`；
  tools/call → 复用 `createVapNode.verify` 三闸裁决；notifications 无 id 不回复；
  stdout 只承载响应、诊断走 stderr；验证根惰性建于 os.tmpdir()。
  测试：spawn 真进程 stdio 交互全链（M19 三条）。

### M20 A2A 桥（规格 + 最小桩）

- **`bridges/a2a-spec.md`（新）**：agent-card 字段映射表、JSON-RPC 任务生命周期→信封映射表、
  流式事件→respondExpand 对接、诚实边界（完整 A2A 任务状态机未实现）。
- **`bridges/a2a-card.mjs`（新，零依赖）**：`generateAgentCard({name,url,version})` 生成
  `.well-known/agent.json`（name/url/capabilities/vapCapabilities 五层映射/skills）；
  可独立运行 `node bridges/a2a-card.mjs --name X`。
  测试：`M20 a2a-card` 两条。

---

## 平台边界说明（诚实标注，非缺陷）

- Windows 上组播发现走本机回环需显式 `mcastInterface: '127.0.0.1'`（测试/实验已显式传）；
  默认 `undefined` 走 OS 默认出接口，是 M17 的目标语义，不是缺陷。
- `doWork` / `respondExpand` 为桩、A2A 完整任务状态机未实现：均为诚实标注的下一阶段题，
  见 `vap-spec.md` §2/§7 与 `bridges/a2a-spec.md` §四。

## 交付物清单

新增：`README.md`、`README.zh-CN.md`、`LICENSE`、`CHANGELOG.md`、`bridges/mcp-server.mjs`、
`bridges/a2a-spec.md`、`bridges/a2a-card.mjs`、`tests/bridge-regression.test.mjs`、
`progress-fix34.md`、`report-fix34.md`。
修改：`vap-spec.md`、`vap-core.mjs`、`phase2/lan-peer.mjs`、`config.mjs`、`package.json`、
`phase2/tests/lan-peer.test.mjs`、`phase2/experiments/phase2-experiment.mjs`。
