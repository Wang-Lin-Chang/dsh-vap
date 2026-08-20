# VAP 开源前修复清单（交叉审计产出）

> 审查方式：四路独立审查（代码安全/部署/文档包装/平台接口）+ 独立复核轮逐条复核（agree/disagree/amplify）
> 总计：5 fatal + 25 major + 22 minor + 9 nit
> 修复纪律：fatal/major 全灭才谈开源；minor 至少修复；nit 记录不阻塞。

## FATAL（5 + 复核升级 2）

| # | 问题 | 文件 | 修复 |
|---|---|---|---|
| F1 | nonce 无校验拼路径 → 单请求远程 DoS | vap-core:197-208 + vap-transport:332 | nonce 白名单 `/^[0-9a-f]{16}$/` + try/catch 返 400 |
| F2 | HTTP 网关 host 硬编码 127.0.0.1，跨机不可达 | vap-transport:184-191/362 | createHttpGateway/createHttpTransport 加 host 参数 |
| F3 | 私钥完全不落盘，重启换身份信任断链 | vap-core/phase5/phase6 | 密钥存储模块：PKCS8 落盘 chmod 600 + 启动加载 |
| F4 | 无 README | 全库 | 中英双语 README |
| F5 | 无 LICENSE | 全库 | Apache-2.0 |
| F6(复核升级) | slash 证据未绑定 pubKey → 嫁祸除名无辜者 | phase6:382-389 | evidence.pubKey === peerMap.get(nodeId) 强制绑定 |
| F7(复核升级) | tx.endorsements 非数组 TypeError 全节点崩 | phase6:345-347 | Array.isArray 守卫 + 判定链路异常边界 |

## MAJOR（核心 25 项，按域）

### 安全
- M1 envelope.id 路径穿越（vap-transport:322-345）→ 白名单 `/^evt-[0-9a-f]{16}$/`
- M2 rotate 不校验新钥 → coerce 抛错（phase6）→ try/catch 校验
- M3 relay 注册无认证/可顶替/无速率 → pubKey 绑定 + 帧速率上限
- M4 consume 失败也登记 + registry 无锁 → 仅 pass 登记 + 串行化写
- M5 heartbeat/complete taskId 穿越 → 白名单
- M6 ledgerFile nodeId 穿越（phase5:213）→ sha256 文件名或白名单
- M7 网关/中继无对端认证（开放中继）→ 签名前置校验或静态 peer 认证

### 部署
- M8 无配置外部化 → JSON/env 配置层（host/port/组播/ledgerDir/trailDir/超时）
- M9 日志体系不达标 → 结构化 logger（ts/level/component）+ 轮转
- M10 无进程管理 → package.json scripts + bin 入口 + SIGTERM 处理 + uncaughtException 兜底
- M11 监控不完整 → /health 真实状态 + /metrics + 共识节点 health 方法
- M12 restore 不完整（phase5 丢 QC/mempool；phase6 不回放成员状态）→ 完整回放 + autoRestore
- M13 ledgerDir/TRAIL_DIR 默认写源码树 → os.tmpdir()/可配置数据目录

### 文档包装
- M14 spec 与代码漂移（nonce 已实现 spec 却写无）→ spec 同步
- M15 未中英双语 → 双语 README/spec 关键段
- M16 无 package.json/版本语义/CHANGELOG/快速开始 → 补齐

### 平台接口
- M17 组播默认回环（mcastInterface=127.0.0.1）→ 默认走 OS 出接口，测试显式回环
- M18 5 函数契约 3/5（respondExpand/doWork 缺失）→ 补桩或 spec 收敛
- M19 MCP 桥接适配器缺失 → 适配器规格 + 最小实现
- M20 A2A 桥接适配器缺失 → 适配器规格 + 最小实现
- M21 Windows 原子写回退非原子 → 标注 + 写侧互斥
- M22 isPidAlive 跨平台语义 → 注释标注 + 启动时间戳比对
- M23 IPv6 组播无支持声明 → 显式拒绝或标注 udp4-only
- M24 engines/os 未声明 → package.json engines + os 字段

## 修复批次计划

- **批次 1（安全，F1/F2/F6/F7/M1-M7）**：路径穿越全灭 + 证据绑定 + 类型守卫
- **批次 2（部署，F3/M8-M13）**：密钥落盘 + 配置/日志/进程/监控/恢复
- **批次 3（包装，F4/F5/M14-M16/M21-M24）**：README/LICENSE/package/spec 同步
- **批次 4（接口，M17-M20）**：组播默认 + 契约补桩 + MCP/A2A 桥
- **最终全检**：全部测试+实验+审查闭环复查

每批修复后：全量测试必须保持全绿（106 个旧测试一个不破）。
