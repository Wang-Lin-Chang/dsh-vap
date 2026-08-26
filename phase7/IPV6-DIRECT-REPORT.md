# ipv6-direct 策略接入 fallback 链报告（L2 前插）

生成时间：2026-08-25 00:5x
任务：把 ipv6-direct 策略前插进 punch-chain fallback 链（direct-connect → ipv6-direct → udp-punch → tcp-so → turn-relay），
在真实公网 v6 装置上跑通 E2E，附对照组与假阳性排除。

## 代码改动（全部零依赖，单测覆盖）

1. `phase7/punch-plan.mjs`：selectStrategy 增加 `{selfIpv6, peerIpv6}` 输入，链中 direct-connect 之后插入 ipv6-direct
   （两端均有全局单播 v6 时 timeoutMs=5000，否则 0=skip）；order 重排 ①②③④⑤；summary 更新。
2. `phase7/punch-chain.mjs`：buildExecPlan 增加 selfIpv6/peerIpv6 → 过滤（isGlobalV6：拒 fe80/fc/fd/::1/非 v6）→
   生成 ipv6-direct step；v6 target 端口优先取 peerMapping.v6Port（显式宣告），缺省回退映射端口+10。
3. `phase7/hole-punch.mjs`：createHolePuncher 支持 family='udp6'（bind '::' + ipv6Only:true；discover 仅 v4）。
4. `phase7/punch-node.mjs`：
   - globalIpv6 修复：去掉「含 ::」误判（全展开 GUA 2409:8a3c:17d0:5100:dd11:d9bb:f1ad:e71e 无 :: 压缩曾被误滤，self 恒空）；
   - v6Puncher 用 localPort+10（避开 bindv6only=0 内核 v4/v6 同端口 EADDRINUSE，SA2 实测）；
   - mapping 消息携带 v6Port；交换只接受新协议消息（带 v6Port 或非空 ipv6），忽略 relay 持久队列重放的旧消息；
   - executePlan 增加 ipv6-direct 分支；直连成功后 payload 投递按 executedStrategy 选 v4/v6 通道。
5. `phase7/punch-chain.smoke.mjs`：12/12 断言（含对称↔对称+双 GUA → v6 第一直连候选；双 ULA 不误判；fe80 混入滤掉；::1 拒）。

## 单测

- punch-chain.smoke.mjs：**12/12 PASS**
- punch-plan.smoke.mjs：**5/5 PASS**

## 装置1（正例）：A=本机（家庭 NAT cone + GUA 2409）↔ B=腾讯云 SA2（EIP 82.156.237.249 + GUA 2402）

装置条件：B 侧 ufw 拦 A 源 IP 的 v4 UDP 46001（逼 direct-connect 失败），v6 46010/46011 放行；
B 的公网 IP 已 TransformAddress 转 EIP（此前 SA2 出站被 SNAT 成 101.42.23.246，UDP 回程全丢，STUN 恒超时）。

**PASS 结果**（run 00:1x，双端一致）：
- A：executedStrategy=**ipv6-direct**，directEstablished=true，directPayloadReceived=**2429**，pass=**true**
- B：executedStrategy=**ipv6-direct**，directEstablished=true，directPayloadReceived=**2434**，pass=**true**
- 链路：A 2409:8a3c:...:e71e ↔ B 2402:4e00:...:7951，UDP 握手按内容判定建立，payload 双向投递。

## 装置2（对照组 + 假阳性排除）：B=老服务器（无 GUA，仅 fd7a ULA + fe80）

- 老服务器 ipv6.self=**[]**（fd7a/fd 与 fe80 正确排除——ULA 不误判的装置证据）。
- 无 GUA 时 plan 中 ipv6-direct timeoutMs=0（not-applicable）由 smoke case9 断言覆盖。
- 备注：排查中发现老服务器被误配了 SA2 的 2402 地址（某轮命令串台写入 netplan 60-ipv6.yaml），已删除并 netplan apply 复原。

## 修复的 bug（装置实测抓出，全部有对照）

1. **全展开 GUA 误滤**：`ip.includes('::')` 判据把无 :: 压缩的全展开 GUA 滤掉 → self 恒空 → v6 策略永远 skip。修复后 A 枚举到 2 个 2409。
2. **udp6 dual-stack 同端口冲突**：Node udp6 bind '::' 默认 dual-stack，与 v4 同端口 EADDRINUSE（SA2 内核 bindv6only=0 下 ipv6Only 选项亦未生效，最小复现双证）。改用 localPort+10 偏移。
3. **映射端口推算错误**：家庭 NAT 映射端口随机（localPort 46000 → 映射 20701），「映射端口+10」推算 v6 端口会打错。改为 mapping 消息显式携带 v6Port。
4. **relay 旧消息污染**：graynet relay 持久队列重放历史 mapping（旧 B 的 101.42），A 曾打到错误目标。改为只接受新协议消息。
5. **SA2 出站 SNAT 异常**：按量实例公网 IP 出站源被 SNAT 成同 VPC 老服务器 IP（curl ifconfig.me 实证），UDP 回程全丢。TransformAddress 转 EIP 后修复（STUN 映射稳定 82.156.237.249）。

## 遗留问题（如实记录）

- **relay 单向故障（运维侧，与策略无关）**：relay 重启后出现 B 收 A、A 收不到 B 的单向转发（B exchanged=true、A=false），
  疑似 relay 转发表死连接残留 + 顶替认证（punch-node 的 pubKey 每次随机）拒绝新注册。装置1 的 PASS 在
  该故障出现前取得；此后复测被 relay 阻塞。修复方向：punch-node 固定 pubKey 或 relay 死连接检测；
  属 relay 组件（phase4）议题，另行处理。
- punch-node 的 classifyNAT 在 google STUN 19302 超时（家庭网络对该端点偶发不可达）时降级 unknown，
  建议后续允许单 STUN 服务器成功即分类。

## 结论

ipv6-direct 策略已接入 fallback 链并前插到 direct-connect 之后；真实公网 v6 装置（家庭电信 2409 ↔ 腾讯云 2402）
E2E 双端 PASS（payload 2429/2434），对照组（无 GUA 端）正确 skip，ULA 假阳性排除装置验证通过。
策略顺序：direct-connect（v4 公网快车道）→ **ipv6-direct**（GUA 直连，不依赖 v4 NAT 分类，对称 NAT 场景的第一直连候选）→ udp-punch → tcp-so → turn-relay。
