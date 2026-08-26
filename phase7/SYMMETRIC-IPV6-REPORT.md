# 对称 NAT × IPv6 直连端到端报告（SYMMETRIC-IPV6）

生成时间：2026-08-25
任务：实测 ipv6-direct 策略在「真对称 NAT 端点」场景的端到端——对称 NAT 下 v4 打洞数学性判死，
公网 IPv6 直连是唯一直连解，验证策略链自动走通。

## 装置

- A = 本机（家庭 NAT，port-restricted cone，公网 IPv6 2409:8a3c）
- B = 腾讯云 SA2 新实例 ins-gwjakce9（62.234.161.137）：
  - **v4 对称 NAT**：netns vapsym + `iptables SNAT --to-source 172.21.128.8:52000-52127 --random`
    （UDP/TCP 各一条）；对称性验证：同一 socket 向同 IP 异端口（3478 vs 50001）映射 **52057 vs 52026——不同端口** = 真对称（endpoint-and-port-dependent）。
  - **公网 IPv6**：2402:4e00:1209:c100:6:59d5:b699:6ee1 从 eth0 移入 netns vs1（host 路由 + ip6tables FORWARD + LL 默认路由），netns 内 ping6 外网 4/4 通（43ms）。
- 中继/STUN：老服务器 101.42.23.246（relay 42050 systemd 常驻；STUN 3478 + 50001）。

## 关键步骤

1. 重建 SA2（RunInstances）→ 转 EIP（出站源稳定）→ 网卡分配 IPv6 → netplan（on-link 路由：/64 link + 默认 via ::1 onlink）→ 传统 EIPv6 控制台开公网带宽（100Mbps 按流量）。
2. 对称 NAT 装置 + v6 入 netns（见装置节）。
3. classifyNAT 用「同 IP 异端口」双 STUN（3478 + 50001）触发 symmetric 判定分支。

## E2E 结果（双端一致）

| 项 | A | B |
|---|---|---|
| 自分类 | endpoint-independent | **symmetric**（evidence: 同 IP 异端口映射不同） |
| plan 的 udp-punch | — | **timeoutMs=0 判死跳过**（note 引用 E10/E11 判死） |
| executedStrategy | **ipv6-direct** | **ipv6-direct** |
| directEstablished | true | true |
| payload 互达 | **2728** | **2733** |
| pass | **true** | **true** |

## 结论

ipv6-direct 策略在「真对称 NAT 端点」装置上端到端成立：B 被正确自分类为 symmetric →
v4 UDP 打洞按判死结论跳过 → 公网 IPv6 直连建立 → 双端 payload 互达。
**对称 NAT 场景的唯一直连解被实测打通**——L2 路线的最后一块空白补齐。

对照组（既有结论，本次未重跑）：无 GUA 端点正确 skip（IPV6-DIRECT-REPORT 装置2）；
ULA 不误判（isGlobalV6 单测）。

## 资源账目

- 新实例 ins-gwjakce9 + EIP eip-7j97ugnd：实验后释放（按量计费停止扣费）。
- IPv6 开白与 VPC/子网 v6 CIDR 永久保留，后续重建仅需几分钟。
