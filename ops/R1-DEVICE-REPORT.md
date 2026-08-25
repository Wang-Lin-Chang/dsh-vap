# R1 多站点冗余 — 装置记录（2026-08-25 实测）

## 装置：双中继打洞 + 主站宕机 failover

| 项 | 值 |
|---|---|
| 第二站点 | SA2.MEDIUM4 按量机 ins-1vfjhc93，公网 82.156.128.229，北京三区（同 VPC vpc-0azq2806，私网 172.21.128.11） |
| 主站 | ins-096pmlyd，101.42.23.246（包年包月） |
| 代码 | phase7/punch-node.mjs 双中继版（--relayHost 逗号分隔） |
| A 侧 | 本机家庭 NAT（2409 GUA，120.225.86.119 映射） |
| B 侧 | 老服务器 101.42.23.246 |

## 结果（三装置全 PASS）

| 装置 | exchanged | executedStrategy | payload | pass |
|---|---|---|---|---|
| 双中继正常打洞 | true | udp-punch | 285 | true |
| **主站 relay 停机 failover** | true | udp-punch | **307** | **true** |
| SA2 单中继（二分定位） | true | udp-punch | 8 | true |

**结论**：主站中继停机时，mapping 交换经第二站点完成，打洞流程不中断——R1 多站点冗余达成（SLO-2 99.9% 的中继冗余前提成立）。

## 过程中修的两个 bug（如实记录）

1. **punch-node 进程不退出**：`relay.close()` 只关第一个中继连接，其余连接挂住事件循环。已修为循环关闭全部 relayClients。
2. 双中继首次装置 exchanged=false（时序/墓碑竞态）——修复后重跑三装置全 PASS；本地双中继复现装置（ops/dual-relay-repro.mjs）作为回归钉死。

## 成本与处置

- SA2 按量 0.42 元/时（约 10 元/天），账户余额 45.67 元（=4567 分）。
- **装置完成即释放 SA2**（按 deploy-second-site.md 手册，重建仅几分钟）。
- 第二站点常驻需老哥决策（包年包月或按需重建）。
