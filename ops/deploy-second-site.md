# R1 多站点冗余：第二站点部署手册

> 现状：单一站点（101.42.23.246）承载 relay/STUN/监控。SLO-2（99.9%）要求
> 中继双实例冗余。本手册给出第二站点的完整部署步骤（待执行；执行后 SLO-2 才算达成）。

## 一、第二站点选型

- 按量计费 CVM（如 SA2 规格）+ EIP，仅测试期保留；包年包月为主站。
- 要求：与主站不同可用区/地域（腾讯云 SA2 与主站不同地域即满足）。
- IPv6 开白（一次开白永久有效；VPC/子网 v6 CIDR 保留——已有记录）。

## 二、部署步骤

```bash
# 1) 新机基础（root）
apt-get update && apt-get install -y nodejs npm openssl ufw
# 2) 同步代码（从主站 scp 或 git clone + bundle）
scp -r ubuntu@101.42.23.246:/home/ubuntu/dsh-vap /home/ubuntu/dsh-vap
# 3) 安装 systemd unit（vap-relay/vap-stun/vap-monitor，注意替换监听参数）
install -m 644 systemd/*.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vap-relay vap-stun vap-monitor.timer
# 4) 安全组放行：42050/tcp、3478/udp、50000-50015/udp（打洞端口区间）
# 5) 验证：node ops/monitor.mjs 全绿 + 从主站 node ops/monitor.mjs 探测第二站点端口
```

## 三、客户端故障转移（双中继）

- punch-node 的 `--relayHost` 支持逗号分隔列表：`--relayHost <主站ip>,<第二站ip>`，
  首选连接失败自动切换下一站（连接级 failover）。
- 交换窗口内两侧节点会向两个中继都发 mapping（mapping 幂等，重复无害）。
- 验证装置：停主站 relay → 打洞流程仍完成（经第二站交换 mapping）；重启主站 → 恢复。

## 四、达成判据（SLO-2 99.9%）

- 两个站点 relay 双活，任一站点下线打洞交换不中断（装置实测）。
- 监控覆盖两站（各站本地 monitor + 主站跨站探测）。
- 故障切换恢复时间 ≤ 30s（装置计时）。

## 五、诚实状态

- 当前：**未部署第二站点**（单点，SLO-1 99%）。本手册为待执行项。
- 待办：开按量机（花钱，需报批）→ 执行上述步骤 → 装置验证 → 更新本文件状态。
