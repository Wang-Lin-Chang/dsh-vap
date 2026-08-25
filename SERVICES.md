# VAP 云服务器常驻服务（样板工程）

服务器：101.42.23.246（腾讯云 CVM，Ubuntu 22.04，包年包月）
交付时间：2026-08-25
验证状态：部署 + 重启自启 + 功能测试全部通过

## 服务清单（systemd 托管）

| 服务 | 端口 | 用途 | 源码 |
|---|---|---|---|
| vap-relay | 42050/tcp | graynet 中继（VAP 信令交换） | experiments/graynet-experiment.mjs relay |
| vap-stun | 3478/udp | 自研 STUN（NAT 映射发现） | phase7/stun-server.mjs |
| vap-files | 8080/tcp | 论文/源码只读分发 | public-jim/_fileserver.mjs |
| vap-monitor.timer | — | 每 5 分钟触发一次生产监控（定时器） | systemd/vap-monitor.timer |
| vap-monitor | — | 生产监控（服务/磁盘/内存/relay/STUN） | ops/monitor.mjs |

## 运维手册

```bash
# 状态总览
systemctl status vap-relay vap-stun vap-files
# 日志
journalctl -u vap-relay -f
# 重启某服务
sudo systemctl restart vap-stun
# 全部禁用（下线）
sudo systemctl disable --now vap-relay vap-stun vap-files
# 监控（7 项检查：服务/磁盘/内存/relay TCP/STUN UDP）
node /home/ubuntu/dsh-vap/ops/monitor.mjs
tail /var/log/vap-monitor.log
# 故障注入演练（kill -9 三服务 → 验证 5-6s 自愈；2026-08-25 实测 3/3 恢复、监控复绿）
bash /home/ubuntu/dsh-vap/ops/chaos-service.sh
# 回滚（切回指定 git 提交并重启；数据文件不在 git 内不受影响）
bash /home/ubuntu/dsh-vap/ops/rollback-service.sh <git-commit>
```

## 设计规范（样板标准）

1. **非 root 运行**：全部以 ubuntu 用户运行（unit 文件 User/Group 显式声明）。
2. **开机自启**：`WantedBy=multi-user.target`，`After=network-online.target`（网络就绪后才启动）。
3. **崩溃自拉起**：`Restart=on-failure` + `RestartSec=5`；`StartLimitIntervalSec=300` + `StartLimitBurst=6` 防无限重启风暴。
4. **日志走 journald**：不在 unit 里重定向文件，统一 `journalctl` 查询。
5. **可复现部署**：unit 文件存档 `/home/ubuntu/systemd-units/`，重装系统后 `install -m 644` 到 `/etc/systemd/system/` + `daemon-reload` + `enable --now` 即可。
6. **监控兜底**：vap-monitor.timer 每 5 分钟全量检查，失败写 `/var/run/vap-monitor-failed.json`（告警联动锚点，接邮件/IM 时读此文件即可）。
7. **journald 尺寸控制**：journald 的磁盘/保留上限是全局配置，不能在 unit 里设；把 `systemd/vap-journald.conf` 装到 `/etc/systemd/journald.conf.d/`（`SystemMaxUse=500M` + `MaxRetentionSec=14day`）并 `systemctl restart systemd-journald` 生效——防止三服务日志撑爆 `/var/log/journal`。

## 验证记录（2026-08-25 实测）

| 验证项 | 结果 |
|---|---|
| systemctl is-enabled ×3 | enabled / enabled / enabled |
| 重启后 systemctl is-active ×3 | active / active / active（uptime 1min 复验） |
| 端口监听 | 42050/tcp ✓ 3478/udp ✓ 8080/tcp ✓ |
| 功能 | STUN 自环 type=257 ✓；文件服务 HTTP 200（21523B）✓ |
| 安全组 | 22/tcp、3478/udp、42050/tcp、46501、50000-50015/udp、8080/tcp 已放行 |
| 监控（R2） | monitor.mjs 7 项全绿 + timer 5min 周期 ✓ |
| 故障注入（R7） | kill -9 三服务 → 5-6s systemd 自愈、监控复绿（3/3）✓ |

## TLS 部署（S6，可选强化）

```bash
# 1) 服务器生成自签 CA + 服务器证书
bash /home/ubuntu/dsh-vap/bin/vap-gencert.sh /home/ubuntu/dsh-vap/tls vap-relay
# 2) relay 启动加 tlsOptions（cert/key 文件路径）；客户端 ca 固定 vap-ca.pem
# 3) 重启服务；明文客户端将无法注册（已实测：明文注册不进表）
```

## 打洞端口与安全组（2026-08-25 装置实测记录）

- 安全组放行区间：3478/udp、42050/tcp、46501、**50000-50015/udp**、8080/tcp。
- punch-node 的 B 侧端口必须落在放行区间内（`--localPort 50001` 起），否则
  udp-punch/tcp-so 被安全组挡（46001/46002 不在区间 → 打洞失败，装置已实测）。
- **IPv6 直连**：老服务器 IPv6 端口未在安全组/ufw 放行 → ipv6-direct 在本装置失败
  （udp-punch 兜底成功）。要启用 v6 直连需放行 v6 端口（如 50011/udp）。
- 生产加固后端到端打洞回归：A(2409 家庭 NAT)↔B(101.42.23.246)，token 交换+校验
  正常，udp-punch 252ms 建立、payload 274、pass=true（2026-08-25 装置）。

## 日志轮转（R4）

journald 的尺寸上限是**全局**配置（`journald.conf`），不能在单个 unit 里设 `JournalMaxUse=`；
正确做法是 drop-in 片段（见 `systemd/vap-journald.conf`）：

```bash
sudo install -m 644 /home/ubuntu/systemd-units/vap-journald.conf \
  /etc/systemd/journald.conf.d/vap-journald.conf
sudo systemctl restart systemd-journald
# 效果：journal 落盘 ≤500M，条目保留 ≤14 天（先到先滚），
# 防止 vap-relay / vap-stun / vap-files 三服务日志把 /var/log/journal 撑爆。
```

## 资源账目

- SA2 测试机 ins-psoo8t6t（82.156.237.249）：2026-08-25 已销毁（实例+系统盘），EIP eip-6n7h9ee9 已释放——按量计费停止扣费。
- 老服务器 ins-096pmlyd：包年包月（2027-03 到期），常驻上述三服务。
