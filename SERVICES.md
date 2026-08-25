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
```

## 设计规范（样板标准）

1. **非 root 运行**：全部以 ubuntu 用户运行（unit 文件 User/Group 显式声明）。
2. **开机自启**：`WantedBy=multi-user.target`，`After=network-online.target`（网络就绪后才启动）。
3. **崩溃自拉起**：`Restart=on-failure` + `RestartSec=5`；`StartLimitIntervalSec=300` + `StartLimitBurst=6` 防无限重启风暴。
4. **日志走 journald**：不在 unit 里重定向文件，统一 `journalctl` 查询。
5. **可复现部署**：unit 文件存档 `/home/ubuntu/systemd-units/`，重装系统后 `install -m 644` 到 `/etc/systemd/system/` + `daemon-reload` + `enable --now` 即可。

## 验证记录（2026-08-25 实测）

| 验证项 | 结果 |
|---|---|
| systemctl is-enabled ×3 | enabled / enabled / enabled |
| 重启后 systemctl is-active ×3 | active / active / active（uptime 1min 复验） |
| 端口监听 | 42050/tcp ✓ 3478/udp ✓ 8080/tcp ✓ |
| 功能 | STUN 自环 type=257 ✓；文件服务 HTTP 200（21523B）✓ |
| 安全组 | 22/tcp、3478/udp、42050/tcp、46501、50000-50015/udp、8080/tcp 已放行 |

## 资源账目

- SA2 测试机 ins-psoo8t6t（82.156.237.249）：2026-08-25 已销毁（实例+系统盘），EIP eip-6n7h9ee9 已释放——按量计费停止扣费。
- 老服务器 ins-096pmlyd：包年包月（2027-03 到期），常驻上述三服务。
