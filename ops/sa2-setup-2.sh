#!/usr/bin/env bash
# SA2 第二站点：安装 systemd 服务并启动（sudo 密码从 stdin 环境传入）
set -e
PW='Vp!1sIhDreNY5@R1'
D=/home/ubuntu/dsh-vap
echo "$PW" | sudo -S cp $D/systemd/vap-relay.service $D/systemd/vap-stun.service $D/systemd/vap-monitor.service $D/systemd/vap-monitor.timer /etc/systemd/system/
echo "$PW" | sudo -S systemctl daemon-reload
echo "$PW" | sudo -S systemctl enable --now vap-relay vap-stun vap-monitor.timer
sleep 5
systemctl is-active vap-relay vap-stun vap-monitor.timer | tr '\n' ' '
echo
node $D/ops/monitor.mjs
