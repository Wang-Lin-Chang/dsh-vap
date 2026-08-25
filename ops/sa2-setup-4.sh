#!/usr/bin/env bash
# SA2：更新 monitor（支持跳过项）+ 替换 monitor unit + 验证
set -e
PW='Vp!1sIhDreNY5@R1'
D=/home/ubuntu/dsh-vap
# monitor.mjs 已在 $D/ops/ 更新（由投递步骤完成）
# 替换 vap-monitor.service 为带 Environment 的版本
cat > /tmp/vap-monitor.service <<'EOF'
[Unit]
Description=VAP production monitor (services/disk/memory/relay/STUN)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/node /home/ubuntu/dsh-vap/ops/monitor.mjs
Environment=VAP_MONITOR_SKIP=vap-files

[Install]
WantedBy=multi-user.target
EOF
echo "$PW" | sudo -S cp /tmp/vap-monitor.service /etc/systemd/system/vap-monitor.service
echo "$PW" | sudo -S systemctl daemon-reload
echo "$PW" | sudo -S systemctl restart vap-monitor.timer
echo "monitor unit updated"
VAP_MONITOR_SKIP=vap-files node $D/ops/monitor.mjs
