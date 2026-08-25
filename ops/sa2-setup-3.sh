#!/usr/bin/env bash
# SA2：node 软链 + 服务重启 + monitor
set -e
PW='Vp!1sIhDreNY5@R1'
echo "$PW" | sudo -S ln -sf /usr/local/bin/node /usr/bin/node
echo "$PW" | sudo -S systemctl restart vap-relay vap-stun
sleep 6
echo -n "services: "
systemctl is-active vap-relay vap-stun | tr '\n' ' '
echo
node /home/ubuntu/dsh-vap/ops/monitor.mjs
