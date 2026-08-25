#!/usr/bin/env bash
# SA2 第二站点初始化（经老服务器内网投递执行）
set -e
PW='Vp!1sIhDreNY5@R1'
echo "$PW" | sudo -S cp /tmp/node /usr/local/bin/node
echo "$PW" | sudo -S chmod +x /usr/local/bin/node
node -v
mkdir -p /home/ubuntu/dsh-vap/phase4 /home/ubuntu/dsh-vap/phase7 /home/ubuntu/dsh-vap/ops /home/ubuntu/dsh-vap/experiments /home/ubuntu/dsh-vap/systemd
echo PREP-OK
