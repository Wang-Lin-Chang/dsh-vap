#!/usr/bin/env bash
# R1 装置 B 侧（老服务器执行）：双中继打洞
set -e
D=/home/ubuntu/dsh-vap
cd $D
pkill -f 'punch-nod[e]' 2>/dev/null || true
sleep 1
setsid nohup node phase7/punch-node.mjs --site B --stunHost 101.42.23.246 --stunPort 3478 \
  --relayHost "101.42.23.246,82.156.128.229" --relayPort 42050 --localPort 50001 \
  --out /home/ubuntu/punch-B-dual.json > /home/ubuntu/punch-B-dual.log 2>&1 < /dev/null &
echo "B started pid $!"
