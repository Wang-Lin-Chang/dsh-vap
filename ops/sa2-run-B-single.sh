#!/usr/bin/env bash
# R1 装置 B 侧（单连 SA2 relay，二分定位）
set -e
cd /home/ubuntu/dsh-vap
pkill -f 'punch-nod[e]' 2>/dev/null || true
sleep 1
setsid nohup node phase7/punch-node.mjs --site B --stunHost 82.156.128.229 --stunPort 3478 \
  --relayHost 82.156.128.229 --relayPort 42050 --localPort 50001 \
  --out /home/ubuntu/punch-B-sa2only.json > /home/ubuntu/punch-B-sa2only.log 2>&1 < /dev/null &
echo "B started (SA2-only relay)"
