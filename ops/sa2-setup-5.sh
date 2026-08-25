#!/usr/bin/env bash
# 老服务器执行：把更新后的 monitor.mjs 投到 SA2 并验证
set -e
PW='Vp!1sIhDreNY5@R1'
sshpass -p "$PW" scp -o StrictHostKeyChecking=no /home/ubuntu/dsh-vap/ops/monitor.mjs ubuntu@172.21.128.11:/home/ubuntu/dsh-vap/ops/monitor.mjs
sshpass -p "$PW" ssh -o StrictHostKeyChecking=no ubuntu@172.21.128.11 'VAP_MONITOR_SKIP=vap-files node /home/ubuntu/dsh-vap/ops/monitor.mjs'
