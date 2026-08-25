#!/usr/bin/env bash
# ops/chaos-service.sh —— R7 故障注入演练（生产级加固）
#
# 演练目标：验证「进程被 kill -9 → systemd Restart=on-failure → 服务恢复 → 监控复绿」全链路。
# 三服务各练一遍，时间线输出到 stdout（供归档）。
#
# 用法：bash ops/chaos-service.sh [服务名，缺省 = 全部三个]
# 前置：vap-monitor.timer 已启用（恢复判据用 ops/monitor.mjs）

set -u
SERVICES="${1:-vap-relay vap-stun vap-files}"
for SVC in $SERVICES; do
  TS0=$(date +%s)
  PID=$(systemctl show -p MainPID --value "$SVC" 2>/dev/null || echo 0)
  if [ "$PID" = "0" ]; then
    echo "[$SVC] SKIP: no MainPID"
    continue
  fi
  echo "[$SVC] kill -9 $PID @ $(date -Is)"
  kill -9 "$PID" 2>/dev/null
  # 等 systemd 重启（RestartSec=5 + 启动时间）
  for i in $(seq 1 30); do
    sleep 1
    ST=$(systemctl is-active "$SVC" 2>/dev/null)
    NPID=$(systemctl show -p MainPID --value "$SVC" 2>/dev/null || echo 0)
    if [ "$ST" = "active" ] && [ "$NPID" != "0" ] && [ "$NPID" != "$PID" ]; then
      echo "[$SVC] RECOVERED in ${i}s newPid=$NPID"
      break
    fi
  done
  ST2=$(systemctl is-active "$SVC" 2>/dev/null)
  if [ "$ST2" != "active" ]; then
    echo "[$SVC] FAIL: still not active after 30s"
    exit 1
  fi
  # 监控复绿
  node /home/ubuntu/dsh-vap/ops/monitor.mjs >/dev/null 2>&1
  echo "[$SVC] monitor exit=$? (0 = all green)"
  sleep 2
done
echo "chaos drill done"
