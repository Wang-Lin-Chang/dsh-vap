#!/usr/bin/env bash
# SA2 第二站点代码投递（老服务器执行：内网 scp 到 SA2）
set -e
PW='Vp!1sIhDreNY5@R1'
D=/home/ubuntu/dsh-vap
FILES=(
  vap-core.mjs vap-transport.mjs key-store.mjs logger.mjs config.mjs laws.json
  phase4/relay-server.mjs phase4/relay-client.mjs
  phase7/stun-server.mjs phase7/stun-fingerprint.mjs phase7/hole-punch.mjs
  phase7/punch-node.mjs phase7/punch-chain.mjs phase7/punch-plan.mjs phase7/nat-classify.mjs
  experiments/graynet-experiment.mjs
  ops/monitor.mjs ops/chaos-service.sh ops/rollback-service.sh ops/backup.mjs
  systemd/vap-relay.service systemd/vap-stun.service systemd/vap-monitor.service systemd/vap-monitor.timer
)
for f in "${FILES[@]}"; do
  sshpass -p "$PW" scp -o StrictHostKeyChecking=no "$D/$f" "ubuntu@172.21.128.11:$D/$f"
done
echo FILES-DELIVERED
