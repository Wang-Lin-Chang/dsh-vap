#!/usr/bin/env bash
# ops/rollback-service.sh —— R6 滚动升级/回滚（生产级加固）
#
# 回滚 = 把服务器 /home/ubuntu/dsh-vap 切回指定 git 提交，重启三服务，跑监控验证。
# 用法：bash ops/rollback-service.sh <git-commit>
# 前置：/home/ubuntu/dsh-vap 是 git 仓库（生产部署目录）。
#
# 注意：只切换代码 + 重启；数据文件（账本/registry/keys）不在 git 内、不受影响。

set -euo pipefail
TARGET="${1:?usage: rollback-service.sh <git-commit>}"
cd /home/ubuntu/dsh-vap
git rev-parse --verify "$TARGET" >/dev/null 2>&1 || { echo "unknown commit: $TARGET"; exit 1; }
echo "rollback: $(git rev-parse --short HEAD) -> $(git rev-parse --short "$TARGET")"
git stash --include-untracked --quiet 2>/dev/null || true
git checkout --quiet "$TARGET"
sudo systemctl restart vap-relay vap-stun vap-files
sleep 6
node /home/ubuntu/dsh-vap/ops/monitor.mjs
echo "rollback done; to return: bash ops/rollback-service.sh <previous-commit>"
