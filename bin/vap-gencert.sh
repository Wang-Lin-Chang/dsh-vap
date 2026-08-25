#!/usr/bin/env bash
# bin/vap-gencert.sh —— S6 中继 TLS 自签证书生成（零 npm 依赖，仅系统 openssl）
#
# 用法：bash bin/vap-gencert.sh [outDir] [serverCN]
# 产出：outDir/vap-ca.pem      —— CA 证书（客户端 tlsOptions.ca 固定）
#       outDir/vap-server.crt  —— 服务器证书（relay-server tlsOptions.cert）
#       outDir/vap-server.key  —— 服务器私钥（relay-server tlsOptions.key，600 权限）
#
# 部署：服务器端 vap-relay 用 cert+key；客户端固定 ca。ca.key 生成后立即删除（仅签发用一次）。
set -euo pipefail
OUT="${1:-./tls}"
CN="${2:-vap-relay}"
mkdir -p "$OUT"
umask 077

# 1) 自签 CA（10 年）
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT/vap-ca.key" -out "$OUT/vap-ca.pem" -days 3650 \
  -subj "/CN=VAP Relay CA"

# 2) 服务器证书（由 CA 签发，SAN 含 CN 与 127.0.0.1）
openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT/vap-server.key" -out "$OUT/vap-server.csr" \
  -subj "/CN=$CN"
openssl x509 -req -in "$OUT/vap-server.csr" \
  -CA "$OUT/vap-ca.pem" -CAkey "$OUT/vap-ca.key" -CAcreateserial \
  -out "$OUT/vap-server.crt" -days 825 \
  -extfile <(printf "subjectAltName=DNS:%s,IP:127.0.0.1" "$CN")

# 3) 清理：签发用私钥与临时文件即用即删
rm -f "$OUT/vap-server.csr" "$OUT/vap-ca.key" "$OUT/vap-ca.srl"
chmod 600 "$OUT/vap-server.key"

echo "generated: $OUT/vap-ca.pem $OUT/vap-server.crt $OUT/vap-server.key"
echo "server: tlsOptions = { cert: readFileSync('$OUT/vap-server.crt'), key: readFileSync('$OUT/vap-server.key') }"
echo "client: tlsOptions = { ca: readFileSync('$OUT/vap-ca.pem') }"
