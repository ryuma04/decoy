#!/bin/sh
set -e

GATEWAY=$(ip route | awk '/default/ { print $3 }')
GATEWAY="${GATEWAY:-172.17.0.1}"

socat TCP-LISTEN:8088,fork,reuseaddr "TCP:${GATEWAY}:8088" &
socat TCP-LISTEN:6443,fork,reuseaddr "TCP:${GATEWAY}:6443" &
socat TCP-LISTEN:8081,fork,reuseaddr "TCP:${GATEWAY}:8081" &
socat TCP-LISTEN:8200,fork,reuseaddr "TCP:${GATEWAY}:8200" &
socat TCP-LISTEN:5432,fork,reuseaddr "TCP:${GATEWAY}:5433" &

echo "127.0.0.1 s3.harborline-logistics.internal k8s.harborline-logistics.internal db.harborline-logistics.internal hal-app-01" >> /etc/hosts 2>/dev/null || true

exec /usr/sbin/sshd -D -e -p 22222
