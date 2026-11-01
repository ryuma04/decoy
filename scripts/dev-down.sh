#!/usr/bin/env bash
# Stop everything scripts/dev-up.sh and scripts/aetees-lab.sh started.
# Linux/macOS: only the PIDs those scripts recorded in .logs/pids plus this repo's own binaries. It never kills by
# port, because on a shared host the same ports may belong to something else (e.g. the live shop on :3000).
# Windows (Git Bash): by process name, then by port, as before.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export MSYS_NO_PATHCONV=1 # Git Bash: keep taskkill's /IM /F flags as they are

if command -v taskkill.exe >/dev/null 2>&1; then
  for p in core.exe decoy-ssh.exe decoy-web.exe decoy-beacon.exe decoy-k8s.exe decoy-db.exe divert-proxy.exe; do
    taskkill.exe /IM "$p" /F /T >/dev/null 2>&1
  done
  for port in 8000 8090 8443 2222 8080 8088 6443 5433 8200 3000 3100 3101; do
    pids=$(netstat.exe -ano 2>/dev/null | tr -d '\r' | awk -v p=":$port" '$2 ~ p"$" && $4 == "LISTENING" {print $5}' | sort -u)
    for pid in $pids; do taskkill.exe /PID "$pid" /F /T >/dev/null 2>&1; done
  done
  echo "stopped"
  exit 0
fi

stop_tree() { # pid: the process and its children (npx -> next-server, nohup subshells)
  local kids
  kids=$(pgrep -P "$1" 2>/dev/null)
  for k in $kids; do stop_tree "$k"; done
  kill "$1" 2>/dev/null
}

if [ -f "$ROOT/.logs/pids" ]; then
  while read -r pid name; do
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { stop_tree "$pid"; echo "  stopped $name ($pid)"; }
  done < "$ROOT/.logs/pids"
  rm -f "$ROOT/.logs/pids"
fi
sleep 1
echo "stopped"
