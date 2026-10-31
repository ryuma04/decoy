#!/usr/bin/env bash
# Stop everything scripts/dev-up.sh started (by process name, then by port).
export MSYS_NO_PATHCONV=1 # Git Bash: keep taskkill's /IM /F flags as they are
kill_name() {
  if command -v taskkill.exe >/dev/null 2>&1; then taskkill.exe /IM "$1" /F /T >/dev/null 2>&1; else pkill -f "$1" 2>/dev/null; fi
  return 0
}
kill_port() {
  local pids
  if command -v netstat.exe >/dev/null 2>&1; then
    pids=$(netstat.exe -ano 2>/dev/null | tr -d '\r' | awk -v p=":$1" '$2 ~ p"$" && $4 == "LISTENING" {print $5}' | sort -u)
    for pid in $pids; do taskkill.exe /PID "$pid" /F /T >/dev/null 2>&1; done
  else
    pids=$(lsof -ti tcp:"$1" 2>/dev/null); [ -n "$pids" ] && kill $pids 2>/dev/null
  fi
  return 0
}
for p in core.exe decoy-ssh.exe decoy-web.exe decoy-beacon.exe decoy-k8s.exe; do kill_name "$p"; done
for port in 8000 8090 8443 2222 8080 8088 6443 3000; do kill_port "$port"; done
sleep 1
left=""
for port in 8000 8090 8443 2222 8080 8088 6443 3000; do
  if command -v netstat.exe >/dev/null 2>&1 && netstat.exe -ano 2>/dev/null | tr -d '\r' | awk -v p=":$port" '$2 ~ p"$" && $4 == "LISTENING"' | grep -q .; then
    left="$left $port"
  fi
done
[ -z "$left" ] && echo "stopped" || echo "still listening on:$left"
