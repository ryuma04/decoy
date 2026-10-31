#!/usr/bin/env bash
# Stop everything scripts/dev-up.sh started.
for p in core.exe decoy-ssh.exe; do taskkill //IM "$p" //F >/dev/null 2>&1 || pkill -f "$p" 2>/dev/null || true; done
for port in 8000 3000; do
  pid=$(netstat -ano 2>/dev/null | grep -E "[:.]$port .*LISTEN" | awk '{print $NF}' | head -1)
  [ -n "${pid:-}" ] && { taskkill //PID "$pid" //F //T >/dev/null 2>&1 || kill "$pid" 2>/dev/null || true; }
done
echo "stopped"
