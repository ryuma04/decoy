#!/usr/bin/env sh
# Decoys must never execute anything (06, backend/CLAUDE.md). Fails if decoy code imports process-starting APIs.
set -eu
cd "$(dirname "$0")/.."
dirs=""
for d in internal/decoy cmd/decoy-ssh cmd/decoy-web cmd/decoy-k8s cmd/decoy-beacon internal/sensorkit internal/fakefs; do
  [ -d "$d" ] && dirs="$dirs $d"
done
[ -z "$dirs" ] && { echo "check-no-exec: no decoy code yet"; exit 0; }
bad=$(grep -rnE '"os/exec"|syscall\.(Exec|ForkExec|StartProcess)|os\.StartProcess|"plugin"|unsafe\.' --include='*.go' $dirs || true)
if [ -n "$bad" ]; then
  echo "check-no-exec: forbidden API in decoy code:"; echo "$bad"; exit 1
fi
echo "check-no-exec: ok ($dirs )"
