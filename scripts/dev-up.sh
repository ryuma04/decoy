#!/usr/bin/env bash
# Start the Deception SOC locally (no Docker): ML service, core, every built decoy, dashboard.
# Logs: .logs/<name>.log   Stop: scripts/dev-down.sh   Needs: .env (see .env.example), Go, Python, Node.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] || { echo "missing .env (copy .env.example and fill it in)"; exit 1; }
set -a; . ./.env; set +a
mkdir -p .logs .data
ML_PORT="${ML_PORT:-8000}" DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"
export ML_URL="http://127.0.0.1:$ML_PORT" SENSOR_ADDR=127.0.0.1:8443 ANALYST_ADDR=127.0.0.1:8090
# Distro Go builds pin GOTOOLCHAIN=local; let go.mod's toolchain be fetched/used instead.
[ "$(go env GOTOOLCHAIN 2>/dev/null)" = local ] && export GOTOOLCHAIN=auto
PIDS="$ROOT/.logs/pids"; : >> "$PIDS"
track() { echo "$1 $2" >> "$PIDS"; disown "$1" 2>/dev/null || true; } # pid name: scripts/dev-down.sh stops exactly these
PY=python; [ -x ai-service/fastapi/.venv/bin/python ] && PY="$ROOT/ai-service/fastapi/.venv/bin/python"

wait_for() { # name url
  for _ in $(seq 1 60); do curl -s -o /dev/null "$2" && { echo "  $1 up"; return 0; }; sleep 1; done
  echo "  $1 did not start; see .logs/$1.log"; return 1
}

# name:sensor-id:key-var:port for every decoy whose cmd exists (k8s joins automatically once it is built)
DECOYS="ssh:ssh-01:KEY_SSH:${SSH_DECOY_PORT:-2222} web:web-01:KEY_WEB:${WEB_DECOY_PORT:-8080} beacon:beacon-01:KEY_BEACON:8088 k8s:k8s-01:KEY_K8S:6443 db:db-01:KEY_DB:${DB_DECOY_PORT:-5433}"

echo "[1/5] building Go binaries"
(cd backend/go && go build -o bin/core.exe ./cmd/core && go build -o bin/seed.exe ./cmd/seed \
  && for d in $DECOYS; do n=${d%%:*}; [ -d "cmd/decoy-$n" ] && go build -o "bin/decoy-$n.exe" "./cmd/decoy-$n"; done \
  && { [ -d "cmd/divert-proxy" ] && go build -o "bin/divert-proxy.exe" "./cmd/divert-proxy" || true; }; true)

echo "[2/5] seed (persona + honeytokens)"
if [ -f backend/go/seed/out/tokens.json ] && [ "${RESEED:-0}" != 1 ]; then
  echo "  using existing seed (RESEED=1 scripts/dev-up.sh to generate new values)"
else
  (cd backend/go && ./bin/seed.exe > ../../.logs/seed.log 2>&1) && tail -1 .logs/seed.log
fi

echo "[3/5] ML service :$ML_PORT"
# Background jobs send ALL their output to log files, so they never hold this script's terminal open.
# Retrain when there is no model, or the generator / training code changed since it was built (models aren't in git).
(cd ai-service/fastapi && { { [ -f models/input.joblib ] && [ -z "$(find data/generators training -newer models/input.joblib -type f 2>/dev/null)" ]; } \
    || { "$PY" -m data.generators.inputs && "$PY" -m training.train_input; }; } \
  && exec nohup "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port "$ML_PORT") > .logs/ml.log 2>&1 < /dev/null &
track $! ml
wait_for ml "http://127.0.0.1:$ML_PORT/health"

echo "[4/5] core :8443 (sensors) :8090 (analyst) + decoys"
(cd backend/go && exec nohup ./bin/core.exe serve) > .logs/core.log 2>&1 < /dev/null &
track $! core
wait_for core http://127.0.0.1:8090/healthz
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if ! docker ps --format '{{.Names}}' | grep -q '^decoy-sandbox$'; then
    docker rm -f decoy-sandbox 2>/dev/null || true
    docker run -d --name decoy-sandbox -p 127.0.0.1:22222:22222 --add-host s3.harborline-logistics.internal:127.0.0.1 --add-host k8s.harborline-logistics.internal:127.0.0.1 --add-host db.harborline-logistics.internal:127.0.0.1 --add-host hal-app-01:127.0.0.1 decoy-sandbox:latest >/dev/null 2>&1 || true
    echo "  decoy-sandbox (Docker real terminal container) up on :22222"
  else
    echo "  decoy-sandbox (Docker real terminal container) running on :22222"
  fi
fi
for d in $DECOYS; do
  IFS=: read -r n sid keyvar port <<< "$d"
  [ -f "backend/go/bin/decoy-$n.exe" ] || { echo "  decoy-$n not built yet, skipped"; continue; }
  mkdir -p ".data/$n"
  : > ".logs/decoy-$n.log"
  (cd backend/go && SENSOR_ID="$sid" SENSOR_KEY="${!keyvar}" CORE_URL=http://127.0.0.1:8443 LISTEN_ADDR=":$port" \
    ADVERTISED_PORT="$([ "$n" = db ] && echo 5432)" DB_ALIASES="$([ "$n" = db ] && echo "${DB_ALIASES:-aetees_prod}")" \
    DATA_DIR="$ROOT/.data/$n" SEED_DIR="$ROOT/backend/go/seed" exec nohup "./bin/decoy-$n.exe") > ".logs/decoy-$n.log" 2>&1 < /dev/null &
  track $! "decoy-$n"
done
sleep 3
for d in $DECOYS; do n=${d%%:*}; [ -f ".logs/decoy-$n.log" ] && echo "  decoy-$n: $(grep -m1 -oiE 'listening[^,]*|error[^,]*' ".logs/decoy-$n.log" || echo 'starting')"; done
# Divert proxy. Lab: real :3100 + clone :3101 (scripts/aetees-lab.sh). Live shop: AETEES_REAL_URL (e.g. the
# production shop on :3000) + clone :3101, with TRUST_CLOUDFLARE / DIVERT_MODE / ADMIN_HONEYPOT_HOSTS from .env.
if [ -d ".lab/aetees" ] && [ -f "backend/go/bin/divert-proxy.exe" ]; then
  curl -s -o /dev/null http://127.0.0.1:3101/ || ./scripts/aetees-lab.sh
  mkdir -p ".data/aetees"
  REAL="${AETEES_REAL_URL:-http://127.0.0.1:3100}"
  (cd backend/go && SENSOR_ID="aetees-01" SENSOR_KEY="${KEY_AETEES:-}" CORE_URL=http://127.0.0.1:8443 \
    LISTEN_ADDR="${PROXY_LISTEN:-:8200}" REAL_URL="$REAL" CLONE_URL="http://127.0.0.1:3101" \
    TRUST_CLOUDFLARE="${TRUST_CLOUDFLARE:-0}" DIVERT_MODE="${DIVERT_MODE:-shadow}" ADMIN_HONEYPOT_HOSTS="${ADMIN_HONEYPOT_HOSTS:-}" \
    DATA_DIR="$ROOT/.data/aetees" SEED_DIR="$ROOT/backend/go/seed" exec nohup "./bin/divert-proxy.exe") > ".logs/divert-proxy.log" 2>&1 < /dev/null &
  track $! divert-proxy
  echo "  divert-proxy ${PROXY_LISTEN:-:8200} -> real $REAL / clone :3101 (mode ${DIVERT_MODE:-shadow}, admin honeypot: ${ADMIN_HONEYPOT_HOSTS:-none})"
fi

echo "[5/5] dashboard :$DASHBOARD_PORT"
# reinstall when package-lock.json changed since the last install (a pulled commit may add a dependency).
# DASHBOARD_HOST=0.0.0.0 (default) lets other devices on the LAN open it for demos; set 127.0.0.1 on the live host.
(cd frontend/nextjs && { [ node_modules/.package-lock.json -nt package-lock.json ] || npm install --no-audit --no-fund; }   && exec nohup npx next dev -H "${DASHBOARD_HOST:-0.0.0.0}" -p "$DASHBOARD_PORT") > .logs/dashboard.log 2>&1 < /dev/null &
track $! dashboard
wait_for dashboard "http://127.0.0.1:$DASHBOARD_PORT/login"

echo
echo "Dashboard: http://localhost:$DASHBOARD_PORT   login: $SOC_ADMIN_EMAIL  (password: SOC_ADMIN_PASSWORD in .env)"
echo "Decoys:    SSH ssh -p ${SSH_DECOY_PORT:-2222} deploy@localhost (deploy_password in backend/go/seed/out/persona.json)"
echo "           Web http://localhost:${WEB_DECOY_PORT:-8080}   Beacon http://localhost:8088   K8s https://localhost:6443"
echo "           DB  psql -h localhost -p ${DB_DECOY_PORT:-5433} -U app orders (password: tok_db in backend/go/seed/out/tokens.json)"
echo "Logs:      .logs/   Stop: scripts/dev-down.sh"
if [ "${DAEMON:-0}" = "1" ]; then
  sleep infinity
fi
