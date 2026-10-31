#!/usr/bin/env bash
# Start the Deception SOC locally (no Docker): ML service, core, every built decoy, dashboard.
# Logs: .logs/<name>.log   Stop: scripts/dev-down.sh   Needs: .env (see .env.example), Go, Python, Node.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] || { echo "missing .env (copy .env.example and fill it in)"; exit 1; }
set -a; . ./.env; set +a
mkdir -p .logs .data
export ML_URL=http://127.0.0.1:8000 SENSOR_ADDR=127.0.0.1:8443 ANALYST_ADDR=127.0.0.1:8090

wait_for() { # name url
  for _ in $(seq 1 60); do curl -s -o /dev/null "$2" && { echo "  $1 up"; return 0; }; sleep 1; done
  echo "  $1 did not start; see .logs/$1.log"; return 1
}

# name:sensor-id:key-var:port for every decoy whose cmd exists (k8s joins automatically once it is built)
DECOYS="ssh:ssh-01:KEY_SSH:2222 web:web-01:KEY_WEB:8080 beacon:beacon-01:KEY_BEACON:8088 k8s:k8s-01:KEY_K8S:6443 db:db-01:KEY_DB:${DB_DECOY_PORT:-5433}"

echo "[1/5] building Go binaries"
(cd backend/go && go build -o bin/core.exe ./cmd/core && go build -o bin/seed.exe ./cmd/seed \
  && for d in $DECOYS; do n=${d%%:*}; [ -d "cmd/decoy-$n" ] && go build -o "bin/decoy-$n.exe" "./cmd/decoy-$n"; done; true)

echo "[2/5] seed (persona + honeytokens)"
if [ -f backend/go/seed/out/tokens.json ] && [ "${RESEED:-0}" != 1 ]; then
  echo "  using existing seed (RESEED=1 scripts/dev-up.sh to generate new values)"
else
  (cd backend/go && ./bin/seed.exe > ../../.logs/seed.log 2>&1) && tail -1 .logs/seed.log
fi

echo "[3/5] ML service :8000"
# Background jobs send ALL their output to log files, so they never hold this script's terminal open.
(cd ai-service/fastapi && { [ -f models/input.joblib ] || { python -m data.generators.inputs && python -m training.train_input; }; } \
  && exec nohup python -m uvicorn app.main:app --host 127.0.0.1 --port 8000) > .logs/ml.log 2>&1 < /dev/null &
wait_for ml http://127.0.0.1:8000/health

echo "[4/5] core :8443 (sensors) :8090 (analyst) + decoys"
(cd backend/go && exec nohup ./bin/core.exe serve) > .logs/core.log 2>&1 < /dev/null &
wait_for core http://127.0.0.1:8090/healthz
for d in $DECOYS; do
  IFS=: read -r n sid keyvar port <<< "$d"
  [ -f "backend/go/bin/decoy-$n.exe" ] || { echo "  decoy-$n not built yet, skipped"; continue; }
  mkdir -p ".data/$n"
  (cd backend/go && SENSOR_ID="$sid" SENSOR_KEY="${!keyvar}" CORE_URL=http://127.0.0.1:8443 LISTEN_ADDR=":$port" \
    ADVERTISED_PORT="$([ "$n" = db ] && echo 5432)" \
    DATA_DIR="$ROOT/.data/$n" SEED_DIR="$ROOT/backend/go/seed" exec nohup "./bin/decoy-$n.exe") > ".logs/decoy-$n.log" 2>&1 < /dev/null &
done
sleep 3
for d in $DECOYS; do n=${d%%:*}; [ -f ".logs/decoy-$n.log" ] && echo "  decoy-$n: $(grep -m1 -oiE 'listening[^,]*|error[^,]*' ".logs/decoy-$n.log" || echo 'starting')"; done

echo "[5/5] dashboard :3000"
(cd frontend/nextjs && { [ -d node_modules ] || npm install --no-audit --no-fund; } && exec nohup npm run dev) > .logs/dashboard.log 2>&1 < /dev/null &
wait_for dashboard http://127.0.0.1:3000/login

echo
echo "Dashboard: http://localhost:3000   login: $SOC_ADMIN_EMAIL  (password: SOC_ADMIN_PASSWORD in .env)"
echo "Decoys:    SSH ssh -p 2222 deploy@localhost (deploy_password in backend/go/seed/out/persona.json)"
echo "           Web http://localhost:8080   Beacon http://localhost:8088   K8s https://localhost:6443"
echo "           DB  psql -h localhost -p ${DB_DECOY_PORT:-5433} -U app orders (password: tok_db in backend/go/seed/out/tokens.json)"
echo "Logs:      .logs/   Stop: scripts/dev-down.sh"
