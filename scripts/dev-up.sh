#!/usr/bin/env bash
# Start the Deception SOC locally (no Docker): ML service, core, SSH decoy, dashboard.
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

echo "[1/5] building Go binaries"
(cd backend/go && go build -o bin/core.exe ./cmd/core && go build -o bin/decoy-ssh.exe ./cmd/decoy-ssh && go build -o bin/seed.exe ./cmd/seed)

echo "[2/5] seed (persona + honeytokens)"
(cd backend/go && ./bin/seed.exe > ../../.logs/seed.log 2>&1) && tail -1 .logs/seed.log

echo "[3/5] ML service :8000"
(cd ai-service/fastapi && { [ -f models/input.joblib ] || { python -m data.generators.inputs && python -m training.train_input; }; } \
  && nohup python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > ../../.logs/ml.log 2>&1 &)
wait_for ml http://127.0.0.1:8000/health

echo "[4/5] core :8443 (sensors) :8090 (analyst) + SSH decoy :2222"
(cd backend/go && nohup ./bin/core.exe serve > ../../.logs/core.log 2>&1 &)
wait_for core http://127.0.0.1:8090/healthz
(cd backend/go && SENSOR_ID=ssh-01 SENSOR_KEY="$KEY_SSH" CORE_URL=http://127.0.0.1:8443 LISTEN_ADDR=:2222 \
  DATA_DIR="$ROOT/.data" SEED_DIR="$ROOT/backend/go/seed" nohup ./bin/decoy-ssh.exe > ../../.logs/decoy-ssh.log 2>&1 &)
sleep 2; grep -m1 -iE "listening|error" .logs/decoy-ssh.log || true

echo "[5/5] dashboard :3000"
(cd frontend/nextjs && { [ -d node_modules ] || npm install --no-audit --no-fund; } && nohup npm run dev > ../../.logs/dashboard.log 2>&1 &)
wait_for dashboard http://127.0.0.1:3000/login

echo
echo "Dashboard: http://localhost:3000   login: $SOC_ADMIN_EMAIL  (password: SOC_ADMIN_PASSWORD in .env)"
echo "SSH decoy: ssh -p 2222 deploy@localhost   (password: deploy_password in backend/go/seed/out/persona.json)"
