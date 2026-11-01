#!/usr/bin/env bash
# Wipe recorded SOC activity for a clean demo; keeps users, sensors, honeytokens, allowlist and scorer weights.
#   scripts/reset-demo.sh        dry run: shows what would be deleted
#   scripts/reset-demo.sh -yes   deletes it (no undo), clears the lab shop's login lockouts, then restart the stack
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] || { echo "missing .env"; exit 1; }
set -a; . ./.env; set +a

(cd backend/go && go run ./cmd/reset-demo "$@")

if [ "${1:-}" = "-yes" ] && [ -d .lab/aetees/prisma ]; then
  # earlier test logins filled the lab shop's 5-tries lockout; only the lab copies (SQLite) are touched
  python - <<'EOF'
import os, sqlite3
for db in ("real", "clone"):
    p = os.path.join(".lab", "aetees", "prisma", db + ".db")
    if os.path.exists(p):
        c = sqlite3.connect(p)
        n = c.execute("DELETE FROM rate_limits").rowcount
        c.commit()
        print(f"lab shop ({db}): cleared {n} login/contact lockouts")
EOF
fi
if [ "${1:-}" = "-yes" ]; then
  echo "Now restart: scripts/dev-down.sh && scripts/aetees-lab.sh && scripts/dev-up.sh"
fi
