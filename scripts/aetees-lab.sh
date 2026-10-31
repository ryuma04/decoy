#!/usr/bin/env bash
# Builds and starts the Aetees Bakehouse lab: two copies of the same app build behind the divert proxy.
#   real  :3100  catalogue only                          (the "production" shop for the demo)
#   clone :3101  same catalogue + synthetic customers/orders, admin password = honeytoken (the honeypot)
# Source: AETEES_SRC (default ../references/aetee). The copy lives in .lab/aetees (gitignored) and uses SQLite,
# so no MySQL is needed; the client's repo itself is never modified.
#   scripts/aetees-lab.sh          set up once (copy, schema, build, seed) and start both
#   REBUILD=1 scripts/aetees-lab.sh   copy and rebuild from the source again
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SRC="${AETEES_SRC:-$ROOT/../references/aetee}"
LAB="$ROOT/.lab/aetees"
TOKENS="$ROOT/backend/go/seed/out/tokens.json"
mkdir -p .logs .lab
[ -d "$SRC/src" ] || { echo "Aetees source not found at $SRC (set AETEES_SRC)"; exit 1; }
[ -f "$TOKENS" ] || { echo "run scripts/dev-up.sh once first (it writes $TOKENS)"; exit 1; }

tok() { python -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]]['match_value'])" "$TOKENS" "$1"; }
ADMIN_TOKEN_PW="$(tok tok_aetees_admin)"
INVOICE_PATH="$(tok tok_aetees_invoice)"
SECRETS="$ROOT/.lab/secrets.env"
if [ ! -f "$SECRETS" ]; then
  rnd() { python -c "import secrets;print(secrets.token_hex(24))"; }
  { echo "REAL_ADMIN_PASSWORD=$(rnd)"; echo "REAL_ADMIN_SECRET=$(rnd)"; echo "CLONE_ADMIN_SECRET=$(rnd)"; } > "$SECRETS"
fi
. "$SECRETS"

if [ "${REBUILD:-0}" = 1 ] || [ ! -f "$LAB/.next/BUILD_ID" ]; then
  echo "[aetees] copying source"
  if [ -e "$LAB/node_modules" ] && command -v cmd.exe >/dev/null 2>&1; then  # older runs linked it; unlink, never follow
    MSYS_NO_PATHCONV=1 cmd.exe /c rmdir "$(cygpath -w "$LAB/node_modules")" 2>/dev/null || true
  fi
  rm -rf "$LAB/src" "$LAB/public" "$LAB/prisma" "$LAB/.next"; mkdir -p "$LAB"
  (cd "$SRC" && tar --exclude=./node_modules --exclude=./.next --exclude=./.git --exclude='./*.msi' -cf - .) | (cd "$LAB" && tar -xf -)
  # own copy of node_modules: the build refuses links that leave the project, and copying avoids re-downloading
  # Prisma engines. No source node_modules -> npm ci.
  echo "[aetees] node_modules"
  rm -rf "$LAB/node_modules"
  if [ -d "$SRC/node_modules" ] && command -v robocopy.exe >/dev/null 2>&1; then
    rc=0 # robocopy: 0-7 = success, 8+ = failure
    MSYS_NO_PATHCONV=1 robocopy.exe "$(cygpath -w "$SRC/node_modules")" "$(cygpath -w "$LAB/node_modules")" /E /MT:16 /NFL /NDL /NJH /NJS /NP \
      > "$ROOT/.logs/aetees-npm.log" 2>&1 || rc=$?
    [ "$rc" -lt 8 ] || { echo "copying node_modules failed; see .logs/aetees-npm.log"; exit 1; }
  elif [ -d "$SRC/node_modules" ]; then
    cp -r "$SRC/node_modules" "$LAB/node_modules"
  else
    (cd "$LAB" && npm ci --prefer-offline --no-audit --no-fund > "$ROOT/.logs/aetees-npm.log" 2>&1) \
      || { echo "npm ci failed; see .logs/aetees-npm.log"; exit 1; }
  fi
  echo "[aetees] schema: mysql -> sqlite (lab only)"
  # native engine only (the deploy binaryTargets would download Linux engines we never use here)
  sed -i -E 's/provider *= *"mysql"/provider = "sqlite"/; s/ @db\.[A-Za-z]+(\([^)]*\))?//g; /binaryTargets/d' "$LAB/prisma/schema.prisma"
  cp scripts/aetees/seed.mjs "$LAB/seed-lab.mjs"
  (cd "$LAB" && npx prisma generate >/dev/null)
  for db in real clone; do
    rm -f "$LAB/prisma/$db.db"
    (cd "$LAB" && DATABASE_URL="file:./$db.db" npx prisma db push --skip-generate >/dev/null)
  done
  (cd "$LAB" && DATABASE_URL="file:./real.db" node seed-lab.mjs real)
  (cd "$LAB" && MSYS_NO_PATHCONV=1 DATABASE_URL="file:./clone.db" CANARY_INVOICE_URL="https://aeteesbakehouse.com$INVOICE_PATH" \
    BREADCRUMB_PATH="/backup/aetees_db_FINAL.sql.gz" node seed-lab.mjs decoy)
  echo "[aetees] next build (one build, two instances)"
  (cd "$LAB" && NEXT_TELEMETRY_DISABLED=1 npx next build > "$ROOT/.logs/aetees-build.log" 2>&1) \
    || { echo "build failed; see .logs/aetees-build.log"; exit 1; }
fi

start() { # name port db admin_password admin_secret
  (cd "$LAB" && DATABASE_URL="file:./$3.db" ADMIN_USERNAME=admin ADMIN_PASSWORD="$4" ADMIN_SECRET="$5" PORT="$2" \
    NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 exec nohup npx next start -p "$2" -H 127.0.0.1) \
    > ".logs/aetees-$1.log" 2>&1 < /dev/null &
}
start real 3100 real "$REAL_ADMIN_PASSWORD" "$REAL_ADMIN_SECRET"
start clone 3101 clone "$ADMIN_TOKEN_PW" "$CLONE_ADMIN_SECRET"
for p in 3100 3101; do
  for _ in $(seq 1 60); do curl -s -o /dev/null "http://127.0.0.1:$p/" && { echo "  aetees :$p up"; break; }; sleep 1; done
done
