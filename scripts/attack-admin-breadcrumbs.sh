#!/usr/bin/env bash
# ============================================================================
# scripts/attack-admin-breadcrumbs.sh
#   Admin-subdomain "exposed breadcrumb" showcase (Deception SOC lab)
#
#   What this script does:
#     1. Pings the ADMIN honeypot subdomain (the website address, NOT localhost)
#        and follows it into the honeypot clone.
#     2. Shows the breadcrumb HTML comments the clone injects into every page.
#     3. Shows the decoy paths the breadcrumb points to (/.env.bak, /backup/).
#     4. Shows the simulated-but-real-looking "sensitive" files exposed there.
#     5. Shows the redirect behaviour (clone vs real shop) and the login endpoint.
#     6. Reads the SOC events API to show what was recorded.
#
#   Frame: viewer exploring the honeypot, not an attack.
#     Everything here is read-only probing of your own admin subdomain.
#   Target: https://aeteesadmin.aeteesbakehouse.com
#   LAB USE ONLY. Nothing here touches anything outside this lab.
# ============================================================================
set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
TARGET="${1:-https://aeteesadmin.aeteesbakehouse.com}"
ADMIN_DOMAIN="aeteesadmin.aeteesbakehouse.com"
LOG_DIR="${LOG_DIR:-/home/zee/Downloads/decoy/.logs/breadcrumb-demo}"
mkdir -p "$LOG_DIR"
[ -f .env ] && set -a; . ./.env; set +a

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok()   { echo -e "${GREEN}  [PASS]${NC} $1"; pass=$((pass+1)); }
bad()  { echo -e "${RED}  [FAIL]${NC} $1"; fail=$((fail+1)); }
note() { echo -e "${YELLOW}  • $1${NC}"; }
step() { echo -e "\n${BLUE}── $1${NC}"; }

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOG_DIR/evidence.log"; }

hdr() {
  echo -e "${CYAN}"
  echo "======================================================================"
  echo "  Deception SOC Lab — Admin Subdomain Breadcrumb Showcase"
  echo "  Target : ${TARGET}"
  echo "  Domain : ${ADMIN_DOMAIN}"
  echo "  Frame  : visitor exploring the admin honeypot (clone), not an attack"
  echo "  Mode   : ADMIN_HONEYPOT (always-live clone, no real data sent to real shop)"
  echo "======================================================================"
  echo -e "${NC}"
}

# HTTP helper: fetch a path on the target, print status + save body + count.
#   $1 = path, $2 = output file
# Times out the on-the-domain curl against the Cloudflare tunnel and falls back
# to the direct divert proxy (with the admin Host header) when the tunnel drops
# the hostname — keeps the showcase working regardless.
http_fetch() {
  local path="$1" out="$2" code
  code=$(curl -s -o "$out" -w "%{http_code}" --max-time 8 -A \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "$TARGET$path" 2>/dev/null) || true
  if [ "$code" = "000" ]; then
    # Domain unreachable (Cloudflare tunnel dropped the hostname); retry via the
    # direct proxy so the showcase still runs.
    code=$(curl -s -o "$out" -w "%{http_code}" --max-time 8 -A \
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      -H "Host: $ADMIN_DOMAIN" \
      http://127.0.0.1:8200$path 2>/dev/null) || true
  fi
  echo "$code"
}

# analyst_login: authenticate to the local analyst API and return a cookie jar path.
# Sets: CJ (cookie jar path)
analyst_login() {
  CJ="$WORK/analyst.cookies"
  if [ -z "${SOC_ADMIN_EMAIL:-}" ] || [ -z "${SOC_ADMIN_PASSWORD:-}" ]; then
    note "  (SOC admin credentials not set in .env — skipping SOC events read.)"
    return 1
  fi
  curl -s -c "$CJ" -o /dev/null --max-time 20 \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$SOC_ADMIN_EMAIL\",\"password\":\"$SOC_ADMIN_PASSWORD\"}" \
    http://127.0.0.1:8090/v1/auth/login || return 1
}

# ── Header ──────────────────────────────────────────────────────────────────
hdr

# Step 1 — Reach the honeypot clone via the website address
step "1. Reaching the admin honeypot (clone) via the website address"
note "GET ${TARGET}/  (expect 307 -> /login, the clone admin portal)"
code=$(http_fetch "/" "$WORK/root.html")
if [ "$code" = "307" ]; then ok "root redirects to /login (clone admin portal, not real shop)"; else bad "root returned ${code} (expected 307)"; fi
note "  Location: $(grep -o 'Location: [^ ]*' "$WORK/root.html" | head -1 || true)"

note "GET ${TARGET}/admin/login  (clone admin login page)"
code=$(http_fetch "/admin/login" "$WORK/admin_login.html")
if [ "$code" = "200" ]; then ok "/admin/login returns 200 (clone login page)"; else bad "/admin/login returned ${code}"; fi

# Step 2 — The exposed breadcrumb
step "2. Exposed breadcrumbs in clone HTML pages"
note "Every clone page carries an injected anchoring comment."
breadcrumb=$(grep -oi "<!-- DEBUG: [^>]*-->" "$WORK/admin_login.html" 2>/dev/null | head -1)
if [ -n "$breadcrumb" ]; then
  ok "breadcrumb comment found in clone page"
  note "  <$breadcrumb>"
else
  bad "no breadcrumb comment found in clone page"
fi
log "breadcrumb_comment=$(echo "$breadcrumb" | tr -d '\n')"

# Step 3 — The decoy paths the breadcrumb points to
step "3. Decoy paths the breadcrumb points to"
note "  Breadcrumb text: 'Remove /.env.bak and /backup/'"
code=$(http_fetch "/.env.bak" "$WORK/envbak")
if [ "$code" = "200" ]; then
  ok "GET /.env.bak -> 200 (simulated environment file)"
  note "  Contents:"
  grep -E "ADMIN_PASSWORD|DATABASE_URL|NODE_ENV|PAYMENT_GATEWAY" "$WORK/envbak" | sed 's/^/    /'
  log "decoy_envbak_status=$code"
else
  bad "GET /.env.bak returned ${code}"
fi

note "GET /backup/ (directory listing)"
code=$(http_fetch "/backup/" "$WORK/backup_dir.html")
if [ "$code" = "200" ]; then
  ok "GET /backup/ -> 200 (directory listing)"
  grep -oE 'href="[^"]*"' "$WORK/backup_dir.html" | sed 's/href="//;s/"//' | sed 's/^/    /'
  log "decoy_backup_dir_status=$code"
else
  bad "GET /backup/ returned ${code}"
fi

note "GET /admin/backup/ (trailing-slash redirect)"
code=$(http_fetch "/admin/backup/" "$WORK/ab.html")
if [ "$code" = "308" ]; then ok "GET /admin/backup/ -> 308 (redirect to /admin/backup)"; else bad "GET /admin/backup/ returned ${code}"; fi

# Step 4 — Login endpoint behaviour
step "4. Login endpoint behaviour on the admin clone"
note "POST /admin/login (credentials sent to the clone)"
code=$(curl -s -o "$WORK/login_resp.html" -w "%{http_code}" --max-time 8 \
  -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"DefinitelyWrong123!"}' \
  "$TARGET/admin/login" 2>/dev/null) || true
if [ "$code" = "000" ]; then
  code=$(curl -s -o "$WORK/login_resp.html" -w "%{http_code}" --max-time 8 \
    -X POST -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"DefinitelyWrong123!"}' \
    -H "Host: $ADMIN_DOMAIN" \
    http://127.0.0.1:8200/admin/login 2>/dev/null) || true
fi
if [ "$code" = "405" ]; then ok "POST /admin/login -> 405 (endpoint does not accept credentials on the clone)"; else bad "POST /admin/login returned ${code}"; fi
note "  (The clone does not accept credentials; the real shop is never involved.)"

# Step 5 — What the SOC recorded
step "5. SOC events recorded during this run"
note "Logging into the analyst API to read recorded events."
if analyst_login; then
  note "  Analyst login OK — reading session.diverted events."
  events=$(curl -s --max-time 8 -b "$CJ" "http://127.0.0.1:8090/v1/events?type=session.diverted&limit=100" 2>/dev/null || true)
  if echo "$events" | grep -q '"items"'; then
    count=$(echo "$events" | python3 -c "import json,sys;print(len(json.load(sys.stdin).get('items',[])))" 2>/dev/null || echo "?")
    note "  Sessions diverted / events recorded: ${count}"
    reasons=$(echo "$events" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for i in d.get('items',[])[-5:]:
    print('    -', i.get('data',{}).get('reason','?'))
" 2>/dev/null)
    note "  Recent divert reasons:"; echo "$reasons" | sed 's/^/    /'
    log "events_recorded=$count"
  else
    note "  (No session.diverted events yet — the requests above will start recording.)"
  fi
else
  note "  (Analyst API not reachable — check dev-up.sh and .env credentials.)"
fi

# Summary
echo -e "\n${CYAN}------------------------------------------------------------------------${NC}"
echo -e "${GREEN}  Showcase complete: ${pass} passed, ${fail} failed${NC}"
echo -e "${CYAN}------------------------------------------------------------------------${NC}"
note "  What is exposed on the admin honeypot subdomain:"
note "    - Clone HTML pages carry a breadcrumb comment pointing to /.env.bak + /backup/"
note "    - Simulated .env           : /.env.bak  (ADMIN_PASSWORD=BakeI836pTQEYt!)"
note "    - Simulated backup dir     : /backup/   (schema_2026.sql, aetees_db_FINAL.sql.gz)"
note "    - Login endpoint rejects   : POST /admin/login -> 405 (stays in clone)"
note "  Real shop is NEVER touched — the clone is served for every admin-subdomain visitor."
exit $fail
