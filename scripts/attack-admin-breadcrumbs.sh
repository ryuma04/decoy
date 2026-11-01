#!/usr/bin/env bash
# ============================================================================
# scripts/attack-admin-breadcrumbs.sh
#   Admin-subdomain breadcrumb showcase — from an attacker's perspective
#
#   What this script does (from an attacker's POV):
#     1. Lands on the admin subdomain of aeteesbakehouse.com and follows the redirect
#        into the honeypot clone (the clone, not the real shop).
#     2. Strips the injected breadcrumb comment off the clone's login page.
#     3. Follows the breadcrumb trail to /.env.bak and /backup/ and grabs the
#        simulated-but-real-looking "sensitive" files.
#     4. Sends a login request and sees the clone reject it (clone never touches the
#        real shop; the real admin_token stays with staff).
#     5. Reads the SOC analyst API to see the alerts queued against you.
#
#   Target: https://aeteesadmin.aeteesbakehouse.com
#   LAB USE ONLY — your own domain/lab. Nothing here touches anything outside it.
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
ok()   { echo -e "${GREEN}  [TARGET ACCOMPLISHED]${NC} $1"; pass=$((pass+1)); }
bad()  { echo -e "${RED}  [EVADED]${NC} $1"; fail=$((fail+1)); }
note() { echo -e "${YELLOW}  • $1${NC}"; }
step() { echo -e "\n${BLUE}── ${1}${NC}"; }

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOG_DIR/evidence.log"; }

hdr() {
  echo -e "${CYAN}"
  echo "======================================================================"
  echo "  Deception SOC Lab — Admin Subdomain Breadcrumb Showcase"
  echo "  You came in through the admin subdomain (the website address)."
  echo "  Target: ${TARGET}"
  echo "  Mode : ADMIN_HONEYPOT — clone served; real shop never reached"
  echo "======================================================================"
  echo -e "${NC}"
}

# HTTP helper: fetch a path on the target, print status + save body.
# Tries the on-the-website domain first; falls back to the divert proxy
# (admin Host header) when the tunnel drops the hostname.
http_fetch() {
  local path="$1" out="$2" code
  code=$(curl -s -o "$out" -w "%{http_code}" --max-time 8 -A \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "$TARGET$path" 2>/dev/null) || true
  if [ "$code" = "000" ]; then
    code=$(curl -s -o "$out" -w "%{http_code}" --max-time 8 -A \
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      -H "Host: $ADMIN_DOMAIN" \
      http://127.0.0.1:8200$path 2>/dev/null) || true
  fi
  echo "$code"
}

# analyst_login: authenticate to the local analyst API and set CJ (cookie jar).
analyst_login() {
  CJ="$WORK/analyst.cookies"
  if [ -z "${SOC_ADMIN_EMAIL:-}" ] || [ -z "${SOC_ADMIN_PASSWORD:-}" ]; then
    note "  (SOC admin credentials not set in .env — skipping SOC read.)"
    return 1
  fi
  curl -s -c "$CJ" -o /dev/null --max-time 20 \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$SOC_ADMIN_EMAIL\",\"password\":\"$SOC_ADMIN_PASSWORD\"}" \
    http://127.0.0.1:8090/v1/auth/login || return 1
}

# ── Header ──────────────────────────────────────────────────────────────────
hdr

# Step 1 — Land on the admin subdomain: clone detected
step "1. Land on the admin subdomain — clone, not the real shop"
note "GET ${TARGET}/  (first request lands here)"
code=$(http_fetch "/" "$WORK/root.html")
if [ "$code" = "307" ]; then ok "you're redirected to /login (clone admin portal)"; else bad "root returned ${code} (expected 307)"; fi
note "  Location: $(grep -o 'Location: [^ ]*' "$WORK/root.html" | head -1 || true)"
note "  The site you reached is the clone — the real shop never serves anyone here."

note "GET ${TARGET}/admin/login  (the admin login page)"
code=$(http_fetch "/admin/login" "$WORK/admin_login.html")
if [ "$code" = "200" ]; then ok "/admin/login returns 200 (clone login page)"; else bad "/admin/login returned ${code}"; fi

# Step 2 — Strip the breadcrumb comment off the clone page
step "2. Strip the breadcrumb comment off the clone page"
note "Every clone page carries a hidden anchoring comment — a breadcrumb for you to follow."
breadcrumb=$(grep -oi "<!-- DEBUG: [^>]*-->" "$WORK/admin_login.html" 2>/dev/null | head -1)
if [ -n "$breadcrumb" ]; then
  ok "breadcrumb comment found in the clone page"
  note "  <$breadcrumb>"
  note "  The clone is pointing you at two paths: /.env.bak and /backup/"
else
  bad "no breadcrumb comment found"
fi
log "breadcrumb_comment=$(echo "$breadcrumb" | tr -d '\n')"

# Step 3 — Follow the breadcrumb: grab the fake sensitive files
step "3. Follow the breadcrumb — grab the sensitive-looking files"
note "Bad path 1: /.env.bak"
code=$(http_fetch "/.env.bak" "$WORK/envbak")
if [ "$code" = "200" ]; then
  ok "GET /.env.bak -> 200 (simulated environment file)"
  note "  Contents:"
  grep -E "ADMIN_PASSWORD|DATABASE_URL|NODE_ENV|PAYMENT_GATEWAY" "$WORK/envbak" | sed 's/^/    /'
  log "decoy_envbak_status=$code"
else
  bad "GET /.env.bak returned ${code}"
fi

note "Bad path 2: /backup/"
code=$(http_fetch "/backup/" "$WORK/backup_dir.html")
if [ "$code" = "200" ]; then
  ok "GET /backup/ -> 200 (directory listing)"
  grep -oE 'href="[^"]*"' "$WORK/backup_dir.html" | sed 's/href="//;s/"//' | sed 's/^/    /'
  log "decoy_backup_dir_status=$code"
else
  bad "GET /backup/ returned ${code}"
fi

note "Trailing-slash redirect: /admin/backup/"
code=$(http_fetch "/admin/backup/" "$WORK/ab.html")
if [ "$code" = "308" ]; then ok "GET /admin/backup/ -> 308 (redirect to /admin/backup)"; else bad "GET /admin/backup/ returned ${code}"; fi

# Step 4 — Try the login: the clone rejects credentials
step "4. Try the login — the clone rejects it"
note "POST /admin/login with a set of credentials"
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
if [ "$code" = "405" ]; then ok "POST /admin/login -> 405 (clone never accepts credentials)"; else bad "POST /admin/login returned ${code}"; fi
note "  The clone doesn't touch the real shop — staff logins (real admin_token) still work there."

# Step 5 — The SOC logs you
step "5. What the SOC logs against you"
note "Logging into the analyst API to read the alerts queued against you."
if analyst_login; then
  note "  Analyst login OK — reading session.diverted events."
  events=$(curl -s --max-time 8 -b "$CJ" "http://127.0.0.1:8090/v1/events?type=session.diverted&limit=100" 2>/dev/null || true)
  if echo "$events" | grep -q '"items"'; then
    count=$(echo "$events" | python3 -c "import json,sys;print(len(json.load(sys.stdin).get('items',[])))" 2>/dev/null || echo "?")
    note "  Events diverted / recorded: ${count}"
    reasons=$(echo "$events" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for i in d.get('items',[])[-5:]:
    print('    -', i.get('data',{}).get('reason','?'))
" 2>/dev/null)
    note "  Latest divert reasons:"; echo "$reasons" | sed 's/^/    /'
    log "events_recorded=$count"
  else
    note "  (No session.diverted events yet — the requests above start recording.)"
  fi
else
  note "  (Analyst API not reachable — check dev-up.sh and .env credentials.)"
fi

# Summary
echo -e "\n${CYAN}----------------------------------------------------------------------${NC}"
echo -e "${GREEN}  Showcase complete: ${pass} target accomplished, ${fail} evaded${NC}"
echo -e "${CYAN}----------------------------------------------------------------------${NC}"
note "  What you'd see on the admin subdomain:"
note "    - Clone HTML pages carry a breadcrumb comment pointing to /.env.bak + /backup/"
note "    - Fake prod env     : /.env.bak  (ADMIN_PASSWORD=BakeI836pTQEYt!)"
note "    - Fake backup dir   : /backup/   (schema_2026.sql, aetees_db_FINAL.sql.gz)"
note "    - Login is rejected : POST /admin/login -> 405 (clone never touches the real shop)"
note "  Real shop is NEVER touched — the clone is served for every admin-subdomain visitor."
exit $fail
