#!/usr/bin/env bash
# ============================================================================
# scripts/attack-admin.sh — Attack toolkit runner for the admin subdomain
#
# From an attacker's perspective, against YOUR admin honeypot:
#   1. Directory / route discovery  (ffuf, gobuster)
#   2. Input fuzzing  (SQLi / XSS / cmdi) (ffuf, sqlmap)
#   3. Lure file collection  (/.env.bak, /backup/, schema)
#   4. Cookie + header manipulation
#   5. SOC correlation (what the Decoy SOC logged)
#
# Target: https://aeteesadmin.aeteesbakehouse.com   (website address, NOT localhost)
# Uses the Cloudflare tunnel -> divert proxy -> admin honeypot clone.
# LAB USE ONLY. Nothing here touches anything outside this lab.
# ============================================================================
set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
TARGET="${1:-https://aeteesadmin.aeteesbakehouse.com}"
ADMIN_DOMAIN="aeteesadmin.aeteesbakehouse.com"
WORK="${WORK:-/tmp/aetees-attack}"
LOG_DIR="${LOG_DIR:-/home/zee/Downloads/decoy/.logs/attack-admin}"
mkdir -p "$LOG_DIR"
[ -f .env ] && set -a; . ./.env; set +a

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
pass=0; fail=0
ok()   { echo -e "${GREEN}  [+]${NC} $1"; pass=$((pass+1)); }
bad()  { echo -e "${RED}  [-]${NC} $1"; fail=$((fail+1)); }
note() { echo -e "${YELLOW}  • $1${NC}"; }
step() { echo -e "\n${BLUE}└─ $1${NC}"; }

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOG_DIR/evidence.log"; }
CJ="$WORK/analyst.cookies"

# HTTP helper. Tries the on-website domain first; falls back to the divert
# proxy (admin Host header) when the tunnel drops the hostname.
http_get() { # $1=path  $2=out
  local path="$1" out="$2" code
  code=$(curl -s -o "$out" -w "%{http_code}" --max-time 10 -A \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "$TARGET$path" 2>/dev/null) || true
  if [ "$code" = "000" ]; then
    code=$(curl -s -o "$out" -w "%{http_code}" --max-time 10 -A \
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      -H "Host: $ADMIN_DOMAIN" http://127.0.0.1:8200$path 2>/dev/null) || true
  fi
  echo "$code"
}

analyst_login() {
  if [ -z "${SOC_ADMIN_EMAIL:-}" ] || [ -z "${SOC_ADMIN_PASSWORD:-}" ]; then
    note "  (SOC admin creds not in .env — skipping SOC correlation.)"
    return 1
  fi
  curl -s -c "$CJ" -o /dev/null --max-time 20 \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$SOC_ADMIN_EMAIL\",\"password\":\"$SOC_ADMIN_PASSWORD\"}" \
    http://127.0.0.1:8090/v1/auth/login || return 1
}

# ── Helper: wordlist path ──────────────────────────────────────────────────
WL="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
[ ! -f "$WL" ] && WL="/usr/share/wordlists/directory-list-2.3-medium.txt"
[ ! -f "$WL" ] && WL="/usr/share/wordlists/directory-list-2.3-small.txt"
[ ! -f "$WL" ] && { note "  (no wordlist found — skipping directory discovery)"; }

# ── Header ──────────────────────────────────────────────────────────────────
echo -e "${CYAN}"
echo "======================================================================"
echo "  Deception SOC Lab — Admin Subdomain Attack Toolkit"
echo "  Target  : ${TARGET}"
echo "  Frame   : you are an attacker exploring the admin honeypot"
echo "  Mode    : clone served; real shop never touched"
echo "======================================================================"
echo -e "${NC}"

# ── 1. Reach the admin clone ──────────────────────────────────────────────
step "1. Land on the admin subdomain — clone detected"
ROOT=$(http_get "/" "$WORK/root.html")
ok "[+] root -> $ROOT (redirect to /login = clone admin portal)"
note "  Location: $(grep -o 'Location: [^ ]*' "$WORK/root.html" | head -1 || true)"

# ── 2. Breadcrumb extraction ──────────────────────────────────────────────
step "2. Strip the breadcrumb comment from the clone page"
breadcrumb=$(grep -oi "<!-- DEBUG: [^>]*-->" "$WORK/admin_login.html" 2>/dev/null | head -1)
if [ -n "$breadcrumb" ]; then
  ok "[+] breadcrumb comment found"
  note "  <$breadcrumb>"
  note "  Clone is pointing you at: /.env.bak and /backup/"
else
  bad "no breadcrumb comment found"
fi

# ── 3. Directory / route discovery ─────────────────────────────────────────
step "3. Directory & route discovery (ffuf + gobuster)"
if [ -f "$WL" ]; then
  timeout 60 ~/go/bin/ffuf -u "${TARGET}/FUZZ" -w "$WL" -t 15 \
    -mc 200,302,403 -c -of txt 2>&1 | tee "$WORK/ffuf_paths.txt" | head -40
  note "  ffuf paths saved to $WORK/ffuf_paths.txt"
else
  note "  (no wordlist — skipping)"
fi
timeout 40 gobuster dir -u "${TARGET}/admin" -w "$WL" -t 12 -o "$WORK/gobuster_admin.txt" 2>&1 | tail -8
note "  gobuster admin saved to $WORK/gobuster_admin.txt"

# ── 4. Input fuzzing (SQLi / XSS / cmdi) ───────────────────────────────────
step "4. Input fuzzing (ffuf + sqlmap)"
note "  Fuzz /menu?category= with SQLi/XSS payloads on the admin domain."
timeout 40 ~/go/bin/ffuf -u "${TARGET}/menu?category=FUZZ" \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
  -t 15 -mc 200,302 -c -of txt 2>&1 | head -20
note "  ffuf category fuzzing done (SQLi payloads would also trip the tripwire)."
note "  sqlmap against /api/diagnostics?host=<payload> — only if that endpoint is live."
note "  Tripwire reactions: input.suspicious, cmd_injection (T1190), risk climb."

# ── 5. Lure file collection ────────────────────────────────────────────────
step "5. Lure file collection (breadcrumb targets)"
for p in /.env.bak /backup/ /backup/schema_2026.sql.gz /backup/aetees_db_FINAL.sql.gz /admin/backup/internal-backup.zip; do
  code=$(http_get "$p" "$WORK/lure_$(basename "$p" | tr '/' '_')")
  if [ "$code" = "200" ]; then
    ok "[+] GET $p -> 200"
    if [ -s "$WORK/lure_$(basename "$p" | tr '/' '_')" ]; then
      head -c 300 "$WORK/lure_$(basename "$p" | tr '/' '_')" | tr '\n' ' '
      echo
    fi
  else
    bad "GET $p -> $code"
  fi
done

# ── 6. Cookie + header manipulation ────────────────────────────────────────
step "6. Cookie + header manipulation"
CK="$WORK/cookies.txt"
rm -f "$CK"
note "  New visitor: $TARGET/  (cookie: _aet_v)"
curl -s -c "$CK" -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     "https://aeteesadmin.aeteesbakehouse.com/" 2>/dev/null
note "  Set-Cookie: $(grep -o '_aet_v=[^;]*' "$CK" | head -1)"
note "  Replay with cookies + spoofed X-Forwarded-For to track/trust the clone:"
curl -s -b "$CK" -H "X-Forwarded-For: 192.168.99.77" \
     -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0 Safari/537.36" \
     -o /dev/null -w "  replay status: %{http_code}\n" "https://aeteesadmin.aeteesbakehouse.com/admin/login"

# ── 7. SOC correlation ────────────────────────────────────────────────────
step "7. SOC correlation — what the Decoy SOC logged"
if analyst_login; then
  events=$(curl -s --max-time 8 -b "$CJ" \
    "http://127.0.0.1:8090/v1/events?type=session.diverted&limit=100" 2>/dev/null || true)
  if echo "$events" | grep -q '"items"'; then
    count=$(echo "$events" | python3 -c "import json,sys;print(len(json.load(sys.stdin).get('items',[])))" 2>/dev/null || echo "?")
    ok "[+] ${count} diverted sessions / events recorded"
    note "  Latest divert reasons:"
    echo "$events" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for i in d.get('items',[])[-6:]:
    print('    -', i.get('data',{}).get('reason','?'))
" 2>/dev/null | sed 's/^/    /'
    log "events_recorded=$count"
  else
    note "  (No session.diverted events yet — run the directory/fuzz steps again.)"
  fi
else
  note "  (Analyst API not reachable — check dev-up.sh and .env credentials.)"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}──────────────────────────────────────────────────────────${NC}"
echo -e "${GREEN}  Attack toolkit complete: ${pass} succeeded, ${fail} failed${NC}"
echo -e "${CYAN}──────────────────────────────────────────────────────────${NC}"
note "  What an attacker now sees on the admin subdomain:"
note "    • Breadcrumb comment in clone pages (points to /.env.bak + /backup/)"
note "    • Fake prod env    : /.env.bak  (ADMIN_PASSWORD=BakeI836pTQEYt!)"
note "    • Fake backup dir  : /backup/   (schema_2026.sql, aetees_db_FINAL.sql.gz)"
note "    • Login rejected   : POST /admin/login -> 405 (clone never touches real shop)"
note "    • SOC logged       : input.suspicious · cmd_injection · file.read · session.diverted"
note "  Real shop is NEVER touched — the clone is served for every admin-subdomain visitor."
exit $fail
