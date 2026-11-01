#!/usr/bin/env bash
# ============================================================================
# scripts/gobuster.sh — Gobuster directory brute-force for admin honeypot
# ============================================================================
# Usage:
#   scripts/gobuster.sh <admin-subdomain-url>
#
# Example:
#   scripts/gobuster.sh https://aeteesadmin.aeteesbakehouse.com
#
# Prerequisites:
#   - Wordlist: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
#   - Tools: gobuster
#
# Output:
#   - Scan results to terminal
#   - Results saved to .logs/gobuster/<hostname>.txt
# ============================================================================

set -euo pipefail

# ── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Args ───────────────────────────────────────────────────────────────────
if [ -z "$1" ]; then
  echo "Usage: $0 <admin-subdomain-url>"
  echo "Example: $0 https://aeteesadmin.aeteesbakehouse.com"
  exit 1
fi

ADMIN_URL="$1"
ADMIN_HOST="$(echo "$ADMIN_URL" | sed -E 's|^https?://||; s|/.*$||')"
WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
LOG_DIR="/home/zee/Downloads/decoy/.logs/gobuster"
mkdir -p "$LOG_DIR"

# ── Banner ─────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Gobuster Directory Brute-Force — Admin Subdomain          ║${NC}"
echo -e "${BLUE}║   Target: ${ADMIN_URL}                                  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e "\n🔧 Tools: gobuster"
echo ""

# ── Run gobuster ──────────────────────────────────────────────────────────
echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Scanning: ${ADMIN_URL}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "\n${CYAN}Command:${NC}"
echo -e "  gobuster dir -u ${ADMIN_URL} -w ${WORDLIST} -t 10 -o ${LOG_DIR}/${ADMIN_HOST}.txt"
echo -e ""

gobuster dir \
  -u "${ADMIN_URL}" \
  -w "${WORDLIST}" \
  -t 10 \
  -o "${LOG_DIR}/${ADMIN_HOST}.txt" \
  2>&1 | tee "${LOG_DIR}/${ADMIN_HOST}.txt"

echo ""
echo -e "${GREEN}=== Scan complete ===${NC}"
echo -e "\n📋 Key findings (200 responses):"
grep "Status: 200" "${LOG_DIR}/${ADMIN_HOST}.txt" 2>/dev/null || echo "  (no 200 responses found)"
echo ""
echo -e "\n📁 Full results saved to: ${LOG_DIR}/${ADMIN_HOST}.txt"
