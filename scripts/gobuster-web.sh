#!/usr/bin/env bash
# ============================================================================
# scripts/gobuster-web.sh — Gobuster for the main Aetees shop
# ============================================================================
# Usage:
#   scripts/gobuster-web.sh
#
# Scans the real Aetees shop (http://localhost:3100) for hidden paths.
# This is the REAL shop - not the honeypot.
#
# Prerequisites:
#   - Lab running: scripts/dev-up.sh
#   - Tools: gobuster, curl
# ============================================================================

set -euo pipefail

ADMIN_URL="${1:-http://localhost:3100}"
WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
LOG_DIR="/home/zee/Downloads/decoy/.logs/gobuster"
mkdir -p "$LOG_DIR"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Banner ─────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Gobuster — Real Aetees Shop                               ║${NC}"
echo -e "${CYAN}║   Target: ${ADMIN_URL}                                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Run gobuster ──────────────────────────────────────────────────────────
echo -e "\n🔧 Tools: gobuster"
echo -e "\n${CYAN}Command:${NC}"
echo "  gobuster dir -u ${ADMIN_URL} -w ${WORDLIST} -t 10 -o ${LOG_DIR}/aetee-shop.txt"
echo ""

gobuster dir \
  -u "${ADMIN_URL}" \
  -w "${WORDLIST}" \
  -t 10 \
  -o "${LOG_DIR}/aetee-shop.txt" \
  2>&1 | tee "${LOG_DIR}/aetee-shop.txt"

echo ""
echo -e "\n📋 Key findings (200 responses):"
grep "Status: 200" "${LOG_DIR}/aetee-shop.txt" 2>/dev/null || echo "  (no 200 responses found)"
echo ""
echo -e "\n📁 Full results saved to: ${LOG_DIR}/aetee-shop.txt"
