#!/usr/bin/env bash
# ============================================================================
# scripts/ssh-tutorial.sh — SSH access tutorial for the Decoy Lab
# ============================================================================
# Usage:
#   scripts/ssh-tutorial.sh
#
# This script walks you through the SSH trap at each step.
# It shows the credentials, the commands, and what the SOC sees.
# ============================================================================

set -euo pipefail

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Banner ─────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   SSH Access Tutorial — Decoy Lab Trap Walkthrough          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: The Decoy SSH Server ─────────────────────────────────────────
print_step() {
  echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}  $1${NC}"
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
  echo -e "\n${YELLOW}📊 SOC RECORDED:${NC}"
  echo -e "${YELLOW}  $1${NC}"
}

print_step "SSH DECOY SERVER"
echo -e "\n🔧 Tools: ssh, sshpass"
echo -e "\nThe SSH decoy is a Go-written fake server running on port ${SSH_PORT}:"
echo -  "It emulates an OpenSSH server over a fake filesystem."
echo -  "It never executes real commands - only simulates output."
echo -  "It records every event (auth.attempt, shell.command, etc.) to core:8443."
echo ""
echo -e "🔑 ${CYAN}So what can you do?${NC}"
echo -  "You can log in, run commands, and view files - but everything is simulated."
echo -  "The outputs look real, but they're fake. The decoy never touches real data."

# ── Step 2: The Credentials ────────────────────────────────────────────────
print_step "SSH CREDENTIALS (FROM THE SEED)"

echo -e "\n🔑 ${CYAN}Decoy SSH server${NC}"
echo -e "  Port:    ${SSH_PORT}"
echo -e "  User:    deploy"
echo -e "  Password: HalSummer2023!"
echo -e "  Host:    localhost"
echo ""
echo -e "🔑 ${CYAN}SSH key (from internal-backup.zip)${NC}"
echo -e "  File:   /tmp/deploy_key"
echo -e "  Fingerprint: SHA256:2TiXkeO9WWFpKw7S93rN9CNtG4AvWDO8uzKTlkqXEP7"
echo -e "  Usage:  ssh -i /tmp/deploy_key deploy@localhost -p 2223"
echo ""
echo -e "🔑 ${CYAN}Admin honeypot${NC}"
echo -e "  URL:    https://aeteesadmin.aeteesbakehouse.com"
echo -e "  Email:   admin@soc.local"
echo -e "  Password: BakeI836pTQEYt!"
echo ""
echo -e "🔑 ${CYAN}K8s kubeconfig token${NC}"
echo -e "  Token:   neaUPVW4RYGJViL9C8iUHxNtr8HULVBeiJKsY0Eg9Lq9GhMv"
echo -e "  Usage:   curl -k -H \"Authorization: Bearer ***\" https://localhost:6443/api/v1/namespaces"

# ── Step 3: SSH Login ─────────────────────────────────────────────────────
print_step "SSH LOGIN (WITH CREDENTIALS)"

echo -e "\n🔧 Command:"
echo "  sshpass -p 'HalSummer2023!' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2223 deploy@localhost 'whoami; pwd; uname -a'"
echo ""
echo -e "${CYAN}The command:${NC}"
sshpass -p 'HalSummer2023!' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2223 deploy@localhost 'whoami; pwd; uname -a' 2>&1 | tail -4

print_trap "The SSH decoy simulated the login — the shell is a Go-written emulator, not a real shell. Every command you run returns simulated output. The 'whoami' returns 'deploy', 'pwd' returns '/home/deploy', and 'uname -a' returns the persona hostname (hal-app-01)."
print_evidence "SSH login successful. Persona hostname: hal-app-01. Persona user: deploy."
print_soc "auth.attempt (password), shell.command (whoami, pwd, uname -a)"

# ── Step 4: The Fake AWS Credentials ──────────────────────────────────────
print_step "FAKE AWS CREDENTIALS (FROM SSH DECOY)"

echo -e "\n🔧 Command:"
echo "  sshpass -p 'HalSummer2023!' ssh -p 2223 deploy@localhost 'cat ~/.aws/credentials'"
echo ""
echo -e "${CYAN}The command:${NC}"
sshpass -p 'HalSummer2023!' ssh -p 2223 deploy@localhost 'cat ~/.aws/credentials' 2>&1 | tail -3

print_trap "The attacker downloads the fake ~/.aws/credentials. These look real, but they're planted honeytoken credentials — they only 'work' inside the simulated environment. The AWS key (AKIA3E...NCD5) is a honeytoken."
print_evidence "Fake AWS credentials: AKIA3E...NCD5 + xoS63WIqPhR61HSDCa3A0s1KxHiN6f4gcZTNBPBP"
print_soc "token.used (SSH key), shell.command (cat ~/.aws/credentials)"

# ── Step 5: Fake K8s kubeconfig ────────────────────────────────────────────
print_step "FAKE K8S KUBECONFIG (FROM SSH DECOY)"

echo -e "\n🔧 Command:"
echo "  sshpass -p 'HalSummer2023!' ssh -p 2223 deploy@localhost 'cat /opt/deploy/kubeconfig'"
echo ""
echo -e "${CYAN}The command:${NC}"
sshpass -p 'HalSummer2023!' ssh -p 2223 deploy@localhost 'cat /opt/deploy/kubeconfig' 2>&1 | tail -5

print_trap "The attacker downloads the fake kubeconfig. The bearer token (neaUPVW4...GhMv) is a honeytoken - it only works inside the simulated K8s API, not against a real cluster."
print_evidence "Fake K8s kubeconfig with bearer token: neaUPVW4RYGJViL9C8iUHxNtr8HULVBeiJKsY0Eg9Lq9GhMv"
print_soc "token.used (SSH key), shell.command (cat /opt/deploy/kubeconfig)"

# ── Step 6: Host Discovery ─────────────────────────────────────────────────
print_step "HOST DISCOVERY (FAKE FILESYSTEM)"

echo -e "\n🔧 Command:"
echo "  sshpass -p 'HalSummer2023!' ssh -p 2223 deploy@localhost 'uname -a; id; cat ~/.aws/credentials'"
echo ""
echo -e "${CYAN}The command:${NC}"
sshpass -p 'HalSummer2023!' ssh -p 2223 deploy@localhost 'uname -a; id; cat ~/.aws/credentials' 2>&1 | tail -6

print_trap "The attacker runs host discovery commands and thinks they're on a real system. The 'uname -a' returns the persona hostname (hal-app-01). The 'id' shows the persona user (deploy). The 'cat ~/.aws/credentials' returns the planted AWS credentials. Everything is simulated."
print_evidence "Host discovery commands run successfully. Persona hostname: hal-app-01. Persona user: deploy."
print_soc "shell.command (uname -a, id, cat ~/.aws/credentials), system_discovery (T1082), cred_file_search (T1552.001)"

# ── Summary ───────────────────────────────────────────────────────────────
echo -e "\n${RED}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   SSH SESSION COMPLETE — You are caught                    ║"
echo "║   All credentials are simulated.                            ║"
echo "║   SOC records: auth.attempt, shell.command, token.used      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
