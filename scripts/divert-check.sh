#!/usr/bin/env bash
# Live divert-proxy check (lab only): 12 harmless shop requests must stay on the real shop, 8 attacks must be
# diverted to the honeypot clone. Each case is a fresh visitor (new cookie) with a browser user-agent.
# Needs scripts/dev-up.sh + scripts/aetees-lab.sh running. IP = a local address of this machine that is not
# 127.0.0.1 (localhost may be marked released), e.g.:  IP=192.168.56.1 scripts/divert-check.sh
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IP=${IP:?set IP to a non-loopback address of this machine, e.g. IP=192.168.56.1}
H=http://$IP:8200
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
J=$(mktemp)
CK=$(mktemp)
set -a; . "$ROOT/.env"; set +a
curl -s -c "$CK" -o /dev/null -H 'Content-Type: application/json' -d "{\"email\":\"$SOC_ADMIN_EMAIL\",\"password\":\"$SOC_ADMIN_PASSWORD\"}" http://127.0.0.1:8090/v1/auth/login
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
API="http://127.0.0.1:8090/v1/events?type=session.diverted&src_ip=$IP&since=$T0"
count() { curl -s -b "$CK" "$API&limit=100" | python -c "import json,sys;print(len(json.load(sys.stdin)['items']))"; }
last() { curl -s -b "$CK" "$API&limit=1" | python -c "import json,sys;d=json.load(sys.stdin)['items'][0]['data'];print(d['severity'],'-',d['reason'][:55])"; }
pass=0; fail=0
t() { # expect name method path body
  rm -f "$J"; before=$(count)
  curl -s -o /dev/null --max-time 10 -A "$UA" -c "$J" -b "$J" "$H/"
  if [ "$3" = POST ]; then
    code=$(curl -s -o /dev/null --max-time 10 -w "%{http_code}" -A "$UA" -b "$J" -H 'Content-Type: application/json' -X POST -d "$5" "$H$4")
  else
    code=$(curl -s -o /dev/null --max-time 10 -w "%{http_code}" -A "$UA" -b "$J" "$H$4")
  fi
  sleep 1.6; after=$(count)
  if [ "$after" -gt "$before" ]; then got=honeypot; detail="$(last)"; else got=real; detail=""; fi
  if [ "$got" = "$1" ]; then mark="OK  "; pass=$((pass+1)); else mark="FAIL"; fail=$((fail+1)); fi
  printf "%s %-46s want %-8s got %-8s %s\n" "$mark" "$2" "$1" "$got" "$detail"
}
msg() { t "$1" "$2" POST /api/contact "{\"name\":\"$3\",\"email\":\"cust@gmail.com\",\"message\":\"$4\"}"; }

echo "---- harmless (must stay on the real shop)"
msg real "contact: normal question" "Riya" "Can I get eggless red velvet for Sunday?"
msg real "contact: apostrophe + semicolon + --" "Sean O'Brien" "Mom's cake; less sugar -- urgent"
msg real "contact: 'or' in a sentence" "Amit" "Chocolate or vanilla, whichever is fresh"
msg real "contact: quotes" "Neha" "Please write \\\"Happy Birthday\\\" on top"
msg real "contact: order number with #" "Karan" "Order #4521 -- can you deliver after 6pm?"
msg real "contact: address with slash" "Pooja" "Flat 12/B, Sea Breeze CHS, Andheri (W)"
msg real "contact: emoji + exclamation" "Isha" "Loved the cheesecake!!! 🎂🎉"
msg real "contact: select/drop words" "Dev" "Select any 2 cupcakes, drop them at the gate"
msg real "contact: ampersand" "Tara" "Cake & cookies for 20 people"
msg real "contact: angle brackets in text" "Rohan" "Budget <2000 rupees, >1kg please"
t real "menu with normal query" GET "/menu?category=cakes" ""
t real "typo URL (404)" GET "/menuu" ""
echo "---- malicious (must go to the honeypot)"
t honeypot "SQLi in URL" GET "/menu?category=cakes'%20OR%20'1'='1" ""
msg honeypot "SQLi in contact form" "x" "1 UNION SELECT username,password FROM users--"
msg honeypot "XSS in contact form" "<script>alert(1)</script>" "hi"
t honeypot "path traversal in URL" GET "/api/uploads/..%2f..%2f..%2fetc%2fpasswd" ""
msg honeypot "command injection in field" "x; cat /etc/passwd" "hi"
t honeypot "probe /.git/config" GET "/.git/config" ""
t honeypot "probe /wp-admin/" GET "/wp-admin/" ""
t honeypot "lure /.env.bak" GET "/.env.bak" ""
echo "---- $pass passed, $fail failed"
rm -f "$J" "$CK"
[ "$fail" -eq 0 ]
