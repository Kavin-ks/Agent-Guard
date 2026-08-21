#!/usr/bin/env bash
# End-to-end demo check against a RUNNING Agent Guard stack.
#
# Proves the full flow through the reverse proxy (the client sends NO API key —
# nginx injects it server-side):
#   ALLOW -> execute · DENY -> blocked · ASK -> approve -> execute ·
#   secret exfiltration -> blocked · approval reuse -> blocked
#
# Usage:  deploy/demo_check.sh [BASE_URL]   (default http://localhost:8080/api)
set -euo pipefail

BASE="${1:-http://localhost:8080/api}"
GOAL="Build a React frontend. Do not modify backend or database, and never access secrets."
FAKE_SECRET="sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"
pass=0; fail=0
ok()   { echo "  ✓ $1"; pass=$((pass+1)); }
bad()  { echo "  ✗ $1"; fail=$((fail+1)); }

jq_get() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }

post() { curl -s -X POST "$BASE/guard/evaluate" -H "Content-Type: application/json" -d "$1"; }

echo "Agent Guard demo check → $BASE"
echo "------------------------------------------------------------"

# 1) ALLOW
d=$(post "{\"goal\":\"$GOAL\",\"action\":\"read\",\"resource\":\"src/App.jsx\"}" | jq_get decision)
[ "$d" = "ALLOW" ] && ok "ALLOW  read src/App.jsx" || bad "expected ALLOW, got '$d'"

# 2) DENY (secret file)
d=$(post "{\"goal\":\"$GOAL\",\"action\":\"read\",\"resource\":\".env\"}" | jq_get decision)
[ "$d" = "DENY" ] && ok "DENY   read .env (blocked)" || bad "expected DENY, got '$d'"

# 3) ASK -> approve -> consume (execute)
ask=$(post "{\"goal\":\"$GOAL\",\"action\":\"delete\",\"resource\":\"src/generated.jsx\",\"resource_kind\":\"file\",\"tool\":\"delete_file\"}")
ap=$(echo "$ask" | jq_get approval_id)
[ "$(echo "$ask" | jq_get decision)" = "ASK" ] && ok "ASK    delete src/generated.jsx" || bad "expected ASK"
curl -s -X POST "$BASE/approvals/$ap/approve" -H "Content-Type: application/json" -d '{"approver":"demo"}' >/dev/null
auth=$(curl -s -X POST "$BASE/approvals/$ap/consume" -H "Content-Type: application/json" \
  -d "{\"goal\":\"$GOAL\",\"action\":\"delete\",\"resource\":\"src/generated.jsx\",\"resource_kind\":\"file\",\"tool\":\"delete_file\"}" | jq_get authorized)
[ "$auth" = "True" ] && ok "APPROVE+CONSUME authorized (execute)" || bad "expected authorized after approve, got '$auth'"

# 4) Secret exfiltration -> DENY, no raw secret leaked
ex=$(post "{\"goal\":\"$GOAL\",\"action\":\"transmit\",\"resource\":\"https://external.example/upload\",\"resource_kind\":\"url\",\"tool\":\"send_external_request\",\"destination\":\"https://external.example/upload\",\"payload\":\"email=a@b.com API_KEY=$FAKE_SECRET\"}")
[ "$(echo "$ex" | jq_get decision)" = "DENY" ] && ok "DENY   exfiltration blocked" || bad "expected exfiltration DENY"
echo "$ex" | grep -q "$FAKE_SECRET" && bad "raw secret leaked in response!" || ok "raw secret redacted in response"

# 5) Approval reuse attack -> blocked (fingerprint mismatch)
ask2=$(post "{\"goal\":\"$GOAL\",\"action\":\"delete\",\"resource\":\"src/generated.jsx\",\"resource_kind\":\"file\",\"tool\":\"delete_file\"}")
ap2=$(echo "$ask2" | jq_get approval_id)
curl -s -X POST "$BASE/approvals/$ap2/approve" -H "Content-Type: application/json" -d '{"approver":"demo"}' >/dev/null
reuse=$(curl -s -X POST "$BASE/approvals/$ap2/consume" -H "Content-Type: application/json" \
  -d "{\"goal\":\"$GOAL\",\"action\":\"delete\",\"resource\":\"database.sql\",\"resource_kind\":\"file\",\"tool\":\"delete_file\"}" | jq_get authorized)
[ "$reuse" = "False" ] && ok "BLOCK  approval reuse for database.sql" || bad "reuse should be blocked, got '$reuse'"

echo "------------------------------------------------------------"
echo "PASS=$pass  FAIL=$fail"
[ "$fail" -eq 0 ] || exit 1
