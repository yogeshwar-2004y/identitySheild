#!/usr/bin/env bash
# Headless run of the demo scenario (architecture.md section 14) against the local lab.
# Prerequisites: docker compose up -d && docker compose exec api python scripts/seed.py
set -euo pipefail
cd "$(dirname "$0")/.."

API="${API:-http://localhost:8000}"
TENANT="${TENANT:-acme}"
env_val() { grep -E "^$1=" .env | head -1 | cut -d= -f2- | sed -E 's/[[:space:]]+#.*$//'; }
LAB_KEY="$(env_val LAB_API_KEY)"
PLATFORM_KEY="$(env_val PLATFORM_API_KEY)"
[[ -n "$LAB_KEY" ]] || { echo "LAB_API_KEY missing in .env"; exit 1; }

B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'
step() { echo; echo "${B}== $* ==${N}"; }
ok() { echo "  ${G}✔${N} $*"; }
bad() { echo "  ${R}✘${N} $*"; FAILS=$((FAILS + 1)); }
FAILS=0
jq_() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }
lab() { curl -s -H "X-Lab-Key: $LAB_KEY" -H "X-Lab-Client-IP: ${IP:-203.0.113.50}" -H "User-Agent: ${UA:-demo-browser}" "$@"; }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
sim() { docker compose run --rm -T simulator "$@" --tenant "$TENANT" --victim "$VICTIM" --i-understand-lab-only 2>/dev/null | sed 's/^/  │ /'; }

curl -sf "$API/health/ready" >/dev/null || { echo "API not ready at $API"; exit 1; }
docker compose build -q simulator >/dev/null

step "1. Tenant + Joiner: provision Asha, then log in"
r=$(curl -s -X POST "$API/tenants" -H "X-Platform-Key: $PLATFORM_KEY" -H "Content-Type: application/json" \
     -d "{\"name\":\"Acme Corp\",\"realm\":\"$TENANT\"}")
echo "  tenant: $(echo "$r" | jq_ "d.get('realm'), d.get('status')")  (idempotent: realm adopted if it exists)"
ADMIN=$(lab -X POST "$API/lab/login" -H "Content-Type: application/json" -d "{\"tenant\":\"$TENANT\",\"username\":\"alice\"}" | jq_ "d['access_token']")
AH=(-H "Authorization: Bearer $ADMIN" -H "X-Lab-Key: $LAB_KEY" -H "X-Lab-Client-IP: 203.0.113.50" -H "User-Agent: demo-browser")
USERS=$(curl -s "${AH[@]}" "$API/users")
VICTIM=asha; n=1
while echo "$USERS" | python3 -c "import sys,json; sys.exit(0 if any(u['username']=='$VICTIM' for u in json.load(sys.stdin)) else 1)"; do
  n=$((n + 1)); VICTIM="asha$n"
done
r=$(curl -s -X POST "${AH[@]}" -H "Content-Type: application/json" "$API/lifecycle/joiner" -d "{\"full_name\":\"Asha Kumar\",
     \"email\":\"$VICTIM@acme.example\",\"username\":\"$VICTIM\",\"department\":\"Engineering\",\"lab_demo_password\":true,
     \"require_mfa\":false,\"send_invite\":false}")
ASHA_ID=$(echo "$r" | jq_ "d['user_id']")
echo "  joiner $(echo "$r" | jq_ "d['status']") · user $VICTIM state=$(echo "$r" | jq_ "d['user']['state']") · roles $(echo "$r" | jq_ "d['access_diff']['added']")"
echo "  ${Y}(headless run skips TOTP enrolment; the UI joiner flow enforces CONFIGURE_TOTP)${N}"
S=$(IP=203.0.113.10 UA="Mozilla/5.0 Chrome/126" lab -X POST "$API/lab/login" -H "Content-Type: application/json" -d "{\"tenant\":\"$TENANT\",\"username\":\"$VICTIM\"}")
ASHA_AT=$(echo "$S" | jq_ "d['access_token']"); ASHA_RT=$(echo "$S" | jq_ "d['refresh_token']"); ASHA_SID=$(echo "$S" | jq_ "d['session_id']")
[[ "$(echo "$S" | jq_ "d['user']['state']")" == "ACTIVE" ]] && ok "$VICTIM logged in; PENDING -> ACTIVE" || bad "login failed"
AS=(-H "Authorization: Bearer $ASHA_AT" -H "X-Lab-Key: $LAB_KEY" -H "X-Lab-Client-IP: 203.0.113.10" -H "User-Agent: Mozilla/5.0 Chrome/126")

step "2. Active session with device / IP binding"
curl -s "${AS[@]}" "$API/sessions" | python3 -c "
import sys,json
for s in json.load(sys.stdin):
    print(f\"  session {s['id'][:8]}  ip={s['ip']}  geo={s['geo']['city']},{s['geo']['country']}  asn={s['asn']}  ua#{s['ua_hash'][:12]}  expires={s['expires_at'][:19]}\")"

step "3-4. Simulator: stolen_session (expect D02 -> risk >= 70 -> auto-revoke -> 401)"
sim stolen_session

step "5. Simulator: impossible_travel (expect D01) + user timeline"
sim impossible_travel
curl -s "${AH[@]}" "$API/users/$ASHA_ID/timeline" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for i in d['items'][:8]: print(f\"  {i['ts'][11:19]}  {i['category']:9s} {i['type']:22s} {i['summary'][:70]}\")"

step "6. Mover: Engineering -> Finance (access diff + session re-issue)"
r=$(curl -s -X POST "${AH[@]}" -H "Content-Type: application/json" "$API/lifecycle/mover" -d "{\"user_id\":\"$ASHA_ID\",\"new_department\":\"Finance\"}")
echo "  status=$(echo "$r" | jq_ "d['status']")  added=$(echo "$r" | jq_ "d['access_diff']['added']")  removed=$(echo "$r" | jq_ "d['access_diff']['removed']")"
c=$(curl -s "${AS[@]}" "$API/auth/me" | jq_ "d.get('detail',{}).get('code')")
[[ "$c" == "claims_changed" ]] && ok "old access token refused: claims_changed" || bad "old token not refused ($c)"
r=$(IP=203.0.113.10 UA="Mozilla/5.0 Chrome/126" lab -X POST "$API/auth/refresh" -H "Content-Type: application/json" -d "{\"refresh_token\":\"$ASHA_RT\"}")
NEW_SID=$(echo "$r" | jq_ "d.get('session_id')")
if [[ "$NEW_SID" != "None" && "$NEW_SID" != "$ASHA_SID" ]]; then
  ok "session re-issued: ${ASHA_SID:0:8} -> ${NEW_SID:0:8} (new claims, new session id)"
  ASHA_AT=$(echo "$r" | jq_ "d['access_token']")
else bad "re-issue failed: $r"; fi
AS=(-H "Authorization: Bearer $ASHA_AT" -H "X-Lab-Key: $LAB_KEY" -H "X-Lab-Client-IP: 203.0.113.10" -H "User-Agent: Mozilla/5.0 Chrome/126")

step "7. Leaver: deprovision $VICTIM and verify"
r=$(curl -s -X POST "${AH[@]}" -H "Content-Type: application/json" "$API/lifecycle/leaver" -d "{\"user_id\":\"$ASHA_ID\",\"reason\":\"demo\"}")
echo "  status=$(echo "$r" | jq_ "d['status']")  steps=$(echo "$r" | jq_ "list(d['steps'])")"
echo "  verification: $(echo "$r" | jq_ "d['steps'].get('verify',{}).get('checks')")"
c=$(code "${AS[@]}" "$API/auth/me"); [[ "$c" == 401 ]] && ok "old access token rejected (401)" || bad "old token still works ($c)"
live=$(curl -s "${AH[@]}" "$API/users/$ASHA_ID" | jq_ "d['active_sessions']"); [[ "$live" == 0 ]] && ok "zero live sessions" || bad "$live live sessions"

step "8. Simulator: ghost_login (expect D04 critical)"
sim ghost_login

step "9. Audit log hash-chain verification"
v=$(curl -s "${AH[@]}" "$API/audit/verify"); echo "  $(echo "$v" | jq_ "('valid' if d['valid'] else 'BROKEN'), d['checked'], 'entries'")"
./scripts/tamper_audit.sh tamper "$TENANT" | sed 's/^/  /'
v=$(curl -s "${AH[@]}" "$API/audit/verify")
[[ "$(echo "$v" | jq_ "d['valid']")" == "False" ]] && ok "tampering detected at entry #$(echo "$v" | jq_ "d['broken_at_id']")" || bad "tampering not detected"
./scripts/tamper_audit.sh restore | sed 's/^/  /'
v=$(curl -s "${AH[@]}" "$API/audit/verify"); [[ "$(echo "$v" | jq_ "d['valid']")" == "True" ]] && ok "chain valid again after restore" || bad "chain still broken"

step "Alerts raised for $VICTIM"
curl -s "${AH[@]}" "$API/alerts?user_id=$ASHA_ID" | python3 -c "
import sys,json
for a in json.load(sys.stdin): print(f\"  {a['rule_key']}  {a['severity']:8s} risk={a['risk']:3d}  {a['title'][:80]}\")"
curl -s -o /dev/null -X POST "${AH[@]}" "$API/auth/logout"
echo
if [[ $FAILS -eq 0 ]]; then echo "${G}${B}Demo completed: all checks passed.${N}"; else echo "${R}${B}Demo finished with $FAILS failed check(s).${N}"; exit 1; fi
