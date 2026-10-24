#!/usr/bin/env bash
# LAB ONLY. Simulates an attacker with direct database access editing one audit row,
# so the hash-chain verification can be demonstrated. `restore` puts the row back.
#   ./scripts/tamper_audit.sh tamper [realm]   # default realm: acme
#   ./scripts/tamper_audit.sh restore
set -euo pipefail
cd "$(dirname "$0")/.."
STATE=".tamper_audit.state"
psql_owner() { docker compose exec -T postgres psql -U identityshield -d identityshield -At -v ON_ERROR_STOP=1 "$@"; }

case "${1:-}" in
  tamper)
    realm="${2:-acme}"
    row=$(psql_owner -v realm="$realm" <<'SQL'
SELECT a.id || '|' || a.detail::text FROM audit_log a JOIN tenants t ON t.id = a.tenant_id
WHERE t.realm = :'realm' AND a.action LIKE 'lifecycle.%' ORDER BY a.id DESC LIMIT 1;
SQL
)
    [[ -n "$row" ]] || { echo "no lifecycle audit row found"; exit 1; }
    id="${row%%|*}"; detail="${row#*|}"
    printf '%s\n%s\n' "$id" "$detail" > "$STATE"
    psql_owner -v id="$id" >/dev/null <<'SQL'
UPDATE audit_log SET detail = detail || '{"reason": "nothing to see here"}'::jsonb WHERE id = :id;
SQL
    echo "Tampered with audit row #$id (as the DB owner, bypassing the app)."
    ;;
  restore)
    [[ -f "$STATE" ]] || { echo "nothing to restore"; exit 0; }
    id=$(sed -n 1p "$STATE"); detail=$(sed -n 2p "$STATE")
    psql_owner -v id="$id" -v detail="$detail" >/dev/null <<'SQL'
UPDATE audit_log SET detail = :'detail'::jsonb WHERE id = :id;
SQL
    rm -f "$STATE"
    echo "Restored audit row #$id."
    ;;
  *) echo "usage: $0 tamper [realm] | restore"; exit 2 ;;
esac
