#!/bin/bash
# Maps Render's DATABASE_URL (postgresql://user:pass@host[:port]/db) onto Keycloak's KC_DB_* settings
# and listens on Render's $PORT. Keycloak keeps its tables in its own schema (KC_DB_SCHEMA).
set -euo pipefail

url="${DATABASE_URL:?DATABASE_URL is required}"
rest="${url#*://}"
creds="${rest%%@*}"
hostpart="${rest#*@}"
hostport="${hostpart%%/*}"
db="${hostpart#*/}"
query=""
[[ "$db" == *\?* ]] && query="${db#*\?}"
db="${db%%\?*}"
host="${hostport%%:*}"
port=5432
[[ "$hostport" == *:* ]] && port="${hostport##*:}"

export KC_DB_USERNAME="${creds%%:*}"
export KC_DB_PASSWORD="${creds#*:}"
# Keep only sslmode (hosted Postgres such as Neon needs sslmode=require); the JDBC driver does
# not understand libpq-only options like channel_binding.
jdbc_params=""
IFS='&' read -ra kv <<< "$query"
for p in "${kv[@]}"; do [[ "$p" == sslmode=* ]] && jdbc_params="?${p}"; done
export KC_DB_URL="jdbc:postgresql://${host}:${port}/${db}${jdbc_params}"
export KC_DB_SCHEMA="${KC_DB_SCHEMA:-keycloak}"
export KC_HTTP_PORT="${PORT:-8080}"

exec /opt/keycloak/bin/kc.sh start --optimized "$@"
