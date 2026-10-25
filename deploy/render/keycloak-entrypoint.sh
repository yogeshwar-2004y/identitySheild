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
db="${db%%\?*}"
host="${hostport%%:*}"
port=5432
[[ "$hostport" == *:* ]] && port="${hostport##*:}"

export KC_DB_USERNAME="${creds%%:*}"
export KC_DB_PASSWORD="${creds#*:}"
export KC_DB_URL="jdbc:postgresql://${host}:${port}/${db}"
export KC_DB_SCHEMA="${KC_DB_SCHEMA:-keycloak}"
export KC_HTTP_PORT="${PORT:-8080}"

exec /opt/keycloak/bin/kc.sh start --optimized "$@"
