#!/usr/bin/env bash
# Creates .env from .env.example, replacing every CHANGE_ME placeholder with a fresh random secret.
# Safe to re-run: an existing .env is never overwritten.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  echo ".env already exists, leaving it untouched."
  exit 0
fi

rand() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "${1:-32}"; }

cp .env.example .env
while IFS= read -r line; do
  key="${line%%=*}"
  case "$key" in
    ENCRYPTION_KEY) val="$(openssl rand -base64 32)" ;;
    DEMO_PASSWORD) val="Demo-$(rand 10)-9a!" ;;
    *) val="$(rand 40)" ;;
  esac
  # escape for sed
  esc=$(printf '%s' "$val" | sed -e 's/[\/&|]/\\&/g')
  sed -i.bak -E "s|^${key}=CHANGE_ME[^ ]*(.*)$|${key}=${esc}\1|" .env
done < <(grep -E '^[A-Z_]+=CHANGE_ME' .env.example)
rm -f .env.bak
chmod 600 .env
echo "Created .env with random secrets."
