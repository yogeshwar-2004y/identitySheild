#!/bin/sh
# Render start command for the API: derive DB URLs, ensure the RLS-bound runtime role,
# migrate as the owner, then serve. The worker runs inside this process (EMBED_WORKER=true).
set -eu
cd /app
eval "$(python -m app.render_boot env)"
python -m app.render_boot db
alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers --forwarded-allow-ips='*'
