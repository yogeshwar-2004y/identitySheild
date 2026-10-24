#!/usr/bin/env bash
# Runs the backend test suite inside the API image (test DB + Redis DB 15), with coverage.
# Source is bind-mounted so edits are picked up without rebuilding.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose run --rm --no-deps \
  -v "$PWD/backend/app:/app/app:ro" -v "$PWD/backend/tests:/app/tests:ro" -v "$PWD/simulator:/app/simulator:ro" \
  -e PYTHONDONTWRITEBYTECODE=1 \
  api pytest -p no:cacheprovider --cov=app --cov-report=term-missing:skip-covered "$@"
