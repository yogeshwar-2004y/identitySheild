#!/usr/bin/env python3
"""Loads demo data. Run inside the API container:

    docker compose exec api python scripts/seed.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # /app inside the container

from app.seed import main  # noqa: E402

if __name__ == "__main__":
    main()
