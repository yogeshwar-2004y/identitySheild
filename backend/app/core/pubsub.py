"""Publish to Redis only after the DB transaction commits, so the dashboard never
receives an alert that was rolled back."""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.redis import get_redis

log = logging.getLogger(__name__)


def queue_publish(db: Session, channel: str, payload: dict[str, Any]) -> None:
    db.info.setdefault("pending_publish", []).append((channel, payload))


@event.listens_for(Session, "after_commit")
def _flush_publishes(session: Session) -> None:
    pending = session.info.pop("pending_publish", [])
    for channel, payload in pending:
        try:
            get_redis().publish(channel, json.dumps(payload, default=str))
        except Exception:  # pragma: no cover - push is best effort; the alert is already stored
            log.exception("publish to %s failed", channel)


@event.listens_for(Session, "after_rollback")
def _drop_publishes(session: Session) -> None:
    session.info.pop("pending_publish", None)


# ---- generic after-commit hooks ------------------------------------------------------
# Keycloak calls our back-channel logout endpoint *synchronously* when we delete a
# session there. If we made that call inside our own transaction, the back-channel
# handler would wait on our row/audit locks while we wait on Keycloak: a deadlock.
# Calls that can trigger back-channel logout therefore run after commit.


def run_after_commit(db: Session, fn: Callable[[], None], label: str) -> None:
    db.info.setdefault("after_commit_calls", []).append((label, fn))


@event.listens_for(Session, "after_commit")
def _run_after_commit(session: Session) -> None:
    calls = session.info.pop("after_commit_calls", [])
    for label, fn in calls:
        try:
            fn()
        except Exception:
            log.exception("after-commit call %s failed", label)


@event.listens_for(Session, "after_rollback")
def _drop_after_commit(session: Session) -> None:
    session.info.pop("after_commit_calls", None)
