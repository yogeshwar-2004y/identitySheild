"""Background worker: Keycloak event poller, scheduled leavers, periodic detections."""
from __future__ import annotations

import logging
import signal
import threading
import time

from app.core.config import get_settings
from app.db.session import tenant_session
from app.detection.engine import run_periodic
from app.events.poller import active_tenant_ids, poll_tenant
from app.lifecycle.service import due_scheduled_leavers, execute_leaver
from app.models import Tenant

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s worker: %(message)s")
log = logging.getLogger("worker")

PERIODIC_SECONDS = 60
_stop_event = threading.Event()


def _stop(*_: object) -> None:
    _stop_event.set()


def run(install_signals: bool = True) -> None:
    if install_signals:
        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
    last_periodic = 0.0
    log.info("worker started")
    while not _stop_event.is_set():
        for tid in active_tenant_ids():
            try:
                res = poll_tenant(tid)
                if res.get("stored"):
                    log.info("tenant %s: ingested %s keycloak events", tid, res["stored"])
            except Exception as exc:
                log.warning("poll failed for %s: %s", tid, exc)
        if time.time() - last_periodic >= PERIODIC_SECONDS:
            last_periodic = time.time()
            for tid in active_tenant_ids():
                try:
                    with tenant_session(tid) as db:
                        due = due_scheduled_leavers(db)
                    for lc_id in due:
                        log.info("running scheduled leaver %s", lc_id)
                        execute_leaver(tid, lc_id, actor="scheduler")
                    with tenant_session(tid) as db:
                        tenant = db.get(Tenant, tid)
                        if tenant:
                            alerts = run_periodic(db, tenant)
                            if alerts:
                                log.info("tenant %s: %d periodic alerts", tid, len(alerts))
                except Exception:
                    log.exception("periodic tasks failed for %s", tid)
        _stop_event.wait(get_settings().worker_poll_seconds)


def start_embedded(seed: bool) -> threading.Thread:
    """Runs the worker loop in a daemon thread of the API process (single-service hosting)."""

    logging.getLogger("httpx").setLevel(logging.WARNING)  # the 2 s poll would flood hosted logs

    def target() -> None:
        if seed:
            from app.render_boot import seed_once

            try:
                seed_once()
            except Exception:
                log.exception("demo seed failed; it is retried on the next restart")
        run(install_signals=False)

    thread = threading.Thread(target=target, name="embedded-worker", daemon=True)
    thread.start()
    return thread


def stop_embedded() -> None:
    _stop_event.set()


if __name__ == "__main__":
    run()
