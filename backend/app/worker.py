"""Background worker: Keycloak event poller, scheduled leavers, periodic detections."""
from __future__ import annotations

import logging
import signal
import time

from app.db.session import tenant_session
from app.detection.engine import run_periodic
from app.events.poller import active_tenant_ids, poll_tenant
from app.lifecycle.service import due_scheduled_leavers, execute_leaver
from app.models import Tenant

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s worker: %(message)s")
log = logging.getLogger("worker")

POLL_SECONDS = 2
PERIODIC_SECONDS = 60
_running = True


def _stop(*_: object) -> None:
    global _running
    _running = False


def run() -> None:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    last_periodic = 0.0
    log.info("worker started")
    while _running:
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
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    run()
