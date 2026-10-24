from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.audit.service import write_audit
from app.core.deps import Ctx, require_roles
from app.hunt.service import BUILTINS, GROUPABLE, SearchFilters, run_query, search_events
from app.models import HuntQuery, HuntRun

router = APIRouter(tags=["hunt"])
ANALYST = require_roles("admin", "analyst")


def hunt_out(h: HuntQuery, last: HuntRun | None = None) -> dict[str, Any]:
    return {
        "id": str(h.id), "name": h.name, "hypothesis": h.hypothesis, "query": h.query,
        "attack_technique": h.attack_technique, "prebuilt": h.prebuilt, "created_by": h.created_by,
        "last_run": run_out(last) if last else None,
    }


def run_out(r: HuntRun, include_results: bool = False) -> dict[str, Any]:
    out = {"id": str(r.id), "hunt_id": str(r.hunt_id), "run_at": r.run_at.isoformat(), "run_by": r.run_by,
           "result_count": r.result_count, "verdict": r.verdict, "notes": r.notes, "params": r.params}
    if include_results:
        out["results"] = r.results
    return out


@router.get("/hunts")
def list_hunts(ctx: Ctx = Depends(ANALYST)) -> dict[str, Any]:
    hunts = ctx.db.execute(select(HuntQuery).order_by(HuntQuery.prebuilt.desc(), HuntQuery.name)).scalars().all()
    out = []
    for h in hunts:
        last = ctx.db.execute(select(HuntRun).where(HuntRun.hunt_id == h.id).order_by(HuntRun.run_at.desc())
                              .limit(1)).scalar_one_or_none()
        out.append(hunt_out(h, last))
    return {"hunts": out, "builtins": sorted(BUILTINS), "group_by": sorted(GROUPABLE)}


class HuntIn(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    hypothesis: str = Field(min_length=5, max_length=2000)
    query: dict[str, Any]
    attack_technique: str = Field(default="", max_length=60)


def _validate_query(q: dict[str, Any]) -> None:
    kind = q.get("kind")
    if kind == "builtin":
        if q.get("name") not in BUILTINS:
            raise HTTPException(422, detail=f"Unknown builtin; choose from {sorted(BUILTINS)}")
        params = q.get("params") or {}
        if not isinstance(params, dict) or not all(isinstance(v, (int, float)) for v in params.values()):
            raise HTTPException(422, detail="builtin params must be numbers")
    elif kind == "filter":
        SearchFilters(**(q.get("filters") or {}))  # validates
        if q.get("group_by") not in (None, *GROUPABLE):
            raise HTTPException(422, detail=f"group_by must be one of {sorted(GROUPABLE)}")
    else:
        raise HTTPException(422, detail="query.kind must be 'builtin' or 'filter'")


@router.post("/hunts", status_code=201)
def create_hunt(body: HuntIn, ctx: Ctx = Depends(ANALYST)) -> dict[str, Any]:
    _validate_query(body.query)
    h = HuntQuery(tenant_id=ctx.tenant.id, name=body.name, hypothesis=body.hypothesis, query=body.query,
                  attack_technique=body.attack_technique, created_by=ctx.actor)
    ctx.db.add(h)
    ctx.db.flush()
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="hunt.created", target=f"hunt:{h.id}",
                detail={"name": h.name})
    return hunt_out(h)


class RunIn(BaseModel):
    params: dict[str, int | float | str] = Field(default_factory=dict)


@router.post("/hunts/{hunt_id}/run")
def run_hunt(hunt_id: uuid.UUID, body: RunIn | None = None, ctx: Ctx = Depends(ANALYST)) -> dict[str, Any]:
    h = ctx.db.get(HuntQuery, hunt_id)
    if h is None:
        raise HTTPException(404, detail="Hunt not found")
    params = (body.params if body else {}) or {}
    try:
        results = run_query(ctx.db, ctx.tenant, h.query, params)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, detail=str(exc))
    run = HuntRun(tenant_id=ctx.tenant.id, hunt_id=h.id, run_by=ctx.actor, params=params,
                  result_count=len(results), results=results[:200])
    ctx.db.add(run)
    ctx.db.flush()
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="hunt.run", target=f"hunt:{h.id}",
                detail={"result_count": len(results), "params": params})
    return {"run": run_out(run), "results": results[:500], "hunt": hunt_out(h)}


@router.get("/hunts/{hunt_id}/runs")
def hunt_runs(hunt_id: uuid.UUID, ctx: Ctx = Depends(ANALYST)) -> list[dict[str, Any]]:
    rows = ctx.db.execute(select(HuntRun).where(HuntRun.hunt_id == hunt_id).order_by(HuntRun.run_at.desc())
                          .limit(50)).scalars()
    return [run_out(r) for r in rows]


class VerdictIn(BaseModel):
    verdict: str = Field(pattern="^(CONFIRMED|BENIGN|INCONCLUSIVE|PENDING)$")
    notes: str = Field(default="", max_length=4000)


@router.patch("/hunts/runs/{run_id}")
def set_verdict(run_id: uuid.UUID, body: VerdictIn, ctx: Ctx = Depends(ANALYST)) -> dict[str, Any]:
    r = ctx.db.get(HuntRun, run_id)
    if r is None:
        raise HTTPException(404, detail="Run not found")
    r.verdict, r.notes = body.verdict, body.notes
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="hunt.verdict", target=f"hunt_run:{r.id}",
                detail={"verdict": body.verdict})
    return run_out(r)


class SearchIn(SearchFilters):
    group_by: str | None = Field(default=None, pattern="^(user|ip|type|country)$")
    min_count: int = Field(default=1, ge=1, le=100000)


@router.post("/hunt/search")
def adhoc_search(body: SearchIn, ctx: Ctx = Depends(ANALYST)) -> dict[str, Any]:
    filters = SearchFilters(**body.model_dump(exclude={"group_by", "min_count"}))
    results = search_events(ctx.db, ctx.tenant.id, filters, body.group_by, body.min_count)
    return {"count": len(results), "results": results}
