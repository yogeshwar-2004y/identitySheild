from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.audit.service import write_audit
from app.core.deps import Ctx, require_roles
from app.detection.scoring import TIERS
from app.models import ResponsePlaybook
from app.response.engine import AVAILABLE_ACTIONS

router = APIRouter(tags=["response"])


def pb_out(p: ResponsePlaybook) -> dict[str, Any]:
    return {"id": str(p.id), "rule_key": p.rule_key, "actions": p.actions, "mode": p.mode, "enabled": p.enabled}


@router.get("/playbooks")
def list_playbooks(ctx: Ctx = Depends(require_roles("admin", "analyst"))) -> dict[str, Any]:
    rows = ctx.db.execute(select(ResponsePlaybook).order_by(ResponsePlaybook.rule_key)).scalars()
    return {
        "playbooks": [pb_out(p) for p in rows],
        "available_actions": AVAILABLE_ACTIONS,
        "risk_tiers": [{"min_risk": floor, "tier": tier, "actions": actions} for floor, tier, actions in TIERS],
    }


class PlaybookIn(BaseModel):
    actions: list[str] = Field(max_length=10)
    mode: str = Field(pattern="^(DRY_RUN|ACTIVE)$")
    enabled: bool = True


@router.put("/playbooks/{playbook_id}")
def update_playbook(playbook_id: uuid.UUID, body: PlaybookIn, ctx: Ctx = Depends(require_roles("admin"))
                    ) -> dict[str, Any]:
    p = ctx.db.get(ResponsePlaybook, playbook_id)
    if p is None:
        raise HTTPException(404, detail="Playbook not found")
    bad = [a for a in body.actions if a not in AVAILABLE_ACTIONS]
    if bad:
        raise HTTPException(422, detail=f"Unknown actions: {bad}")
    before = pb_out(p)
    p.actions, p.mode, p.enabled = list(dict.fromkeys(body.actions)), body.mode, body.enabled
    write_audit(ctx.db, ctx.tenant.id, actor=ctx.actor, action="playbook.updated", target=f"playbook:{p.rule_key}",
                detail={"before": before, "after": pb_out(p)})
    return pb_out(p)
