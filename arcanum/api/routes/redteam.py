"""Red Team governance API (F0).

Exposes the engagement (ROE) lifecycle, the immutable action audit log (+ chain
verification), the foothold/implant registry, and the global kill-switch. These
endpoints are the operator's control surface for the safety rails that gate
every real Red/Blue/Purple action.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ...redteam.engagement import EngagementManager
from ...redteam.audit import ActionAuditLog
from ...redteam.sessions import SessionRegistry
from ...redteam.action_classes import ActionClass

router = APIRouter(prefix="/api/redteam", tags=["redteam"])


# ---------------------------------------------------------------------------
# Engagements (ROE)
# ---------------------------------------------------------------------------

class CreateEngagementRequest(BaseModel):
    name: str
    scope: list[str] | None = None
    allowed_classes: list[str] | None = None
    window_start: str | None = None
    window_end: str | None = None
    session_id: str | None = None
    operator: str | None = None


def _valid_classes(classes: list[str] | None) -> list[str]:
    valid = {c.value for c in ActionClass}
    out = []
    for c in (classes or []):
        cv = str(c).strip().lower()
        if cv not in valid:
            raise HTTPException(400, f"invalid action class '{c}'. Valid: {sorted(valid)}")
        out.append(cv)
    return out


@router.post("/engagements")
async def create_engagement(request: Request, body: CreateEngagementRequest):
    classes = _valid_classes(body.allowed_classes) or None
    mgr = EngagementManager(request.app.state.db)
    window = None
    if body.window_start or body.window_end:
        window = {"start": body.window_start, "end": body.window_end}
    eng = await mgr.create(
        name=body.name,
        scope=body.scope,
        allowed_classes=classes,
        window=window,
        session_id=body.session_id,
        operator=body.operator,
    )
    return {"engagement": eng}


@router.get("/engagements")
async def list_engagements(request: Request, status: str | None = None):
    mgr = EngagementManager(request.app.state.db)
    return {"engagements": await mgr.list(status=status)}


@router.get("/engagements/active")
async def active_engagement(request: Request, session_id: str | None = None):
    mgr = EngagementManager(request.app.state.db)
    return {"engagement": await mgr.active_for(session_id)}


@router.get("/engagements/{engagement_id}")
async def get_engagement(request: Request, engagement_id: str):
    mgr = EngagementManager(request.app.state.db)
    eng = await mgr.get(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    return {"engagement": eng}


@router.post("/engagements/{engagement_id}/close")
async def close_engagement(request: Request, engagement_id: str):
    mgr = EngagementManager(request.app.state.db)
    ok = await mgr.close(engagement_id)
    if not ok:
        raise HTTPException(404, "engagement not found")
    # Closing an engagement triggers cleanup of its footholds (cleanup obligation).
    cleaned = await SessionRegistry(request.app.state.db).cleanup(engagement_id)
    return {"status": "closed", "engagement_id": engagement_id, "cleanup": cleaned}


# ---------------------------------------------------------------------------
# Action audit log (immutable)
# ---------------------------------------------------------------------------

@router.get("/actions")
async def list_actions(request: Request, limit: int = 200, engagement_id: str | None = None):
    log = ActionAuditLog(request.app.state.db)
    return {"actions": await log.list(limit=limit, engagement_id=engagement_id)}


@router.get("/actions/verify")
async def verify_actions(request: Request):
    log = ActionAuditLog(request.app.state.db)
    return await log.verify_chain()


# ---------------------------------------------------------------------------
# Foothold / implant registry
# ---------------------------------------------------------------------------

@router.get("/sessions")
async def list_footholds(request: Request, engagement_id: str | None = None, status: str | None = "open"):
    reg = SessionRegistry(request.app.state.db)
    return {"sessions": await reg.list(engagement_id=engagement_id, status=status)}


@router.delete("/sessions/{foothold_id}")
async def close_foothold(request: Request, foothold_id: str):
    reg = SessionRegistry(request.app.state.db)
    ok = await reg.close(foothold_id, status="cleaned")
    if not ok:
        raise HTTPException(404, "foothold not found")
    return {"status": "cleaned", "foothold_id": foothold_id}


# ---------------------------------------------------------------------------
# Global kill-switch
# ---------------------------------------------------------------------------

@router.post("/killswitch")
async def killswitch(request: Request):
    """Abort every active run and clean up every open foothold/implant."""
    app = request.app
    engines = getattr(app.state, "active_engines", {}) or {}
    aborted = 0
    for eng in list(engines.values()):
        try:
            eng.abort()
            aborted += 1
        except Exception:
            pass

    db = app.state.db
    cleaned = await SessionRegistry(db).cleanup(None)  # all open footholds

    # Record the global kill-switch itself in the immutable trail.
    try:
        await ActionAuditLog(db).record(
            tool="kill_switch", action_class=ActionClass.PASSIVE.value,
            decision="kill_switch_global",
            result_summary=f"engines_aborted={aborted}, sessions_cleaned={cleaned.get('cleaned', 0)}",
            operator="operator",
        )
    except Exception:
        pass

    return {
        "status": "killed",
        "engines_aborted": aborted,
        "sessions_cleaned": cleaned.get("cleaned", 0),
        "cleaned_ids": cleaned.get("ids", []),
    }
