"""API endpoints for Continuous Threat Exposure Management (CTEM) and CISA KEV."""

from __future__ import annotations

from typing import Any, Optional
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from arcanum.core.ctem import CTEMDaemon
from arcanum.core.kev import CISAKEVEngine

router = APIRouter()


class CreateScheduleRequest(BaseModel):
    session_id: str
    target: str
    frequency_minutes: int = 1440


def _get_ctem_daemon(request: Request) -> CTEMDaemon:
    daemon = getattr(request.app.state, "ctem_daemon", None)
    if not daemon:
        db = request.app.state.db
        hub = getattr(request.app.state, "enterprise_hub", None)
        daemon = CTEMDaemon(db=db, enterprise_hub=hub)
        request.app.state.ctem_daemon = daemon
    return daemon


def _get_kev_engine(request: Request) -> CISAKEVEngine:
    engine = getattr(request.app.state, "kev_engine", None)
    if not engine:
        db = request.app.state.db
        engine = CISAKEVEngine(db=db)
        request.app.state.kev_engine = engine
    return engine


# ============================================================================
# CTEM Schedules Endpoints
# ============================================================================

@router.get("/schedules")
async def list_schedules(request: Request):
    daemon = _get_ctem_daemon(request)
    schedules = await daemon.list_schedules()
    return {"schedules": schedules, "count": len(schedules)}


@router.post("/schedules")
async def create_schedule(request: Request, body: CreateScheduleRequest):
    daemon = _get_ctem_daemon(request)
    # Verify session exists
    cursor = await request.app.state.db.execute("SELECT id FROM sessions WHERE id = ? OR name = ?", (body.session_id, body.session_id))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(404, f"Session '{body.session_id}' not found.")

    actual_session_id = row["id"]
    schedule = await daemon.create_schedule(
        session_id=actual_session_id,
        target=body.target,
        frequency_minutes=body.frequency_minutes,
    )
    return {"schedule": schedule}


@router.get("/schedules/{schedule_id}")
async def get_schedule(request: Request, schedule_id: str):
    daemon = _get_ctem_daemon(request)
    schedule = await daemon.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(404, f"Schedule '{schedule_id}' not found.")
    return {"schedule": schedule}


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(request: Request, schedule_id: str):
    daemon = _get_ctem_daemon(request)
    deleted = await daemon.delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(404, f"Schedule '{schedule_id}' not found.")
    return {"success": True, "schedule_id": schedule_id}


@router.post("/schedules/{schedule_id}/pause")
async def pause_schedule(request: Request, schedule_id: str):
    daemon = _get_ctem_daemon(request)
    updated = await daemon.update_schedule_status(schedule_id, "paused")
    if not updated:
        raise HTTPException(404, f"Schedule '{schedule_id}' not found.")
    return {"success": True, "status": "paused"}


@router.post("/schedules/{schedule_id}/resume")
async def resume_schedule(request: Request, schedule_id: str):
    daemon = _get_ctem_daemon(request)
    updated = await daemon.update_schedule_status(schedule_id, "active")
    if not updated:
        raise HTTPException(404, f"Schedule '{schedule_id}' not found.")
    return {"success": True, "status": "active"}


@router.post("/schedules/{schedule_id}/run-now")
async def run_schedule_now(request: Request, schedule_id: str):
    daemon = _get_ctem_daemon(request)
    try:
        result = await daemon.run_assessment_cycle(schedule_id)
        return {"result": result}
    except ValueError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"Assessment cycle failed: {e}")


# ============================================================================
# CISA KEV Intelligence Endpoints
# ============================================================================

@router.get("/kev/stats")
async def get_kev_stats(request: Request):
    kev = _get_kev_engine(request)
    stats = await kev.get_statistics()
    return {"kev_stats": stats}


@router.post("/kev/sync")
async def sync_kev_feed(request: Request, force: bool = False):
    kev = _get_kev_engine(request)
    sync_res = await kev.sync_cisa_kev(force=force)
    return {"sync": sync_res}


@router.get("/kev/check/{cve_id}")
async def check_cve_kev(request: Request, cve_id: str):
    kev = _get_kev_engine(request)
    is_kev = await kev.is_cisa_kev(cve_id)
    details = await kev.get_cve_details(cve_id) if is_kev else None
    return {
        "cve_id": cve_id.upper(),
        "is_cisa_kev": is_kev,
        "details": details,
    }
