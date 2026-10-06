"""API endpoints for Distributed Satellite Probes and remote task queues."""

from __future__ import annotations

from typing import Any, Optional
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from arcanum.probes.hub import ProbeHubManager

router = APIRouter()


class RegisterProbeRequest(BaseModel):
    name: str
    hostname: str = ""
    ip_address: str = ""
    tags: list[str] = ["internal"]
    capabilities: list[str] = ["all"]
    probe_id: Optional[str] = None
    version: str = "3.0.0"


class HeartbeatRequest(BaseModel):
    probe_id: str
    status: str = "online"


class DispatchTaskRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = {}
    session_id: str = ""


class SubmitTaskResultRequest(BaseModel):
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None


def _get_probe_hub(request: Request) -> ProbeHubManager:
    hub = getattr(request.app.state, "probe_hub", None)
    if not hub:
        hub = ProbeHubManager(db=request.app.state.db)
        request.app.state.probe_hub = hub
    return hub


@router.post("/register")
async def register_probe(request: Request, body: RegisterProbeRequest):
    hub = _get_probe_hub(request)
    probe = await hub.register_probe(
        name=body.name,
        hostname=body.hostname,
        ip_address=body.ip_address,
        tags=body.tags,
        capabilities=body.capabilities,
        probe_id=body.probe_id,
        version=body.version,
    )
    return {"probe": probe}


@router.post("/heartbeat")
async def probe_heartbeat(request: Request, body: HeartbeatRequest):
    hub = _get_probe_hub(request)
    res = await hub.heartbeat(probe_id=body.probe_id, status=body.status)
    if not res.get("success"):
        raise HTTPException(404, res.get("error", "Probe not found"))
    return res


@router.get("/")
async def list_probes(request: Request, tag: Optional[str] = None):
    hub = _get_probe_hub(request)
    probes = await hub.list_probes(tag=tag)
    return {"probes": probes, "count": len(probes)}


@router.get("/{probe_id}")
async def get_probe_details(request: Request, probe_id: str):
    hub = _get_probe_hub(request)
    probe = await hub.get_probe(probe_id)
    if not probe:
        raise HTTPException(404, f"Probe '{probe_id}' not found")
    return {"probe": probe}


@router.delete("/{probe_id}")
async def deregister_probe(request: Request, probe_id: str):
    hub = _get_probe_hub(request)
    deleted = await hub.deregister_probe(probe_id)
    if not deleted:
        raise HTTPException(404, f"Probe '{probe_id}' not found")
    return {"success": True, "probe_id": probe_id}


@router.post("/{probe_id}/dispatch")
async def dispatch_job_to_probe(request: Request, probe_id: str, body: DispatchTaskRequest):
    hub = _get_probe_hub(request)
    try:
        task = await hub.dispatch_task(
            probe_id=probe_id,
            tool_name=body.tool_name,
            arguments=body.arguments,
            session_id=body.session_id,
        )
        return {"task": task}
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/{probe_id}/tasks")
async def poll_probe_tasks(request: Request, probe_id: str, limit: int = 5):
    hub = _get_probe_hub(request)
    tasks = await hub.poll_tasks(probe_id=probe_id, limit=limit)
    return {"tasks": tasks, "count": len(tasks)}


@router.post("/{probe_id}/tasks/{task_id}/result")
async def submit_task_result(
    request: Request,
    probe_id: str,
    task_id: str,
    body: SubmitTaskResultRequest,
):
    hub = _get_probe_hub(request)
    res = await hub.submit_task_result(
        task_id=task_id,
        probe_id=probe_id,
        result=body.result,
        error=body.error,
    )
    if not res.get("success"):
        raise HTTPException(404, res.get("error", "Failed to submit result"))
    return res


@router.get("/tasks/{task_id}")
async def get_task_status(request: Request, task_id: str):
    hub = _get_probe_hub(request)
    task = await hub.get_task(task_id)
    if not task:
        raise HTTPException(404, f"Task '{task_id}' not found")
    return {"task": task}
