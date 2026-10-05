"""Blue Team API (F2): inspect and roll back deployed defensive actions."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ...core.config import get_config
from ...blue.registry import DeploymentRegistry
from ...blue.deployers.siem import SIEMDeployer
from ...blue.deployers.waf import WAFDeployer
from ...blue.deployers.edr import EDRDeployer
from ...blue.hardening import HardeningApplier
from ...blue.response import IncidentResponder

router = APIRouter(prefix="/api/blue", tags=["blue"])


def _deployer_for(record: dict):
    cfg = get_config()
    kind = record.get("kind")
    if kind == "hardening":
        return HardeningApplier(config=cfg, registry=None)
    if kind == "ir_action":
        return IncidentResponder(config=cfg, registry=None)
    cls = {"siem": SIEMDeployer, "waf": WAFDeployer, "edr": EDRDeployer}.get(record.get("target_system"))
    return cls(config=cfg, registry=None) if cls else None


@router.get("/deployments")
async def list_deployments(request: Request, kind: str | None = None,
                           status: str | None = None, target_system: str | None = None):
    reg = DeploymentRegistry(request.app.state.db)
    return {"deployments": await reg.list(kind=kind, status=status, target_system=target_system)}


@router.get("/deployments/{deployment_id}")
async def get_deployment(request: Request, deployment_id: str):
    reg = DeploymentRegistry(request.app.state.db)
    rec = await reg.get(deployment_id)
    if not rec:
        raise HTTPException(404, "deployment not found")
    return {"deployment": rec}


@router.post("/deployments/{deployment_id}/verify")
async def verify_deployment(request: Request, deployment_id: str):
    reg = DeploymentRegistry(request.app.state.db)
    rec = await reg.get(deployment_id)
    if not rec:
        raise HTTPException(404, "deployment not found")
    obj = _deployer_for(rec)
    if obj is None:
        raise HTTPException(400, "no adapter for this deployment")
    obj.registry = reg
    return await obj.verify(deployment_id)


@router.delete("/deployments/{deployment_id}")
async def rollback_deployment(request: Request, deployment_id: str):
    """Roll back / reverse a deployed detection rule, hardening item or IR action."""
    reg = DeploymentRegistry(request.app.state.db)
    rec = await reg.get(deployment_id)
    if not rec:
        raise HTTPException(404, "deployment not found")
    obj = _deployer_for(rec)
    if obj is None:
        raise HTTPException(400, "no adapter for this deployment")
    obj.registry = reg
    if rec.get("kind") == "ir_action":
        return await obj.revert(deployment_id)
    return await obj.rollback(deployment_id)
