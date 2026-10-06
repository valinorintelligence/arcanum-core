"""REST API endpoints for Active Directory & Identity Graph Analysis (BloodHound / Pentera Engine)."""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from arcanum.identity.analyzer import ADIdentityAnalyzer

router = APIRouter(prefix="/api/identity", tags=["Identity & Active Directory"])

# Global shared instance or lazily initialized in app state
_analyzer_instance: Optional[ADIdentityAnalyzer] = None


def get_analyzer(request: Optional[Request] = None) -> ADIdentityAnalyzer:
    global _analyzer_instance
    if request and hasattr(request.app.state, "identity_analyzer"):
        return request.app.state.identity_analyzer
    if _analyzer_instance is None:
        _analyzer_instance = ADIdentityAnalyzer()
    return _analyzer_instance


class IngestDomainRequest(BaseModel):
    domain_name: str = Field(..., examples=["corp.local"])
    forest_name: Optional[str] = Field(None, examples=["corp.local"])
    domain_sid: Optional[str] = Field(None, examples=["S-1-5-21-123456-789012-345678"])
    objects: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)


class SimulateAttackRequest(BaseModel):
    start_identity: str = Field(..., examples=["carlos.estagiario"])


@router.post("/ingest")
async def ingest_ad_data(payload: IngestDomainRequest, request: Request):
    """Ingest Active Directory objects, groups, computers and ACL edges into the identity graph."""
    analyzer = get_analyzer(request)
    result = analyzer.ingest_domain(
        domain_name=payload.domain_name,
        objects_data=payload.objects,
        edges_data=payload.edges,
        forest_name=payload.forest_name,
        domain_sid=payload.domain_sid,
    )
    return {"status": "success", "data": result}


@router.get("/domains")
async def list_domains(request: Request):
    """List all registered Active Directory domains."""
    analyzer = get_analyzer(request)
    return {"domains": list(analyzer.domains.values())}


@router.get("/{domain_id}/summary")
async def get_domain_summary(domain_id: str, request: Request):
    """Get high-level security metrics, Tier Zero counts, and roasting exposures for a domain."""
    analyzer = get_analyzer(request)
    if domain_id not in analyzer.domains:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")

    domain_info = analyzer.domains[domain_id]
    domain_objects = [o for o in analyzer.objects.values() if analyzer._sid_to_domain.get(o.object_sid) == domain_id]
    tier_zero = [o for o in domain_objects if o.is_tier_zero]
    kerberoastable = analyzer.find_kerberoastable_accounts(domain_id=domain_id)
    asrep_roastable = analyzer.find_asrep_roastable_accounts(domain_id=domain_id)
    dcsync = analyzer.find_dcsync_principals(domain_id=domain_id)
    choke_points = analyzer.calculate_choke_points(domain_id=domain_id)

    return {
        "domain": domain_info,
        "total_objects": len(domain_objects),
        "total_tier_zero": len(tier_zero),
        "kerberoastable_count": len(kerberoastable),
        "asrep_roastable_count": len(asrep_roastable),
        "dcsync_count": len(dcsync),
        "top_choke_point": choke_points[0].to_dict() if choke_points else None,
    }


@router.get("/{domain_id}/attack-paths")
async def get_attack_paths(domain_id: str, request: Request, start_sid: Optional[str] = None, limit: int = 15):
    """Retrieve shortest attack chains from unprivileged users to Tier-Zero targets."""
    analyzer = get_analyzer(request)
    if domain_id not in analyzer.domains:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")

    paths = analyzer.find_attack_paths_to_tier_zero(domain_id=domain_id, start_sid=start_sid, limit=limit)
    return {
        "domain_id": domain_id,
        "total_paths": len(paths),
        "paths": [p.to_dict() for p in paths],
    }


@router.get("/{domain_id}/choke-points")
async def get_choke_points(domain_id: str, request: Request, limit: int = 10):
    """Calculate key identity choke points where removing privileges blocks the most attack paths."""
    analyzer = get_analyzer(request)
    if domain_id not in analyzer.domains:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")

    choke_points = analyzer.calculate_choke_points(domain_id=domain_id)
    return {
        "domain_id": domain_id,
        "choke_points": [c.to_dict() for c in choke_points[:limit]],
    }


@router.get("/{domain_id}/roasting")
async def get_roasting_exposures(domain_id: str, request: Request):
    """Get all accounts vulnerable to Kerberoasting (SPN) and AS-REP Roasting (No Pre-Auth)."""
    analyzer = get_analyzer(request)
    if domain_id not in analyzer.domains:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")

    kerberoastable = analyzer.find_kerberoastable_accounts(domain_id=domain_id)
    asrep = analyzer.find_asrep_roastable_accounts(domain_id=domain_id)

    return {
        "domain_id": domain_id,
        "kerberoastable_users": [k.to_dict() for k in kerberoastable],
        "asrep_roastable_users": [a.to_dict() for a in asrep],
    }


@router.get("/{domain_id}/dcsync")
async def get_dcsync_accounts(domain_id: str, request: Request):
    """Get principals capable of replicating directory secrets via DCSync."""
    analyzer = get_analyzer(request)
    if domain_id not in analyzer.domains:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")

    dcsync_list = analyzer.find_dcsync_principals(domain_id=domain_id)
    return {
        "domain_id": domain_id,
        "dcsync_principals": dcsync_list,
    }


@router.post("/{domain_id}/simulate-attack")
async def simulate_attack_from_identity(domain_id: str, payload: SimulateAttackRequest, request: Request):
    """Simulate step-by-step lateral movement and privilege escalation from a specific identity."""
    analyzer = get_analyzer(request)
    if domain_id not in analyzer.domains:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")

    result = analyzer.simulate_attack(start_identity=payload.start_identity, domain_id=domain_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result
