"""Session/Operation management endpoints."""
from __future__ import annotations

import re
import unicodedata

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

router = APIRouter()


class CreateSessionRequest(BaseModel):
    name: str
    target: str | None = None
    mode: str = "manual"
    scope: dict | None = None


class UpdateSessionRequest(BaseModel):
    target: str | None = None
    mode: str | None = None
    status: str | None = None
    scope: dict | None = None


@router.get("/")
async def list_sessions(request: Request):
    sessions = await request.app.state.session_mgr.list_sessions()
    return {"sessions": sessions}


@router.post("/")
async def create_session(request: Request, body: CreateSessionRequest):
    name = (body.name or "").strip()
    if name and not re.match(r"^[A-Za-z0-9._-]{1,64}$", name):
        normalized = unicodedata.normalize("NFKD", name).encode("ASCII", "ignore").decode("utf-8")
        slug = re.sub(r'[\s/\\:;,]+', '-', normalized.strip().lower())
        slug = re.sub(r'[^a-zA-Z0-9._-]', '', slug)
        slug = re.sub(r'-+', '-', slug).strip('-._')[:64]
        if slug and slug not in (".", ".."):
            name = slug

    try:
        session = await request.app.state.session_mgr.create_session(
            name=name, target=body.target, mode=body.mode, scope=body.scope,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"session": session}


@router.get("/{name}")
async def get_session(request: Request, name: str):
    session = await request.app.state.session_mgr.get_session(name)
    if not session:
        raise HTTPException(404, "Session not found")
    return {"session": session}


@router.patch("/{name}")
async def update_session(request: Request, name: str, body: UpdateSessionRequest):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    session = await request.app.state.session_mgr.update_session(name, **updates)
    if not session:
        raise HTTPException(404, "Session not found")
    return {"session": session}


@router.delete("/{name}")
async def delete_session(request: Request, name: str):
    session = await request.app.state.session_mgr.get_session(name)
    if session and hasattr(request.app.state, "active_engines"):
        request.app.state.active_engines.pop(session.get("id"), None)
    deleted = await request.app.state.session_mgr.delete_session(name)
    if not deleted:
        raise HTTPException(404, "Session not found")
    return {"status": "deleted"}


@router.get("/{name}/wiki")
async def get_session_wiki(request: Request, name: str):
    """Retrieve operational wiki sections (TARGET_MAP, ATTACK_SURFACE, OPERATION_LOG)."""
    session = await request.app.state.session_mgr.get_session(name)
    if not session:
        raise HTTPException(404, "Session not found")
    from ...core.config import get_config
    op_name = session.get("name", name)
    wiki_dir = get_config().ops_dir / op_name / "workspace" / "wiki"
    wiki_dir.mkdir(parents=True, exist_ok=True)

    sections = {}
    for filename in ["TARGET_MAP.md", "ATTACK_SURFACE.md", "OPERATION_LOG.md"]:
        fpath = wiki_dir / filename
        key = filename.replace(".md", "").lower()
        if fpath.exists():
            sections[key] = fpath.read_text(encoding="utf-8")
        else:
            sections[key] = ""
    return {"wiki": sections}


@router.get("/{name}/drift")
async def get_session_drift(request: Request, name: str, compare_to: str | None = None):
    """Retrieve exposure drift (remediated, new, regressed findings) compared to a previous session or baseline."""
    session = await request.app.state.session_mgr.get_session(name)
    if not session:
        raise HTTPException(404, "Session not found")
    session_id = session.get("id") or name

    from arcanum.core.drift import ExposureDrift
    drift_engine = ExposureDrift(db=request.app.state.db)

    compare_id = compare_to
    if compare_to:
        prev_sess = await request.app.state.session_mgr.get_session(compare_to)
        if prev_sess and prev_sess.get("id"):
            compare_id = prev_sess["id"]

    drift_report = await drift_engine.calculate_drift(
        current_session_id=session_id,
        baseline_session_id=compare_id,
    )
    return {"drift": drift_report}


@router.get("/{name}/graph")
async def get_session_graph(request: Request, name: str):
    """Retrieve visual attack graph (nodes and edges) for interactive D3.js rendering."""
    session = await request.app.state.session_mgr.get_session(name)
    if not session:
        raise HTTPException(404, "Session not found")
    session_id = session.get("id") or name

    from arcanum.core.graph import GraphManager
    gm = GraphManager(request.app.state.db)
    graph_data = await gm.get_visual_graph(session_id)
    return {"graph": graph_data}


@router.get("/{name}/graph/choke-points")
async def get_session_choke_points(request: Request, name: str):
    """Retrieve critical choke points (bottlenecks) where mitigations sever attack paths."""
    session = await request.app.state.session_mgr.get_session(name)
    if not session:
        raise HTTPException(404, "Session not found")
    session_id = session.get("id") or name

    from arcanum.core.graph import GraphManager
    gm = GraphManager(request.app.state.db)
    choke_points = await gm.calculate_choke_points(session_id)
    return {"choke_points": choke_points}


@router.get("/{name}/graph/blast-radius")
async def simulate_session_blast_radius(request: Request, name: str, node_id: str, depth: int = 4):
    """Simulate lateral movement blast radius originating from a specific compromised node."""
    session = await request.app.state.session_mgr.get_session(name)
    if not session:
        raise HTTPException(404, "Session not found")
    session_id = session.get("id") or name

    from arcanum.core.graph import GraphManager
    gm = GraphManager(request.app.state.db)
    result = await gm.simulate_blast_radius(session_id, node_id, max_depth=depth)
    if "error" in result:
        raise HTTPException(404, result["error"])
    return {"blast_radius": result}



