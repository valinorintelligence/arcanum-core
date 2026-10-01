"""Session/Operation management endpoints."""
from __future__ import annotations

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
    try:
        session = await request.app.state.session_mgr.create_session(
            name=body.name, target=body.target, mode=body.mode, scope=body.scope,
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

