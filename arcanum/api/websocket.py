"""WebSocket handler for real-time streaming."""
from __future__ import annotations

import json
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..core.config import get_config
from ..agent.engine import AgentEngine
from ..agent.tools import ToolExecutor

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active: dict[str, list[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        if session_id not in self.active:
            self.active[session_id] = []
        self.active[session_id].append(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket):
        if session_id in self.active:
            self.active[session_id].remove(websocket)
            if not self.active[session_id]:
                del self.active[session_id]

    async def broadcast(self, session_id: str, message: dict):
        if session_id in self.active:
            data = json.dumps(message)
            for ws in self.active[session_id]:
                try:
                    await ws.send_text(data)
                except Exception:
                    pass


manager = ConnectionManager()


@router.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    # Authenticate before accepting: the browser can't set headers on a WS
    # upgrade, so the token comes as a ?token= query param (same secret the UI
    # received via window.ARCANUM_TOKEN).
    from .auth import token_valid
    expected = getattr(websocket.app.state, "api_token", "") or ""
    provided = websocket.query_params.get("token")
    if not token_valid(expected, provided):
        await websocket.close(code=1008)  # policy violation
        return

    await manager.connect(session_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "")

            if msg_type == "chat":
                user_input = data.get("content", "")
                # Get or create engine for this session
                app = websocket.app
                engine = app.state.active_engines.get(session_id)

                if not engine:
                    session = await app.state.session_mgr.get_session(session_id)
                    if not session:
                        await websocket.send_json({"type": "error", "message": "Session not found"})
                        continue
                    # Create a basic engine (sandbox/browser setup would be more complex in production)
                    from ..agent.tools import ToolExecutor
                    from ..core.alerts import AlertEngine
                    # Per-session alert engine so alerts from different operations
                    # don't bleed into each other (the app-level one was shared).
                    tool_executor = ToolExecutor(
                        sandbox=getattr(app.state, "sandbox", None),
                        browser=getattr(app.state, "browser", None),
                        workspace_dir=get_config().ops_dir / session.get("name", "default") / "workspace",
                        db=app.state.db,
                        cve_kb=getattr(app.state, "cve_kb", None),
                        stash_mgr=getattr(app.state, "stash_mgr", None),
                        alert_engine=AlertEngine(),
                        session_id=session.get("id"),
                    )
                    engine = AgentEngine(
                        llm=app.state.llm,
                        tool_executor=tool_executor,
                        session=session,
                        deep_llm=getattr(app.state, "deep_llm", None),
                    )
                    app.state.active_engines[session_id] = engine

                # Check if chat message is a conversational approval or rejection for a pending action
                clean_input = user_input.strip().lower().rstrip(".!?,")
                affirmative_phrases = {
                    "pode fazer", "pode executar", "pode", "sim", "ok", "autorizado",
                    "aprovar", "aprovado", "prossiga", "executa", "executar", "confirmo",
                    "vai", "faça", "fazer", "manda ver", "com certeza", "positivo", "bora",
                    "pode rodar", "roda", "rodar", "pode sim", "claro", "sim pode", "pode ir"
                }
                cancel_phrases = {
                    "recusar", "cancelar", "cancela", "não", "nao", "aborta", "abortar", "não faça", "nao faca"
                }

                if engine.pending_action and clean_input in affirmative_phrases:
                    await manager.broadcast(session_id, {"type": "approved", "content": "Ação aprovada pelo operador"})
                    try:
                        async for event in engine.execute_approved():
                            await manager.broadcast(session_id, event)
                    except Exception as e:
                        await websocket.send_json({"type": "error", "message": str(e)})
                    continue

                if engine.pending_action and clean_input in cancel_phrases:
                    cancelled_tool = engine.cancel_pending()
                    await manager.broadcast(session_id, {"type": "cancelled", "content": f"Ação {cancelled_tool} cancelada pelo operador"})
                    continue

                # Stream agent events
                try:
                    async for event in engine.run(user_input):
                        await manager.broadcast(session_id, event)
                except Exception as e:
                    await websocket.send_json({"type": "error", "message": str(e)})

            elif msg_type == "approve":
                # Handle copilot / manual approval
                app = websocket.app
                engine = app.state.active_engines.get(session_id)
                if engine and engine.pending_action:
                    await manager.broadcast(session_id, {"type": "approved", "content": "Action approved by operator"})
                    try:
                        async for event in engine.execute_approved():
                            await manager.broadcast(session_id, event)
                    except Exception as e:
                        await websocket.send_json({"type": "error", "message": str(e)})
                else:
                    await manager.broadcast(session_id, {"type": "info", "content": "No action pending approval"})

            elif msg_type == "cancel":
                # Handle cancellation
                app = websocket.app
                engine = app.state.active_engines.get(session_id)
                if engine and engine.pending_action:
                    cancelled_tool = engine.cancel_pending()
                    await manager.broadcast(session_id, {"type": "cancelled", "content": f"Action {cancelled_tool} cancelled by operator"})
                else:
                    await manager.broadcast(session_id, {"type": "info", "content": "No action pending cancellation"})

    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)
        # Drop the per-session engine once no sockets remain, so engines (and
        # their message history) don't accumulate unbounded across reconnects.
        # The sandbox is a shared singleton, so it is NOT torn down here (that
        # happens at app shutdown); only the engine is released.
        if session_id not in manager.active:
            try:
                websocket.app.state.active_engines.pop(session_id, None)
            except Exception:
                pass
