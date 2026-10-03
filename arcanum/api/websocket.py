"""WebSocket handler for real-time streaming."""
from __future__ import annotations

import json
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketDisconnected

from ..core.config import get_config
from ..agent.engine import AgentEngine
from ..agent.tools import ToolExecutor

router = APIRouter()

# Sessions with an agent run currently in flight. The engine is shared per
# session_id (app.state.active_engines), and two concurrent engine.run() calls
# would corrupt its message list / iteration counter — so a session runs one at
# a time. A second request while busy is rejected with an info event.
_running_sessions: set[str] = set()


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active: dict[str, list[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket) -> bool:
        try:
            await websocket.accept()
        except Exception:
            return False
        if session_id not in self.active:
            self.active[session_id] = []
        self.active[session_id].append(websocket)
        return True

    def disconnect(self, session_id: str, websocket: WebSocket):
        if session_id in self.active:
            if websocket in self.active[session_id]:
                self.active[session_id].remove(websocket)
            if not self.active[session_id]:
                del self.active[session_id]

    async def broadcast(self, session_id: str, message: dict):
        if session_id in self.active:
            data = json.dumps(message)
            stale = []
            for ws in list(self.active[session_id]):
                try:
                    await ws.send_text(data)
                except Exception:
                    stale.append(ws)
            for ws in stale:
                self.disconnect(session_id, ws)


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
        try:
            await websocket.close(code=1008)  # policy violation
        except Exception:
            pass
        return

    connected = await manager.connect(session_id, websocket)
    if not connected:
        return

    # If this session has an active engine with a pending action, immediately notify the client
    existing_engine = getattr(websocket.app.state, "active_engines", {}).get(session_id)
    if existing_engine and existing_engine.pending_action:
        p = existing_engine.pending_action
        risk = existing_engine._assess_risk(p["tool"], p["arguments"])
        risk_pt = {"LOW": "BAIXO", "MEDIUM": "MÉDIO", "HIGH": "ALTO"}.get(risk, risk)
        explanation = existing_engine._explain_tool_action(p["tool"], p["arguments"])
        try:
            await websocket.send_json({
                "type": "suggestion",
                "tool": p["tool"],
                "arguments": p["arguments"],
                "risk": risk,
                "risk_pt": risk_pt,
                "explanation": explanation,
                "iteration": existing_engine.iteration,
                "content": (
                    f"[SUGESTÃO / APROVAÇÃO NECESSÁRIA] Ferramenta: {p['tool']} (RISCO: {risk_pt})\n"
                    f"Modo {existing_engine.mode.capitalize()}: aprovação do operador necessária (Risco: {risk_pt}).\n\n"
                    f"📌 O QUE FAZ:\n{explanation['what']}\n\n"
                    f"🎯 POR QUE EXECUTAR:\n{explanation['why']}\n\n"
                    f"⚙️ PARÂMETROS / EXEMPLO:\n{explanation.get('params') or explanation.get('example', '')}"
                ),
            })
        except Exception:
            pass

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
                        try:
                            await websocket.send_json({"type": "error", "message": str(e)})
                        except Exception:
                            pass
                    continue

                if engine.pending_action and clean_input in cancel_phrases:
                    cancelled_tool = engine.cancel_pending()
                    await manager.broadcast(session_id, {"type": "cancelled", "content": f"Ação {cancelled_tool} cancelada pelo operador"})
                    continue

                # Concurrency guard: one run per session (shared engine state).
                if session_id in _running_sessions:
                    await websocket.send_json({
                        "type": "info",
                        "content": "Já existe uma operação em execução nesta sessão. Aguarde a conclusão ou interrompa-a antes de enviar uma nova instrução.",
                    })
                    continue

                # Stream agent events
                _running_sessions.add(session_id)
                _es = getattr(engine, "session", None) or {}
                sess_name = _es.get("name") if isinstance(_es, dict) else getattr(_es, "name", None)
                try:
                    if sess_name:
                        await app.state.session_mgr.update_session(sess_name, status="running")
                except Exception:
                    pass
                try:
                    async for event in engine.run(user_input):
                        await manager.broadcast(session_id, event)
                except Exception as e:
                    try:
                        await websocket.send_json({"type": "error", "message": str(e)})
                    except Exception:
                        pass
                finally:
                    _running_sessions.discard(session_id)
                    # Reflect the real lifecycle state: 'running' only while a run
                    # is awaiting operator approval; otherwise the run finished.
                    try:
                        if sess_name:
                            new_status = "running" if getattr(engine, "pending_action", None) else "complete"
                            await app.state.session_mgr.update_session(sess_name, status=new_status)
                    except Exception:
                        pass

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
                        try:
                            await websocket.send_json({"type": "error", "message": str(e)})
                        except Exception:
                            pass
                else:
                    await manager.broadcast(session_id, {"type": "info", "content": "No action pending approval"})

            elif msg_type in ("cancel", "stop"):
                # Handle cancellation or immediate execution abort
                app = websocket.app
                engine = app.state.active_engines.get(session_id)
                if engine:
                    engine.abort()
                    cancelled_tool = engine.cancel_pending()
                    msg = f"Ação {cancelled_tool} cancelada pelo operador" if cancelled_tool else "Operação interrompida a pedido do operador."
                    await manager.broadcast(session_id, {"type": "cancelled", "content": msg})
                else:
                    await manager.broadcast(session_id, {"type": "info", "content": "Nenhuma ação em execução para interromper."})

    except (WebSocketDisconnect, WebSocketDisconnected, RuntimeError):
        pass
    finally:
        manager.disconnect(session_id, websocket)
        # If this was the last connection for the session, stop any run still
        # executing for it. An abandoned run otherwise keeps issuing slow local
        # inferences server-side — with OLLAMA_NUM_PARALLEL=1 these queue up and
        # stall every subsequent run (observed as multi-minute contention).
        if session_id not in manager.active:
            engine = getattr(websocket.app.state, "active_engines", {}).get(session_id)
            if engine is not None:
                try:
                    engine.abort()
                except Exception:
                    pass
