"""Direct operator console (manual execution, NO LLM).

Runs a raw command in the Kali sandbox WITHOUT the agent/LLM — the operator is the
human-in-the-loop (they chose/typed the command). The safety rails STILL apply:

* the command is classified (``redteam/action_classes``),
* checked against the active engagement's ROE (blocked deterministically when the
  class/scope/window is not permitted),
* recorded in the immutable audit log (decision ``console_executed`` /
  ``blocked_by_roe`` / ``console_cancelled``) with the deconfliction tag.

No sandbox => refused (never runs on the host). This is "manual mode" taken to its
conclusion: a real terminal, still scoped and audited.

Two transports share the exact same governance (``_govern``):

* ``POST /api/console/execute`` — one-shot, returns the full result (fallback).
* ``WS   /api/console/stream``  — live: streams stdout/stderr chunk-by-chunk as the
  command runs, so long scans can be watched in real time and cancelled mid-flight.
"""
from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketDisconnected
from pydantic import BaseModel

from ...redteam.action_classes import classify as _classify
from ...redteam.engagement import EngagementManager
from ...redteam.audit import ActionAuditLog, summarize_result

router = APIRouter(prefix="/api/console", tags=["console"])
# WebSocket lives on its own router included WITHOUT the HTTP token dependency
# (a browser cannot set an Authorization header on a WS upgrade); it authenticates
# via the ?token= query param inside the handler, exactly like /ws/{session_id}.
stream_router = APIRouter()


class ConsoleExecRequest(BaseModel):
    command: str
    session_id: str | None = None
    operator: str | None = None


def _target_of(command: str) -> str | None:
    """Best-effort primary target (URL or host/IP) from a raw command, for ROE scope."""
    m = re.search(r"https?://[^\s\"']+", command or "")
    if m:
        return m.group(0)
    for tok in (command or "").split():
        if tok.startswith("-"):
            continue
        base = tok.split("/")[0].split(":")[0]
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", base) or ("." in base and re.match(r"^[A-Za-z0-9.\-]+$", base)):
            return tok
    return None


async def _govern(app, command: str, session_id: str | None):
    """Classify + ROE-gate a raw command. Returns (cls, cls_val, target, eng, reason).

    ``reason`` is non-None only when an engagement is active AND the command's
    class/scope/window is not permitted — the caller must then block. No active
    engagement => no block (legacy behaviour; the engine's deterministic scope
    still applies separately). Shared by the POST and WS transports so both gate
    identically."""
    cls = _classify("execute", {"command": command})
    cls_val = getattr(cls, "value", str(cls))
    db = getattr(app.state, "db", None)
    target = _target_of(command)
    eng = None
    reason = None
    if db is not None:
        try:
            mgr = EngagementManager(db)
            eng = await mgr.active_for(session_id)
            if eng:
                allowed, why = mgr.is_allowed(eng, cls, target)
                if not allowed:
                    reason = why
        except Exception:
            eng = None
    return cls, cls_val, target, eng, reason


def _sandbox_of(app):
    """The real SandboxManager backing the console (via the app-level ToolExecutor)."""
    te = getattr(app.state, "tool_executor", None)
    sandbox = getattr(te, "sandbox", None) if te is not None else None
    if sandbox is None:
        sandbox = getattr(app.state, "sandbox", None)
    return te, sandbox


@router.post("/execute")
async def console_execute(request: Request, body: ConsoleExecRequest):
    """Execute one command directly in the sandbox (governed, no LLM, one-shot)."""
    app = request.app
    command = (body.command or "").strip()
    if not command:
        raise HTTPException(400, "command vazio")

    te = getattr(app.state, "tool_executor", None)
    if te is None or getattr(te, "sandbox", None) is None:
        return {"command": command, "blocked": False, "ran": False, "exit_code": -1,
                "stdout": "", "stderr": "",
                "error": ("Sandbox indisponivel - construa a imagem com 'arcanum sandbox build' "
                          "e verifique o Docker. (O console so executa no sandbox, nunca no host.)")}

    cls, cls_val, target, eng, reason = await _govern(app, command, body.session_id)
    db = getattr(app.state, "db", None)
    audit = ActionAuditLog(db) if db is not None else None
    operator = body.operator or "console"
    eng_id = (eng or {}).get("id")
    tag = (eng or {}).get("deconfliction_tag")

    if reason:
        if audit:
            try:
                await audit.record(tool="execute", action_class=cls_val, decision="blocked_by_roe",
                                   target=target, arguments={"command": command},
                                   result_summary=reason, engagement_id=eng_id,
                                   session_id=body.session_id, operator=operator, deconfliction_tag=tag)
            except Exception:
                pass
        return {"command": command, "action_class": cls_val, "blocked": True, "ran": False,
                "reason": reason, "exit_code": -1, "stdout": "", "stderr": ""}

    result = await te.execute_tool("execute", {"command": command})
    out = result.get("output") if isinstance(result, dict) else None
    out = out if isinstance(out, dict) else {}
    if audit:
        try:
            await audit.record(tool="execute", action_class=cls_val, decision="console_executed",
                               target=target, arguments={"command": command},
                               result_summary=summarize_result(result), engagement_id=eng_id,
                               session_id=body.session_id, operator=operator, deconfliction_tag=tag)
        except Exception:
            pass
    return {"command": command, "action_class": cls_val, "blocked": False, "ran": True,
            "stdout": out.get("stdout", ""), "stderr": out.get("stderr", ""),
            "exit_code": out.get("exit_code"), "duration": out.get("duration")}


async def _stream_one(app, websocket: WebSocket, send_lock: asyncio.Lock,
                      command: str, session_id: str | None, operator: str | None) -> None:
    """Run one command with live streaming over the WebSocket, fully governed.

    Emits: ``start`` -> (``blocked`` | ``chunk``* ) -> ``end``. All sends go through
    ``send_lock`` because the receive loop may also send small acks concurrently."""
    async def _send(msg: dict) -> None:
        async with send_lock:
            try:
                await websocket.send_json(msg)
            except Exception:
                pass

    cls, cls_val, target, eng, reason = await _govern(app, command, session_id)
    db = getattr(app.state, "db", None)
    audit = ActionAuditLog(db) if db is not None else None
    operator = operator or "console"
    eng_id = (eng or {}).get("id")
    tag = (eng or {}).get("deconfliction_tag")

    await _send({"type": "start", "command": command, "action_class": cls_val, "target": target})

    # ---- ROE block (deterministic) ----
    if reason:
        if audit:
            try:
                await audit.record(tool="execute", action_class=cls_val, decision="blocked_by_roe",
                                   target=target, arguments={"command": command},
                                   result_summary=reason, engagement_id=eng_id,
                                   session_id=session_id, operator=operator, deconfliction_tag=tag)
            except Exception:
                pass
        await _send({"type": "blocked", "reason": reason})
        await _send({"type": "end", "blocked": True, "exit_code": -1})
        return

    # ---- sandbox required (never run on host) ----
    te, sandbox = _sandbox_of(app)
    if sandbox is None:
        await _send({"type": "end", "exit_code": -1,
                     "error": ("Sandbox indisponivel - construa a imagem com 'arcanum sandbox build' "
                               "e verifique o Docker. (O console so executa no sandbox, nunca no host.)")})
        return

    # Normalise the command the same way the LLM path does (strip scheme/:port from
    # scan targets, downgrade -sS->-sT, etc.) so the console behaves consistently.
    try:
        from ...agent.tools import _auto_repair_command
        repaired = _auto_repair_command(command)
    except Exception:
        repaired = command
    if repaired != command:
        await _send({"type": "chunk", "stream": "stderr",
                     "data": f"[auto-ajuste] comando normalizado para: {repaired}\n"})

    # Ensure a container (reuse the active one; create on first use).
    try:
        cid = sandbox._active_container
        if not cid:
            wd = getattr(te, "workspace_dir", None)
            if wd is not None:
                wd.mkdir(parents=True, exist_ok=True)
            cid = await sandbox.create_container(wd)
    except Exception as exc:
        await _send({"type": "end", "exit_code": -1,
                     "error": f"Falha ao preparar o sandbox: {type(exc).__name__}: {exc}"})
        return

    try:
        from ...core.config import get_config
        cap = get_config().command_timeout
    except Exception:
        cap = 900

    out_tail = ""
    err_tail = ""
    exit_code = None
    duration = None
    timed_out = False
    note = None
    cancelled = False
    try:
        async for piece in sandbox.execute_stream(cid, repaired, timeout=cap):
            st = piece.get("stream")
            if st == "exit":
                exit_code = piece.get("exit_code")
                duration = piece.get("duration")
                timed_out = piece.get("timed_out", False)
                note = piece.get("note")
                break
            data = piece.get("data", "")
            if st == "stdout":
                out_tail = (out_tail + data)[-8000:]
            else:
                err_tail = (err_tail + data)[-8000:]
            await _send({"type": "chunk", "stream": st, "data": data})
    except asyncio.CancelledError:
        cancelled = True
    except Exception as exc:
        await _send({"type": "chunk", "stream": "stderr", "data": f"\n[erro no stream] {type(exc).__name__}: {exc}\n"})

    # ---- audit the outcome ----
    if audit:
        decision = "console_cancelled" if cancelled else "console_executed"
        env = {"success": (exit_code == 0) and not cancelled,
               "output": {"stdout": out_tail[-4000:], "stderr": err_tail[-2000:],
                          "exit_code": exit_code, "duration": duration},
               "error": "cancelado pelo operador" if cancelled else None}
        try:
            await audit.record(tool="execute", action_class=cls_val, decision=decision,
                               target=target, arguments={"command": repaired},
                               result_summary=summarize_result(env), engagement_id=eng_id,
                               session_id=session_id, operator=operator, deconfliction_tag=tag)
        except Exception:
            pass

    if cancelled:
        await _send({"type": "chunk", "stream": "stderr", "data": "\n[cancelado pelo operador]\n"})
        await _send({"type": "end", "cancelled": True, "exit_code": -1})
    else:
        end = {"type": "end", "exit_code": exit_code, "duration": duration, "timed_out": timed_out}
        if note:
            end["note"] = note
        await _send(end)


@stream_router.websocket("/api/console/stream")
async def console_stream(websocket: WebSocket):
    """Live operator console over WebSocket. Protocol (JSON):

      client -> {"type":"exec","command":...,"session_id":...,"operator":...}
      client -> {"type":"cancel"}            # abort the command in flight
      server -> {"type":"start"|"chunk"|"blocked"|"end"|"info", ...}
    """
    from ..auth import token_valid
    expected = getattr(websocket.app.state, "api_token", "") or ""
    if not token_valid(expected, websocket.query_params.get("token")):
        try:
            await websocket.close(code=1008)  # policy violation
        except Exception:
            pass
        return

    await websocket.accept()
    app = websocket.app
    send_lock = asyncio.Lock()
    current: asyncio.Task | None = None
    try:
        while True:
            data = await websocket.receive_json()
            mtype = data.get("type")

            if mtype == "cancel":
                if current and not current.done():
                    current.cancel()
                continue

            if mtype != "exec":
                continue

            if current and not current.done():
                async with send_lock:
                    try:
                        await websocket.send_json({"type": "info",
                                                   "content": "Ja existe um comando em execucao. Aguarde ou cancele."})
                    except Exception:
                        pass
                continue

            command = (data.get("command") or "").strip()
            if not command:
                async with send_lock:
                    try:
                        await websocket.send_json({"type": "end", "exit_code": -1, "error": "command vazio"})
                    except Exception:
                        pass
                continue

            current = asyncio.create_task(
                _stream_one(app, websocket, send_lock, command,
                            data.get("session_id"), data.get("operator"))
            )
    except (WebSocketDisconnect, WebSocketDisconnected, RuntimeError):
        pass
    finally:
        if current and not current.done():
            current.cancel()
            try:
                await current
            except Exception:
                pass
