"""Adaptive campaign engine API (Phase 2).

Drives :class:`arcanum.campaigns.CampaignRunner` over a WebSocket, so a non-expert
can click one campaign and watch it adapt (recon -> fingerprint -> conditional
deep tests) with live output and auto-created findings.

Governance is identical to the manual console — in fact it REUSES the console's
``_govern`` (classify + ROE) and the same sandbox ``execute`` path:

* every step is classified and ROE-checked; an out-of-scope/-class step PAUSES the
  campaign and is logged ``blocked_by_roe`` (never silently skipped),
* each executed step is recorded in the immutable audit log,
* intrusive steps require operator approval (``approval_required`` over the socket)
  unless a lab ``auto_approve`` engagement pre-authorizes them,
* no sandbox => refused (never runs on the host),
* findings are created only from real tool output (nuclei JSONL).

There is **no** HTTP endpoint that launches a campaign (that would be ungoverned
offense): execution happens only over the authenticated WebSocket. The plain
``router`` is read-only (catalog + run history).
"""
from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketDisconnected

from ...campaigns import CampaignRunner, CAMPAIGNS, get_campaign
from ...redteam.action_classes import classify as _classify
from ...redteam.engagement import EngagementManager
from ...redteam.audit import ActionAuditLog, summarize_result
from .console import _govern, _sandbox_of, _target_of

router = APIRouter(prefix="/api/campaigns", tags=["campaigns"])
# WS on its own router, included WITHOUT the HTTP token dependency (validated via
# ?token= in the handler, exactly like /ws/{session_id} and /api/console/stream).
stream_router = APIRouter()


# ---------------------------------------------------------------------------
# Read-only surface (authenticated via the router's dependency in main.py)
# ---------------------------------------------------------------------------

@router.get("/catalog")
async def catalog():
    """The adaptive campaign definitions (for the UI to render the cards)."""
    def _public(c: dict) -> dict:
        return {
            "key": c["key"], "icon": c.get("icon"), "title": c["title"],
            "desc": c.get("desc"), "risk": c.get("risk", "ativo"),
            "steps": [{"id": s["id"], "title": s["title"], "why": s.get("why", ""),
                       "intrusive": bool(s.get("intrusive")), "when": s.get("when")}
                      for s in c.get("steps", [])],
        }
    return {"campaigns": [_public(c) for c in CAMPAIGNS]}


@router.get("/runs")
async def list_runs(request: Request, session_id: str | None = None, limit: int = 50):
    db = getattr(request.app.state, "db", None)
    if db is None:
        return {"runs": []}
    sql = "SELECT * FROM campaign_runs"
    params: tuple = ()
    if session_id:
        sql += " WHERE session_id = ?"
        params = (session_id,)
    sql += " ORDER BY started_at DESC LIMIT ?"
    params = params + (int(limit),)
    rows = await (await db.execute(sql, params)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for k in ("context", "steps_log"):
            if isinstance(d.get(k), str):
                try:
                    d[k] = json.loads(d[k])
                except Exception:
                    pass
        out.append(d)
    return {"runs": out}


# ---------------------------------------------------------------------------
# DB helpers for the run row
# ---------------------------------------------------------------------------

async def _insert_run(db, run_id, session_id, engagement_id, campaign, target):
    if db is None:
        return
    try:
        await db.execute(
            """INSERT INTO campaign_runs (id, session_id, engagement_id, campaign, target, status)
               VALUES (?, ?, ?, ?, ?, 'running')""",
            (run_id, session_id, engagement_id, campaign, target),
        )
    except Exception:
        pass


async def _finish_run(db, run_id, status, context, steps_log, findings_count):
    if db is None:
        return
    try:
        await db.execute(
            """UPDATE campaign_runs SET status = ?, context = ?, steps_log = ?,
               findings_count = ?, ended_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (status, json.dumps(context or {}), json.dumps(steps_log or []),
             int(findings_count or 0), run_id),
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# WebSocket: run an adaptive campaign (governed, live)
# ---------------------------------------------------------------------------

@stream_router.websocket("/api/campaigns/stream")
async def campaign_stream(websocket: WebSocket):
    """Protocol (JSON):

      client -> {"type":"run","campaign":<key>,"target":<host|url>,"session_id":...,"operator":...}
      client -> {"type":"approve"} | {"type":"skip"}   # answer an approval_required
      client -> {"type":"cancel"}                        # abort the campaign
      server -> campaign_start | step_start | step_skip | step_blocked | chunk |
                step_end | finding | approval_required | campaign_end | info | error
    """
    from ..auth import token_valid
    expected = getattr(websocket.app.state, "api_token", "") or ""
    if not token_valid(expected, websocket.query_params.get("token")):
        try:
            await websocket.close(code=1008)
        except Exception:
            pass
        return

    await websocket.accept()
    app = websocket.app
    send_lock = asyncio.Lock()
    current: asyncio.Task | None = None
    approval = {"event": asyncio.Event(), "ok": False}

    async def _send(msg: dict) -> None:
        async with send_lock:
            try:
                await websocket.send_json(msg)
            except Exception:
                pass

    try:
        while True:
            data = await websocket.receive_json()
            mtype = data.get("type")

            if mtype in ("approve", "skip"):
                approval["ok"] = (mtype == "approve")
                approval["event"].set()
                continue
            if mtype == "cancel":
                if current and not current.done():
                    current.cancel()
                continue
            if mtype != "run":
                continue
            if current and not current.done():
                await _send({"type": "info", "content": "Já existe uma campanha em execução. Aguarde ou cancele."})
                continue

            current = asyncio.create_task(_run_campaign(app, data, _send, approval))
    except (WebSocketDisconnect, WebSocketDisconnected, RuntimeError):
        pass
    finally:
        if current and not current.done():
            current.cancel()
            try:
                await current
            except Exception:
                pass


async def _run_campaign(app, body: dict, send, approval: dict) -> None:
    """Execute one adaptive campaign end-to-end, fully governed. Shared with tests
    through the injected callables on :class:`CampaignRunner`."""
    campaign = get_campaign(body.get("campaign"))
    if not campaign:
        await send({"type": "error", "content": f"Campanha desconhecida: {body.get('campaign')}"})
        return

    session_id = body.get("session_id")
    operator = body.get("operator") or "console"
    db = getattr(app.state, "db", None)

    eng = None
    if db is not None:
        try:
            eng = await EngagementManager(db).active_for(session_id)
        except Exception:
            eng = None
    auto = bool((eng or {}).get("auto_approve"))
    eng_id = (eng or {}).get("id")
    tag = (eng or {}).get("deconfliction_tag")

    target = (body.get("target") or "").strip()
    if not target and eng and (eng.get("scope") or []):
        target = str(eng["scope"][0]).lstrip("*.").strip()
    if not target:
        await send({"type": "error", "content": "Defina o alvo/programa primeiro (sem alvo não há o que rodar)."})
        return

    te, sandbox = _sandbox_of(app)
    if sandbox is None:
        await send({"type": "error",
                    "content": ("Sandbox indisponível — construa a imagem com 'arcanum sandbox build' "
                                "e verifique o Docker. (As campanhas só rodam no sandbox, nunca no host.)")})
        return

    audit = ActionAuditLog(db) if db is not None else None
    runner = CampaignRunner()
    run_id = "camp-" + uuid.uuid4().hex[:8]
    await _insert_run(db, run_id, session_id, eng_id, campaign["key"], target)
    await send({"type": "run_id", "run_id": run_id})

    try:
        from ...core.config import get_config
        cap = get_config().command_timeout
    except Exception:
        cap = 900

    steps_log: list[dict] = []
    findings_total = {"n": 0}

    async def govern_fn(command: str):
        cls, cls_val, tgt, _e, reason = await _govern(app, command, session_id)
        if reason:
            if audit:
                try:
                    await audit.record(tool="execute", action_class=cls_val, decision="blocked_by_roe",
                                       target=tgt, arguments={"command": command}, result_summary=reason,
                                       engagement_id=eng_id, session_id=session_id, operator=operator,
                                       deconfliction_tag=tag)
                except Exception:
                    pass
            return (False, reason, cls_val)
        return (True, None, cls_val)

    async def exec_fn(command: str) -> dict:
        try:
            from ...agent.tools import _auto_repair_command
            repaired = _auto_repair_command(command)
        except Exception:
            repaired = command
        if repaired != command:
            await send({"type": "chunk", "stream": "stderr", "data": f"[auto-ajuste] {repaired}\n"})
        cid = sandbox._active_container
        if not cid:
            wd = getattr(te, "workspace_dir", None)
            if wd is not None:
                try:
                    wd.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
            cid = await sandbox.create_container(wd)
        out_full = ""
        err_tail = ""
        code = None
        dur = None
        async for piece in sandbox.execute_stream(cid, repaired, timeout=cap):
            st = piece.get("stream")
            if st == "exit":
                code = piece.get("exit_code")
                dur = piece.get("duration")
                if piece.get("note"):
                    await send({"type": "chunk", "stream": "stderr", "data": "\n" + piece["note"] + "\n"})
                break
            payload = piece.get("data", "")
            if st == "stdout":
                out_full = (out_full + payload)[-2000000:]
            else:
                err_tail = (err_tail + payload)[-8000:]
            await send({"type": "chunk", "stream": st, "data": payload})
        cls_val = getattr(_classify("execute", {"command": command}), "value", "active")
        if audit:
            try:
                env = {"success": (code == 0), "error": None,
                       "output": {"stdout": out_full[-4000:], "stderr": err_tail[-2000:], "exit_code": code}}
                await audit.record(tool="execute", action_class=cls_val, decision="campaign_step_executed",
                                   target=_target_of(command), arguments={"command": repaired},
                                   result_summary=summarize_result(env), engagement_id=eng_id,
                                   session_id=session_id, operator=operator, deconfliction_tag=tag)
            except Exception:
                pass
        return {"stdout": out_full, "stderr": err_tail, "exit_code": code, "duration": dur}

    async def approve_fn(step: dict, command: str) -> bool:
        approval["ok"] = False
        approval["event"].clear()
        await send({"type": "approval_required", "id": step["id"], "title": step["title"],
                    "why": step.get("why", ""), "command": command})
        try:
            await asyncio.wait_for(approval["event"].wait(), timeout=600)
        except asyncio.TimeoutError:
            return False
        return bool(approval["ok"])

    async def finding_fn(f: dict):
        fid = "finding-" + uuid.uuid4().hex[:8]
        if db is not None:
            try:
                # dedupe by (session, title) so re-runs don't flood the findings list
                existing = await (await db.execute(
                    "SELECT id FROM findings WHERE session_id IS ? AND title = ? LIMIT 1",
                    (session_id, f["title"]))).fetchone()
                if existing:
                    return existing["id"]
                await db.execute(
                    """INSERT INTO findings (id, session_id, title, type, severity, status, cvss_score,
                       affected, evidence, poc, remediation, verified)
                       VALUES (?, ?, ?, ?, ?, 'confirmed', ?, ?, ?, ?, ?, ?)""",
                    (fid, session_id, f["title"], f.get("type"), f.get("severity"), f.get("cvss_score"),
                     json.dumps(f.get("affected", {})), json.dumps(f.get("evidence", {})),
                     json.dumps(f.get("poc", {})), f.get("remediation", ""), True),
                )
                if session_id:
                    try:
                        await db.execute("UPDATE sessions SET findings_count = findings_count + 1 WHERE id = ?", (session_id,))
                    except Exception:
                        pass
            except Exception:
                pass
        findings_total["n"] += 1
        return fid

    async def emit(ev: dict):
        if ev.get("type") == "step_end":
            steps_log.append({"id": ev.get("id"), "exit_code": ev.get("exit_code"),
                              "findings": ev.get("findings"), "context": ev.get("context")})
        await send(ev)

    status = "completed"
    result_ctx: dict = {}
    try:
        result = await runner.run(
            campaign, target,
            exec_fn=exec_fn, govern_fn=govern_fn, emit=emit,
            approve_fn=approve_fn, finding_fn=finding_fn, auto_approve=auto,
        )
        status = result.get("status", "completed")
        result_ctx = result.get("context", {})
    except asyncio.CancelledError:
        status = "cancelled"
        await send({"type": "campaign_end", "status": "cancelled", "reason": "cancelada pelo operador"})
    except Exception as exc:
        status = "error"
        await send({"type": "campaign_end", "status": "error", "reason": f"{type(exc).__name__}: {exc}"})
    finally:
        await _finish_run(db, run_id, status, result_ctx, steps_log, findings_total["n"])
