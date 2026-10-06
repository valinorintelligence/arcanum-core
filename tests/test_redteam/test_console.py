"""Direct operator console endpoint (no LLM) — stays governed: runs in the sandbox,
blocked by ROE when out of policy, and recorded in the immutable audit log.

Covers both transports: the one-shot POST (``/api/console/execute``) and the live
WebSocket stream (``_stream_one``), which must gate identically (both call
``_govern``) and audit the outcome."""

import asyncio

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from arcanum.core.database import Database
from arcanum.api.routes import console as console_route
from arcanum.api.routes.console import _target_of, _stream_one
from arcanum.redteam.engagement import EngagementManager
from arcanum.redteam.audit import ActionAuditLog
from arcanum.redteam.action_classes import ActionClass


class _Sandbox:
    pass


class _FakeExec:
    def __init__(self, sandbox=True):
        self.sandbox = _Sandbox() if sandbox else None
        self.ran = []

    async def execute_tool(self, tool, args):
        self.ran.append(args.get("command"))
        return {"success": True, "error": None,
                "output": {"stdout": "uid=0(root)", "stderr": "", "exit_code": 0, "duration": 0.2}}


class _StreamSandbox:
    """Fake SandboxManager whose execute_stream yields a couple of chunks + exit."""
    def __init__(self):
        self._active_container = "c1"
        self.stream_calls = []

    async def create_container(self, workspace_dir):
        self._active_container = "c1"
        return "c1"

    async def execute_stream(self, container_id, command, timeout=None):
        self.stream_calls.append(command)
        yield {"stream": "stdout", "data": "scanning...\n"}
        yield {"stream": "stdout", "data": "uid=0(root)\n"}
        yield {"stream": "exit", "exit_code": 0, "duration": 0.3}


class _StreamExec:
    """Fake app-level ToolExecutor backing the streaming console."""
    def __init__(self, tmp_path, sandbox=True):
        self.sandbox = _StreamSandbox() if sandbox else None
        self.workspace_dir = tmp_path


class _FakeWS:
    """Captures every send_json so the test can assert the emitted protocol."""
    def __init__(self):
        self.sent = []

    async def send_json(self, msg):
        self.sent.append(msg)


@pytest_asyncio.fixture
async def app_db(tmp_path):
    db = Database(db_path=tmp_path / "console.db")
    await db.connect()
    await db.init_db()
    app = FastAPI()
    app.state.db = db
    app.state.tool_executor = _FakeExec()
    app.include_router(console_route.router)   # no auth dep in the test app
    yield app, db
    await db.close()


async def _post(app, body):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/console/execute", json=body)
        return r.json()


def test_target_of_extracts_host_or_url():
    assert _target_of("nmap -sV host.docker.internal:8080") == "host.docker.internal:8080"
    assert _target_of("curl -sI http://x.y/z") == "http://x.y/z"
    assert _target_of("id; whoami") is None


@pytest.mark.asyncio
async def test_console_runs_and_audits(app_db):
    app, db = app_db
    out = await _post(app, {"command": "id", "session_id": "op1"})
    assert out["ran"] is True and out["blocked"] is False
    assert "uid=0" in out["stdout"] and out["exit_code"] == 0
    rows = await ActionAuditLog(db).list(limit=5)
    assert any(r["decision"] == "console_executed" for r in rows)


@pytest.mark.asyncio
async def test_console_refuses_without_sandbox(app_db):
    app, db = app_db
    app.state.tool_executor = _FakeExec(sandbox=False)
    out = await _post(app, {"command": "id"})
    assert out["ran"] is False and "Sandbox" in (out.get("error") or "")


@pytest.mark.asyncio
async def test_console_blocked_by_roe(app_db):
    app, db = app_db
    # Engagement permits only PASSIVE; a raw 'nmap' (execute => ACTIVE) must be blocked.
    await EngagementManager(db).create(name="op", session_id="op1", scope=["lab"],
                                       allowed_classes=[ActionClass.PASSIVE])
    out = await _post(app, {"command": "nmap -sV lab", "session_id": "op1"})
    assert out["blocked"] is True and out["ran"] is False
    rows = await ActionAuditLog(db).list(limit=10)
    assert any(r["decision"] == "blocked_by_roe" for r in rows)
    # And nothing was executed in the sandbox.
    assert app.state.tool_executor.ran == []


# ----------------------------- streaming (WebSocket) -----------------------------

@pytest.mark.asyncio
async def test_stream_runs_and_audits(app_db, tmp_path):
    app, db = app_db
    app.state.tool_executor = _StreamExec(tmp_path)
    ws = _FakeWS()
    await _stream_one(app, ws, asyncio.Lock(), "id", "op1", None)

    types = [m["type"] for m in ws.sent]
    assert types[0] == "start"
    assert "chunk" in types and types[-1] == "end"
    end = ws.sent[-1]
    assert end["exit_code"] == 0 and not end.get("blocked")
    # Streamed chunks carried the live output.
    streamed = "".join(m.get("data", "") for m in ws.sent if m["type"] == "chunk")
    assert "uid=0(root)" in streamed
    # The command actually reached the sandbox stream.
    assert app.state.tool_executor.sandbox.stream_calls == ["id"]
    rows = await ActionAuditLog(db).list(limit=5)
    assert any(r["decision"] == "console_executed" for r in rows)


@pytest.mark.asyncio
async def test_stream_blocked_by_roe_never_touches_sandbox(app_db, tmp_path):
    app, db = app_db
    app.state.tool_executor = _StreamExec(tmp_path)
    await EngagementManager(db).create(name="op", session_id="op1", scope=["lab"],
                                       allowed_classes=[ActionClass.PASSIVE])
    ws = _FakeWS()
    await _stream_one(app, ws, asyncio.Lock(), "nmap -sV lab", "op1", None)

    types = [m["type"] for m in ws.sent]
    assert "blocked" in types and ws.sent[-1]["type"] == "end"
    assert ws.sent[-1].get("blocked") is True
    # Deterministic gate: the sandbox stream must never have been invoked.
    assert app.state.tool_executor.sandbox.stream_calls == []
    rows = await ActionAuditLog(db).list(limit=10)
    assert any(r["decision"] == "blocked_by_roe" for r in rows)


@pytest.mark.asyncio
async def test_stream_refuses_without_sandbox(app_db, tmp_path):
    app, db = app_db
    app.state.tool_executor = _StreamExec(tmp_path, sandbox=False)
    ws = _FakeWS()
    await _stream_one(app, ws, asyncio.Lock(), "id", None, None)

    end = ws.sent[-1]
    assert end["type"] == "end" and end["exit_code"] == -1
    assert "Sandbox" in (end.get("error") or "")
