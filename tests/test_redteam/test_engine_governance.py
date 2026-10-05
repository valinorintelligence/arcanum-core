"""F0 — engine-level governance: ROE gating, audit on block, dual-approval, kill-switch.

These lock in the F0 acceptance criteria (roadmap §10):
- engagement [PASSIVE, ACTIVE] => an EXPLOIT tool is blocked AND logged;
- the audit chain stays intact;
- dual-approval classes need two approvals;
- the engine kill-switch cleans up open footholds.
"""

from pathlib import Path

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.agent.tools import ToolExecutor
from arcanum.agent.engine import AgentEngine
from arcanum.redteam.engagement import EngagementManager
from arcanum.redteam.audit import ActionAuditLog
from arcanum.redteam.sessions import SessionRegistry
from arcanum.redteam.action_classes import ActionClass


@pytest_asyncio.fixture
async def wired(tmp_path):
    """A real DB + ToolExecutor + engine for session 'op-f0'.

    Uses pytest's ``tmp_path`` (lock-tolerant cleanup) because the aiosqlite
    connection's background thread can briefly hold the DB file on Windows."""
    db = Database(db_path=tmp_path / "f0.db")
    await db.connect()
    await db.init_db()
    await db.execute("INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
                     ("op-f0", "f0", "example.com"))
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path,
                      db=db, session_id="op-f0")
    eng = AgentEngine.__new__(AgentEngine)
    # Minimal attributes the governance paths touch:
    eng.tool_executor = te
    eng.session = {"id": "op-f0", "name": "f0", "target": "example.com"}
    eng.mode = "copilot"
    eng._gov_cache = "unset"
    eng._active_engagement = None
    eng._engagement_loaded = False
    try:
        yield eng, db
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_roe_blocks_exploit_and_logs(wired):
    eng, db = wired
    mgr = EngagementManager(db)
    await mgr.create(name="F0 Op", session_id="op-f0",
                     allowed_classes=[ActionClass.PASSIVE, ActionClass.ACTIVE])

    # EXPLOIT command (metasploit) must be blocked by the ROE.
    reason = await eng._roe_authorize("execute", {"command": "msfconsole -q -x 'use exploit/x'"})
    assert reason is not None and "class" in reason.lower()

    # The block must be recorded in the immutable audit trail.
    log = ActionAuditLog(db)
    rows = await log.list(limit=10)
    assert any(r["decision"] == "blocked_by_roe" and r["action_class"] == "exploit" for r in rows)
    assert (await log.verify_chain())["valid"] is True


@pytest.mark.asyncio
async def test_roe_allows_permitted_classes(wired):
    eng, db = wired
    mgr = EngagementManager(db)
    await mgr.create(name="F0 Op", session_id="op-f0",
                     allowed_classes=[ActionClass.PASSIVE, ActionClass.ACTIVE])

    assert await eng._roe_authorize("audit_security_headers", {"url": "https://example.com"}) is None
    assert await eng._roe_authorize("execute", {"command": "nmap -sV example.com"}) is None


@pytest.mark.asyncio
async def test_no_engagement_is_legacy_no_block(wired):
    eng, db = wired
    # No engagement created => even an exploit command is not ROE-blocked
    # (legacy operator-driven behavior; the engine's scope check still applies).
    assert await eng._roe_authorize("execute", {"command": "hydra ssh://x"}) is None


@pytest.mark.asyncio
async def test_executed_action_is_audited(wired):
    eng, db = wired
    mgr = EngagementManager(db)
    await mgr.create(name="F0 Op", session_id="op-f0",
                     allowed_classes=[ActionClass.PASSIVE, ActionClass.ACTIVE])
    await eng._audit_record(tool="audit_tls_ssl", arguments={"domain": "example.com"},
                            action_cls=ActionClass.PASSIVE, decision="executed",
                            result={"success": True, "output": {"grade": "A"}})
    rows = await ActionAuditLog(db).list(limit=5)
    assert rows and rows[0]["tool"] == "audit_tls_ssl"
    assert rows[0]["decision"] == "executed"
    assert rows[0]["deconfliction_tag"] and rows[0]["deconfliction_tag"].startswith("ARC-")


@pytest.mark.asyncio
async def test_dual_approval_requires_two_approvals(wired):
    eng, db = wired
    eng.findings_count = 0
    # Arm a dual-approval pending action (as the dispatch loop would for EXPLOIT).
    eng.pending_action = {
        "tool": "execute",
        "arguments": {"command": "msfconsole -q"},
        "action_class": ActionClass.EXPLOIT.value,
        "approvals_required": 2,
        "approvals_given": 0,
    }
    events = [e async for e in eng.execute_approved()]
    # First approval must NOT execute: it re-pends and asks for a second.
    assert eng.pending_action is not None
    assert eng.pending_action["approvals_given"] == 1
    assert any(e.get("type") == "suggestion" and e.get("approvals_given") == 1
               and e.get("approvals_required") == 2 for e in events)


@pytest.mark.asyncio
async def test_engine_kill_switch_cleans_footholds(wired):
    eng, db = wired
    mgr = EngagementManager(db)
    engagement = await mgr.create(name="F0 Op", session_id="op-f0",
                                  allowed_classes=[ActionClass.POST_EXPLOIT])
    reg = SessionRegistry(db)
    await reg.create_foothold(engagement_id=engagement["id"], session_id="op-f0", host="10.0.0.5")

    summary = await eng.kill_switch()
    assert eng._abort_requested is True
    assert summary["cleaned_sessions"] == 1
    assert await reg.list(engagement_id=engagement["id"], status="open") == []
