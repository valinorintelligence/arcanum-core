"""F0 follow-ups (safety hardening) — regression tests.

Covers the four non-offensive F0 follow-ups:
  #3 fail-closed audit for EXPLOIT/POST_EXPLOIT/DESTRUCTIVE;
  #1/#2 operator identity + the real two-person rule in dual approval;
  #4 tamper anchor that catches tail truncation of the audit chain;
  #5 real teardown in SessionRegistry.cleanup (honest when it cannot run).
"""

from pathlib import Path

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.agent.tools import ToolExecutor
from arcanum.agent.engine import AgentEngine
from arcanum.redteam.audit import ActionAuditLog
from arcanum.redteam.sessions import SessionRegistry
from arcanum.redteam.action_classes import ActionClass


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "f0f.db")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


@pytest_asyncio.fixture
async def wired(tmp_path):
    db = Database(db_path=tmp_path / "f0f-eng.db")
    await db.connect()
    await db.init_db()
    await db.execute("INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
                     ("op-f0f", "f0f", "example.com"))
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path,
                      db=db, session_id="op-f0f")
    eng = AgentEngine.__new__(AgentEngine)
    eng.tool_executor = te
    eng.session = {"id": "op-f0f", "name": "f0f", "target": "example.com"}
    eng.mode = "copilot"
    eng._gov_cache = "unset"
    eng._active_engagement = None
    eng._engagement_loaded = False
    eng.iteration = 0
    eng.pending_action = None
    try:
        yield eng, db
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# #4 — tamper anchor catches TAIL TRUNCATION (chain alone cannot)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_anchor_table_exists(db):
    row = await db.fetch_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_anchor'")
    assert row is not None


@pytest.mark.asyncio
async def test_anchor_tracks_count_and_last_hash(db):
    log = ActionAuditLog(db)
    last = None
    for i in range(5):
        last = await log.record(tool=f"t{i}", action_class="passive", decision="executed")
    a = await db.fetch_one("SELECT entry_count, last_hash FROM audit_anchor WHERE id = 1")
    assert a["entry_count"] == 5
    assert a["last_hash"] == last["entry_hash"]
    assert (await log.verify_chain())["valid"] is True


@pytest.mark.asyncio
async def test_anchor_detects_tail_truncation(db):
    log = ActionAuditLog(db)
    for i in range(3):
        await log.record(tool=f"t{i}", action_class="active", decision="executed")
    assert (await log.verify_chain())["valid"] is True
    # Delete the last row. The remaining 2-row chain is still internally consistent
    # (prev/entry hashes line up), so the hash chain alone would say "valid" — but
    # the anchor knows an entry is missing.
    await db.execute("DELETE FROM actions_log WHERE id = (SELECT MAX(id) FROM actions_log)")
    v = await log.verify_chain()
    assert v["valid"] is False
    assert v["broken_at"] == "anchor"
    assert v["expected_count"] == 3 and v["actual_count"] == 2


@pytest.mark.asyncio
async def test_anchor_absent_falls_back_to_chain_only(db):
    # A fresh log with no records has no anchor row — verify_chain must not choke.
    v = await ActionAuditLog(db).verify_chain()
    assert v["valid"] is True and v["length"] == 0


# ---------------------------------------------------------------------------
# #5 — real teardown in cleanup (honest when it cannot actually run)
# ---------------------------------------------------------------------------

class _OKExec:
    def __init__(self):
        self.ran = []

    async def execute_tool(self, tool, args):
        self.ran.append(args["command"])
        return {"success": True, "output": "ok"}


class _FailExec:
    async def execute_tool(self, tool, args):
        return {"success": False, "error": "boom"}


@pytest.mark.asyncio
async def test_cleanup_no_recipe_is_bookkeeping(db):
    reg = SessionRegistry(db)
    f = await reg.create_foothold(engagement_id="e1", host="h")
    res = await reg.cleanup("e1")
    assert res["cleaned"] == 1 and res["pending"] == [] and res["failed"] == []
    assert (await reg.get(f["id"]))["status"] == "cleaned"


@pytest.mark.asyncio
async def test_cleanup_recipe_without_executor_is_pending_not_faked(db):
    reg = SessionRegistry(db)
    f = await reg.create_foothold(engagement_id="e1", host="h",
                                  teardown_recipe=["rm -f /tmp/implant"])
    res = await reg.cleanup("e1")  # recipe present but NO executor
    assert res["cleaned"] == 0 and res["pending"] == [f["id"]]
    # Honest: NOT flipped to 'cleaned' when nothing was actually torn down.
    assert (await reg.get(f["id"]))["status"] == "cleanup_pending"


@pytest.mark.asyncio
async def test_cleanup_with_executor_runs_recipe(db):
    reg = SessionRegistry(db)
    f = await reg.create_foothold(engagement_id="e1", host="h",
                                  teardown_recipe=["rm -f /tmp/a", "crontab -r"])
    ex = _OKExec()
    res = await reg.cleanup("e1", executor=ex)
    assert res["cleaned"] == 1 and res["failed"] == []
    assert ex.ran == ["rm -f /tmp/a", "crontab -r"]
    assert (await reg.get(f["id"]))["status"] == "cleaned"


@pytest.mark.asyncio
async def test_cleanup_failed_teardown_stays_visible(db):
    reg = SessionRegistry(db)
    f = await reg.create_foothold(engagement_id="e1", host="h",
                                  teardown_recipe=["rm -f /tmp/a"])
    res = await reg.cleanup("e1", executor=_FailExec())
    assert res["failed"] == [f["id"]] and res["cleaned"] == 0
    assert (await reg.get(f["id"]))["status"] == "cleanup_failed"
    # A later run WITH a working executor retries pending/failed and cleans it.
    res2 = await reg.cleanup("e1", executor=_OKExec())
    assert res2["cleaned"] == 1
    assert (await reg.get(f["id"]))["status"] == "cleaned"


# ---------------------------------------------------------------------------
# #3 — fail-closed audit for high-risk classes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_preaudit_blocks_exploit_when_audit_fails(wired):
    eng, db = wired
    gov = eng._governance()
    assert gov is not None

    async def boom(**kw):
        raise RuntimeError("db down")
    gov["audit"].record = boom

    # EXPLOIT with a broken audit must be aborted (fail-closed).
    err = await eng._preaudit_high_risk(tool="execute",
                                        arguments={"command": "msfconsole -q"},
                                        action_cls=ActionClass.EXPLOIT)
    assert err and "fail-closed" in err.lower()
    # PASSIVE never needs a pre-audit, so it proceeds even if audit is broken.
    assert await eng._preaudit_high_risk(tool="audit_tls_ssl", arguments={},
                                         action_cls=ActionClass.PASSIVE) is None


@pytest.mark.asyncio
async def test_audit_record_strict_raises_but_passive_path_swallows(wired):
    eng, db = wired
    gov = eng._governance()

    async def boom(**kw):
        raise RuntimeError("db down")
    gov["audit"].record = boom

    with pytest.raises(Exception):
        await eng._audit_record(tool="execute", arguments={}, action_cls=ActionClass.EXPLOIT,
                                decision="authorized", strict=True)
    # Best-effort path returns False instead of raising (passive recon must not die).
    ok = await eng._audit_record(tool="execute", arguments={}, action_cls=ActionClass.EXPLOIT,
                                 decision="executed", strict=False)
    assert ok is False


# ---------------------------------------------------------------------------
# #1/#2 — operator identity + the real two-person rule
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_two_person_rule_rejects_same_operator_twice(wired):
    eng, db = wired
    eng.pending_action = {
        "tool": "execute", "arguments": {"command": "msfconsole -q"},
        "action_class": ActionClass.EXPLOIT.value,
        "approvals_required": 2, "approvals_given": 0, "approvers": [],
    }
    # alice approves once → 1/2, re-pended.
    await _drain(eng.execute_approved(operator="alice"))
    assert eng.pending_action is not None
    assert eng.pending_action["approvals_given"] == 1
    assert eng.pending_action["approvers"] == ["alice"]
    # alice approves AGAIN → rejected; still 1/2 (no double-count by one person).
    events = await _drain(eng.execute_approved(operator="alice"))
    assert eng.pending_action is not None
    assert eng.pending_action["approvals_given"] == 1
    assert any("DIFERENTE" in e.get("message", "") for e in events)


@pytest.mark.asyncio
async def test_two_distinct_operators_pass_the_gate_and_audit_records_both(wired):
    eng, db = wired

    async def boom(tool, args):  # stop right after the gate, cleanly
        raise RuntimeError("stop-after-gate")
    eng.tool_executor.execute_tool = boom

    eng.pending_action = {
        "tool": "execute", "arguments": {"command": "id"},  # ACTIVE
        "action_class": ActionClass.ACTIVE.value,
        "approvals_required": 2, "approvals_given": 0, "approvers": [],
    }
    await _drain(eng.execute_approved(operator="alice"))       # 1/2
    assert eng.pending_action["approvers"] == ["alice"]
    events = await _drain(eng.execute_approved(operator="bob"))  # 2/2 → proceeds
    assert eng.pending_action is None                            # gate passed, consumed
    assert any(e.get("type") == "error" and "stop-after-gate" in e.get("error", "")
               for e in events)
    # Accountability: the audit trail names BOTH approvers, not the mode.
    rows = await ActionAuditLog(db).list(limit=5)
    assert any(r["operator"] == "alice, bob" for r in rows)


async def _drain(agen):
    return [e async for e in agen]
