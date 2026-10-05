"""F4/F5 are governed by F0: correct action classes, dual-approval tiers, and ROE
blocking. These lock in that post-exploitation / impact cannot bypass the rails."""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.agent.tools import ToolExecutor
from arcanum.agent.engine import AgentEngine
from arcanum.redteam.engagement import EngagementManager
from arcanum.redteam.audit import ActionAuditLog
from arcanum.redteam.action_classes import classify, hitl_tier, ActionClass


def test_f4_f5_action_classes():
    assert classify("run_on_target") == ActionClass.POST_EXPLOIT
    assert classify("dump_credentials") == ActionClass.POST_EXPLOIT
    assert classify("establish_c2") == ActionClass.POST_EXPLOIT
    assert classify("lateral_move") == ActionClass.EXPLOIT
    assert classify("setup_pivot") == ActionClass.EXPLOIT
    assert classify("crack_hashes") == ActionClass.ACTIVE
    assert classify("collect_sample") == ActionClass.POST_EXPLOIT
    assert classify("demo_exfiltration") == ActionClass.DESTRUCTIVE
    assert classify("impact_poc") == ActionClass.DESTRUCTIVE
    # Post-exploitation, exploitation and destructive all require dual approval.
    for cls in (ActionClass.POST_EXPLOIT, ActionClass.EXPLOIT, ActionClass.DESTRUCTIVE):
        assert hitl_tier(cls) == "double"


@pytest_asyncio.fixture
async def wired(tmp_path):
    db = Database(db_path=tmp_path / "f45.db")
    await db.connect()
    await db.init_db()
    await db.execute("INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
                     ("op-f45", "f45", "target.lab"))
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path, db=db, session_id="op-f45")
    eng = AgentEngine.__new__(AgentEngine)
    eng.tool_executor = te
    eng.session = {"id": "op-f45", "name": "f45", "target": "target.lab"}
    eng.mode = "copilot"
    eng._gov_cache = "unset"
    eng._active_engagement = None
    eng._engagement_loaded = False
    try:
        yield eng, db
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_post_exploit_blocked_when_roe_only_allows_active(wired):
    eng, db = wired
    await EngagementManager(db).create(name="F4 Op", session_id="op-f45",
                                       allowed_classes=[ActionClass.PASSIVE, ActionClass.ACTIVE])
    # dump_credentials is POST_EXPLOIT => blocked when ROE doesn't allow it.
    reason = await eng._roe_authorize("dump_credentials", {"foothold_id": "fh-1"})
    assert reason is not None
    # demo_exfiltration is DESTRUCTIVE => also blocked.
    reason2 = await eng._roe_authorize("demo_exfiltration", {"foothold_id": "fh-1"})
    assert reason2 is not None
    rows = await ActionAuditLog(db).list(limit=10)
    assert any(r["decision"] == "blocked_by_roe" for r in rows)


@pytest.mark.asyncio
async def test_post_exploit_allowed_when_roe_permits(wired):
    eng, db = wired
    await EngagementManager(db).create(
        name="F4 Op", session_id="op-f45",
        allowed_classes=[ActionClass.ACTIVE, ActionClass.EXPLOIT,
                         ActionClass.POST_EXPLOIT, ActionClass.DESTRUCTIVE])
    assert await eng._roe_authorize("dump_credentials", {"foothold_id": "fh-1"}) is None
    assert await eng._roe_authorize("lateral_move", {"target_host": "10.0.0.9"}) is None
    assert await eng._roe_authorize("impact_poc", {"foothold_id": "fh-1"}) is None
