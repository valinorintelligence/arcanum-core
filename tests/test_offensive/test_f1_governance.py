"""F1 is governed by F0: exploit_webapp = EXPLOIT (ROE + dual approval),
map_service_to_exploits = ACTIVE. These lock in that the offensive tools cannot
bypass the safety rails."""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.agent.tools import ToolExecutor
from arcanum.agent.engine import AgentEngine
from arcanum.redteam.engagement import EngagementManager
from arcanum.redteam.audit import ActionAuditLog
from arcanum.redteam.action_classes import classify, hitl_tier, ActionClass


def test_f1_action_classes_and_tiers():
    assert classify("exploit_webapp", {"target": "t"}) == ActionClass.EXPLOIT
    assert hitl_tier(ActionClass.EXPLOIT) == "double"       # dual approval
    assert classify("map_service_to_exploits", {"target": "t"}) == ActionClass.ACTIVE
    assert classify("capture_proof", {}) == ActionClass.PASSIVE


@pytest_asyncio.fixture
async def wired(tmp_path):
    db = Database(db_path=tmp_path / "f1.db")
    await db.connect()
    await db.init_db()
    await db.execute("INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
                     ("op-f1", "f1", "target.lab"))
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path, db=db, session_id="op-f1")
    eng = AgentEngine.__new__(AgentEngine)
    eng.tool_executor = te
    eng.session = {"id": "op-f1", "name": "f1", "target": "target.lab"}
    eng.mode = "copilot"
    eng._gov_cache = "unset"
    eng._active_engagement = None
    eng._engagement_loaded = False
    try:
        yield eng, db
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_exploit_webapp_blocked_by_roe_without_exploit_class(wired):
    eng, db = wired
    await EngagementManager(db).create(name="F1 Op", session_id="op-f1",
                                       allowed_classes=[ActionClass.PASSIVE, ActionClass.ACTIVE])
    reason = await eng._roe_authorize("exploit_webapp", {"target": "target.lab"})
    assert reason is not None and "class" in reason.lower()
    rows = await ActionAuditLog(db).list(limit=5)
    assert any(r["decision"] == "blocked_by_roe" and r["action_class"] == "exploit" for r in rows)


@pytest.mark.asyncio
async def test_exploit_webapp_allowed_when_roe_permits(wired):
    eng, db = wired
    await EngagementManager(db).create(name="F1 Op", session_id="op-f1",
                                       allowed_classes=[ActionClass.ACTIVE, ActionClass.EXPLOIT])
    assert await eng._roe_authorize("exploit_webapp", {"target": "target.lab"}) is None
    assert await eng._roe_authorize("map_service_to_exploits", {"target": "target.lab"}) is None
