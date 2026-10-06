"""Full-scope LAB ROE preset + engine pre-authorization.

The preset pre-authorizes classes for an operator's OWN lab so there is no per-action
human pause (``auto_approve``), WITHOUT removing any rail: scope is required, audit /
deconfliction / cleanup stay, and DESTRUCTIVE still needs allow_destructive_testing.
"""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.agent.tools import ToolExecutor
from arcanum.agent.engine import AgentEngine
from arcanum.redteam.engagement import EngagementManager
from arcanum.redteam.action_classes import ActionClass


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "lab.db")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


# ---------------------------------------------------------------------------
# Preset creation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lab_preset_requires_scope(db):
    with pytest.raises(ValueError):
        await EngagementManager(db).create_lab_preset(name="x", scope=[])


@pytest.mark.asyncio
async def test_lab_preset_grants_all_nondestructive_and_auto_approve(db):
    eng = await EngagementManager(db).create_lab_preset(name="lab", scope=["10.0.0.0/24"])
    assert eng["auto_approve"] is True
    assert set(eng["allowed_classes"]) == {"passive", "active", "exploit", "post_exploit"}
    assert "destructive" not in eng["allowed_classes"]
    assert eng["scope"] == ["10.0.0.0/24"]


@pytest.mark.asyncio
async def test_lab_preset_can_include_destructive(db):
    eng = await EngagementManager(db).create_lab_preset(
        name="lab", scope=["10.0.0.0/24"], include_destructive=True)
    assert "destructive" in eng["allowed_classes"]


@pytest.mark.asyncio
async def test_auto_approve_is_covered_by_roe_hash(db):
    """auto_approve is part of the contract, so flipping it changes the tamper hash."""
    mgr = EngagementManager(db)
    a = await mgr.create(name="n", scope=["h"], allowed_classes=[ActionClass.ACTIVE], auto_approve=False)
    b = await mgr.create(name="n", scope=["h"], allowed_classes=[ActionClass.ACTIVE], auto_approve=True)
    assert a["roe_hash"] != b["roe_hash"]


# ---------------------------------------------------------------------------
# Engine pre-authorization (the per-action pause is waived — rails stay)
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def wired(tmp_path):
    db = Database(db_path=tmp_path / "labeng.db")
    await db.connect()
    await db.init_db()
    await db.execute("INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
                     ("op-lab", "lab", "10.0.0.5"))
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path, db=db, session_id="op-lab")
    eng = AgentEngine.__new__(AgentEngine)
    eng.tool_executor = te
    eng.session = {"id": "op-lab", "name": "lab", "target": "10.0.0.5"}
    eng.mode = "copilot"
    eng._gov_cache = "unset"
    eng._active_engagement = None
    eng._engagement_loaded = False
    try:
        yield eng, db
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_no_preauthorization_without_auto_approve(wired):
    eng, db = wired
    await EngagementManager(db).create(name="x", session_id="op-lab",
                                       allowed_classes=[ActionClass.EXPLOIT])  # auto_approve=False
    assert await eng._preauthorized(ActionClass.EXPLOIT) is False


@pytest.mark.asyncio
async def test_lab_preset_preauthorizes_offensive_classes(wired):
    eng, db = wired
    await EngagementManager(db).create_lab_preset(name="lab", scope=["10.0.0.5"], session_id="op-lab")
    assert await eng._preauthorized(ActionClass.EXPLOIT) is True
    assert await eng._preauthorized(ActionClass.POST_EXPLOIT) is True
    # A class the preset does NOT grant is never pre-authorized.
    assert await eng._preauthorized(ActionClass.DESTRUCTIVE) is False


@pytest.mark.asyncio
async def test_destructive_preauth_gated_by_config(wired, monkeypatch):
    eng, db = wired
    await EngagementManager(db).create_lab_preset(
        name="lab", scope=["10.0.0.5"], session_id="op-lab", include_destructive=True)

    class _Cfg:
        allow_destructive_testing = False
    monkeypatch.setattr("arcanum.core.config.get_config", lambda: _Cfg())
    assert await eng._preauthorized(ActionClass.DESTRUCTIVE) is False

    class _Cfg2:
        allow_destructive_testing = True
    monkeypatch.setattr("arcanum.core.config.get_config", lambda: _Cfg2())
    assert await eng._preauthorized(ActionClass.DESTRUCTIVE) is True
