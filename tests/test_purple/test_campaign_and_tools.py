"""F3 — Purple campaign, agent tools, governance classes, and read API."""

import pytest
import pytest_asyncio
import httpx

from arcanum.core.database import Database
from arcanum.agent.tools import ToolExecutor
from arcanum.api.main import create_app
from arcanum.purple.campaign import PurpleCampaign
from arcanum.redteam.action_classes import classify, hitl_tier, ActionClass


@pytest_asyncio.fixture
async def te(tmp_path):
    db = Database(db_path=tmp_path / "purple.db")
    await db.connect()
    await db.init_db()
    ex = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path, db=db, session_id="op-p")
    try:
        yield ex, db
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_campaign_measures_coverage_and_closes_gaps(te):
    _, db = te
    camp = PurpleCampaign(db, config=None, sandbox=None)
    out = await camp.run(["T1190", "T1059.001", "T1110.003"], auto_tune=True)
    # auto-tune deploys covering rules => full INCLUSIVE coverage, but without
    # real controls (mock deploys) REAL coverage is 0 and it is flagged simulated.
    assert out["coverage"]["coverage_percent"] == 100.0
    assert out["coverage"]["coverage_percent_real"] == 0.0
    assert out["gap_report"]["remaining_gaps"] == []
    assert set(out["gap_report"]["simulated_coverage_gaps"]) == {"T1190", "T1059.001", "T1110.003"}
    assert all(r["tuned"] and r["detected_after"] and r["detection_simulated"] for r in out["results"])


@pytest.mark.asyncio
async def test_campaign_without_autotune_reports_gaps(te):
    _, db = te
    camp = PurpleCampaign(db, config=None, sandbox=None)
    out = await camp.run(["T1071.001", "T1048.003"], auto_tune=False)
    assert out["coverage"]["coverage_percent"] == 0.0
    assert set(out["gap_report"]["remaining_gaps"]) == {"T1071.001", "T1048.003"}


@pytest.mark.asyncio
async def test_bas_and_coverage_tools(te):
    ex, _ = te
    run = await ex.execute_tool("run_bas_test", {"technique_id": "T1190", "campaign_id": "tc1"})
    # Mock deploy (no creds) => simulated coverage, honestly labeled.
    assert run["success"] is True and run["output"]["status"] == "tuned_simulated"

    # verify_detection tool (read-only) reports a simulated hit
    v = await ex.execute_tool("verify_detection", {"technique_id": "T1190"})
    assert v["output"]["detected"] is True and v["output"]["simulated"] is True

    cov = await ex.execute_tool("measure_coverage", {"campaign_id": "tc1"})
    assert cov["output"]["coverage_percent"] == 100.0
    assert cov["output"]["coverage_percent_real"] == 0.0
    assert cov["output"]["measured_efficacy"]["source"] == "measured"
    assert cov["output"]["measured_efficacy"]["detection_rate_real"] == 0.0


@pytest.mark.asyncio
async def test_run_bas_requires_technique(te):
    ex, _ = te
    out = await ex.execute_tool("run_bas_test", {})
    assert out["success"] is True and "error" in out["output"]


def test_purple_tool_action_classes():
    # Adversary emulation is EXPLOIT (ROE + dual approval); measurement is PASSIVE.
    assert classify("run_bas_test", {}) == ActionClass.EXPLOIT
    assert classify("run_purple_campaign", {}) == ActionClass.EXPLOIT
    assert hitl_tier(ActionClass.EXPLOIT) == "double"
    assert classify("verify_detection", {}) == ActionClass.PASSIVE
    assert classify("measure_coverage", {}) == ActionClass.PASSIVE


@pytest_asyncio.fixture
async def client_and_exec(tmp_path):
    db = Database(db_path=tmp_path / "purple.db")
    await db.connect()
    await db.init_db()
    app = create_app()
    app.state.db = db
    app.state.api_token = "test-token"
    app.state.active_engines = {}
    ex = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path, db=db, session_id="op-api")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        try:
            yield c, ex
        finally:
            await db.close()


@pytest.mark.asyncio
async def test_purple_read_api(client_and_exec):
    c, ex = client_and_exec
    await ex.execute_tool("run_purple_campaign", {"techniques": ["T1190", "T1071.001"],
                                                  "auto_tune": True, "campaign_id": "api-camp"})
    H = {"Authorization": "Bearer test-token"}
    res = await c.get("/api/purple/results?campaign_id=api-camp", headers=H)
    assert res.status_code == 200 and len(res.json()["results"]) >= 2

    cov = await c.get("/api/purple/coverage/api-camp", headers=H)
    assert cov.status_code == 200
    body = cov.json()
    assert body["coverage_percent"] == 100.0
    assert body["measured_efficacy"]["source"] == "measured"

    assert (await c.get("/api/purple/results")).status_code in (401, 403)
