"""F2 — Blue Team API: deploy (via tool) → list → verify → rollback (via API)."""

import pytest
import pytest_asyncio
import httpx

from arcanum.core.database import Database
from arcanum.api.main import create_app
from arcanum.agent.tools import ToolExecutor


@pytest_asyncio.fixture
async def client_and_exec(tmp_path):
    db = Database(db_path=tmp_path / "blue.db")
    await db.connect()
    await db.init_db()
    app = create_app()
    app.state.db = db                       # blue routes only need the DB
    app.state.api_token = "test-token"
    app.state.active_engines = {}
    ex = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path, db=db, session_id="op-api")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        try:
            yield c, ex
        finally:
            await db.close()


HEADERS = {"Authorization": "Bearer test-token"}


@pytest.mark.asyncio
async def test_deploy_list_verify_rollback_via_api(client_and_exec):
    c, ex = client_and_exec

    # Deploy a Sigma rule to the (mock) SIEM through the agent tool.
    dep = (await ex.execute_tool("deploy_detection_rule", {
        "rule": "title: Test\ndetection:\n  condition: selection",
        "rule_type": "sigma", "target_system": "siem", "name": "api-sigma"}))["output"]
    did = dep["id"]

    # List via API.
    lst = await c.get("/api/blue/deployments", headers=HEADERS)
    assert lst.status_code == 200
    assert any(d["id"] == did for d in lst.json()["deployments"])

    # Verify active via API.
    v = await c.post(f"/api/blue/deployments/{did}/verify", headers=HEADERS)
    assert v.status_code == 200 and v.json()["active"] is True

    # Rollback via API, then confirm it is no longer active.
    rb = await c.delete(f"/api/blue/deployments/{did}", headers=HEADERS)
    assert rb.status_code == 200 and rb.json()["success"] is True
    v2 = await c.post(f"/api/blue/deployments/{did}/verify", headers=HEADERS)
    assert v2.json()["active"] is False


@pytest.mark.asyncio
async def test_api_requires_auth(client_and_exec):
    c, _ = client_and_exec
    assert (await c.get("/api/blue/deployments")).status_code in (401, 403)


@pytest.mark.asyncio
async def test_rollback_missing_deployment(client_and_exec):
    c, _ = client_and_exec
    assert (await c.delete("/api/blue/deployments/dep-missing", headers=HEADERS)).status_code == 404
