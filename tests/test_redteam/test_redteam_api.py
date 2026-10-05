"""F0 — Red Team governance API (engagements, actions log, sessions, kill-switch)."""

import pytest
import pytest_asyncio
import httpx

from arcanum.api.main import create_app
from arcanum.core.config import get_config
from arcanum.redteam.sessions import SessionRegistry


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCANUM_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ARCANUM_API_TOKEN", "test-secret-token")
    get_config.cache_clear()
    app = create_app()
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            c.app = app
            yield c


HEADERS = {"Authorization": "Bearer test-secret-token"}


@pytest.mark.asyncio
async def test_engagement_lifecycle_and_actions(client):
    # Create an engagement limited to passive+active.
    resp = await client.post("/api/redteam/engagements", headers=HEADERS, json={
        "name": "API Op",
        "scope": ["example.com"],
        "allowed_classes": ["passive", "active"],
        "session_id": "op-api",
    })
    assert resp.status_code == 200
    eng = resp.json()["engagement"]
    assert eng["roe_hash"] and set(eng["allowed_classes"]) == {"passive", "active"}

    # It shows up in the list and as the active engagement for its session.
    lst = await client.get("/api/redteam/engagements", headers=HEADERS)
    assert any(e["id"] == eng["id"] for e in lst.json()["engagements"])
    act = await client.get("/api/redteam/engagements/active?session_id=op-api", headers=HEADERS)
    assert act.json()["engagement"]["id"] == eng["id"]

    # Actions log starts empty but the chain still verifies.
    verify = await client.get("/api/redteam/actions/verify", headers=HEADERS)
    assert verify.json()["valid"] is True

    # Invalid action class is rejected.
    bad = await client.post("/api/redteam/engagements", headers=HEADERS,
                            json={"name": "x", "allowed_classes": ["nope"]})
    assert bad.status_code == 400


@pytest.mark.asyncio
async def test_killswitch_cleans_sessions(client):
    # Seed an open foothold directly via the registry (no offensive tool needed).
    reg = SessionRegistry(client.app.state.db)
    await reg.create_foothold(engagement_id="eng-x", session_id="op-api", host="10.0.0.9")
    assert len(await reg.list(status="open")) == 1

    resp = await client.post("/api/redteam/killswitch", headers=HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "killed"
    assert body["sessions_cleaned"] == 1
    assert await reg.list(status="open") == []

    # The kill-switch itself is recorded and the chain remains valid.
    actions = await client.get("/api/redteam/actions", headers=HEADERS)
    assert any(a["decision"] == "kill_switch_global" for a in actions.json()["actions"])
    assert (await client.get("/api/redteam/actions/verify", headers=HEADERS)).json()["valid"] is True


@pytest.mark.asyncio
async def test_requires_auth(client):
    assert (await client.get("/api/redteam/engagements")).status_code in (401, 403)
