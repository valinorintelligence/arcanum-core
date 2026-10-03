"""Integration tests for Continuous Threat Exposure Management (CTEM) and CISA KEV API routes."""

import json
import pytest
import pytest_asyncio
import httpx

from arcanum.api.main import create_app
from arcanum.core.config import get_config


@pytest_asyncio.fixture
async def async_client(tmp_path, monkeypatch):
    """Provides an AsyncClient with an isolated database and test token."""
    monkeypatch.setenv("ARCANUM_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ARCANUM_API_TOKEN", "test-secret-token")
    get_config.cache_clear()

    app = create_app()

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            client.app = app
            yield client


@pytest.mark.asyncio
async def test_cisa_kev_api_endpoints(async_client):
    """Test CISA KEV stats, sync and check HTTP endpoints."""
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}

    # 1. Sync CISA KEV
    sync_resp = await client.post("/api/ctem/kev/sync", headers=headers)
    assert sync_resp.status_code == 200
    sync_data = sync_resp.json()["sync"]
    assert sync_data["success"] is True
    assert sync_data["total_synced"] >= 6

    # 2. Get KEV statistics
    stats_resp = await client.get("/api/ctem/kev/stats", headers=headers)
    assert stats_resp.status_code == 200
    stats = stats_resp.json()["kev_stats"]
    assert stats["total_cves"] >= 6
    assert stats["engine_status"] in ("active", "fallback_cache")

    # 3. Check known KEV CVE (Log4Shell)
    check_resp = await client.get("/api/ctem/kev/check/CVE-2021-44228", headers=headers)
    assert check_resp.status_code == 200
    cve_data = check_resp.json()
    assert cve_data["is_cisa_kev"] is True
    assert cve_data["details"]["due_date"] == "2021-12-24"

    # 4. Check non-KEV CVE
    check_none = await client.get("/api/ctem/kev/check/CVE-1999-0001", headers=headers)
    assert check_none.status_code == 200
    assert check_none.json()["is_cisa_kev"] is False


@pytest.mark.asyncio
async def test_ctem_schedules_api_lifecycle(async_client):
    """Test CTEM schedule creation, pause, resume, run-now and deletion endpoints."""
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}
    db = client.app.state.db

    # Create session and finding in DB
    session_id = "sess-ctem-api-01"
    await db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        (session_id, "ctem-portal", "https://portal.corp.local"),
    )
    await db.execute(
        """INSERT INTO findings (id, session_id, title, severity, status, cve_id, retest_tool, retest_arguments)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "f-ctem-01",
            session_id,
            "Apache Log4Shell Remote Code Execution",
            "critical",
            "confirmed",
            "CVE-2021-44228",
            "audit_security_headers",
            json.dumps({"url": "https://portal.corp.local"}),
        ),
    )

    # 1. Create schedule
    create_resp = await client.post(
        "/api/ctem/schedules",
        headers=headers,
        json={
            "session_id": "ctem-portal",
            "target": "https://portal.corp.local",
            "frequency_minutes": 180,
        },
    )
    assert create_resp.status_code == 200
    sched = create_resp.json()["schedule"]
    sched_id = sched["schedule_id"]
    assert sched_id.startswith("ctem-")
    assert sched["frequency_minutes"] == 180
    assert sched["status"] == "active"

    # 2. List schedules
    list_resp = await client.get("/api/ctem/schedules", headers=headers)
    assert list_resp.status_code == 200
    schedules = list_resp.json()["schedules"]
    assert any(s["id"] == sched_id for s in schedules)

    # 3. Get schedule details
    get_resp = await client.get(f"/api/ctem/schedules/{sched_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["schedule"]["id"] == sched_id

    # 4. Pause schedule
    pause_resp = await client.post(f"/api/ctem/schedules/{sched_id}/pause", headers=headers)
    assert pause_resp.status_code == 200
    assert pause_resp.json()["status"] == "paused"

    # 5. Resume schedule
    resume_resp = await client.post(f"/api/ctem/schedules/{sched_id}/resume", headers=headers)
    assert resume_resp.status_code == 200
    assert resume_resp.json()["status"] == "active"

    # 6. Run assessment cycle immediately (run-now)
    run_resp = await client.post(f"/api/ctem/schedules/{sched_id}/run-now", headers=headers)
    assert run_resp.status_code == 200
    cycle_res = run_resp.json()["result"]
    assert cycle_res["schedule_id"] == sched_id
    assert cycle_res["total_runs"] == 1
    assert cycle_res["retested_count"] == 1
    assert cycle_res["kev_alert_count"] == 1

    # 7. Delete schedule
    del_resp = await client.delete(f"/api/ctem/schedules/{sched_id}", headers=headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True

    # 8. Verify deletion
    get_after = await client.get(f"/api/ctem/schedules/{sched_id}", headers=headers)
    assert get_after.status_code == 404
