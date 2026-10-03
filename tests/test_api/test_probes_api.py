"""Integration tests for Distributed Satellite Probes API routes."""

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
async def test_satellite_probes_api_full_lifecycle(async_client):
    """Test probe registration, heartbeat, task dispatch, polling and submission via HTTP."""
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}

    # 1. Register Probe
    reg_resp = await client.post(
        "/api/probes/register",
        headers=headers,
        json={
            "name": "worker-dmz-01",
            "hostname": "srv-dmz.corp.local",
            "ip_address": "192.168.50.10",
            "tags": ["dmz", "datacenter-sp"],
            "capabilities": ["execute", "audit_security_headers"],
        },
    )
    assert reg_resp.status_code == 200
    probe = reg_resp.json()["probe"]
    pid = probe["probe_id"]
    assert pid.startswith("probe-")
    assert probe["status"] == "online"

    # 2. Send Heartbeat
    hb_resp = await client.post(
        "/api/probes/heartbeat",
        headers=headers,
        json={"probe_id": pid, "status": "online"},
    )
    assert hb_resp.status_code == 200
    assert hb_resp.json()["success"] is True

    # 3. List Probes
    list_resp = await client.get("/api/probes/", headers=headers)
    assert list_resp.status_code == 200
    probes = list_resp.json()["probes"]
    assert any(p["id"] == pid for p in probes)

    # Filter by tag
    filtered_resp = await client.get("/api/probes/?tag=dmz", headers=headers)
    assert filtered_resp.status_code == 200
    assert len(filtered_resp.json()["probes"]) == 1

    # 4. Get Probe Details
    get_resp = await client.get(f"/api/probes/{pid}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["probe"]["hostname"] == "srv-dmz.corp.local"

    # 5. Dispatch task to Probe
    dispatch_resp = await client.post(
        f"/api/probes/{pid}/dispatch",
        headers=headers,
        json={
            "tool_name": "execute",
            "arguments": {"command": "curl -sI https://internal.corp"},
            "session_id": "sess-dmz",
        },
    )
    assert dispatch_resp.status_code == 200
    task_id = dispatch_resp.json()["task"]["task_id"]
    assert task_id.startswith("ptask-")

    # 6. Poll tasks for Probe
    poll_resp = await client.get(f"/api/probes/{pid}/tasks", headers=headers)
    assert poll_resp.status_code == 200
    tasks = poll_resp.json()["tasks"]
    assert len(tasks) == 1
    assert tasks[0]["id"] == task_id
    assert tasks[0]["status"] == "assigned"

    # 7. Submit task result
    result_payload = {"stdout": "HTTP/1.1 200 OK\r\nServer: nginx\r\n", "exit_code": 0}
    submit_resp = await client.post(
        f"/api/probes/{pid}/tasks/{task_id}/result",
        headers=headers,
        json={"result": result_payload},
    )
    assert submit_resp.status_code == 200
    assert submit_resp.json()["status"] == "completed"

    # 8. Check Task status
    status_resp = await client.get(f"/api/probes/tasks/{task_id}", headers=headers)
    assert status_resp.status_code == 200
    t_data = status_resp.json()["task"]
    assert t_data["status"] == "completed"
    assert t_data["result"]["exit_code"] == 0

    # 9. Deregister Probe
    del_resp = await client.delete(f"/api/probes/{pid}", headers=headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True

    # 10. Verify Deletion
    get_after = await client.get(f"/api/probes/{pid}", headers=headers)
    assert get_after.status_code == 404
