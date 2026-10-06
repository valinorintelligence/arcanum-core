"""Integration tests for Active Directory & Identity Graph API routes."""

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
async def test_identity_api_full_workflow(async_client):
    """Test ingestion, attack path discovery, choke points, roasting and attack simulation via REST."""
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}

    # 1. Ingest AD dataset
    ingest_payload = {
        "domain_name": "megacorp.internal",
        "forest_name": "megacorp.internal",
        "objects": [
            {"sid": "S-1-5-21-500", "name": "Administrator", "object_type": "user", "is_tier_zero": True, "is_admin": True},
            {"sid": "S-1-5-21-512", "name": "Domain Admins", "object_type": "group", "is_tier_zero": True, "is_admin": True},
            {"sid": "S-1-5-21-1001", "name": "carlos.estagiario", "object_type": "user", "is_tier_zero": False},
            {"sid": "S-1-5-21-1002", "name": "Suporte TI", "object_type": "group", "is_tier_zero": False},
            {"sid": "S-1-5-21-1003", "name": "SRV-FILE-01", "object_type": "computer", "is_tier_zero": False},
            {"sid": "S-1-5-21-1004", "name": "svc-backup-sql", "object_type": "user", "has_spn": True, "metadata": {"spn": "MSSQLSvc/db.corp:1433"}},
            {"sid": "S-1-5-21-1005", "name": "legado.terminal", "object_type": "user", "dont_req_preauth": True},
        ],
        "edges": [
            {"source": "S-1-5-21-1001", "target": "S-1-5-21-1002", "rel": "ForceChangePassword"},
            {"source": "S-1-5-21-1002", "target": "S-1-5-21-1003", "rel": "AdminTo"},
            {"source": "S-1-5-21-1003", "target": "S-1-5-21-512", "rel": "GenericAll"},
            {"source": "S-1-5-21-500", "target": "S-1-5-21-512", "rel": "MemberOf"},
        ],
    }

    resp = await client.post("/api/identity/ingest", headers=headers, json=ingest_payload)
    assert resp.status_code == 200
    data = resp.json()["data"]
    domain_id = data["domain_id"]
    assert domain_id == "dom-megacorp-internal"
    assert data["total_objects"] == 7
    assert data["total_edges"] == 4

    # 2. List Domains
    doms_resp = await client.get("/api/identity/domains", headers=headers)
    assert doms_resp.status_code == 200
    domains = doms_resp.json()["domains"]
    assert any(d["id"] == domain_id for d in domains)

    # 3. Domain Summary
    sum_resp = await client.get(f"/api/identity/{domain_id}/summary", headers=headers)
    assert sum_resp.status_code == 200
    summary = sum_resp.json()
    assert summary["total_objects"] == 7
    assert summary["total_tier_zero"] >= 2
    assert summary["kerberoastable_count"] == 1
    assert summary["asrep_roastable_count"] == 1
    assert summary["top_choke_point"] is not None

    # 4. Attack Paths
    paths_resp = await client.get(f"/api/identity/{domain_id}/attack-paths", headers=headers)
    assert paths_resp.status_code == 200
    paths_data = paths_resp.json()
    assert paths_data["total_paths"] >= 2
    assert any(p["start_name"] == "carlos.estagiario" for p in paths_data["paths"])
    assert any(p["start_name"] == "SRV-FILE-01" for p in paths_data["paths"])

    # Test filtering attack path starting specifically from carlos
    carlos_resp = await client.get(f"/api/identity/{domain_id}/attack-paths?start_sid=S-1-5-21-1001", headers=headers)
    assert carlos_resp.status_code == 200
    carlos_paths = carlos_resp.json()["paths"]
    assert len(carlos_paths) >= 1
    assert carlos_paths[0]["start_name"] == "carlos.estagiario"
    assert carlos_paths[0]["target_name"] == "Domain Admins"
    assert carlos_paths[0]["length"] == 3

    # 5. Choke Points
    chokes_resp = await client.get(f"/api/identity/{domain_id}/choke-points", headers=headers)
    assert chokes_resp.status_code == 200
    chokes = chokes_resp.json()["choke_points"]
    assert len(chokes) >= 1
    assert chokes[0]["name"] in ("Suporte TI", "SRV-FILE-01")

    # 6. Roasting Exposures
    roast_resp = await client.get(f"/api/identity/{domain_id}/roasting", headers=headers)
    assert roast_resp.status_code == 200
    roast_data = roast_resp.json()
    assert len(roast_data["kerberoastable_users"]) == 1
    assert roast_data["kerberoastable_users"][0]["name"] == "svc-backup-sql"
    assert len(roast_data["asrep_roastable_users"]) == 1
    assert roast_data["asrep_roastable_users"][0]["name"] == "legado.terminal"

    # 7. Simulate Attack
    sim_resp = await client.post(
        f"/api/identity/{domain_id}/simulate-attack",
        headers=headers,
        json={"start_identity": "carlos.estagiario"},
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["success"] is True
    assert sim_data["target_reached"] is True
    assert sim_data["hops_count"] == 3
    assert "Cadeia de Invasão" in sim_data["narrative_ptbr"]
