"""Integration tests for MITRE ATT&CK Matrix & Defensive Efficacy REST API (/api/mitre/*)."""
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
async def test_mitre_api_full_workflow(async_client):
    """
    Test the complete MITRE ATT&CK & Defensive Efficacy workflow:
    1. GET /api/mitre/matrix — Initial matrix state
    2. POST /api/mitre/simulate — Execute BAS campaign
    3. GET /api/mitre/efficacy — Picus Efficacy metrics
    4. GET /api/mitre/techniques/T1190 — View technique details
    5. GET /api/mitre/remediation/T1059.001 — View Sigma detection rule
    6. PATCH /api/mitre/techniques/T1003.001 — Update defensive state
    """
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}

    # 1. GET /api/mitre/matrix
    matrix_resp = await client.get("/api/mitre/matrix", headers=headers)
    assert matrix_resp.status_code == 200, matrix_resp.text
    matrix_data = matrix_resp.json()
    assert "matrix" in matrix_data
    assert "tactics_summary" in matrix_data
    assert matrix_data["total_techniques"] >= 15

    # 2. POST /api/mitre/simulate
    sim_resp = await client.post(
        "/api/mitre/simulate",
        json={
            "target_environment": "Global Financial SOC",
            "scenario": "full_adversary",
        },
        headers=headers,
    )
    assert sim_resp.status_code == 200, sim_resp.text
    sim_data = sim_resp.json()
    assert sim_data["campaign_id"].startswith("bas-")
    assert sim_data["target_environment"] == "Global Financial SOC"
    assert sim_data["overall_efficacy_score"] > 0
    assert sim_data["prevention_rate"] > 0
    assert sim_data["detection_rate"] > 0
    assert len(sim_data["critical_gaps"]) > 0

    # 3. GET /api/mitre/efficacy
    eff_resp = await client.get("/api/mitre/efficacy", headers=headers)
    assert eff_resp.status_code == 200
    eff_data = eff_resp.json()
    assert eff_data["tested_techniques"] >= 15
    assert eff_data["blocked_count"] > 0
    assert eff_data["missed_count"] > 0

    # 4. GET /api/mitre/techniques/T1190
    tech_resp = await client.get("/api/mitre/techniques/T1190", headers=headers)
    assert tech_resp.status_code == 200
    tech_data = tech_resp.json()
    assert tech_data["technique_id"] == "T1190"
    assert tech_data["name"] == "Exploit Public-Facing Application"
    assert tech_data["status"] == "blocked"

    # 5. GET /api/mitre/remediation/T1059.001
    rem_resp = await client.get("/api/mitre/remediation/T1059.001", headers=headers)
    assert rem_resp.status_code == 200
    rem_data = rem_resp.json()
    assert "Script Block Logging" in rem_data["remediation_guidance"]
    assert "sigma_rule_yaml" in rem_data
    assert "powershell" in rem_data["sigma_rule_yaml"].lower()

    # 6. PATCH /api/mitre/techniques/T1003.001
    patch_resp = await client.patch(
        "/api/mitre/techniques/T1003.001",
        json={
            "status": "blocked",
            "prevention_control": "Windows Defender Credential Guard Enabled",
            "execution_log": "Acesso a LSASS bloqueado por isolamento de virtualização LSA.",
        },
        headers=headers,
    )
    assert patch_resp.status_code == 200
    patch_data = patch_resp.json()
    assert patch_data["status"] == "blocked"
    assert "Credential Guard" in patch_data["prevention_control"]

    # 7. Test 404 for unknown technique
    unknown_resp = await client.get("/api/mitre/techniques/T9999", headers=headers)
    assert unknown_resp.status_code == 404
