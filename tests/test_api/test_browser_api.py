"""Integration tests for Headless Web Browser Agent API routes (/api/browser/*)."""
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
async def test_browser_api_full_workflow(async_client):
    """
    Testa o fluxo completo da API de auditoria de navegador:
    1. POST /api/browser/simulate — Inicia auditoria simulada rápida
    2. GET /api/browser/sessions — Lista sessões ativas
    3. GET /api/browser/sessions/{id} — Detalhes da sessão
    4. GET /api/browser/sessions/{id}/findings — Lista achados
    """
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}

    # 1. POST /api/browser/simulate
    sim_resp = await client.post(
        "/api/browser/simulate",
        json={
            "target_url": "https://loja.corp.local/carrinho",
            "workflow_description": "fluxo de checkout e carrinho de compras e-commerce",
        },
        headers=headers,
    )
    assert sim_resp.status_code == 200, sim_resp.text
    session_data = sim_resp.json()
    session_id = session_data["id"]
    assert session_data["status"] == "completed"
    assert session_data["total_findings"] > 0
    assert len(session_data["findings"]) > 0

    # 2. GET /api/browser/sessions
    list_resp = await client.get("/api/browser/sessions", headers=headers)
    assert list_resp.status_code == 200
    assert isinstance(list_resp.json(), list)

    # 4. POST /api/browser/audit
    audit_resp = await client.post(
        "/api/browser/audit",
        json={
            "target_url": "https://portal.corp.local/login",
            "workflow_description": "login e autenticacao de usuarios",
            "max_depth": 2,
        },
        headers=headers,
    )
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()
    audit_id = audit_data["id"]
    assert audit_data["status"] in ("completed", "running")

    # 5. GET /api/browser/sessions/{audit_id}
    detail_resp = await client.get(f"/api/browser/sessions/{audit_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == audit_id

    # 6. GET /api/browser/sessions/{audit_id}/findings
    findings_resp = await client.get(f"/api/browser/sessions/{audit_id}/findings", headers=headers)
    assert findings_resp.status_code == 200
    assert isinstance(findings_resp.json(), list)

    # 7. GET /api/browser/profiles (Perfis de evasão Stealth)
    profiles_resp = await client.get("/api/browser/profiles", headers=headers)
    assert profiles_resp.status_code == 200
    profiles = profiles_resp.json()
    assert len(profiles) >= 3
    profile_ids = [p["id"] for p in profiles]
    assert "windows_desktop" in profile_ids
    assert "mac_laptop" in profile_ids
    assert "iphone_mobile" in profile_ids

