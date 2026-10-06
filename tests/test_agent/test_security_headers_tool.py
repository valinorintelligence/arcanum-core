import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from arcanum.agent.engine import AgentEngine
from arcanum.agent.tools import ToolExecutor, _auto_repair_command, RECON_TOOLS, ANALYSIS_TOOLS


def test_native_tool_registered_in_phases():
    assert "audit_security_headers" in RECON_TOOLS
    assert "audit_security_headers" in ANALYSIS_TOOLS


def test_auto_repair_arjun():
    cmd = "arjun http://example.com/api"
    repaired = _auto_repair_command(cmd)
    assert repaired.startswith("arjun -u http://example.com/api")


def test_auto_repair_testssl():
    cmd = "testssl.sh example.com"
    repaired = _auto_repair_command(cmd)
    assert "--fast" in repaired
    assert "--quiet" in repaired


def test_pedagogical_explanation_audit_headers():
    eng = AgentEngine(llm=None, tool_executor=None,
                      session={"name": "op", "target": "site.com", "mode": "autopilot"})
    exp = eng._explain_tool_action("audit_security_headers", {"url": "https://site.com"})
    assert "what" in exp and "cabeçalhos de segurança" in exp["what"].lower()
    assert "why" in exp and "owasp" in exp["why"].lower()


@pytest.mark.asyncio
async def test_audit_security_headers_missing_all():
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # Mock response with minimal headers (missing CSP, HSTS, XFO, etc.)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL("https://target.local")
    mock_resp.headers = httpx.Headers({
        "Content-Type": "text/html",
        "Server": "Apache/2.4.41",
    })
    mock_resp.cookies = []

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await te._handle_audit_security_headers("https://target.local")

    assert res["status_code"] == 200
    assert res["score"] < 70
    assert res["grade"] in ("C", "D", "F")
    missing_names = [m["header"] for m in res["missing_headers"]]
    assert "Content-Security-Policy" in missing_names
    assert "Strict-Transport-Security" in missing_names
    assert "X-Frame-Options" in missing_names
    assert "X-Content-Type-Options" in missing_names
    assert "server" in res["server_banners"]


@pytest.mark.asyncio
async def test_audit_security_headers_hardened():
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # Mock response with full security headers and secure cookie
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL("https://secure.local")
    mock_resp.headers = httpx.Headers([
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Security-Policy", "default-src 'self'; script-src 'self'"),
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=()"),
        ("Set-Cookie", "session=xyz123; Secure; HttpOnly; SameSite=Strict"),
    ])
    mock_resp.cookies = []

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await te._handle_audit_security_headers("https://secure.local")

    assert res["status_code"] == 200
    assert res["score"] >= 90
    assert res["grade"] == "A"
    assert len(res["missing_headers"]) == 0
    assert len(res["cookies_audit"]) == 1
    assert len(res["cookies_audit"][0]["issues"]) == 0


@pytest.mark.asyncio
async def test_audit_security_headers_insecure_cookies_and_cors():
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL("https://api.local")
    mock_resp.headers = httpx.Headers([
        ("Access-Control-Allow-Origin", "*"),
        ("Set-Cookie", "token=abc; Path=/"),
    ])
    mock_resp.cookies = []

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await te._handle_audit_security_headers("https://api.local")

    assert any("Access-Control-Allow-Origin" in r for r in res["recommendations"])
    assert len(res["cookies_audit"]) == 1
    cookie_issues = res["cookies_audit"][0]["issues"]
    assert any("Secure" in issue for issue in cookie_issues)
    assert any("HttpOnly" in issue for issue in cookie_issues)
    assert any("SameSite" in issue for issue in cookie_issues)


@pytest.mark.asyncio
async def test_audit_security_headers_connection_error():
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.ConnectError("Connection refused")
        res = await te._handle_audit_security_headers("https://offline.local")

    assert res["score"] == 0
    assert res["grade"] == "F"
    assert "Falha na requisição" in res["error"]
