"""Tests for Batch 7 of Red Team / Frontier Security Audit Tools (Milestone: 100 Native Tools).

Tools covered:
- audit_clickjacking_and_ui_redressing
- audit_bfla_api_authorization
- audit_kerberoasting_surface
- audit_linux_privesc_vectors
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from arcanum.agent.tools import NATIVE_TOOLS, ToolExecutor, RECON_TOOLS, ANALYSIS_TOOLS
from arcanum.agent.engine import AgentEngine


@pytest.fixture
def executor():
    return ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)


# ============================================================================
# 1. Registration & Schema Validation (The Centurion Milestone: 100 Tools)
# ============================================================================

def test_batch7_registrations(executor):
    """Verify all 4 tools are registered in NATIVE_TOOLS and ToolExecutor handlers, reaching at least 100 tools."""
    assert len(NATIVE_TOOLS) >= 100

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    expected = [
        "audit_clickjacking_and_ui_redressing",
        "audit_bfla_api_authorization",
        "audit_kerberoasting_surface",
        "audit_linux_privesc_vectors",
    ]
    for name in expected:
        assert name in tool_names, f"Tool {name} should be in NATIVE_TOOLS"
        assert name in ANALYSIS_TOOLS, f"Tool {name} should be in ANALYSIS_TOOLS"

    assert "audit_clickjacking_and_ui_redressing" in RECON_TOOLS

    for name in expected:
        assert name in executor._handlers, f"Handler for {name} missing in ToolExecutor"


def test_batch7_engine_normalization_and_risk():
    """Verify engine normalizes calls, explains actions and assesses risk properly."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "corp.local"}

    batch7_tools = [
        ("audit_clickjacking_and_ui_redressing", {"url": "https://corp.local/login"}),
        ("audit_bfla_api_authorization", {"url": "https://corp.local/api"}),
        ("audit_kerberoasting_surface", {"domain": "corp.local"}),
        ("audit_linux_privesc_vectors", {"system_info": {"suid_binaries": ["/usr/bin/find"]}}),
    ]

    for tool_name, args in batch7_tools:
        # Normalization
        norm = AgentEngine._normalize_tool_call_dict({"name": tool_name, "arguments": args})
        assert norm is not None
        assert norm["function"]["name"] == tool_name

        # Risk assessment
        risk = AgentEngine._assess_risk(tool_name, args)
        assert risk == "LOW"

        # Pedagogical explanation
        exp = engine._explain_tool_action(tool_name, args)
        assert "what" in exp
        assert "why" in exp
        assert "params" in exp
        assert len(exp["what"]) > 5
        assert len(exp["why"]) > 10


# ============================================================================
# 2. Clickjacking & UI Redressing
# ============================================================================

@pytest.mark.asyncio
async def test_audit_clickjacking_vulnerable_unprotected(executor):
    """Test web page missing XFO and CSP frame-ancestors (vulnerable to Clickjacking)."""
    mock_resp = MagicMock()
    mock_resp.text = "<html><body><h1>Login Form</h1></body></html>"
    mock_resp.headers = {}

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    with patch("httpx.AsyncClient", return_value=mock_client):
        res = await executor._handle_audit_clickjacking_and_ui_redressing(
            url="https://corp.com.br/login",
        )

        assert res["frameable"] is True
        assert res["x_frame_options"] == "None"
        assert res["csp_frame_ancestors"] == "None"
        assert res["score"] < 60
        assert any("Clickjacking" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_clickjacking_frame_busting_bypass(executor):
    """Test detection of client-side frame-busting scripts susceptible to sandbox bypass."""
    html_with_busting = """
    <html>
    <head>
        <script>
            if (top.location != self.location) {
                top.location = self.location;
            }
        </script>
    </head>
    <body>Sensitive Page</body>
    </html>
    """
    res = await executor._handle_audit_clickjacking_and_ui_redressing(
        url="https://corp.com.br/transfer",
        html_content=html_with_busting,
    )

    assert res["frame_busting_detected"] is True
    assert res["frameable"] is True
    assert any("Frame-Busting" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_clickjacking_hardened(executor):
    """Test web page properly protected via CSP frame-ancestors 'self' and XFO DENY."""
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>Protected Dashboard</body></html>"
    mock_resp.headers = {
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    }

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    with patch("httpx.AsyncClient", return_value=mock_client):
        res = await executor._handle_audit_clickjacking_and_ui_redressing(
            url="https://corp.com.br/dashboard",
        )

        assert res["frameable"] is False
        assert res["x_frame_options"] == "DENY"
        assert res["csp_frame_ancestors"] == "'self'"
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 3. BFLA - Broken Function Level Authorization (OWASP API5:2023)
# ============================================================================

@pytest.mark.asyncio
async def test_audit_bfla_vulnerable_admin_endpoint(executor):
    """Test BFLA audit discovering exposed administrative routes returning 200 OK."""
    def mock_get(url, **kwargs):
        resp = MagicMock()
        if "/admin" in url:
            resp.status_code = 200
            resp.text = '{"status": "ok", "users": ["admin", "root"], "admin": true}'
        else:
            resp.status_code = 404
            resp.text = '{"error": "not found"}'
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.side_effect = mock_get

    with patch("httpx.AsyncClient", return_value=mock_client):
        res = await executor._handle_audit_bfla_api_authorization(
            url="https://corp.com.br/api",
            admin_routes=["/admin", "/api/v1/admin/users"],
        )

        assert len(res["vulnerable_routes"]) >= 1
        assert res["score"] < 50
        assert res["grade"] == "F"
        assert any("BFLA" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_bfla_method_tampering_bypass(executor):
    """Test BFLA audit discovering authorization bypass via HTTP method swapping (HEAD 200)."""
    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 403
    mock_get_resp.text = '{"error": "Forbidden"}'

    mock_head_resp = MagicMock()
    mock_head_resp.status_code = 200
    mock_head_resp.text = ""

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = mock_get_resp
    mock_client.head.return_value = mock_head_resp

    with patch("httpx.AsyncClient", return_value=mock_client):
        res = await executor._handle_audit_bfla_api_authorization(
            url="https://corp.com.br/api",
            admin_routes=["/actuator/env"],
        )

        assert any(r["method"] == "HEAD" for r in res["vulnerable_routes"])
        assert any("Method Tampering" in r["reason"] for r in res["vulnerable_routes"])


# ============================================================================
# 4. Kerberoasting Surface & SPN Posture
# ============================================================================

@pytest.mark.asyncio
async def test_audit_kerberoasting_high_priv_and_rc4(executor):
    """Test Kerberoasting audit detecting privileged Domain Admin account with weak RC4 SPN."""
    accounts = [
        {
            "sAMAccountName": "admin_service",
            "servicePrincipalName": ["HTTP/sharepoint.corp.local"],
            "encryption_type": "RC4-HMAC",
            "admin_count": 1,
            "password_age_days": 400,
        }
    ]
    res = await executor._handle_audit_kerberoasting_surface(
        domain="corp.local",
        accounts_data=accounts,
    )

    assert res["domain"] == "corp.local"
    assert "admin_service" in res["high_privilege_spns"]
    assert "admin_service" in res["rc4_encryption_spns"]
    assert res["score"] <= 35
    assert res["grade"] == "F"
    assert any("alto privilégio" in f["issue"] for f in res["findings"])
    assert any("RC4-HMAC" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_kerberoasting_hardened(executor):
    """Test Kerberoasting audit with hardened service accounts using AES256 and unprivileged roles."""
    accounts = [
        {
            "sAMAccountName": "gmsa_sql$",
            "servicePrincipalName": ["MSSQLSvc/sql.corp.local:1433"],
            "encryption_type": "AES256",
            "admin_count": 0,
            "password_age_days": 30,
        }
    ]
    res = await executor._handle_audit_kerberoasting_surface(
        domain="corp.local",
        accounts_data=accounts,
    )

    assert len(res["high_privilege_spns"]) == 0
    assert len(res["rc4_encryption_spns"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 5. Linux Local Privilege Escalation Vectors (GTFOBins)
# ============================================================================

@pytest.mark.asyncio
async def test_audit_linux_privesc_vulnerable_gtfobins(executor):
    """Test Linux privesc audit identifying GTFOBins SUID binary, sudoers NOPASSWD and backdoor UID 0."""
    system_info = {
        "suid_binaries": ["/usr/bin/find", "/bin/mount"],
        "sudo_rules": ["appuser ALL=(ALL) NOPASSWD: /usr/bin/vim"],
        "writable_files": ["/etc/passwd", "/tmp"],
        "passwd_content": "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/home/backdoor:/bin/bash\nappuser:x:1000:1000::/home/appuser:/bin/bash",
    }
    res = await executor._handle_audit_linux_privesc_vectors(
        system_info=system_info,
        target_name="prod-web-server",
    )

    assert "suid_find" in res["escalation_vectors_found"]
    assert "sudo_nopasswd_gtfobin" in res["escalation_vectors_found"]
    assert "uid0_backdoor" in res["escalation_vectors_found"]
    assert any("passwd" in v for v in res["escalation_vectors_found"])
    assert res["risk_level"] == "critical"
    assert res["score"] <= 15
    assert res["grade"] == "F"


@pytest.mark.asyncio
async def test_audit_linux_privesc_hardened(executor):
    """Test Linux privesc audit for a hardened Linux environment."""
    system_info = {
        "suid_binaries": ["/usr/bin/passwd", "/usr/bin/sudo"],
        "sudo_rules": ["appuser ALL=(ALL) /bin/systemctl restart nginx"],
        "writable_files": ["/tmp", "/var/tmp"],
        "passwd_content": "root:x:0:0:root:/root:/bin/bash\nappuser:x:1001:1001::/home/appuser:/bin/bash",
    }
    res = await executor._handle_audit_linux_privesc_vectors(
        system_info=system_info,
        target_name="hardened-node",
    )

    assert len(res["escalation_vectors_found"]) == 0
    assert res["risk_level"] == "low"
    assert res["score"] == 100
    assert res["grade"] == "A"
