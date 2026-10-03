"""Unit tests for the 5 advanced security audit and posture tools (Batch 4) in Arcanum.

Tools tested:
1. audit_git_and_env_leakage (Exposed .git/HEAD, .env, docker-compose, and backups)
2. audit_content_security_policy_deep (CSP bypasses, missing base-uri, frame-ancestors, unsafe-inline)
3. audit_api_excessive_data_exposure (OWASP API3:2023 - BOPLA / Sensitive Data Exposure)
4. audit_dns_zone_transfer_and_nsec (DNS AXFR Zone Transfer and DNSSEC NSEC Walk)
5. audit_smtp_open_relay_and_spoofing (RFC 5321 Open Mail Relay and STARTTLS encryption)
"""

import json
import struct
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from arcanum.agent.tools import (
    NATIVE_TOOLS,
    RECON_TOOLS,
    ANALYSIS_TOOLS,
    ToolExecutor,
)
from arcanum.agent.engine import AgentEngine


# ============================================================================
# 1. Registration & Schema Validation
# ============================================================================

def test_batch4_registrations():
    """Verify all 5 tools are registered in NATIVE_TOOLS and ToolExecutor handlers."""
    assert len(NATIVE_TOOLS) >= 86

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    expected = [
        "audit_git_and_env_leakage",
        "audit_content_security_policy_deep",
        "audit_api_excessive_data_exposure",
        "audit_dns_zone_transfer_and_nsec",
        "audit_smtp_open_relay_and_spoofing",
    ]
    for name in expected:
        assert name in tool_names, f"Missing tool in NATIVE_TOOLS: {name}"

    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for name in expected:
        assert name in executor._handlers, f"Missing handler in ToolExecutor: {name}"

    assert "audit_git_and_env_leakage" in RECON_TOOLS
    assert "audit_content_security_policy_deep" in RECON_TOOLS
    assert "audit_dns_zone_transfer_and_nsec" in RECON_TOOLS
    assert "audit_smtp_open_relay_and_spoofing" in RECON_TOOLS

    for name in expected:
        assert name in ANALYSIS_TOOLS


def test_batch4_normalizer_and_risk_scoring():
    """Verify tool normalization and low-risk rating in AgentEngine."""
    expected = [
        "audit_git_and_env_leakage",
        "audit_content_security_policy_deep",
        "audit_api_excessive_data_exposure",
        "audit_dns_zone_transfer_and_nsec",
        "audit_smtp_open_relay_and_spoofing",
    ]
    for name in expected:
        norm = AgentEngine._normalize_tool_call_dict({"name": name, "arguments": {}})
        assert norm is not None, f"Failed to normalize {name}"
        assert norm["function"]["name"] == name

        risk = AgentEngine._assess_risk(name, {})
        assert risk == "LOW", f"Risk for {name} should be LOW, got {risk}"


def test_batch4_pedagogical_explanations():
    """Verify pedagogical explanations for the 5 tools in Portuguese."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "corp.com.br"}

    exp_git = engine._explain_tool_action("audit_git_and_env_leakage", {"url": "https://corp.com.br"})
    assert "git" in exp_git["what"].lower() or "ambiente" in exp_git["what"].lower()
    assert ".git" in exp_git["why"].lower() or ".env" in exp_git["why"].lower()

    exp_csp = engine._explain_tool_action("audit_content_security_policy_deep", {"url": "https://corp.com.br"})
    assert "csp" in exp_csp["what"].lower() or "content-security-policy" in exp_csp["what"].lower()
    assert "xss" in exp_csp["why"].lower() or "clickjacking" in exp_csp["why"].lower()

    exp_bopla = engine._explain_tool_action("audit_api_excessive_data_exposure", {"url": "https://corp.com.br/api/me"})
    assert "excessiva" in exp_bopla["what"].lower() or "api" in exp_bopla["what"].lower()
    assert "senha" in exp_bopla["why"].lower() or "vazamento" in exp_bopla["why"].lower() or "confidenciais" in exp_bopla["why"].lower()

    exp_axfr = engine._explain_tool_action("audit_dns_zone_transfer_and_nsec", {"domain": "corp.com.br"})
    assert "zona" in exp_axfr["what"].lower() or "axfr" in exp_axfr["what"].lower()
    assert "dns" in exp_axfr["why"].lower() or "subdomínios" in exp_axfr["why"].lower()

    exp_smtp = engine._explain_tool_action("audit_smtp_open_relay_and_spoofing", {"host": "mail.corp.com.br"})
    assert "relay" in exp_smtp["what"].lower() or "smtp" in exp_smtp["what"].lower()
    assert "starttls" in exp_smtp["why"].lower() or "não autenticado" in exp_smtp["why"].lower()


# ============================================================================
# 2. Git & Env Leakage
# ============================================================================

@pytest.mark.asyncio
async def test_audit_git_and_env_leakage_detected():
    """Test detection of exposed .git/HEAD and .env files."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    def side_effect_get(url):
        mock_r = MagicMock()
        if url.endswith("/.git/HEAD"):
            mock_r.status_code = 200
            mock_r.headers = {"content-type": "text/plain"}
            mock_r.text = "ref: refs/heads/main\n"
            return mock_r
        elif url.endswith("/.env"):
            mock_r.status_code = 200
            mock_r.headers = {"content-type": "text/plain"}
            mock_r.text = "DB_HOST=localhost\nDB_PASSWORD=secret123\nAPP_KEY=base64:xyz\n"
            return mock_r
        mock_r.status_code = 404
        mock_r.headers = {}
        mock_r.text = "Not Found"
        return mock_r

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=side_effect_get):
        res = await executor._handle_audit_git_and_env_leakage(url="https://corp.com.br")

    assert res["git_exposed"] is True
    assert res["env_exposed"] is True
    assert len(res["sensitive_files_found"]) >= 2
    assert res["score"] <= 20
    assert res["grade"] == "F"
    assert any("Git" in f["issue"] for f in res["findings"])
    assert any(".env" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_git_and_env_leakage_clean():
    """Test clean web server returning 404 for all sensitive paths."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"
    mock_resp.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await executor._handle_audit_git_and_env_leakage(url="https://corp.com.br")

    assert res["git_exposed"] is False
    assert res["env_exposed"] is False
    assert len(res["sensitive_files_found"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 3. Content Security Policy Deep
# ============================================================================

@pytest.mark.asyncio
async def test_audit_content_security_policy_deep_vulnerable():
    """Test detection of weak CSP with missing frame-ancestors, base-uri, and unsafe-inline."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    weak_csp = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;"

    res = await executor._handle_audit_content_security_policy_deep(
        url="https://corp.com.br",
        csp_header=weak_csp
    )

    assert res["csp_present"] is True
    assert "frame-ancestors" in res["missing_critical_directives"]
    assert "base-uri" in res["missing_critical_directives"]
    assert "'unsafe-inline'" in res["weak_directives"]
    assert "cdnjs.cloudflare.com" in res["jsonp_gadget_cdns"]
    assert res["clickjacking_protection"] is False
    assert res["score"] < 50
    assert res["grade"] in ("C", "F")


@pytest.mark.asyncio
async def test_audit_content_security_policy_deep_strict():
    """Test strict CSP protecting against XSS and Clickjacking."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    strict_csp = (
        "default-src 'self'; "
        "script-src 'self' 'nonce-R4nd0m123'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none';"
    )

    res = await executor._handle_audit_content_security_policy_deep(
        url="https://corp.com.br",
        csp_header=strict_csp
    )

    assert res["csp_present"] is True
    assert res["clickjacking_protection"] is True
    assert len(res["missing_critical_directives"]) == 0
    assert len(res["weak_directives"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 4. API Excessive Data Exposure (OWASP API3:2023)
# ============================================================================

@pytest.mark.asyncio
async def test_audit_api_excessive_data_exposure_detected():
    """Test detection of sensitive fields (password_hash, CPF, tokens) in API responses."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    payload = {
        "id": 1042,
        "name": "Carlos Silva",
        "email": "carlos@corp.com.br",
        "password_hash": "$2b$12$e8Fv2K8gM3jU7aQ0eG9fL.5q1W3e5R7t9Y1u3I5o7P9a1S3d5F7g9",
        "cpf": "123.456.789-00",
        "is_admin": True,
        "api_key": "sec_live_98a72b891c98",
        "preferences": {
            "theme": "dark",
            "internal_id": "SYS_ADM_ROOT_01"
        }
    }

    res = await executor._handle_audit_api_excessive_data_exposure(
        url="https://corp.com.br/api/v1/profile",
        sample_response=payload
    )

    assert res["excessive_exposure_detected"] is True
    assert len(res["sensitive_fields_exposed"]) >= 4
    exposed_fields = [f["field"] for f in res["sensitive_fields_exposed"]]
    assert "password_hash" in exposed_fields
    assert "cpf" in exposed_fields
    assert "is_admin" in exposed_fields
    assert "api_key" in exposed_fields
    assert res["score"] <= 30
    assert res["grade"] == "F"


@pytest.mark.asyncio
async def test_audit_api_excessive_data_exposure_clean():
    """Test clean API payload exposing only public/safe attributes."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    payload = {
        "id": 1042,
        "display_name": "Carlos S.",
        "avatar_url": "https://cdn.corp.com.br/avatars/1042.png",
        "status": "active"
    }

    res = await executor._handle_audit_api_excessive_data_exposure(
        url="https://corp.com.br/api/v1/users/1042",
        sample_response=payload
    )

    assert res["excessive_exposure_detected"] is False
    assert len(res["sensitive_fields_exposed"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 5. DNS Zone Transfer (AXFR) & NSEC Walk
# ============================================================================

@pytest.mark.asyncio
async def test_audit_dns_zone_transfer_and_nsec_open_axfr():
    """Test detection of open AXFR zone transfer."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_sock = MagicMock()
    # Mock header with RCODE 0 and ANCOUNT 15
    resp_header = struct.pack(">HHHHHH", 0x1234, 0x8000, 1, 15, 0, 0)
    resp_data = resp_header + b"\x00" * 30
    resp_len_bytes = struct.pack(">H", len(resp_data))

    mock_sock.recv.side_effect = [resp_len_bytes, resp_data]

    with patch("socket.socket", return_value=mock_sock):
        res = await executor._handle_audit_dns_zone_transfer_and_nsec(
            domain="corp.com.br",
            nameserver="ns1.corp.com.br"
        )

    assert res["domain"] == "corp.com.br"
    assert res["axfr_open"] is True
    assert res["score"] <= 30
    assert res["grade"] == "F"
    assert any("AXFR" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_dns_zone_transfer_and_nsec_clean():
    """Test clean nameserver refusing AXFR transfers."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    with patch("socket.socket", side_effect=Exception("Connection refused or query rejected")):
        res = await executor._handle_audit_dns_zone_transfer_and_nsec(
            domain="corp.com.br",
            nameserver="ns1.corp.com.br"
        )

    assert res["domain"] == "corp.com.br"
    assert res["axfr_open"] is False
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 6. SMTP Open Relay & STARTTLS
# ============================================================================

@pytest.mark.asyncio
async def test_audit_smtp_open_relay_and_spoofing_vulnerable():
    """Test detection of SMTP Open Relay without STARTTLS."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_sock = MagicMock()
    # 1. banner, 2. ehlo resp (no STARTTLS), 3. mail resp, 4. rcpt resp (250 OK)
    mock_sock.recv.side_effect = [
        b"220 mail.corp.com.br ESMTP Sendmail 8.14.4\r\n",
        b"250-mail.corp.com.br\r\n250-PIPELINING\r\n250 SIZE 10240000\r\n",
        b"250 2.1.0 Sender ok\r\n",
        b"250 2.1.5 Recipient ok\r\n",
    ]

    with patch("socket.socket", return_value=mock_sock):
        res = await executor._handle_audit_smtp_open_relay_and_spoofing(
            host="mail.corp.com.br",
            port=25
        )

    assert res["host"] == "mail.corp.com.br"
    assert res["open_relay_detected"] is True
    assert res["starttls_supported"] is False
    assert res["score"] <= 15
    assert res["grade"] == "F"
    assert any("OPEN RELAY" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_smtp_open_relay_and_spoofing_hardened():
    """Test hardened SMTP server supporting STARTTLS and denying relay."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [
        b"220 mail.corp.com.br ESMTP Postfix\r\n",
        b"250-mail.corp.com.br\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
        b"250 2.1.0 Ok\r\n",
        b"554 5.7.1 <relay-test@external-recipient.org>: Relay access denied\r\n",
    ]

    with patch("socket.socket", return_value=mock_sock):
        res = await executor._handle_audit_smtp_open_relay_and_spoofing(
            host="mail.corp.com.br",
            port=25
        )

    assert res["host"] == "mail.corp.com.br"
    assert res["open_relay_detected"] is False
    assert res["starttls_supported"] is True
    assert res["score"] == 100
    assert res["grade"] == "A"
