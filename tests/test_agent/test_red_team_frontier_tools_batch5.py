"""Unit tests for the 5 advanced security audit and posture tools (Batch 5) in Arcanum.

Tools tested:
1. audit_server_side_prototype_pollution (Node.js backend SSPP)
2. audit_ip_spoofing_access_controls (Reverse proxy IP header bypass)
3. audit_kerberos_delegation_risks (Active Directory Unconstrained, Constrained S4U, RBCD)
4. audit_http3_quic_exposure (HTTP/3 Alt-Svc, UDP 443, WAF bypass, 0-RTT)
5. audit_snmp_community_exposure (UDP 161 default community strings and MIB disclosure)
"""

import json
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

def test_batch5_registrations():
    """Verify all 5 tools are registered in NATIVE_TOOLS and ToolExecutor handlers."""
    assert len(NATIVE_TOOLS) >= 91

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    expected = [
        "audit_server_side_prototype_pollution",
        "audit_ip_spoofing_access_controls",
        "audit_kerberos_delegation_risks",
        "audit_http3_quic_exposure",
        "audit_snmp_community_exposure",
    ]
    for name in expected:
        assert name in tool_names, f"Missing tool in NATIVE_TOOLS: {name}"

    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for name in expected:
        assert name in executor._handlers, f"Missing handler in ToolExecutor: {name}"

    assert "audit_ip_spoofing_access_controls" in RECON_TOOLS
    assert "audit_http3_quic_exposure" in RECON_TOOLS
    assert "audit_snmp_community_exposure" in RECON_TOOLS

    for name in expected:
        assert name in ANALYSIS_TOOLS


def test_batch5_normalizer_and_risk_scoring():
    """Verify tool normalization and low-risk rating in AgentEngine."""
    expected = [
        "audit_server_side_prototype_pollution",
        "audit_ip_spoofing_access_controls",
        "audit_kerberos_delegation_risks",
        "audit_http3_quic_exposure",
        "audit_snmp_community_exposure",
    ]
    for name in expected:
        norm = AgentEngine._normalize_tool_call_dict({"name": name, "arguments": {}})
        assert norm is not None, f"Failed to normalize {name}"
        assert norm["function"]["name"] == name

        risk = AgentEngine._assess_risk(name, {})
        assert risk == "LOW", f"Risk for {name} should be LOW, got {risk}"


def test_batch5_pedagogical_explanations():
    """Verify pedagogical explanations for the 5 tools in Portuguese."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "corp.com.br"}

    exp_sspp = engine._explain_tool_action("audit_server_side_prototype_pollution", {"url": "https://corp.com.br/api/profile"})
    assert "prototype pollution" in exp_sspp["what"].lower() or "sspp" in exp_sspp["what"].lower()
    assert "node.js" in exp_sspp["what"].lower() or "node.js" in exp_sspp["why"].lower() or "prototype" in exp_sspp["why"].lower()

    exp_ip = engine._explain_tool_action("audit_ip_spoofing_access_controls", {"url": "https://corp.com.br/admin"})
    assert "ip" in exp_ip["what"].lower() or "controle de acesso" in exp_ip["what"].lower()
    assert "x-forwarded-for" in exp_ip["why"].lower() or "proxy" in exp_ip["why"].lower()

    exp_kerb = engine._explain_tool_action("audit_kerberos_delegation_risks", {"domain": "corp.local"})
    assert "kerberos" in exp_kerb["what"].lower() or "delegação" in exp_kerb["what"].lower()
    assert "unconstrained" in exp_kerb["why"].lower() or "tgt" in exp_kerb["why"].lower() or "rbcd" in exp_kerb["why"].lower()

    exp_h3 = engine._explain_tool_action("audit_http3_quic_exposure", {"url": "https://corp.com.br"})
    assert "http/3" in exp_h3["what"].lower() or "quic" in exp_h3["what"].lower()
    assert "udp" in exp_h3["why"].lower() or "alt-svc" in exp_h3["why"].lower() or "waf" in exp_h3["why"].lower()

    exp_snmp = engine._explain_tool_action("audit_snmp_community_exposure", {"host": "192.168.1.1"})
    assert "snmp" in exp_snmp["what"].lower()
    assert "comunidades" in exp_snmp["why"].lower() or "mib" in exp_snmp["why"].lower()


# ============================================================================
# 2. Server-Side Prototype Pollution (SSPP)
# ============================================================================

@pytest.mark.asyncio
async def test_audit_server_side_prototype_pollution_detected():
    """Test detection of Server-Side Prototype Pollution."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status": "ok", "user": {"name": "test"}, "arcanum_polluted": "true"}'

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        res = await executor._handle_audit_server_side_prototype_pollution(
            url="https://corp.com.br/api/users",
            method="POST"
        )

    assert res["sspp_detected"] is True
    assert len(res["vulnerable_vectors"]) > 0
    assert res["score"] <= 15
    assert res["grade"] == "F"
    assert any("Server-Side Prototype Pollution" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_server_side_prototype_pollution_clean():
    """Test clean backend handling object merges safely."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status": "ok", "user": {"name": "test"}}'

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        res = await executor._handle_audit_server_side_prototype_pollution(
            url="https://corp.com.br/api/users",
            method="POST"
        )

    assert res["sspp_detected"] is False
    assert len(res["vulnerable_vectors"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 3. IP Spoofing Access Controls
# ============================================================================

@pytest.mark.asyncio
async def test_audit_ip_spoofing_access_controls_bypassed():
    """Test IP spoofing bypass detection when restricted route unlocks."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_base = MagicMock()
    mock_base.status_code = 403

    mock_bypass = MagicMock()
    mock_bypass.status_code = 200
    mock_bypass.text = "<h1>Admin Dashboard - Internal Access Granted</h1>"

    def side_effect_get(url, headers=None):
        if headers and headers.get("X-Forwarded-For") == "127.0.0.1":
            return mock_bypass
        return mock_base

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=side_effect_get):
        res = await executor._handle_audit_ip_spoofing_access_controls(
            url="https://corp.com.br/admin",
            method="GET",
            trusted_ip="127.0.0.1"
        )

    assert res["ip_spoofing_bypass_detected"] is True
    assert "X-Forwarded-For: 127.0.0.1" in res["effective_headers"]
    assert res["bypass_status"] == 200
    assert res["score"] <= 20
    assert res["grade"] == "F"


@pytest.mark.asyncio
async def test_audit_ip_spoofing_access_controls_secure():
    """Test secure gateway enforcing real socket IP."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 403

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await executor._handle_audit_ip_spoofing_access_controls(
            url="https://corp.com.br/internal",
            method="GET"
        )

    assert res["ip_spoofing_bypass_detected"] is False
    assert len(res["effective_headers"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 4. Kerberos Delegation Risks
# ============================================================================

@pytest.mark.asyncio
async def test_audit_kerberos_delegation_risks_detected():
    """Test detection of Unconstrained, Constrained S4U, and RBCD."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    objects = [
        {
            "sAMAccountName": "SRV-WEB01$",
            "userAccountControl": 524288,  # TRUSTED_FOR_DELEGATION
        },
        {
            "sAMAccountName": "svc_sql",
            "userAccountControl": 16777216,  # TRUSTED_TO_AUTH_FOR_DELEGATION
            "msDS-AllowedToDelegateTo": ["MSSQLSvc/db01.corp.local:1433"],
        },
        {
            "sAMAccountName": "DC01$",
            "userAccountControl": 512,
            "msDS-AllowedToActOnBehalfOfOtherIdentity": b"\x01\x00\x04\x80...",
        },
    ]

    res = await executor._handle_audit_kerberos_delegation_risks(
        domain="corp.local",
        objects_data=objects
    )

    assert res["domain"] == "corp.local"
    assert "SRV-WEB01$" in res["unconstrained_delegation_accounts"]
    assert "svc_sql" in res["constrained_delegation_accounts"]
    assert "DC01$" in res["rbcd_vulnerable_targets"]
    assert res["delegation_risks_found"] is True
    assert res["score"] <= 15
    assert res["grade"] == "F"


@pytest.mark.asyncio
async def test_audit_kerberos_delegation_risks_clean():
    """Test clean accounts without dangerous delegation flags."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    objects = [
        {"sAMAccountName": "user_john", "userAccountControl": 512},
        {"sAMAccountName": "PC-FINANCE01$", "userAccountControl": 4096},
    ]

    res = await executor._handle_audit_kerberos_delegation_risks(
        domain="corp.local",
        objects_data=objects
    )

    assert res["delegation_risks_found"] is False
    assert len(res["unconstrained_delegation_accounts"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 5. HTTP/3 & QUIC Exposure
# ============================================================================

@pytest.mark.asyncio
async def test_audit_http3_quic_exposure_detected():
    """Test detection of HTTP/3 advertised via Alt-Svc."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.headers = {"alt-svc": 'h3=":443"; ma=86400, h3-29=":443"; ma=86400'}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp), \
         patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock

        res = await executor._handle_audit_http3_quic_exposure(url="https://corp.com.br")

    assert res["http3_supported"] is True
    assert "h3" in res["alt_svc_header"]
    assert res["quic_udp_port_open"] is True
    assert res["waf_bypass_risk"] is True
    assert res["score"] <= 75
    assert res["grade"] in ("B", "C")


@pytest.mark.asyncio
async def test_audit_http3_quic_exposure_clean():
    """Test clean endpoint without HTTP/3 Alt-Svc advertisement."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp), \
         patch("socket.socket", side_effect=Exception("UDP port closed")):
        res = await executor._handle_audit_http3_quic_exposure(url="https://corp.com.br")

    assert res["http3_supported"] is False
    assert res["waf_bypass_risk"] is False
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 6. SNMP Community Exposure
# ============================================================================

@pytest.mark.asyncio
async def test_audit_snmp_community_exposure_detected():
    """Test detection of exposed SNMP service with public community string."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_sock = MagicMock()
    # Mock ASN.1 sequence 0x30 response with sysDescr
    mock_sock.recvfrom.return_value = (
        b"\x30\x40\x02\x01\x00\x04\x06public\xa2\x33\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x26\x30\x24\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x04\x18Linux Cisco-Switch 5.15.0",
        ("192.168.1.1", 161)
    )

    with patch("socket.socket", return_value=mock_sock):
        res = await executor._handle_audit_snmp_community_exposure(
            host="192.168.1.1",
            port=161,
            community_strings=["public"]
        )

    assert res["host"] == "192.168.1.1"
    assert res["snmp_accessible"] is True
    assert "public" in res["vulnerable_communities"]
    assert "Cisco-Switch" in res["sys_descr"] or len(res["sys_descr"]) > 0
    assert res["score"] <= 15
    assert res["grade"] == "F"
    assert any("SNMP" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_snmp_community_exposure_clean():
    """Test secure host with closed UDP 161 or rejecting default communities."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    with patch("socket.socket", side_effect=Exception("Port unreachable / timeout")):
        res = await executor._handle_audit_snmp_community_exposure(
            host="192.168.1.1",
            port=161
        )

    assert res["snmp_accessible"] is False
    assert len(res["vulnerable_communities"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"
