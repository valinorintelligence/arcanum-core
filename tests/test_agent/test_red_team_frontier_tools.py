"""Unit tests for the 6 Red Team frontier tools in Arcanum.

Tools tested:
1. audit_http_request_smuggling (HTTP Desync / CL.TE / TE.CL / TE Obfuscation)
2. audit_ssti_injection (Server-Side Template Injection & SpEL)
3. audit_nosql_injection (NoSQL & Operator Tampering)
4. generate_subdomain_permutations (Lexical Subdomain Mutation & Shadow IT)
5. audit_ntlm_relay_coercion (SMB/LDAP Signing & MS-RPRN/WebDAV Coercion)
6. simulate_cloud_iam_privesc (Cloud IAM Privilege Escalation Mapper)
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

def test_red_team_frontier_tools_registrations():
    """Verify all 6 tools are registered in NATIVE_TOOLS and ToolExecutor handlers."""
    assert len(NATIVE_TOOLS) >= 71

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    expected = {
        "audit_http_request_smuggling",
        "audit_ssti_injection",
        "audit_nosql_injection",
        "generate_subdomain_permutations",
        "audit_ntlm_relay_coercion",
        "simulate_cloud_iam_privesc",
    }
    for name in expected:
        assert name in tool_names, f"Missing tool in NATIVE_TOOLS: {name}"

    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for name in expected:
        assert name in executor._handlers, f"Missing handler in ToolExecutor._handlers: {name}"

    assert "generate_subdomain_permutations" in RECON_TOOLS
    assert "audit_http_request_smuggling" in RECON_TOOLS
    assert "audit_ssti_injection" in RECON_TOOLS
    assert "audit_nosql_injection" in RECON_TOOLS

    for name in expected:
        assert name in ANALYSIS_TOOLS


def test_engine_normalizer_and_risk_scoring():
    """Verify tool normalization and low-risk rating in AgentEngine."""
    expected = [
        "audit_http_request_smuggling",
        "audit_ssti_injection",
        "audit_nosql_injection",
        "generate_subdomain_permutations",
        "audit_ntlm_relay_coercion",
        "simulate_cloud_iam_privesc",
    ]
    for name in expected:
        norm = AgentEngine._normalize_tool_call_dict({"name": name, "arguments": {}})
        assert norm is not None, f"Failed to normalize {name}"
        assert norm["function"]["name"] == name

        risk = AgentEngine._assess_risk(name, {})
        assert risk == "LOW", f"Risk for {name} should be LOW, got {risk}"


def test_engine_pedagogical_explanations():
    """Verify engine generates pedagogical explanations for operators."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "corp.com.br"}

    exp_smuggle = engine._explain_tool_action("audit_http_request_smuggling", {"url": "https://corp.com.br"})
    assert "HTTP Request Smuggling" in exp_smuggle["what"]
    assert "Transfer-Encoding" in exp_smuggle["why"]

    exp_ssti = engine._explain_tool_action("audit_ssti_injection", {"url": "https://corp.com.br/search", "parameter": "q"})
    assert "Template Injection" in exp_ssti["what"]
    assert "RCE" in exp_ssti["why"]

    exp_nosql = engine._explain_tool_action("audit_nosql_injection", {"url": "https://corp.com.br/api/login"})
    assert "NoSQL" in exp_nosql["what"]
    assert "MongoDB" in exp_nosql["why"]

    exp_perm = engine._explain_tool_action("generate_subdomain_permutations", {"domain": "corp.com.br"})
    assert "Shadow IT" in exp_perm["what"]
    assert "altdns" in exp_perm["why"]

    exp_ntlm = engine._explain_tool_action("audit_ntlm_relay_coercion", {"target": "192.168.1.10"})
    assert "NTLM Relay" in exp_ntlm["what"]
    assert "SMB" in exp_ntlm["why"]

    exp_iam = engine._explain_tool_action("simulate_cloud_iam_privesc", {"provider": "aws"})
    assert "IAM" in exp_iam["what"]
    assert "escala" in exp_iam["what"].lower()
    assert "iam" in exp_iam["why"].lower()


# ============================================================================
# 2. HTTP Request Smuggling & Desync
# ============================================================================

@pytest.mark.asyncio
async def test_audit_http_request_smuggling_detected():
    """Verify detection when dual CL.TE or obfuscated TE is accepted by server."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_post(url, headers=None, content=None, *args, **kwargs):
        resp = MagicMock()
        headers = headers or {}
        # If dual CL.TE accepted without 400
        if "Transfer-Encoding" in headers and "Content-Length" in headers:
            resp.status_code = 200
            resp.text = "Accepted request"
        else:
            resp.status_code = 200
            resp.text = "OK"
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_post):
        res = await executor._handle_audit_http_request_smuggling("https://app.alvo.com.br")
        assert res["cl_te_detected"] is True
        assert res["score"] <= 60
        assert res["grade"] in ("C", "F")
        assert any("Request Smuggling" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_http_request_smuggling_hardened():
    """Verify compliant server returning 400 Bad Request to ambiguous requests."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_post_hardened(url, headers=None, content=None, *args, **kwargs):
        resp = MagicMock()
        headers = headers or {}
        if any("Transfer-Encoding" in k for k in headers):
            resp.status_code = 400
            resp.text = "Bad Request: Ambiguous or malformed transfer-encoding"
        else:
            resp.status_code = 200
            resp.text = "OK"
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_post_hardened):
        res = await executor._handle_audit_http_request_smuggling("https://hardened.alvo.com.br")
        assert res["cl_te_detected"] is False
        assert res["te_obfuscation_accepted"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 3. Server-Side Template Injection (SSTI)
# ============================================================================

@pytest.mark.asyncio
async def test_audit_ssti_injection_jinja2_detected():
    """Verify detection of mathematical evaluation {{7*7}} -> 49 and Jinja2 differentiation."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_get(url, params=None, *args, **kwargs):
        resp = MagicMock()
        url_str = str(url)
        params = params or {}
        if "{{7*'7'}}" in url_str or params.get("q") == "{{7*'7'}}":
            resp.text = "<html>Result: 7777777</html>"
        elif "%7B%7B7%2A7%7D%7D" in url_str or "{{7*7}}" in url_str or "7*7" in url_str:
            resp.text = "<html>Result: 49</html>"
        else:
            resp.text = "<html>Search page</html>"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        res = await executor._handle_audit_ssti_injection("https://app.alvo.com.br/search", parameter="q")
        assert res["ssti_detected"] is True
        assert "Jinja2" in res["detected_engine"]
        assert res["score"] <= 15
        assert any("Template Injection" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_ssti_injection_clean():
    """Verify clean response when parameter is rendered literally."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_get_clean(url, params=None, *args, **kwargs):
        resp = MagicMock()
        resp.text = "<html>Search: {{7*7}} not found</html>"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get_clean):
        res = await executor._handle_audit_ssti_injection("https://app.alvo.com.br/search", parameter="q")
        assert res["ssti_detected"] is False
        assert res["detected_engine"] == "None"
        assert res["score"] == 100


# ============================================================================
# 4. NoSQL & Operator Injection
# ============================================================================

@pytest.mark.asyncio
async def test_audit_nosql_injection_detected():
    """Verify detection when $ne operator bypasses 401 authentication."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_post(url, json=None, *args, **kwargs):
        resp = MagicMock()
        json = json or {}
        pw = json.get("password")
        # Injected operator bypasses login
        if isinstance(pw, dict) and "$ne" in pw:
            resp.status_code = 200
            resp.text = '{"success": true, "token": "jwt_token_admin_xyz"}'
        else:
            resp.status_code = 401
            resp.text = '{"error": "Invalid credentials"}'
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_post):
        res = await executor._handle_audit_nosql_injection("https://app.alvo.com.br/api/login")
        assert res["nosql_injection_risk"] is True
        assert "$ne" in res["vulnerable_operators"]
        assert res["score"] <= 20
        assert any("NoSQL" in f["issue"] for f in res["findings"])


# ============================================================================
# 5. Subdomain Permutations & Shadow IT
# ============================================================================

@pytest.mark.asyncio
async def test_generate_subdomain_permutations():
    """Verify lexical permutations generation and DNS resolution."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_dns_get(url, *args, **kwargs):
        resp = MagicMock()
        if "stg-api.empresa.com.br" in url:
            resp.status_code = 200
            resp.json = MagicMock(return_value={"Answer": [{"data": "198.51.100.5"}]})
        else:
            resp.status_code = 200
            resp.json = MagicMock(return_value={})
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_dns_get):
        res = await executor._handle_generate_subdomain_permutations(
            domain="empresa.com.br",
            known_subdomains=["api", "vpn"],
            resolve_dns=True,
            max_permutations=30,
        )
        assert res["domain"] == "empresa.com.br"
        assert res["total_permutations_generated"] > 0
        assert res["active_count"] == 1
        assert res["resolved_active_subdomains"][0]["subdomain"] == "stg-api.empresa.com.br"
        assert res["score"] <= 80


# ============================================================================
# 6. NTLM Relay & Coercion Attack Surface
# ============================================================================

@pytest.mark.asyncio
async def test_audit_ntlm_relay_coercion_vulnerabilities():
    """Detect unhardened SMB/LDAP signing and active coercion services."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    res = await executor._handle_audit_ntlm_relay_coercion(
        target="dc01.corp.local",
        smb_signing="not_required",
        ldap_signing="not_enforced",
        webdav_enabled=True,
        spooler_running=True,
    )

    assert res["smb_relay_risk"] is True
    assert res["ldap_relay_risk"] is True
    assert res["coercion_risk"] is True
    assert res["score"] <= 20
    assert any("SMB" in f["issue"] for f in res["findings"])
    assert any("LDAP" in f["issue"] for f in res["findings"])
    assert any("coerção" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_ntlm_relay_coercion_hardened():
    """Verify hardened configuration with required signing and no spooler."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    res = await executor._handle_audit_ntlm_relay_coercion(
        target="dc01.corp.local",
        smb_signing="required",
        ldap_signing="required",
        webdav_enabled=False,
        spooler_running=False,
    )

    assert res["smb_relay_risk"] is False
    assert res["ldap_relay_risk"] is False
    assert res["coercion_risk"] is False
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 7. Cloud IAM Privilege Escalation Mapper
# ============================================================================

@pytest.mark.asyncio
async def test_simulate_cloud_iam_privesc_detected():
    """Detect PassRole + RunInstances escalation path in IAM policy."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    vulnerable_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:PassRole",
                    "ec2:RunInstances",
                ],
                "Resource": "*",
            }
        ]
    }

    res = await executor._handle_simulate_cloud_iam_privesc(
        policy_document=vulnerable_policy,
        provider="aws",
        entity_name="junior_dev_role",
    )

    assert res["privilege_escalation_detected"] is True
    assert res["identified_paths_count"] >= 1
    assert any("PassRole" in p for p in res["identified_paths"])
    assert res["score"] <= 20
    assert any("escala" in f["issue"].lower() for f in res["findings"])


@pytest.mark.asyncio
async def test_simulate_cloud_iam_privesc_least_privilege():
    """Verify safe IAM policy without known escalation paths."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    safe_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket",
                ],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ]
    }

    res = await executor._handle_simulate_cloud_iam_privesc(
        policy_document=safe_policy,
        provider="aws",
        entity_name="read_only_role",
    )

    assert res["privilege_escalation_detected"] is False
    assert res["identified_paths_count"] == 0
    assert res["score"] == 100
    assert res["grade"] == "A"
