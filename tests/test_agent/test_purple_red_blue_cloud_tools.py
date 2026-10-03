"""Unit and integration tests for Arcanum's 7 new Purple, Red, Blue, and Threat Intel tools:
- audit_ssrf_cloud_metadata (Purple Team: AWS IMDSv2, GCP, Azure, and RFC 1918 loopback SSRF resilience)
- calculate_cvss_vector (Purple Team: Mathematical CVSS v3.1 base score, severity rating, and vector generation)
- audit_api_idor_matrix (Red Team: OWASP API1:2023 BOLA/IDOR pattern detection and authorization matrix)
- audit_prototype_pollution (Red Team: Client-side JS __proto__ and prototype pollution audit)
- generate_hardening_baseline (Blue Team: CIS Benchmarks production-ready hardening configs for Nginx, Linux sysctl, SSH)
- audit_dkim_bimi (Blue Team: DKIM selector public key strength evaluation and BIMI anti-impersonation records)
- query_threat_feeds (Threat Intel: Open IOC correlation with URLhaus and AbuseIPDB)
"""

import base64
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from arcanum.agent.tools import (
    NATIVE_TOOLS,
    RECON_TOOLS,
    ANALYSIS_TOOLS,
    ToolExecutor,
)
from arcanum.agent.engine import AgentEngine


# ============================================================================
# 1. Registrations, Normalizer, Risk, and Pedagogical Explanations
# ============================================================================

def test_purple_red_blue_cloud_tools_registrations():
    """Verify all 7 new tools are correctly registered in NATIVE_TOOLS, phases, and executor."""
    tool_names = [t["function"]["name"] for t in NATIVE_TOOLS]
    new_tools = [
        "audit_ssrf_cloud_metadata",
        "calculate_cvss_vector",
        "audit_api_idor_matrix",
        "audit_prototype_pollution",
        "generate_hardening_baseline",
        "audit_dkim_bimi",
        "query_threat_feeds",
    ]
    for nt in new_tools:
        assert nt in tool_names, f"{nt} must be in NATIVE_TOOLS"
        assert nt in ANALYSIS_TOOLS, f"{nt} must be in ANALYSIS_TOOLS"

    # Recon tools check
    assert "audit_dkim_bimi" in RECON_TOOLS
    assert "query_threat_feeds" in RECON_TOOLS

    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for nt in new_tools:
        assert nt in te._handlers, f"{nt} must be registered in ToolExecutor._handlers"


def test_engine_normalizer_and_risk_scoring():
    """Verify AgentEngine normalizer and LOW risk scoring for the 7 tools."""
    norm = AgentEngine._normalize_tool_call_dict({
        "name": "audit_ssrf_cloud_metadata",
        "arguments": {"url": "https://empresa.com.br/api/fetch", "param": "url"}
    })
    assert norm is not None
    assert norm["function"]["name"] == "audit_ssrf_cloud_metadata"

    new_tools = [
        "audit_ssrf_cloud_metadata",
        "calculate_cvss_vector",
        "audit_api_idor_matrix",
        "audit_prototype_pollution",
        "generate_hardening_baseline",
        "audit_dkim_bimi",
        "query_threat_feeds",
    ]
    for nt in new_tools:
        assert AgentEngine._assess_risk(nt, {"url": "https://empresa.com.br"}) == "LOW"


def test_engine_pedagogical_explanations():
    """Verify pedagogical explanations for the 7 new tools in Portuguese."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "alvo.com.br"}

    exp_ssrf = engine._explain_tool_action("audit_ssrf_cloud_metadata", {"url": "https://alvo.com.br/api"})
    assert "SSRF" in exp_ssrf["what"]
    assert "IMDSv2" in exp_ssrf["why"]

    exp_cvss = engine._explain_tool_action("calculate_cvss_vector", {"av": "N", "c": "H"})
    assert "CVSS v3.1" in exp_cvss["what"]

    exp_idor = engine._explain_tool_action("audit_api_idor_matrix", {"endpoints": ["/api/users/{id}"]})
    assert "IDOR/BOLA" in exp_idor["what"]

    exp_proto = engine._explain_tool_action("audit_prototype_pollution", {"url": "https://alvo.com.br"})
    assert "Prototype Pollution" in exp_proto["what"]

    exp_hard = engine._explain_tool_action("generate_hardening_baseline", {"technology": "nginx"})
    assert "Hardening CIS" in exp_hard["what"]

    exp_dkim = engine._explain_tool_action("audit_dkim_bimi", {"domain": "alvo.com.br"})
    assert "DKIM" in exp_dkim["what"]

    exp_threat = engine._explain_tool_action("query_threat_feeds", {"ioc": "alvo.com.br"})
    assert "Threat Intelligence" in exp_threat["what"]


# ============================================================================
# 2. Purple Team: SSRF & Cloud Metadata Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_ssrf_cloud_metadata_vulnerable():
    """Detect SSRF when cloud metadata reflection is present."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_ssrf_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "169.254.169.254" in url:
            resp.text = "ami-id: ami-0123456789abcdef\ninstance-id: i-9876543210\nsecurity-credentials"
        else:
            resp.text = "Error connecting"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_ssrf_get):
        res = await executor._handle_audit_ssrf_cloud_metadata(
            url="https://app.empresa.com.br/api/preview?url=test",
            param_name="url"
        )
        assert res["ssrf_detected"] is True
        assert res["score"] == 10
        assert res["grade"] == "F"
        assert any("SSRF" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_ssrf_cloud_metadata_safe():
    """Verify clean status when target does not reflect any metadata."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_safe_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "Access Denied by WAF"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_safe_get):
        res = await executor._handle_audit_ssrf_cloud_metadata(
            url="https://app.empresa.com.br/api/safe",
            param="url"
        )
        assert res["ssrf_detected"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 3. Purple Team: Mathematical CVSS v3.1 Base Score & Vector Calculator
# ============================================================================

@pytest.mark.asyncio
async def test_calculate_cvss_vector_critical():
    """Verify calculation for maximum critical vector with Scope Changed."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    res = await executor._handle_calculate_cvss_vector(
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
        scope="CHANGED",
        confidentiality="HIGH",
        integrity="HIGH",
        availability="HIGH",
    )
    assert res["cvss_version"] == "3.1"
    assert res["base_score"] == 10.0
    assert res["severity"] == "CRITICAL"
    assert res["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert res["scope_changed"] is True


@pytest.mark.asyncio
async def test_calculate_cvss_vector_unchanged_critical():
    """Verify standard CVSS v3.1 9.8 score for Network/Low/None/None/Unchanged/High/High/High."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    res = await executor._handle_calculate_cvss_vector(
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
        scope="UNCHANGED",
        confidentiality="HIGH",
        integrity="HIGH",
        availability="HIGH",
    )
    assert res["base_score"] == 9.8
    assert res["severity"] == "CRITICAL"
    assert "S:U" in res["vector_string"]


@pytest.mark.asyncio
async def test_calculate_cvss_vector_low_and_zero():
    """Verify calculation for low severity and zero impact."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # Low severity
    res_low = await executor._handle_calculate_cvss_vector(
        av="P", ac="H", pr="H", ui="R", scope="U", c="L", i="N", a="N"
    )
    assert res_low["severity"] in ("LOW", "NONE")
    assert res_low["base_score"] < 4.0

    # Zero impact
    res_zero = await executor._handle_calculate_cvss_vector(
        confidentiality="NONE", integrity="NONE", availability="NONE"
    )
    assert res_zero["base_score"] == 0.0
    assert res_zero["severity"] == "NONE"


# ============================================================================
# 4. Red Team: OWASP API1:2023 BOLA/IDOR Matrix
# ============================================================================

@pytest.mark.asyncio
async def test_audit_api_idor_matrix_detection():
    """Identify sequential and UUID IDOR patterns across API endpoints."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    endpoints = [
        "/api/v1/users/{id}",
        "/api/v1/orders/{order_id}/receipt",
        "/api/v1/documents/{uuid}",
        "/api/v1/invoices/1042/",
        "/api/v1/health",
        "/api/v1/status",
    ]

    res = await executor._handle_audit_api_idor_matrix(endpoints=endpoints)
    assert res["total_endpoints_analyzed"] == 6
    assert res["idor_suspect_endpoints_count"] == 4
    assert res["score"] <= 50
    assert res["grade"] in ("C", "F")
    assert any("BOLA/IDOR" in f["issue"] for f in res["findings"])

    matrix_map = {item["endpoint"]: item for item in res["authorization_matrix"]}
    assert matrix_map["/api/v1/users/{id}"]["idor_suspect"] is True
    assert matrix_map["/api/v1/health"]["idor_suspect"] is False


# ============================================================================
# 5. Red Team: Client-Side Prototype Pollution Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_prototype_pollution_detected():
    """Detect prototype pollution patterns and parameter reflection."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_proto_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "arcanum_test_polluted" in url:
            resp.text = "<html><body>Debug: arcanum_test_polluted=1 reflected</body></html>"
        else:
            resp.text = "<html><script>let target = {}; target.__proto__.admin = true;</script></html>"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_proto_get):
        res = await executor._handle_audit_prototype_pollution("https://app.empresa.com.br")
        assert res["prototype_pollution_risk"] is True
        assert len(res["patterns_detected"]) >= 1
        assert res["score"] <= 60
        assert any("Prototype Pollution" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_prototype_pollution_clean():
    """Verify clean response for application with no prototype pollution."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_clean_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html><body><h1>Bem-vindo</h1></body></html>"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_clean_get):
        res = await executor._handle_audit_prototype_pollution("https://clean.empresa.com.br")
        assert res["prototype_pollution_risk"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 6. Blue Team: CIS Benchmark Hardening Baseline
# ============================================================================

@pytest.mark.asyncio
async def test_generate_hardening_baseline_nginx_and_sysctl():
    """Generate production-ready hardening baselines for Nginx, Linux sysctl, and SSH."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # Nginx
    res_nginx = await executor._handle_generate_hardening_baseline(target_technology="nginx")
    assert "CIS Nginx Benchmark" in res_nginx["benchmark_reference"]
    assert "server_tokens off;" in res_nginx["hardening_snippet"]
    assert "Content-Security-Policy" in res_nginx["hardening_snippet"]
    assert len(res_nginx["deployment_steps"]) >= 2

    # Linux Sysctl
    res_sysctl = await executor._handle_generate_hardening_baseline(technology="linux_sysctl")
    assert "CIS Linux Benchmark" in res_sysctl["benchmark_reference"]
    assert "net.ipv4.tcp_syncookies = 1" in res_sysctl["hardening_snippet"]
    assert "fs.protected_hardlinks = 1" in res_sysctl["hardening_snippet"]

    # SSH
    res_ssh = await executor._handle_generate_hardening_baseline(technology="ssh")
    assert "CIS SSH Server Benchmark" in res_ssh["benchmark_reference"]
    assert "PermitRootLogin no" in res_ssh["hardening_snippet"]


# ============================================================================
# 7. Blue Team: DKIM & BIMI Anti-Impersonation Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_dkim_bimi_weak_key_and_no_bimi():
    """Detect weak RSA 1024-bit DKIM key and missing BIMI record."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # 1024-bit key mock (128 bytes base64)
    dummy_1024_bytes = b"A" * 128
    b64_1024 = base64.b64encode(dummy_1024_bytes).decode("ascii")

    async def mock_doh_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "default._domainkey" in url:
            resp.json = MagicMock(return_value={
                "Answer": [{"data": f'"v=DKIM1; k=rsa; p={b64_1024}"'}]
            })
        else:
            resp.json = MagicMock(return_value={"Answer": []})
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_doh_get):
        res = await executor._handle_audit_dkim_bimi("empresa.com.br", selectors=["default"])
        assert res["dkim_selectors_found"] == 1
        assert res["weak_dkim_keys_count"] == 1
        assert res["dkim_details"][0]["key_length_bits"] == 1024
        assert res["dkim_details"][0]["is_weak"] is True
        assert res["bimi_configured"] is False
        assert any("2048 bits" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_dkim_bimi_strong_and_bimi_present():
    """Verify score 100 when RSA 2048-bit key and BIMI are both present."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    dummy_2048_bytes = b"A" * 256
    b64_2048 = base64.b64encode(dummy_2048_bytes).decode("ascii")

    async def mock_doh_strong(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "default._domainkey" in url:
            resp.json = MagicMock(return_value={
                "Answer": [{"data": f'"v=DKIM1; k=rsa; p={b64_2048}"'}]
            })
        elif "default._bimi" in url:
            resp.json = MagicMock(return_value={
                "Answer": [{"data": '"v=BIMI1; l=https://empresa.com.br/logo.svg; a=https://empresa.com.br/vmc.pem"'}]
            })
        else:
            resp.json = MagicMock(return_value={"Answer": []})
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_doh_strong):
        res = await executor._handle_audit_dkim_bimi("empresa.com.br", selectors=["default"])
        assert res["dkim_selectors_found"] == 1
        assert res["weak_dkim_keys_count"] == 0
        assert res["bimi_configured"] is True
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 8. Threat Intelligence: Open IOC Threat Feeds
# ============================================================================

@pytest.mark.asyncio
async def test_query_threat_feeds_malicious_match():
    """Detect active malware host listing in URLhaus threat feed."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_urlhaus_post(url, data=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.json = MagicMock(return_value={
            "query_status": "ok",
            "urlhaus_reference": "https://urlhaus.abuse.ch/host/malware-c2.net/",
            "urls": [
                {"url": "http://malware-c2.net/payload.exe", "url_status": "online"},
                {"url": "http://malware-c2.net/bot.bin", "url_status": "online"},
            ]
        })
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_urlhaus_post):
        res = await executor._handle_query_threat_feeds(target="malware-c2.net")
        assert res["threat_detected"] is True
        assert res["threat_category"] == "Malware Distribution / C2"
        assert res["score"] == 10
        assert res["grade"] == "F"
        assert any("URLhaus" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_query_threat_feeds_clean():
    """Verify clean status when IOC is not found in threat feeds."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_clean_post(url, data=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.json = MagicMock(return_value={"query_status": "no_results"})
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_clean_post):
        res = await executor._handle_query_threat_feeds(ioc="safe-domain.com.br")
        assert res["threat_detected"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"
