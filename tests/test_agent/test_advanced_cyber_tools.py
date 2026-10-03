"""Unit and integration tests for Arcanum's 4 advanced cybersecurity audit tools:
- audit_subdomain_takeover (CNAME orphan cloud detection via DoH)
- detect_waf_firewall (WAF/CDN banner, header, and probe fingerprinting)
- audit_cors_advanced (SOP bypass, origin reflection, and credential exposure)
- audit_http_methods (OPTIONS verb inspection, TRACE & XST vulnerability checks)
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from arcanum.agent.tools import (
    NATIVE_TOOLS,
    RECON_TOOLS,
    ANALYSIS_TOOLS,
    ToolExecutor,
    get_tools_for_phase,
)
from arcanum.agent.engine import AgentEngine


# ============================================================================
# 1. Tool Registration & Engine Architecture Integration
# ============================================================================

def test_advanced_cyber_tools_registration():
    """Verify all 4 new tools are registered across tools.py data structures and executor handlers."""
    tool_names = [t["function"]["name"] for t in NATIVE_TOOLS]
    new_tools = [
        "audit_subdomain_takeover",
        "detect_waf_firewall",
        "audit_cors_advanced",
        "audit_http_methods",
    ]
    for nt in new_tools:
        assert nt in tool_names, f"{nt} must be registered in NATIVE_TOOLS"

    # Recon phase tools
    assert "audit_subdomain_takeover" in RECON_TOOLS
    assert "detect_waf_firewall" in RECON_TOOLS
    assert "audit_http_methods" in RECON_TOOLS

    # Analysis phase tools
    assert "audit_subdomain_takeover" in ANALYSIS_TOOLS
    assert "detect_waf_firewall" in ANALYSIS_TOOLS
    assert "audit_cors_advanced" in ANALYSIS_TOOLS
    assert "audit_http_methods" in ANALYSIS_TOOLS

    # Phase subsets
    recon_names = [t["function"]["name"] for t in get_tools_for_phase("recon")]
    analysis_names = [t["function"]["name"] for t in get_tools_for_phase("analysis")]
    assert "detect_waf_firewall" in recon_names
    assert "audit_cors_advanced" in analysis_names

    # Executor handlers
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for nt in new_tools:
        assert nt in te._handlers, f"Handler for {nt} must be registered in ToolExecutor._handlers"


def test_engine_normalizer_and_risk_assessment():
    """Verify AgentEngine recognizes the new tools in normalizer, scope checking, and risk scoring."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "recon"
    engine.session = {"target": "exemplo.com.br", "scope": {"include": ["exemplo.com.br"]}}

    # Normalizer test
    norm = AgentEngine._normalize_tool_call_dict({
        "name": "detect_waf_firewall",
        "arguments": {"url": "https://exemplo.com.br"}
    })
    assert norm is not None
    assert norm["function"]["name"] == "detect_waf_firewall"

    # Risk level test (defensive audit tools must be LOW)
    assert AgentEngine._assess_risk("audit_subdomain_takeover", {"domain": "sub.exemplo.com.br"}) == "LOW"
    assert AgentEngine._assess_risk("detect_waf_firewall", {"url": "https://exemplo.com.br"}) == "LOW"
    assert AgentEngine._assess_risk("audit_cors_advanced", {"url": "https://exemplo.com.br"}) == "LOW"
    assert AgentEngine._assess_risk("audit_http_methods", {"url": "https://exemplo.com.br"}) == "LOW"


def test_engine_explanations():
    """Verify pedagogical explanations in Portuguese for all 4 tools."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "recon"
    engine.session = {"target": "alvo.com.br"}

    exp_takeover = engine._explain_tool_action("audit_subdomain_takeover", {"domain": "blog.alvo.com.br"})
    assert "Subdomain Takeover" in exp_takeover["what"]
    assert "CNAME" in exp_takeover["why"]

    exp_waf = engine._explain_tool_action("detect_waf_firewall", {"url": "https://alvo.com.br"})
    assert "WAF" in exp_waf["what"]
    assert "Cloudflare" in exp_waf["why"]

    exp_cors = engine._explain_tool_action("audit_cors_advanced", {"url": "https://alvo.com.br/api"})
    assert "CORS" in exp_cors["what"]
    assert "Origin" in exp_cors["why"]

    exp_http = engine._explain_tool_action("audit_http_methods", {"url": "https://alvo.com.br"})
    assert "métodos" in exp_http["what"].lower()
    assert "TRACE" in exp_http["why"]


# ============================================================================
# 2. Subdomain Takeover Vulnerability Audit
# ============================================================================

@pytest.mark.asyncio
async def test_subdomain_takeover_no_cname():
    """When a domain has no CNAME, report as not vulnerable."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = MagicMock(return_value={"Answer": [{"type": 1, "data": "93.184.216.34"}]})

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_audit_subdomain_takeover("direct.example.com")
        assert res["has_cname"] is False
        assert res["vulnerable"] is False
        assert res["status"] == "NOT_VULNERABLE"


@pytest.mark.asyncio
async def test_subdomain_takeover_vulnerable_aws_s3():
    """Detect orphaned AWS S3 bucket CNAME and match NoSuchBucket fingerprint."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # 1. Mock DoH response with CNAME to s3
    doh_mock = MagicMock()
    doh_mock.status_code = 200
    doh_mock.json = MagicMock(return_value={
        "Answer": [{"type": 5, "data": "orphan-bucket.s3.amazonaws.com."}]
    })

    # 2. Mock HTTP probe response returning S3 404 NoSuchBucket
    http_mock = MagicMock()
    http_mock.status_code = 404
    http_mock.text = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"

    async def custom_get(url, *args, **kwargs):
        if "cloudflare-dns.com" in str(url):
            return doh_mock
        return http_mock

    with patch("httpx.AsyncClient.get", side_effect=custom_get):
        res = await executor._handle_audit_subdomain_takeover("storage.empresa.com.br")
        assert res["has_cname"] is True
        assert res["cname_target"] == "orphan-bucket.s3.amazonaws.com"
        assert res["matched_service"] == "AWS S3 Bucket"
        assert res["vulnerable"] is True
        assert res["score"] == 0
        assert res["grade"] == "F"
        assert len(res["findings"]) == 1
        assert "Subdomain Takeover" in res["findings"][0]["issue"]


# ============================================================================
# 3. WAF & Reverse Proxy Detection
# ============================================================================

@pytest.mark.asyncio
async def test_detect_waf_cloudflare_headers():
    """Detect Cloudflare via cf-ray and Server header with high confidence and tactical guidance."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "server": "cloudflare",
        "cf-ray": "8db30f81b19a-GRU",
        "cf-cache-status": "DYNAMIC",
    }
    mock_resp.text = "<html>Protected by Cloudflare</html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_detect_waf_firewall("https://alvo-protegido.com.br")
        assert res["waf_detected"] is True
        assert "Cloudflare" in res["waf_vendor"]
        assert res["confidence"] == "HIGH"
        assert "cf-ray" in res["detected_headers"]
        assert "Cloudflare ativo na borda" in res["tactical_guidance"]


@pytest.mark.asyncio
async def test_detect_waf_clean_server():
    """Verify clean baseline web server without WAF flags."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"server": "nginx/1.24.0"}
    mock_resp.text = "<html>Welcome to nginx</html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_detect_waf_firewall("http://servidor-limpo.local")
        assert res["waf_detected"] is False
        assert res["confidence"] == "NONE"
        assert "Varreduras padrão autorizadas" in res["tactical_guidance"]


# ============================================================================
# 4. Advanced CORS Misconfiguration Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_cors_critical_origin_reflection_with_credentials():
    """Detect critical CORS vulnerability when origin is reflected and credentials allowed."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_cors_get(url, headers=None, *args, **kwargs):
        origin = headers.get("Origin", "")
        resp = MagicMock()
        resp.status_code = 200
        # Dangerously reflects the Origin back with credentials true!
        resp.headers = {
            "access-control-allow-origin": origin,
            "access-control-allow-credentials": "true",
        }
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_cors_get):
        res = await executor._handle_audit_cors_advanced("https://api.banco.com/v1/user")
        assert res["vulnerable"] is True
        assert res["score"] == 20
        assert res["grade"] == "F"
        assert any(f["severity"] == "critical" for f in res["findings"])
        assert any("Vulnerabilidade Crítica de CORS" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_cors_safe_configuration():
    """Verify strict CORS configuration passes without vulnerabilities."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "access-control-allow-origin": "https://allowed.empresa.com.br",
        "access-control-allow-credentials": "false",
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_audit_cors_advanced("https://api.empresa.com.br")
        assert res["vulnerable"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"
        assert len(res["findings"]) == 0


# ============================================================================
# 5. Supported & Risky HTTP Methods Audit (OPTIONS & TRACE / XST)
# ============================================================================

@pytest.mark.asyncio
async def test_audit_http_methods_trace_and_xst_vulnerability():
    """Detect TRACE enabled reflecting request header and unsafe PUT/DELETE verbs."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # 1. OPTIONS response
    mock_options = MagicMock()
    mock_options.status_code = 200
    mock_options.headers = {"allow": "GET, POST, OPTIONS, TRACE, PUT, DELETE"}

    # 2. TRACE response reflecting test header
    mock_trace = MagicMock()
    mock_trace.status_code = 200
    mock_trace.text = "TRACE / HTTP/1.1\r\nHost: alvo.com\r\nX-Arcanum-XST: ArcanumXSTTestToken123\r\n\r\n"

    with patch("httpx.AsyncClient.options", new_callable=AsyncMock) as mock_opt_call, \
         patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req_call:
        mock_opt_call.return_value = mock_options
        mock_req_call.return_value = mock_trace

        res = await executor._handle_audit_http_methods("https://alvo.com.br")
        assert res["trace_enabled"] is True
        assert res["xst_vulnerable"] is True
        assert "PUT" in res["dangerous_methods"]
        assert "DELETE" in res["dangerous_methods"]
        assert any("Cross-Site Tracing" in f["issue"] for f in res["findings"])
        assert any(f["severity"] == "high" for f in res["findings"])
        assert res["score"] <= 40


@pytest.mark.asyncio
async def test_audit_http_methods_safe():
    """Verify safe HTTP methods configuration (no TRACE, no PUT/DELETE)."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_options = MagicMock()
    mock_options.status_code = 200
    mock_options.headers = {"allow": "GET, HEAD, POST, OPTIONS"}

    mock_trace = MagicMock()
    mock_trace.status_code = 405
    mock_trace.text = "Method Not Allowed"

    with patch("httpx.AsyncClient.options", new_callable=AsyncMock) as mock_opt_call, \
         patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req_call:
        mock_opt_call.return_value = mock_options
        mock_req_call.return_value = mock_trace

        res = await executor._handle_audit_http_methods("https://alvo.com.br")
        assert res["trace_enabled"] is False
        assert res["xst_vulnerable"] is False
        assert len(res["dangerous_methods"]) == 0
        assert res["score"] == 100
        assert res["grade"] == "A"
        assert len(res["findings"]) == 0
