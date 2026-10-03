"""Unit and integration tests for Arcanum's Purple Team, Blue Team, and Red Team tools:
- map_mitre_attack (MITRE ATT&CK Enterprise tactics and techniques mapping)
- generate_detection_rules (Sigma YAML, ModSecurity WAF, and Suricata IDS rule synthesis)
- audit_jwt_security (JWT alg:none, weak HMAC secrets, expiry, and PII leakage)
- audit_rate_limiting (Brute-force resilience, RateLimit headers, and HTTP 429 verification)
- audit_websocket_security (TLS enforcement, Origin handshake validation, and CSWSH audit)
- audit_supply_chain_libs (Front-end JS library versions, CVE matching, and SRI audit)
- audit_compliance_matrix (OWASP Top 10 2021 & LGPD Art. 46/48 compliance scoring)
"""

from unittest.mock import AsyncMock, MagicMock, patch
import base64
import hmac
import hashlib
import json
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
# 1. Registrations, Normalizer, Risk, and Pedagogical Explanations
# ============================================================================

def test_purple_and_blue_tools_registrations():
    """Verify all 7 new tools are correctly registered in NATIVE_TOOLS, phases, and executor."""
    tool_names = [t["function"]["name"] for t in NATIVE_TOOLS]
    new_tools = [
        "map_mitre_attack",
        "generate_detection_rules",
        "audit_jwt_security",
        "audit_rate_limiting",
        "audit_websocket_security",
        "audit_supply_chain_libs",
        "audit_compliance_matrix",
    ]
    for nt in new_tools:
        assert nt in tool_names, f"{nt} must be in NATIVE_TOOLS"

    # Verify phase presence
    for nt in new_tools:
        assert nt in ANALYSIS_TOOLS, f"{nt} must be in ANALYSIS_TOOLS"

    assert "audit_rate_limiting" in RECON_TOOLS
    assert "audit_websocket_security" in RECON_TOOLS
    assert "audit_supply_chain_libs" in RECON_TOOLS
    assert "map_mitre_attack" in RECON_TOOLS

    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for nt in new_tools:
        assert nt in te._handlers, f"{nt} must be registered in ToolExecutor._handlers"


def test_engine_normalizer_and_risk_scoring():
    """Verify AgentEngine normalizer and LOW risk scoring for all 7 tools."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "empresa.com.br", "scope": {"include": ["empresa.com.br"]}}

    norm = AgentEngine._normalize_tool_call_dict({
        "name": "map_mitre_attack",
        "arguments": {"findings": ["sql injection"]}
    })
    assert norm is not None
    assert norm["function"]["name"] == "map_mitre_attack"

    new_tools = [
        "map_mitre_attack",
        "generate_detection_rules",
        "audit_jwt_security",
        "audit_rate_limiting",
        "audit_websocket_security",
        "audit_supply_chain_libs",
        "audit_compliance_matrix",
    ]
    for nt in new_tools:
        assert AgentEngine._assess_risk(nt, {"url": "https://empresa.com.br"}) == "LOW"


def test_engine_pedagogical_explanations():
    """Verify pedagogical explanations for all 7 tools in Portuguese."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "alvo.com.br"}

    exp_mitre = engine._explain_tool_action("map_mitre_attack", {"findings": ["xss"]})
    assert "MITRE ATT&CK" in exp_mitre["what"]
    assert "Táticas" in exp_mitre["why"]

    exp_rules = engine._explain_tool_action("generate_detection_rules", {"finding_type": "sql_injection"})
    assert "Sigma" in exp_rules["what"]
    assert "Purple Team" in exp_rules["why"]

    exp_jwt = engine._explain_tool_action("audit_jwt_security", {"token": "a.b.c"})
    assert "JSON Web Token" in exp_jwt["what"]

    exp_rate = engine._explain_tool_action("audit_rate_limiting", {"url": "https://alvo.com.br/login"})
    assert "força bruta" in exp_rate["what"]

    exp_ws = engine._explain_tool_action("audit_websocket_security", {"url": "wss://alvo.com.br/ws"})
    assert "WebSocket" in exp_ws["what"]

    exp_sc = engine._explain_tool_action("audit_supply_chain_libs", {"url": "https://alvo.com.br"})
    assert "supply chain" in exp_sc["what"].lower()

    exp_comp = engine._explain_tool_action("audit_compliance_matrix", {"target": "alvo.com.br"})
    assert "LGPD" in exp_comp["what"]


# ============================================================================
# 2. Purple Team: MITRE ATT&CK Mapping
# ============================================================================

@pytest.mark.asyncio
async def test_map_mitre_attack_findings_and_ports():
    """Map vulnerabilities, cloud exposure, and open ports to MITRE ATT&CK."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    findings = [
        "Vulnerabilidade de SQL Injection no login",
        "Subdomain Takeover no AWS S3 bucket",
        "Exposição de secret token em script cliente",
    ]
    technologies = ["nginx", "wordpress"]
    open_ports = [80, 443, 8080]

    res = await executor._handle_map_mitre_attack(
        findings=findings,
        technologies=technologies,
        open_ports=open_ports,
    )

    assert res["total_techniques_mapped"] >= 4
    assert "Reconnaissance" in res["tactics_covered"]
    assert "Initial Access" in res["tactics_covered"]
    assert "Credential Access" in res["tactics_covered"]
    assert "Collection" in res["tactics_covered"]
    assert len(res["defensive_gaps"]) >= 1


# ============================================================================
# 3. Purple/Blue Team: Defensive Detection Rules
# ============================================================================

@pytest.mark.asyncio
async def test_generate_detection_rules_sqli():
    """Generate Sigma YAML, ModSecurity SecRule, and Suricata IDS rule for SQLi."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    res = await executor._handle_generate_detection_rules(
        finding_type="sql_injection",
        target_path="/api/v1/search",
    )

    assert "title: SQL Injection Attempt on /api/v1/search" in res["sigma_rule_yaml"]
    assert "logsource:" in res["sigma_rule_yaml"]
    assert "SecRule REQUEST_URI" in res["modsecurity_rule"]
    assert "OWASP_CRS/WEB_ATTACK/SQL_INJECTION" in res["modsecurity_rule"]
    assert "alert http" in res["suricata_rule"]
    assert "/api/v1/search" in res["suricata_rule"]


# ============================================================================
# 4. Blue/Red Team: JWT Security Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_jwt_security_alg_none():
    """Detect critical alg:none flaw in JWT."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # Header with alg none
    h_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "admin": True}).encode()).decode().rstrip("=")
    raw_jwt = f"{h_b64}.{p_b64}."

    res = await executor._handle_audit_jwt_security(raw_jwt)
    assert res["valid_format"] is True
    assert res["vulnerable"] is True
    assert res["score"] == 0
    assert res["grade"] == "F"
    assert any("Algoritmo 'none'" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_jwt_security_weak_hmac_secret():
    """Detect and crack weak HMAC secret ('secret') with PII exposure."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    secret = "secret"
    h_bytes = json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    p_bytes = json.dumps({"sub": "user123", "cpf": "123.456.789-00", "exp": 9999999999}).encode()

    h_b64 = base64.urlsafe_b64encode(h_bytes).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(p_bytes).decode().rstrip("=")
    head_payload = f"{h_b64}.{p_b64}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), head_payload, hashlib.sha256).digest()).decode().rstrip("=")

    raw_jwt = f"{h_b64}.{p_b64}.{sig}"
    res = await executor._handle_audit_jwt_security(raw_jwt)

    assert res["valid_format"] is True
    assert res["weak_secret_cracked"] is True
    assert res["payload"]["cpf"] == "***MASKED***"
    assert res["score"] <= 10
    assert any("Chave secreta HMAC fraca" in f["issue"] for f in res["findings"])


# ============================================================================
# 5. Blue Team: Rate Limiting & Brute-Force Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_rate_limiting_triggered():
    """Detect rate limit triggered via 429 response and standard headers."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp_ok = MagicMock()
    mock_resp_ok.status_code = 200
    mock_resp_ok.headers = {"X-RateLimit-Limit": "5", "X-RateLimit-Remaining": "3"}

    mock_resp_limit = MagicMock()
    mock_resp_limit.status_code = 429
    mock_resp_limit.headers = {"Retry-After": "60", "X-RateLimit-Remaining": "0"}

    call_count = 0
    async def custom_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count >= 3:
            return mock_resp_limit
        return mock_resp_ok

    with patch("httpx.AsyncClient.get", side_effect=custom_get):
        res = await executor._handle_audit_rate_limiting("https://empresa.com.br/api/login", probes_count=5)
        assert res["rate_limit_active"] is True
        assert res["http_429_received"] is True
        assert "x-ratelimit-limit" in res["rate_limit_headers"]
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 6. Red Team: WebSocket & CSWSH Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_websocket_security_cswsh_vulnerable():
    """Detect CSWSH vulnerability when handshake returns 101 for untrusted origin."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_handshake = MagicMock()
    mock_handshake.status_code = 101

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_handshake
        res = await executor._handle_audit_websocket_security("ws://chat.empresa.com.br/socket")
        assert res["tls_enforced"] is False
        assert res["cswsh_vulnerable"] is True
        assert res["grade"] == "F"
        assert any("Cross-Site WebSocket Hijacking" in f["issue"] for f in res["findings"])
        assert any("não criptografado" in f["issue"] for f in res["findings"])


# ============================================================================
# 7. Red/Blue Team: Client-Side Supply Chain Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_supply_chain_libs_vulnerable_jquery_and_missing_sri():
    """Detect vulnerable jQuery version and missing Subresource Integrity on external CDN."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://code.jquery.com/jquery-3.3.1.min.js"></script>
        <script src="/local/app.js"></script>
    </head>
    <body><h1>Home</h1></body>
    </html>
    """

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = html_content

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_audit_supply_chain_libs("https://site.com.br")
        assert res["missing_sri_count"] == 1
        assert len(res["detected_vulnerable_libraries"]) == 1
        assert res["detected_vulnerable_libraries"][0]["name"] == "jquery"
        assert res["detected_vulnerable_libraries"][0]["version"] == "3.3.1"
        assert any("CVE-2020-11022" in f["issue"] for f in res["findings"])
        assert any("Subresource Integrity" in f["issue"] for f in res["findings"])


# ============================================================================
# 8. Governance: OWASP Top 10 & LGPD Compliance Matrix
# ============================================================================

@pytest.mark.asyncio
async def test_audit_compliance_matrix_with_findings():
    """Verify OWASP Top 10 and LGPD compliance matrix computation."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    findings = [
        "Vulnerabilidade de SQL Injection no login",
        "Vulnerabilidade de CORS com credenciais",
        "Vazamento de secret token de API no código cliente",
    ]

    res = await executor._handle_audit_compliance_matrix("portal.empresa.com.br", findings_summary=findings)
    assert res["target"] == "portal.empresa.com.br"
    assert res["owasp_top_10"]["compliance_percentage"] < 100
    assert res["owasp_top_10"]["matrix"]["A01: Broken Access Control"]["status"] == "NON_COMPLIANT"
    assert res["owasp_top_10"]["matrix"]["A03: Injection"]["status"] == "NON_COMPLIANT"
    assert res["lgpd"]["articles"]["Art. 46 (Segurança e Sigilo de Dados)"]["compliant"] is False
    assert "conformidade" in res["executive_summary"].lower()
