"""Unit and integration tests for Arcanum's Advanced Purple, Red, and Blue Team tools:
- generate_atomic_test (Atomic Red Team simulation script generation)
- simulate_attack_path (Graph attack paths, multi-hop chaining, and choke points)
- audit_graphql_security (GraphQL Introspection, field suggestions, and batching)
- audit_oauth_sso (OAuth 2.0 / OIDC redirect_uri, state CSRF, and implicit flow)
- generate_ir_playbook (Incident Response Playbook NIST SP 800-61 / SANS)
- audit_dnsbl_reputation (Global DNSBL / RBL blacklist reputation query)
- generate_canary_tokens (Cyber deception, honeytokens, and canary credentials)
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
# 1. Registrations, Normalizer, Risk, and Pedagogical Explanations
# ============================================================================

def test_purple_red_blue_advanced_registrations():
    """Verify all 7 new tools are correctly registered in NATIVE_TOOLS, phases, and executor."""
    tool_names = [t["function"]["name"] for t in NATIVE_TOOLS]
    new_tools = [
        "generate_atomic_test",
        "simulate_attack_path",
        "audit_graphql_security",
        "audit_oauth_sso",
        "generate_ir_playbook",
        "audit_dnsbl_reputation",
        "generate_canary_tokens",
    ]
    for nt in new_tools:
        assert nt in tool_names, f"{nt} must be in NATIVE_TOOLS"
        assert nt in ANALYSIS_TOOLS, f"{nt} must be in ANALYSIS_TOOLS"

    # Recon tools check
    assert "audit_graphql_security" in RECON_TOOLS
    assert "audit_oauth_sso" in RECON_TOOLS
    assert "audit_dnsbl_reputation" in RECON_TOOLS

    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for nt in new_tools:
        assert nt in te._handlers, f"{nt} must be registered in ToolExecutor._handlers"


def test_engine_normalizer_and_risk_scoring():
    """Verify AgentEngine normalizer and LOW risk scoring for the 7 tools."""
    norm = AgentEngine._normalize_tool_call_dict({
        "name": "audit_graphql_security",
        "arguments": {"url": "https://empresa.com.br/graphql"}
    })
    assert norm is not None
    assert norm["function"]["name"] == "audit_graphql_security"

    new_tools = [
        "generate_atomic_test",
        "simulate_attack_path",
        "audit_graphql_security",
        "audit_oauth_sso",
        "generate_ir_playbook",
        "audit_dnsbl_reputation",
        "generate_canary_tokens",
    ]
    for nt in new_tools:
        assert AgentEngine._assess_risk(nt, {"url": "https://empresa.com.br"}) == "LOW"


def test_engine_pedagogical_explanations():
    """Verify pedagogical explanations for the 7 new tools in Portuguese."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "alvo.com.br"}

    exp_atom = engine._explain_tool_action("generate_atomic_test", {"technique_id": "T1190"})
    assert "Atomic Red Team" in exp_atom["what"]

    exp_path = engine._explain_tool_action("simulate_attack_path", {"entry_point": "Internet"})
    assert "Attack Path" in exp_path["what"]

    exp_gql = engine._explain_tool_action("audit_graphql_security", {"url": "https://alvo.com.br/graphql"})
    assert "GraphQL" in exp_gql["what"]

    exp_oauth = engine._explain_tool_action("audit_oauth_sso", {"authorization_url": "https://auth.alvo.com.br"})
    assert "OAuth" in exp_oauth["what"]

    exp_ir = engine._explain_tool_action("generate_ir_playbook", {"incident_type": "data_exfiltration"})
    assert "NIST 800-61" in exp_ir["what"]

    exp_dnsbl = engine._explain_tool_action("audit_dnsbl_reputation", {"target": "1.2.3.4"})
    assert "DNSBL" in exp_dnsbl["what"]

    exp_canary = engine._explain_tool_action("generate_canary_tokens", {"token_type": "aws_key"})
    assert "Honeytoken" in exp_canary["what"]


# ============================================================================
# 2. Purple Team: Atomic Red Team Test Generation
# ============================================================================

@pytest.mark.asyncio
async def test_generate_atomic_test_t1190_powershell_and_bash():
    """Generate safe adversary simulation tests for T1190."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # PowerShell
    res_ps = await executor._handle_generate_atomic_test("T1190", target_url="https://alvo.com.br", platform="powershell")
    assert res_ps["technique_id"] == "T1190"
    assert res_ps["platform"] == "powershell"
    assert "Invoke-WebRequest" in res_ps["test_command"]
    assert "https://alvo.com.br" in res_ps["test_command"]
    assert "WAF alert" in res_ps["expected_detection"]

    # Bash
    res_bash = await executor._handle_generate_atomic_test("T1190", target_url="https://alvo.com.br", platform="bash")
    assert res_bash["platform"] == "bash"
    assert "curl" in res_bash["test_command"]


# ============================================================================
# 3. Purple Team: Attack Path & Choke Point Simulation
# ============================================================================

@pytest.mark.asyncio
async def test_simulate_attack_path_multi_hop():
    """Simulate attack chain from external internet to database crown jewels."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    findings = [
        "Injeção de SQL em /api/search",
        "Vulnerabilidade de CORS em /api/profile",
    ]

    res = await executor._handle_simulate_attack_path(
        entry_point="Porta 443 Web",
        target_asset="Banco PostgreSQL de Clientes",
        findings=findings,
    )

    assert res["total_hops"] == 4
    assert res["overall_path_risk"] >= 7.0
    assert len(res["critical_choke_points"]) >= 1
    assert any("Prepared Statements" in cp for cp in res["critical_choke_points"])
    assert "T1190" in res["attack_path"][1]["mitre_technique"]


# ============================================================================
# 4. Red Team: GraphQL Endpoint Security Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_graphql_security_vulnerable():
    """Detect GraphQL endpoint with Introspection enabled, field suggestions, and batching."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # Mock responses for GraphQL probes
    async def mock_post(url, json=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if isinstance(json, list):
            # Batching probe
            resp.json = MagicMock(return_value=[{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}])
            resp.text = '[{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}]'
        elif "__schema" in json.get("query", ""):
            # Introspection probe
            resp.json = MagicMock(return_value={
                "data": {
                    "__schema": {
                        "types": [{"name": "User"}, {"name": "AdminRole"}, {"name": "CreditCard"}]
                    }
                }
            })
            resp.text = '{"data": {"__schema": {"types": [{"name": "User"}]}}}'
        elif "__schma" in json.get("query", ""):
            # Typo query probe for field suggestions
            resp.text = '{"errors": [{"message": "Cannot query field \'__schma\'. Did you mean \'__schema\'?"}]}'
        else:
            resp.text = '{"data": {}}'
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_post):
        res = await executor._handle_audit_graphql_security("https://api.empresa.com.br/graphql")
        assert res["graphql_detected"] is True
        assert res["introspection_enabled"] is True
        assert res["extracted_types_count"] == 3
        assert res["field_suggestions_enabled"] is True
        assert res["batching_supported"] is True
        assert res["score"] <= 40
        assert res["grade"] == "F"
        assert any("GraphQL Introspection" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_graphql_security_not_found():
    """Return clean status when no GraphQL endpoints exist."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "404 Not Found"

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await executor._handle_audit_graphql_security("https://site-estatico.com.br")
        assert res["graphql_detected"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 5. Red Team: OAuth 2.0 & SSO Flow Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_oauth_sso_vulnerabilities():
    """Detect OAuth endpoint with missing state CSRF and open redirect_uri reflection."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_oauth_get(url, *args, **kwargs):
        resp = MagicMock()
        if "evil-attacker.example.com" in url:
            resp.status_code = 302
            resp.headers = {"location": "https://evil-attacker.example.com/oauth/steal?code=stolen123"}
            resp.text = ""
        elif "response_type=token" in url:
            resp.status_code = 200
            resp.text = "<html>Login with token</html>"
        else:
            resp.status_code = 200
            resp.text = "<html>Authorize Login</html>"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_oauth_get):
        res = await executor._handle_audit_oauth_sso("https://auth.empresa.com.br/oauth/authorize")
        assert res["state_parameter_enforced"] is False
        assert res["implicit_flow_supported"] is True
        assert res["open_redirect_detected"] is True
        assert res["vulnerable"] is True
        assert res["score"] <= 30
        assert res["grade"] == "F"
        assert any("redirect_uri" in f["issue"] for f in res["findings"])
        assert any("CSRF" in f["issue"] for f in res["findings"])


# ============================================================================
# 6. Blue Team: Incident Response Playbook Synthesis
# ============================================================================

@pytest.mark.asyncio
async def test_generate_ir_playbook_data_exfiltration():
    """Synthesize NIST SP 800-61 / SANS incident response playbook for data leak."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    res = await executor._handle_generate_ir_playbook(
        incident_type="data_exfiltration",
        affected_asset="cluster-db.empresa.internal",
        severity="CRITICAL",
    )

    assert "NIST SP 800-61" in res["framework"]
    assert "cluster-db.empresa.internal" in res["playbook_title"]
    assert len(res["phases"]["3_containment"]) >= 2
    assert len(res["phases"]["4_eradication"]) >= 1
    assert any("ss -tunap" in cmd for cmd in res["cli_evidence_commands"])


# ============================================================================
# 7. Blue Team: IP/Domain Reputation & DNSBL Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_dnsbl_reputation_clean():
    """Query DNSBL providers via DoH and return clean status."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = MagicMock(return_value={"Answer": []})

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_audit_dnsbl_reputation("203.0.113.50")
        assert res["is_blacklisted"] is False
        assert res["blacklists_count"] == 0
        assert res["reputation_status"] == "CLEAN"
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 8. Active Defense: Honeytokens & Canary Assets
# ============================================================================

@pytest.mark.asyncio
async def test_generate_canary_tokens_aws_and_jwt():
    """Generate AWS IAM canary keys and fake JWT honeytokens."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # AWS Canary
    res_aws = await executor._handle_generate_canary_tokens(
        token_type="aws_key",
        memo="Planted in staging server .env",
    )
    assert res_aws["status"] == "ARMED_AND_READY"
    assert res_aws["canary_payload"]["aws_access_key_id"].startswith("AKIA")
    assert "CloudTrail" in res_aws["detection_mechanism"]
    assert len(res_aws["deployment_recommendations"]) >= 1

    # JWT Honeytoken
    res_jwt = await executor._handle_generate_canary_tokens(
        token_type="jwt_honeytoken",
        memo="Injected in test database users table",
    )
    assert res_jwt["status"] == "ARMED_AND_READY"
    assert res_jwt["canary_payload"]["token"].startswith("eyJ")
    assert "WAF" in res_jwt["detection_mechanism"]
