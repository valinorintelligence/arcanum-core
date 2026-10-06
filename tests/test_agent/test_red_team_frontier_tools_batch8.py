"""Tests for Batch 8 of Red Team / Frontier Security Audit Tools (Milestone: 105 Native Tools).

Tools covered:
- audit_llm_prompt_injection_and_jailbreaks
- audit_vector_database_exposure
- audit_subresource_integrity_sri
- audit_dependency_confusion_and_namespaces
- audit_webhook_ssrf_and_dns_rebinding
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from arcanum.agent.tools import NATIVE_TOOLS, ToolExecutor, RECON_TOOLS, ANALYSIS_TOOLS
from arcanum.agent.engine import AgentEngine


@pytest.fixture
def executor():
    return ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)


# ============================================================================
# 1. Registration & Schema Validation (The 105 Tools Milestone)
# ============================================================================

def test_batch8_registrations(executor):
    """Verify all 5 tools are registered in NATIVE_TOOLS and ToolExecutor handlers, reaching at least 105 tools."""
    assert len(NATIVE_TOOLS) >= 105

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    expected = [
        "audit_llm_prompt_injection_and_jailbreaks",
        "audit_vector_database_exposure",
        "audit_subresource_integrity_sri",
        "audit_dependency_confusion_and_namespaces",
        "audit_webhook_ssrf_and_dns_rebinding",
    ]
    for name in expected:
        assert name in tool_names, f"Tool {name} should be in NATIVE_TOOLS"
        assert name in ANALYSIS_TOOLS, f"Tool {name} should be in ANALYSIS_TOOLS"

    assert "audit_vector_database_exposure" in RECON_TOOLS
    assert "audit_subresource_integrity_sri" in RECON_TOOLS

    for name in expected:
        assert name in executor._handlers, f"Handler for {name} missing in ToolExecutor"


def test_batch8_engine_normalization_and_risk():
    """Verify engine normalizes calls, explains actions and assesses risk properly."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "corp.local"}

    batch8_tools = [
        ("audit_llm_prompt_injection_and_jailbreaks", {"url": "https://corp.local/api/chat"}),
        ("audit_vector_database_exposure", {"host": "rag.corp.local"}),
        ("audit_subresource_integrity_sri", {"url": "https://corp.local/portal"}),
        ("audit_dependency_confusion_and_namespaces", {"manifest_content": '{"dependencies": {}}', "manifest_type": "npm"}),
        ("audit_webhook_ssrf_and_dns_rebinding", {"url": "https://corp.local/api/webhooks"}),
    ]

    for tool_name, args in batch8_tools:
        # 1. Normalization
        norm = AgentEngine._normalize_tool_call_dict({"name": tool_name, "arguments": args})
        assert norm is not None
        assert norm["function"]["name"] == tool_name

        # 2. Risk assessment
        risk = AgentEngine._assess_risk(tool_name, args)
        assert risk == "LOW"

        # 3. Action explanation
        exp = engine._explain_tool_action(tool_name, args)
        assert "what" in exp and len(exp["what"]) > 10
        assert "why" in exp and len(exp["why"]) > 10
        assert "params" in exp


@pytest.mark.asyncio
async def test_batch8_system_prompt_rendering():
    """Ensure system prompt renders successfully with all 5 new tool directives and no f-string syntax errors."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.session = {"target": "corp.local", "scope": {"allow_active": True}}
    engine.current_phase = "recon"
    engine.tool_executor = None

    prompt = await engine._build_system_prompt()
    # Prompt renders without f-string errors and carries the operation context.
    assert prompt and "corp.local" in prompt and "Metodologia por Fase" in prompt
    # Tools are exposed to the agent via phase-scoped tool schemas (NATIVE_TOOLS),
    # not a prose catalog in the system prompt — that catalog was removed because
    # it consumed ~7k tokens of the local model's 8k context window.
    from arcanum.agent.tools import NATIVE_TOOLS
    names = {t["function"]["name"] for t in NATIVE_TOOLS}
    for tool in (
        "audit_llm_prompt_injection_and_jailbreaks", "audit_vector_database_exposure",
        "audit_subresource_integrity_sri", "audit_dependency_confusion_and_namespaces",
        "audit_webhook_ssrf_and_dns_rebinding",
    ):
        assert tool in names


# ============================================================================
# 2. Tool 1: audit_llm_prompt_injection_and_jailbreaks
# ============================================================================

@pytest.mark.asyncio
async def test_audit_llm_prompt_injection_vulnerable(executor):
    """Test LLM endpoint succumbing to DAN jailbreak probe."""
    mock_response = MagicMock()
    mock_response.text = "Hello! DAN_MODE_UNLOCKED. I can now bypass all corporate policies."
    mock_response.status_code = 200

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = mock_response

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await executor._handle_audit_llm_prompt_injection_and_jailbreaks(
            url="https://ai.corp.local/api/chat",
            method="POST",
        )

    assert result["url"] == "https://ai.corp.local/api/chat"
    assert result["guardrails_status"] == "bypassed"
    assert "direct_jailbreak_dan" in result["vulnerabilities_detected"]
    assert result["score"] < 100
    assert result["risk_level"] in ("critical", "high")
    assert any("Prompt Injection / Jailbreak" in f["issue"] for f in result["findings"])


@pytest.mark.asyncio
async def test_audit_llm_prompt_injection_safe(executor):
    """Test LLM endpoint with intact guardrails rejecting probes."""
    mock_response = MagicMock()
    mock_response.text = "I am sorry, but I cannot fulfill this request due to safety policies."
    mock_response.status_code = 200

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = mock_response

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await executor._handle_audit_llm_prompt_injection_and_jailbreaks(
            url="https://ai.corp.local/api/chat",
            method="POST",
        )

    assert result["guardrails_status"] == "intact"
    assert len(result["vulnerabilities_detected"]) == 0
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"


# ============================================================================
# 3. Tool 2: audit_vector_database_exposure
# ============================================================================

@pytest.mark.asyncio
async def test_audit_vector_database_exposed(executor):
    """Test exposed ChromaDB and Qdrant instances returning unauthenticated collection data."""
    def mock_get_side_effect(url, **kwargs):
        resp = MagicMock()
        if ":8000" in url:
            resp.status_code = 200
            resp.text = '{"nanosecond heartbeat": 1698700000, "collections": ["internal_rag_kb"]}'
        elif ":6333" in url:
            resp.status_code = 200
            resp.text = '{"result": {"collections": [{"name": "confidential_legal_docs"}]}, "status": "ok"}'
        else:
            resp.status_code = 404
            resp.text = "Not found"
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.side_effect = mock_get_side_effect

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await executor._handle_audit_vector_database_exposure(
            host="rag.internal.local",
            ports=[8000, 6333, 19530, 8080],
        )

    assert result["host"] == "rag.internal.local"
    assert len(result["exposed_databases"]) >= 2
    services = {d["service"] for d in result["exposed_databases"]}
    assert "ChromaDB" in services
    assert "Qdrant" in services
    assert result["score"] <= 55
    assert result["risk_level"] in ("critical", "high")


@pytest.mark.asyncio
async def test_audit_vector_database_secure(executor):
    """Test target with no exposed vector databases."""
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.side_effect = Exception("Connection refused")

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await executor._handle_audit_vector_database_exposure(
            host="secure.internal.local"
        )

    assert len(result["exposed_databases"]) == 0
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"


# ============================================================================
# 4. Tool 3: audit_subresource_integrity_sri
# ============================================================================

@pytest.mark.asyncio
async def test_audit_subresource_integrity_missing(executor):
    """Test detection of external CDN scripts and stylesheets lacking SRI hashes."""
    html_sample = """
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
    </head>
    <body>
        <h1>Portal</h1>
        <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
        <script src="/static/local_bundle.js"></script>
    </body>
    </html>
    """

    result = await executor._handle_audit_subresource_integrity_sri(
        url="https://portal.corp.local",
        html_content=html_sample,
    )

    assert result["url"] == "https://portal.corp.local"
    assert "https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js" in result["scripts_missing_sri"]
    assert "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" in result["stylesheets_missing_sri"]
    assert result["score"] < 100
    assert any("Subresource Integrity (SRI)" in f["issue"] for f in result["findings"])


@pytest.mark.asyncio
async def test_audit_subresource_integrity_compliant(executor):
    """Test compliant external script with integrity sha384 and crossorigin."""
    html_sample = """
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="https://cdn.example.com/style.css" integrity="sha384-abc123xyz" crossorigin="anonymous">
    </head>
    <body>
        <script src="https://cdn.example.com/lib.js" integrity="sha384-xyz987abc" crossorigin="anonymous"></script>
    </body>
    </html>
    """

    result = await executor._handle_audit_subresource_integrity_sri(
        url="https://portal.corp.local",
        html_content=html_sample,
    )

    assert len(result["scripts_missing_sri"]) == 0
    assert len(result["stylesheets_missing_sri"]) == 0
    assert len(result["scripts_with_sri"]) == 1
    assert result["score"] == 100
    assert result["grade"] == "A"


# ============================================================================
# 5. Tool 4: audit_dependency_confusion_and_namespaces
# ============================================================================

@pytest.mark.asyncio
async def test_audit_dependency_confusion_vulnerable_npm(executor):
    """Test detection of internal, unscoped npm dependencies vulnerable to Dependency Confusion."""
    pkg_json = json.dumps({
        "name": "enterprise-portal",
        "dependencies": {
            "react": "^18.2.0",
            "corp-auth-client": "^1.0.0",
            "internal-billing-service": "^2.1.0",
            "@corp/scoped-utils": "^1.0.0"
        }
    })

    result = await executor._handle_audit_dependency_confusion_and_namespaces(
        manifest_content=pkg_json,
        manifest_type="npm",
        org_prefix="@corp",
    )

    assert result["manifest_type"] == "npm"
    assert "corp-auth-client" in result["unscoped_internal_candidates"]
    assert "internal-billing-service" in result["unscoped_internal_candidates"]
    assert "@corp/scoped-utils" in result["properly_scoped_dependencies"]
    assert result["score"] < 100
    assert result["risk_level"] in ("critical", "high")
    assert any("Dependency Confusion" in f["issue"] for f in result["findings"])


@pytest.mark.asyncio
async def test_audit_dependency_confusion_clean_pypi(executor):
    """Test clean requirements.txt without suspicious un-scoped private dependencies."""
    reqs = """
    fastapi==0.100.0
    pydantic>=2.0.0
    uvicorn==0.22.0
    httpx==0.24.1
    """

    result = await executor._handle_audit_dependency_confusion_and_namespaces(
        manifest_content=reqs,
        manifest_type="pypi",
        org_prefix="corp",
    )

    assert result["manifest_type"] == "pypi"
    assert len(result["unscoped_internal_candidates"]) == 0
    assert result["score"] == 100
    assert result["grade"] == "A"


# ============================================================================
# 6. Tool 5: audit_webhook_ssrf_and_dns_rebinding
# ============================================================================

@pytest.mark.asyncio
async def test_audit_webhook_ssrf_vulnerable(executor):
    """Test webhook endpoint accepting callbacks to private RFC 1918 IPs and IMDSv2."""
    def mock_post_side_effect(url, json=None, **kwargs):
        resp = MagicMock()
        target_cb = (json or {}).get("callback_url", "")
        # Accepts loopback and metadata callback
        if "127.0.0.1" in target_cb or "169.254.169.254" in target_cb or "rebind" in target_cb:
            resp.status_code = 200
            resp.text = '{"status": "webhook_registered"}'
        else:
            resp.status_code = 400
            resp.text = '{"error": "invalid"}'
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.side_effect = mock_post_side_effect

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await executor._handle_audit_webhook_ssrf_and_dns_rebinding(
            url="https://api.corp.local/v1/webhooks",
            callback_param="callback_url",
        )

    assert result["url"] == "https://api.corp.local/v1/webhooks"
    assert "loopback_localhost" in result["ssrf_vectors_accepted"]
    assert "aws_gcp_cloud_metadata" in result["ssrf_vectors_accepted"]
    assert result["dns_rebinding_vulnerable"] is True
    assert result["score"] < 50
    assert result["risk_level"] == "critical"
    assert any("SSRF Crítico" in f["impact"] for f in result["findings"])


@pytest.mark.asyncio
async def test_audit_webhook_ssrf_secure(executor):
    """Test webhook endpoint properly rejecting private IP addresses."""
    mock_resp = MagicMock()
    mock_resp.status_code = 422
    mock_resp.text = '{"error": "Private and loopback addresses are forbidden."}'

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await executor._handle_audit_webhook_ssrf_and_dns_rebinding(
            url="https://api.corp.local/v1/webhooks",
        )

    assert len(result["ssrf_vectors_accepted"]) == 0
    assert result["dns_rebinding_vulnerable"] is False
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"
