"""Unit tests for the 5 advanced Red Team frontier tools (Batch 2) in Arcanum.

Tools tested:
1. audit_race_conditions_concurrency (Concurrency / Limit Overrun / TOCTOU)
2. audit_dom_clobbering (DOM Clobbering & Client Execution Hijacking)
3. audit_xxe_injection (XML External Entity & DTD Resolution)
4. audit_open_redirect_bypasses (12 Modern Filter Bypass Techniques)
5. audit_ldap_injection (Active Directory / OpenLDAP Filter Injection)
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

def test_batch2_registrations():
    """Verify all 5 tools are registered in NATIVE_TOOLS and ToolExecutor handlers."""
    assert len(NATIVE_TOOLS) >= 76

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    expected = [
        "audit_race_conditions_concurrency",
        "audit_dom_clobbering",
        "audit_xxe_injection",
        "audit_open_redirect_bypasses",
        "audit_ldap_injection",
    ]
    for name in expected:
        assert name in tool_names, f"Missing tool in NATIVE_TOOLS: {name}"

    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for name in expected:
        assert name in executor._handlers, f"Missing handler in ToolExecutor: {name}"

    assert "audit_open_redirect_bypasses" in RECON_TOOLS
    assert "audit_dom_clobbering" in RECON_TOOLS

    for name in expected:
        assert name in ANALYSIS_TOOLS


def test_batch2_normalizer_and_risk_scoring():
    """Verify tool normalization and low-risk rating in AgentEngine."""
    expected = [
        "audit_race_conditions_concurrency",
        "audit_dom_clobbering",
        "audit_xxe_injection",
        "audit_open_redirect_bypasses",
        "audit_ldap_injection",
    ]
    for name in expected:
        norm = AgentEngine._normalize_tool_call_dict({"name": name, "arguments": {}})
        assert norm is not None, f"Failed to normalize {name}"
        assert norm["function"]["name"] == name

        risk = AgentEngine._assess_risk(name, {})
        assert risk == "LOW", f"Risk for {name} should be LOW, got {risk}"


def test_batch2_pedagogical_explanations():
    """Verify pedagogical explanations for the 5 tools in Portuguese."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "corp.com.br"}

    exp_race = engine._explain_tool_action("audit_race_conditions_concurrency", {"url": "https://corp.com.br/api/coupon"})
    assert "corrida" in exp_race["what"].lower() or "race" in exp_race["what"].lower()
    assert "toctou" in exp_race["why"].lower() or "concorrência" in exp_race["why"].lower()

    exp_dom = engine._explain_tool_action("audit_dom_clobbering", {"url": "https://corp.com.br"})
    assert "dom clobbering" in exp_dom["what"].lower()
    assert "javascript" in exp_dom["why"].lower()

    exp_xxe = engine._explain_tool_action("audit_xxe_injection", {"url": "https://corp.com.br/soap"})
    assert "xxe" in exp_xxe["what"].lower()
    assert "parser" in exp_xxe["why"].lower()

    exp_redir = engine._explain_tool_action("audit_open_redirect_bypasses", {"url": "https://corp.com.br/login?url="})
    assert "redirect" in exp_redir["what"].lower()
    assert "oauth" in exp_redir["why"].lower() or "filtro" in exp_redir["why"].lower()

    exp_ldap = engine._explain_tool_action("audit_ldap_injection", {"url": "https://corp.com.br/ldap-login"})
    assert "ldap" in exp_ldap["what"].lower()
    assert "diretório" in exp_ldap["why"].lower() or "ad" in exp_ldap["why"].lower()


# ============================================================================
# 2. Race Conditions & Concurrency
# ============================================================================

@pytest.mark.asyncio
async def test_audit_race_conditions_concurrency_detected():
    """Verify detection when multiple parallel requests succeed on single-use actions."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_post(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = '{"success": true, "voucher_redeemed": 50}'
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_post):
        res = await executor._handle_audit_race_conditions_concurrency(
            url="https://app.alvo.com.br/api/redeem",
            concurrency_level=4,
        )
        assert res["race_condition_detected"] is True
        assert res["success_count"] >= 2
        assert res["score"] <= 20
        assert any("Race Condition" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_race_conditions_concurrency_atomic():
    """Verify proper behavior when only 1 request succeeds and others are rejected."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    call_count = 0

    async def mock_post_atomic(url, *args, **kwargs):
        nonlocal call_count
        resp = MagicMock()
        if call_count == 0:
            resp.status_code = 200
            resp.text = '{"success": true}'
        else:
            resp.status_code = 409
            resp.text = '{"error": "Voucher already used"}'
        call_count += 1
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_post_atomic):
        res = await executor._handle_audit_race_conditions_concurrency(
            url="https://app.alvo.com.br/api/redeem",
            concurrency_level=3,
        )
        assert res["race_condition_detected"] is False
        assert res["success_count"] == 1
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 3. DOM Clobbering
# ============================================================================

@pytest.mark.asyncio
async def test_audit_dom_clobbering_detected():
    """Detect HTML tags with reserved IDs overriding global JavaScript variables."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    vulnerable_markup = """
    <html>
      <body>
        <a id="config" href="https://evil.com/app.js">Settings</a>
        <script>
          const scriptSrc = window.config.href || '/static/app.js';
        </script>
      </body>
    </html>
    """

    res = await executor._handle_audit_dom_clobbering(html_or_js_content=vulnerable_markup)
    assert res["clobbering_risk_detected"] is True
    assert "config" in res["clobbered_elements_detected"]
    assert res["score"] <= 70
    assert any("DOM" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_dom_clobbering_clean():
    """Verify clean response when markup doesn't clobber global variables."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    clean_markup = """
    <html>
      <body>
        <p class="intro">Welcome to safe portal</p>
      </body>
    </html>
    """

    res = await executor._handle_audit_dom_clobbering(html_or_js_content=clean_markup)
    assert res["clobbering_risk_detected"] is False
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 4. XML External Entity (XXE) Injection
# ============================================================================

@pytest.mark.asyncio
async def test_audit_xxe_injection_detected():
    """Detect XML entity expansion reflecting canary value."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_xxe_post(url, content=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<response><data>arcanum_xxe_canary_confirmed</data></response>"
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_xxe_post):
        res = await executor._handle_audit_xxe_injection("https://app.alvo.com.br/xml-api")
        assert res["xxe_vulnerability_detected"] is True
        assert res["score"] <= 20
        assert any("XXE" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_xxe_injection_hardened():
    """Verify parser that rejects DOCTYPE declarations with 400 Bad Request."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_xxe_hardened(url, content=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 400
        resp.text = "Error: DOCTYPE declarations are prohibited"
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_xxe_hardened):
        res = await executor._handle_audit_xxe_injection("https://app.alvo.com.br/xml-api")
        assert res["xxe_vulnerability_detected"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 5. Open Redirect & Filter Bypass
# ============================================================================

@pytest.mark.asyncio
async def test_audit_open_redirect_bypasses_detected():
    """Detect open redirect through protocol-relative and backslash bypass."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_redir_get(url, *args, **kwargs):
        resp = MagicMock()
        url_str = str(url)
        if "arcanum-redirect-test.net" in url_str:
            resp.status_code = 302
            resp.headers = {"Location": "//arcanum-redirect-test.net"}
        else:
            resp.status_code = 200
            resp.headers = {}
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_redir_get):
        res = await executor._handle_audit_open_redirect_bypasses("https://app.alvo.com.br/login?redirect=/home")
        assert res["open_redirect_detected"] is True
        assert len(res["bypassed_techniques"]) >= 1
        assert res["score"] <= 30
        assert any("Open Redirect" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_open_redirect_bypasses_hardened():
    """Verify hardened endpoint rejecting external redirect targets."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_redir_clean(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_redir_clean):
        res = await executor._handle_audit_open_redirect_bypasses("https://app.alvo.com.br/login?redirect=/home")
        assert res["open_redirect_detected"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 6. LDAP Filter Injection
# ============================================================================

@pytest.mark.asyncio
async def test_audit_ldap_injection_detected():
    """Detect LDAP filter injection causing auth bypass from baseline 401."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_ldap_post(url, json=None, *args, **kwargs):
        resp = MagicMock()
        json = json or {}
        user = json.get("username", "")
        if user == "*)(&":
            resp.status_code = 200
            resp.text = '{"status": "authenticated", "user": "administrator"}'
        else:
            resp.status_code = 401
            resp.text = '{"error": "Invalid LDAP credentials"}'
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_ldap_post):
        res = await executor._handle_audit_ldap_injection(
            url="https://intranet.empresa.com.br/login",
            probe_field="username",
        )
        assert res["ldap_injection_detected"] is True
        assert len(res["vulnerable_patterns"]) >= 1
        assert res["score"] <= 25
        assert any("LDAP" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_ldap_injection_clean():
    """Verify endpoint that sanitizes LDAP characters rejecting all injection attempts."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_ldap_clean(url, json=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 401
        resp.text = '{"error": "Invalid credentials"}'
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_ldap_clean):
        res = await executor._handle_audit_ldap_injection(
            url="https://intranet.empresa.com.br/login",
            probe_field="username",
        )
        assert res["ldap_injection_detected"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"
