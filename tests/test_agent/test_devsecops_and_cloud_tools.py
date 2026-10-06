"""Unit and integration tests for Arcanum's DevSecOps, Cloud Native, Threat Hunting, and Governance tools:
- audit_waf_bypass_heuristics (Purple Team: WAF normalization, Unicode, double-encoding, and evasion resilience)
- audit_sbom_dependencies (Blue Team / DevSecOps: Open source vulnerability auditing via Google OSV.dev)
- audit_saml_xml_security (Red Team / AppSec: Enterprise SSO SAML 2.0 signatures, SHA-1, XSW, and XXE)
- generate_yara_rule (Blue Team / Threat Hunting: Parametrized YARA detection rule compilation)
- audit_dockerfile_security (Blue Team / DevSecOps: Static Dockerfile linting, root user, secrets, and escape vectors)
- audit_kubernetes_rbac (Purple Team / Cloud Native: K8s RBAC wildcards, privileged pods, and container escape)
- calculate_breach_risk_cost (Management / Governance: Financial breach impact and LGPD Art. 52 sanctions calculator)
"""

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

def test_devsecops_and_cloud_tools_registrations():
    """Verify all 7 new tools are correctly registered in NATIVE_TOOLS, phases, and executor."""
    tool_names = [t["function"]["name"] for t in NATIVE_TOOLS]
    new_tools = [
        "audit_waf_bypass_heuristics",
        "audit_sbom_dependencies",
        "audit_saml_xml_security",
        "generate_yara_rule",
        "audit_dockerfile_security",
        "audit_kubernetes_rbac",
        "calculate_breach_risk_cost",
    ]
    for nt in new_tools:
        assert nt in tool_names, f"{nt} must be in NATIVE_TOOLS"
        assert nt in ANALYSIS_TOOLS, f"{nt} must be in ANALYSIS_TOOLS"

    # Recon tools check
    assert "audit_waf_bypass_heuristics" in RECON_TOOLS
    assert "audit_saml_xml_security" in RECON_TOOLS

    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for nt in new_tools:
        assert nt in te._handlers, f"{nt} must be registered in ToolExecutor._handlers"


def test_engine_normalizer_and_risk_scoring():
    """Verify AgentEngine normalizer and LOW risk scoring for the 7 tools."""
    norm = AgentEngine._normalize_tool_call_dict({
        "name": "audit_dockerfile_security",
        "arguments": {"dockerfile_content": "FROM alpine\nUSER app"}
    })
    assert norm is not None
    assert norm["function"]["name"] == "audit_dockerfile_security"

    new_tools = [
        "audit_waf_bypass_heuristics",
        "audit_sbom_dependencies",
        "audit_saml_xml_security",
        "generate_yara_rule",
        "audit_dockerfile_security",
        "audit_kubernetes_rbac",
        "calculate_breach_risk_cost",
    ]
    for nt in new_tools:
        assert AgentEngine._assess_risk(nt, {"url": "https://empresa.com.br"}) == "LOW"


def test_engine_pedagogical_explanations():
    """Verify pedagogical explanations for the 7 new tools in Portuguese."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "alvo.com.br"}

    exp_waf = engine._explain_tool_action("audit_waf_bypass_heuristics", {"url": "https://alvo.com.br/search"})
    assert "WAF" in exp_waf["what"]
    assert "Unicode" in exp_waf["why"]

    exp_sbom = engine._explain_tool_action("audit_sbom_dependencies", {"ecosystem": "PyPI"})
    assert "OSV.dev" in exp_sbom["what"]

    exp_saml = engine._explain_tool_action("audit_saml_xml_security", {"metadata_url": "https://sso.alvo.com.br"})
    assert "SAML" in exp_saml["what"]

    exp_yara = engine._explain_tool_action("generate_yara_rule", {"rule_name": "malware_trojan"})
    assert "YARA" in exp_yara["what"]

    exp_dock = engine._explain_tool_action("audit_dockerfile_security", {"image_name": "api"})
    assert "Dockerfile" in exp_dock["what"]

    exp_k8s = engine._explain_tool_action("audit_kubernetes_rbac", {"cluster_name": "prod-k8s"})
    assert "Kubernetes" in exp_k8s["what"]

    exp_cost = engine._explain_tool_action("calculate_breach_risk_cost", {"records_count": 10000})
    assert "LGPD" in exp_cost["what"]


# ============================================================================
# 2. Purple Team: WAF Evasion & Normalization Resilience
# ============================================================================

@pytest.mark.asyncio
async def test_audit_waf_bypass_heuristics_detected():
    """Detect when baseline payload is blocked by WAF but Unicode variant bypasses it."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_waf_get(url, *args, **kwargs):
        resp = MagicMock()
        # Unicode full-width payload bypasses WAF with 200 OK
        if "%EF%BC%9Cscript" in url or "＜script" in url:
            resp.status_code = 200
            resp.text = "Search results for: ＜script＞"
        else:
            # Baseline literal payload is blocked with 403 Forbidden
            resp.status_code = 403
            resp.text = "<html><body>403 Forbidden - WAF Blocked</body></html>"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_waf_get):
        res = await executor._handle_audit_waf_bypass_heuristics("https://app.empresa.com.br/search")
        assert res["baseline_blocked"] is True
        assert res["evasion_heuristics_bypassed"] >= 1
        assert res["score"] <= 80
        assert any("contornou o bloqueio" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_waf_bypass_heuristics_resilient():
    """Verify resilience when all variants are blocked by WAF."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_waf_block_all(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "<html>403 Forbidden - Cloudflare WAF</html>"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_waf_block_all):
        res = await executor._handle_audit_waf_bypass_heuristics("https://app.empresa.com.br/search")
        assert res["baseline_blocked"] is True
        assert res["evasion_heuristics_bypassed"] == 0
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 3. Blue Team: OSV.dev Software Supply Chain Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_sbom_dependencies_vulnerable():
    """Identify vulnerable open-source dependencies via Google OSV.dev."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    manifest = "requests==2.20.0\nurllib3==1.24.1\nflask==0.12.2"

    async def mock_osv_post(url, json=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        pkg_name = json.get("package", {}).get("name", "")
        if pkg_name == "urllib3":
            resp.json = MagicMock(return_value={
                "vulns": [
                    {
                        "id": "GHSA-m64q-p8jr-7g97",
                        "aliases": ["CVE-2019-11324"],
                        "summary": "CRLF injection in urllib3 via connection pool",
                    }
                ]
            })
        else:
            resp.json = MagicMock(return_value={"vulns": []})
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_osv_post):
        res = await executor._handle_audit_sbom_dependencies(manifest_content=manifest, ecosystem="PyPI")
        assert res["packages_analyzed"] == 3
        assert res["vulnerabilities_found"] == 1
        assert res["vulnerable_packages"][0]["package"] == "urllib3"
        assert res["score"] < 100
        assert any("urllib3" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_sbom_dependencies_clean():
    """Verify clean status when dependencies have no known CVEs."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    packages = [{"name": "safe-package", "version": "1.0.0", "ecosystem": "PyPI"}]

    async def mock_osv_clean(url, json=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.json = MagicMock(return_value={"vulns": []})
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_osv_clean):
        res = await executor._handle_audit_sbom_dependencies(packages=packages)
        assert res["vulnerabilities_found"] == 0
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 4. Red Team: SAML 2.0 & SSO XML Security Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_saml_xml_security_vulnerable():
    """Detect weak SHA-1 signature and missing assertion signing (XSW risk)."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    vulnerable_saml = """<?xml version="1.0"?>
    <EntityDescriptor entityID="https://idp.empresa.com.br" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
        <IDPSSODescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                </SignedInfo>
            </Signature>
        </IDPSSODescriptor>
    </EntityDescriptor>
    """

    res = await executor._handle_audit_saml_xml_security(saml_xml=vulnerable_saml)
    assert res["sha1_detected"] is True
    assert res["assertions_signed_enforced"] is False
    assert res["score"] <= 45
    assert res["grade"] in ("C", "F")
    assert any("SHA-1" in f["issue"] for f in res["findings"])
    assert any("WantAssertionsSigned" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_saml_xml_security_hardened():
    """Verify hardened SAML metadata with SHA-256 and encryption."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    hardened_saml = """<?xml version="1.0"?>
    <EntityDescriptor entityID="https://idp.empresa.com.br" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
        <IDPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                    <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                </SignedInfo>
            </Signature>
            <KeyDescriptor use="encryption">
                <EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
            </KeyDescriptor>
        </IDPSSODescriptor>
    </EntityDescriptor>
    """

    res = await executor._handle_audit_saml_xml_security(saml_xml=hardened_saml)
    assert res["sha1_detected"] is False
    assert res["assertions_signed_enforced"] is True
    assert res["encryption_supported"] is True
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 5. Blue Team: Parametrized YARA Rule Generator
# ============================================================================

@pytest.mark.asyncio
async def test_generate_yara_rule_structure():
    """Generate standardized YARA detection rule."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    res = await executor._handle_generate_yara_rule(
        rule_name="webshell_eval_c99",
        strings_to_match=["eval(base64_decode(", "passthru(", "system($_GET"],
        description="Detects generic PHP webshell evasion patterns",
        severity="CRITICAL",
    )

    assert res["rule_name"] == "webshell_eval_c99"
    assert res["severity"] == "CRITICAL"
    assert res["strings_count"] == 3
    assert "rule webshell_eval_c99 {" in res["yara_rule"]
    assert '$s1 = "eval(base64_decode(" ascii wide nocase' in res["yara_rule"]
    assert "filesize < 15MB" in res["yara_rule"]
    assert len(res["deployment_instructions"]) >= 2


# ============================================================================
# 6. Blue Team: Static Dockerfile Security Linting
# ============================================================================

@pytest.mark.asyncio
async def test_audit_dockerfile_security_vulnerabilities():
    """Detect root user execution and hardcoded secret in ENV."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    dockerfile = """
    FROM python:latest
    ENV AWS_SECRET_KEY="AKIAIOSFODNN7EXAMPLE123"
    WORKDIR /app
    COPY . /app
    RUN pip install -r requirements.txt
    CMD ["python", "app.py"]
    """

    res = await executor._handle_audit_dockerfile_security(dockerfile_content=dockerfile, image_name="test-api")
    assert res["runs_as_root"] is True
    assert res["unpinned_images_count"] >= 1
    assert res["exposed_secrets_count"] >= 1
    assert res["has_healthcheck"] is False
    assert res["score"] <= 40
    assert any("root" in f["issue"] for f in res["findings"])
    assert any("Segredos" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_dockerfile_security_hardened():
    """Verify clean score for non-root Dockerfile with healthcheck."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    hardened_dockerfile = """
    FROM alpine:3.19.1
    RUN addgroup -S appgroup && adduser -S appuser -G appgroup
    WORKDIR /home/appuser
    USER appuser
    HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1
    CMD ["./server"]
    """

    res = await executor._handle_audit_dockerfile_security(dockerfile_content=hardened_dockerfile)
    assert res["runs_as_root"] is False
    assert res["has_healthcheck"] is True
    assert res["exposed_secrets_count"] == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 7. Purple Team: Kubernetes RBAC & Container Escape Audit
# ============================================================================

@pytest.mark.asyncio
async def test_audit_kubernetes_rbac_dangerous_wildcard_and_privileged():
    """Detect wildcard verbs in ClusterRole and privileged container escape."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    manifest = """
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      name: broad-admin
    rules:
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["*"]
    ---
    apiVersion: v1
    kind: Pod
    metadata:
      name: privileged-pod
    spec:
      hostPID: true
      containers:
      - name: root-shell
        image: alpine
        securityContext:
          privileged: true
    """

    res = await executor._handle_audit_kubernetes_rbac(manifest_content=manifest, cluster_name="prod-cluster")
    assert res["wildcard_rbac_detected"] is True
    assert res["privileged_container_detected"] is True
    assert res["host_namespace_sharing"] is True
    assert res["score"] <= 20
    assert res["grade"] == "F"
    assert any("wildcard" in f["issue"].lower() for f in res["findings"])
    assert any("privileged: true" in f["issue"] for f in res["findings"])


# ============================================================================
# 8. Management: Financial Breach Impact & LGPD Sanctions
# ============================================================================

@pytest.mark.asyncio
async def test_calculate_breach_risk_cost_large_enterprise():
    """Calculate financial impact for 50,000 healthcare records with company revenue."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    res = await executor._handle_calculate_breach_risk_cost(
        records_count=50000,
        data_types=["health", "cpf", "financial"],
        company_annual_revenue_brl=100_000_000.0,
        industry_sector="healthcare",
    )

    assert res["records_affected_count"] == 50000
    assert res["industry_sector"] == "healthcare"
    assert res["effective_cost_per_record_brl"] > 650.0  # multiplier applied
    assert res["projected_lgpd_sanction_brl"] == 2_000_000.0  # 2% of 100M
    assert res["total_estimated_breach_cost_brl"] > 10_000_000.0
    assert res["risk_classification"] == "CRITICAL"
    assert "LGPD" in res["regulatory_framework"]
