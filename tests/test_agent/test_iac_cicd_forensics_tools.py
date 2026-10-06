"""Unit and integration tests for Arcanum's 8 frontier tools:
- audit_iac_misconfigurations (IaC Security: Terraform/CloudFormation open SGs, unencrypted storage, public RDS)
- audit_cicd_pipeline_security (DevSecOps: GitHub Actions & GitLab CI pull_request_target, script injections, unpinned actions)
- audit_web_cache_poisoning (Purple Team: Web Cache Poisoning & Deception via unkeyed headers and static extensions)
- audit_api_mass_assignment (Red Team: OWASP API3:2023 Mass Assignment and unauthorized property tampering)
- audit_mta_sts_dane (Blue Team: MTA-STS enforcement policies and DANE TLSA DNSSEC records)
- audit_identity_access_hygiene (Blue/Purple Team: Active Directory / Entra ID Kerberoasting, AS-REP Roasting, delegation)
- analyze_forensic_artifacts (Blue Team / DFIR: Forensic log analysis, Event ID 4625 brute-force, process execution, lateral movement)
- audit_binary_protections (Blue Team: Checksec ELF/PE binary exploit mitigations ASLR/PIE, Stack Canaries, NX/DEP, RELRO)
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

def test_iac_cicd_forensics_tools_registrations():
    """Verify all 8 new tools are correctly registered in NATIVE_TOOLS, phases, and executor."""
    tool_names = [t["function"]["name"] for t in NATIVE_TOOLS]
    new_tools = [
        "audit_iac_misconfigurations",
        "audit_cicd_pipeline_security",
        "audit_web_cache_poisoning",
        "audit_api_mass_assignment",
        "audit_mta_sts_dane",
        "audit_identity_access_hygiene",
        "analyze_forensic_artifacts",
        "audit_binary_protections",
    ]
    for nt in new_tools:
        assert nt in tool_names, f"{nt} must be in NATIVE_TOOLS"
        assert nt in ANALYSIS_TOOLS, f"{nt} must be in ANALYSIS_TOOLS"

    # Recon tools check
    assert "audit_web_cache_poisoning" in RECON_TOOLS
    assert "audit_mta_sts_dane" in RECON_TOOLS

    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for nt in new_tools:
        assert nt in te._handlers, f"{nt} must be registered in ToolExecutor._handlers"


def test_engine_normalizer_and_risk_scoring():
    """Verify AgentEngine normalizer and LOW risk scoring for the 8 tools."""
    norm = AgentEngine._normalize_tool_call_dict({
        "name": "audit_iac_misconfigurations",
        "arguments": {"template_content": "resource \"aws_s3_bucket\" \"test\" {}"}
    })
    assert norm is not None
    assert norm["function"]["name"] == "audit_iac_misconfigurations"

    new_tools = [
        "audit_iac_misconfigurations",
        "audit_cicd_pipeline_security",
        "audit_web_cache_poisoning",
        "audit_api_mass_assignment",
        "audit_mta_sts_dane",
        "audit_identity_access_hygiene",
        "analyze_forensic_artifacts",
        "audit_binary_protections",
    ]
    for nt in new_tools:
        assert AgentEngine._assess_risk(nt, {"url": "https://empresa.com.br"}) == "LOW"


def test_engine_pedagogical_explanations():
    """Verify pedagogical explanations for the 8 new tools in Portuguese."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "alvo.com.br"}

    exp_iac = engine._explain_tool_action("audit_iac_misconfigurations", {"template_type": "terraform"})
    assert "IaC" in exp_iac["what"]
    assert "Security Groups" in exp_iac["why"]

    exp_cicd = engine._explain_tool_action("audit_cicd_pipeline_security", {"platform": "github_actions"})
    assert "CI/CD" in exp_cicd["what"]
    assert "Pwn Request" in exp_cicd["why"]

    exp_cache = engine._explain_tool_action("audit_web_cache_poisoning", {"url": "https://alvo.com.br"})
    assert "Cache Poisoning" in exp_cache["what"]

    exp_mass = engine._explain_tool_action("audit_api_mass_assignment", {"url": "https://alvo.com.br/api"})
    assert "Mass Assignment" in exp_mass["what"]

    exp_mta = engine._explain_tool_action("audit_mta_sts_dane", {"domain": "alvo.com.br"})
    assert "MTA-STS" in exp_mta["what"]

    exp_ad = engine._explain_tool_action("audit_identity_access_hygiene", {"domain_name": "corp.local"})
    assert "Active Directory" in exp_ad["what"]

    exp_dfir = engine._explain_tool_action("analyze_forensic_artifacts", {"log_type": "windows_event"})
    assert "pericial forense" in exp_dfir["what"]

    exp_bin = engine._explain_tool_action("audit_binary_protections", {"binary_name": "daemon"})
    assert "checksec" in exp_bin["what"]


# ============================================================================
# 2. DevSecOps: IaC Security & Misconfigurations
# ============================================================================

@pytest.mark.asyncio
async def test_audit_iac_misconfigurations_vulnerabilities():
    """Detect open security groups, public S3 buckets, and public RDS in Terraform."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    vulnerable_tf = """
    resource "aws_security_group" "allow_all" {
      name        = "allow_all"
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }

    resource "aws_s3_bucket" "public_bucket" {
      bucket = "my-public-data"
      acl    = "public-read"
    }

    resource "aws_db_instance" "public_rds" {
      allocated_storage   = 20
      engine              = "postgres"
      publicly_accessible = true
    }
    """

    res = await executor._handle_audit_iac_misconfigurations(template_content=vulnerable_tf)
    assert res["open_security_groups"] is True
    assert res["public_storage_detected"] is True
    assert res["public_database_detected"] is True
    assert res["score"] <= 30
    assert res["grade"] == "F"
    assert any("Security Group" in f["issue"] for f in res["findings"])
    assert any("Bucket" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_iac_misconfigurations_hardened():
    """Verify clean status for hardened Terraform template."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    hardened_tf = """
    resource "aws_security_group" "internal_only" {
      ingress {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["10.0.0.0/16"]
      }
    }

    resource "aws_s3_bucket" "secure_bucket" {
      bucket = "my-secure-data"
      block_public_acls = true
      server_side_encryption_configuration {
        rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
      }
    }
    """

    res = await executor._handle_audit_iac_misconfigurations(template_content=hardened_tf)
    assert res["open_security_groups"] is False
    assert res["public_storage_detected"] is False
    assert res["public_database_detected"] is False
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 3. DevSecOps: CI/CD Pipeline Security
# ============================================================================

@pytest.mark.asyncio
async def test_audit_cicd_pipeline_security_vulnerabilities():
    """Detect pull_request_target, command injection, and unpinned actions."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    vulnerable_workflow = """
    name: Build & Test
    on:
      pull_request_target:
        branches: [ main ]
    permissions: write-all
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v2
          - name: Echo PR Title
            run: |
              echo "Title: ${{ github.event.pull_request.title }}"
    """

    res = await executor._handle_audit_cicd_pipeline_security(pipeline_content=vulnerable_workflow)
    assert res["has_pull_request_target"] is True
    assert res["command_injections_found"] >= 1
    assert res["overprivileged_token"] is True
    assert res["unpinned_actions_count"] >= 1
    assert res["score"] <= 30
    assert res["grade"] == "F"
    assert any("pull_request_target" in f["issue"] for f in res["findings"])
    assert any("Injeção de comandos" in f["issue"] for f in res["findings"])


# ============================================================================
# 4. Purple Team: Web Cache Poisoning & Deception
# ============================================================================

@pytest.mark.asyncio
async def test_audit_web_cache_poisoning_detected():
    """Detect unkeyed header reflection and cache deception."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_cache_get(url, headers=None, *args, **kwargs):
        resp = MagicMock()
        headers = headers or {}
        if "arcanum-test-deception.css" in url:
            resp.status_code = 200
            resp.headers = {"Cache-Control": "public, max-age=3600"}
            resp.text = "<html>User profile dynamic content</html>"
        elif "X-Forwarded-Host" in headers:
            resp.status_code = 200
            resp.headers = {"Cache-Control": "public, max-age=600", "X-Cache": "HIT"}
            resp.text = f"<html><script src='https://{headers['X-Forwarded-Host']}/app.js'></script></html>"
        else:
            resp.status_code = 200
            resp.headers = {"Cache-Control": "private, no-cache"}
            resp.text = "<html>Normal page</html>"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_cache_get):
        res = await executor._handle_audit_web_cache_poisoning("https://app.empresa.com.br")
        assert res["cache_poisoning_risk"] is True
        assert res["cache_deception_risk"] is True
        assert "X-Forwarded-Host" in res["reflected_unkeyed_headers"]
        assert res["score"] <= 50
        assert any("Web Cache Poisoning" in f["issue"] for f in res["findings"])


# ============================================================================
# 5. Red Team: OWASP API3:2023 Mass Assignment
# ============================================================================

@pytest.mark.asyncio
async def test_audit_api_mass_assignment_vulnerable():
    """Detect Mass Assignment when administrative role is accepted."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_api_post(url, json=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        # API accepts and reflects role=admin and isAdmin=True
        resp.json = MagicMock(return_value={
            "id": 1042,
            "username": "arcanum_test",
            "role": "admin",
            "isAdmin": True,
        })
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_api_post):
        res = await executor._handle_audit_api_mass_assignment(
            url="https://api.empresa.com.br/v1/users",
            privilege_fields=["isAdmin", "role"]
        )
        assert res["vulnerable"] is True
        assert "isAdmin" in res["accepted_privilege_fields"]
        assert "role" in res["accepted_privilege_fields"]
        assert res["score"] <= 30
        assert any("Mass Assignment" in f["issue"] for f in res["findings"])


# ============================================================================
# 6. Blue Team: MTA-STS & DANE TLSA Email Security
# ============================================================================

@pytest.mark.asyncio
async def test_audit_mta_sts_dane_enforced():
    """Verify score 100 when MTA-STS is in mode enforce."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    async def mock_mta_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "_mta-sts" in url:
            resp.json = MagicMock(return_value={"Answer": [{"data": '"v=STSv1; id=20240101"'}]})
        elif "mta-sts.txt" in url:
            resp.text = "version: STSv1\nmode: enforce\nmx: mail.empresa.com.br\nmax_age: 86400"
        elif "TLSA" in url:
            resp.json = MagicMock(return_value={"Answer": [{"data": "3 1 1 abcdef"}]})
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_mta_get):
        res = await executor._handle_audit_mta_sts_dane("empresa.com.br")
        assert res["mta_sts_configured"] is True
        assert res["mta_sts_mode"] == "enforce"
        assert res["dane_tlsa_configured"] is True
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 7. Blue / Purple Team: Active Directory Identity Hygiene
# ============================================================================

@pytest.mark.asyncio
async def test_audit_identity_access_hygiene_vectors():
    """Detect Kerberoasting, AS-REP Roasting, and Delegation risks in AD accounts."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    accounts = [
        {"sAMAccountName": "svc_sql", "servicePrincipalName": "MSSQLSvc/db01.corp:1433", "is_computer": False},
        {"sAMAccountName": "usr_legacy", "userAccountControl": 4194304},  # DONT_REQ_PREAUTH
        {"sAMAccountName": "srv_web", "userAccountControl": 524288, "is_dc": False},  # TRUSTED_FOR_DELEGATION
        {"sAMAccountName": "adm_finance", "userAccountControl": 65536, "is_admin": True},  # DONT_EXPIRE_PASSWORD
    ]

    res = await executor._handle_audit_identity_access_hygiene(accounts_data=accounts, domain_name="corp.local")
    assert res["total_accounts_audited"] == 4
    assert res["kerberoastable_accounts_count"] == 1
    assert res["asrep_roastable_accounts_count"] == 1
    assert res["unconstrained_delegation_count"] == 1
    assert res["stale_admin_passwords_count"] == 1
    assert res["score"] <= 30
    assert res["grade"] in ("C", "F")
    assert any("Kerberoasting" in f["issue"] for f in res["findings"])
    assert any("AS-REP Roasting" in f["issue"] for f in res["findings"])


# ============================================================================
# 8. Blue Team / DFIR: Forensic Artifacts Log Analysis
# ============================================================================

@pytest.mark.asyncio
async def test_analyze_forensic_artifacts_attacks_detected():
    """Identify brute force, mimikatz, and SQL injection patterns in logs."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    sample_logs = """
    2026-10-02 10:00:01 EventID 4625: An account failed to log on. User: administrator
    2026-10-02 10:00:02 EventID 4625: An account failed to log on. User: administrator
    2026-10-02 10:00:03 EventID 4625: An account failed to log on. User: administrator
    2026-10-02 10:00:04 EventID 4625: An account failed to log on. User: administrator
    2026-10-02 10:00:05 EventID 4625: An account failed to log on. User: administrator
    2026-10-02 10:00:06 EventID 4625: An account failed to log on. User: administrator
    2026-10-02 10:05:00 EventID 4688: Process Created: C:\\Windows\\System32\\cmd.exe /c powershell -enc JAB4...
    2026-10-02 10:06:00 Nginx Access: GET /api/search?q=UNION+SELECT+1,2,username,password+FROM+users HTTP/1.1 200
    """

    res = await executor._handle_analyze_forensic_artifacts(log_content=sample_logs, log_type="windows_event")
    assert res["failed_logons_count"] >= 6
    assert res["suspicious_process_executions"] >= 1
    assert res["web_attack_patterns"] >= 1
    assert res["score"] <= 40
    assert any("força bruta" in f["issue"].lower() for f in res["findings"])
    assert any("processos" in f["issue"].lower() for f in res["findings"])


# ============================================================================
# 9. Blue Team: Binary Checksec Protections
# ============================================================================

@pytest.mark.asyncio
async def test_audit_binary_protections_elf():
    """Detect missing PIE and Stack Canaries on vulnerable ELF header."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # ELF 64-bit header (7f454c46) without ET_DYN (e_type = 0200 = ET_EXEC, no PIE)
    elf_no_pie_hex = "7f454c4602010100000000000000000002003e0001000000"

    res = await executor._handle_audit_binary_protections(
        binary_hex_header=elf_no_pie_hex,
        binary_name="legacy_server"
    )
    assert res["format"] == "ELF"
    assert res["mitigations"]["pie_aslr"] is False
    assert res["score"] <= 50
    assert any("ASLR / PIE" in f["issue"] for f in res["findings"])
