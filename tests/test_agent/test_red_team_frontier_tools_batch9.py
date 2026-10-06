"""Tests for Batch 9 of Red Team / Frontier Security Audit Tools (Milestone: 110 Native Tools).

Tools covered:
- audit_ad_dacl_abuse_paths
- audit_windows_token_privileges
- audit_cicd_workflow_poisoning
- audit_mtls_and_mesh_security
- audit_ebpf_integrity_and_rootkits
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from arcanum.agent.tools import NATIVE_TOOLS, ToolExecutor, RECON_TOOLS, ANALYSIS_TOOLS
from arcanum.agent.engine import AgentEngine


@pytest.fixture
def executor():
    return ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)


# ============================================================================
# 1. Registration & Schema Validation (The 110 Tools Milestone)
# ============================================================================

def test_batch9_registrations(executor):
    """Verify all 5 tools are registered in NATIVE_TOOLS and ToolExecutor handlers, reaching 110 tools."""
    assert len(NATIVE_TOOLS) >= 110

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    expected = [
        "audit_ad_dacl_abuse_paths",
        "audit_windows_token_privileges",
        "audit_cicd_workflow_poisoning",
        "audit_mtls_and_mesh_security",
        "audit_ebpf_integrity_and_rootkits",
    ]
    for name in expected:
        assert name in tool_names, f"Tool {name} should be in NATIVE_TOOLS"
        assert name in ANALYSIS_TOOLS, f"Tool {name} should be in ANALYSIS_TOOLS"

    assert "audit_mtls_and_mesh_security" in RECON_TOOLS

    for name in expected:
        assert name in executor._handlers, f"Handler for {name} missing in ToolExecutor"


def test_batch9_engine_normalization_and_risk():
    """Verify engine normalizes calls, explains actions and assesses risk properly."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "corp.local"}

    batch9_tools = [
        ("audit_ad_dacl_abuse_paths", {"domain": "corp.local"}),
        ("audit_windows_token_privileges", {"privileges_data": ["SeImpersonatePrivilege"]}),
        ("audit_cicd_workflow_poisoning", {"workflow_content": "name: test\non: push"}),
        ("audit_mtls_and_mesh_security", {"url": "https://mesh.corp.local"}),
        ("audit_ebpf_integrity_and_rootkits", {"ebpf_programs": [{"id": 1, "name": "cilium"}]}),
    ]

    for tool_name, args in batch9_tools:
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
async def test_batch9_system_prompt_rendering():
    """Ensure system prompt renders successfully with all 5 new tool directives and no f-string syntax errors."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.session = {"target": "corp.local", "scope": {"allow_active": True}}
    engine.current_phase = "recon"
    engine.tool_executor = None
    engine.mode = "offensive"

    prompt = await engine._build_system_prompt()
    # Prompt renders without f-string errors and carries the operation context.
    assert prompt and "corp.local" in prompt and "Metodologia por Fase" in prompt
    # Tools are exposed to the agent via phase-scoped tool schemas (NATIVE_TOOLS),
    # not a prose catalog in the system prompt (removed to fit the local model's
    # 8k context window).
    from arcanum.agent.tools import NATIVE_TOOLS
    names = {t["function"]["name"] for t in NATIVE_TOOLS}
    for tool in (
        "audit_ad_dacl_abuse_paths", "audit_windows_token_privileges",
        "audit_cicd_workflow_poisoning", "audit_mtls_and_mesh_security",
        "audit_ebpf_integrity_and_rootkits",
    ):
        assert tool in names


# ============================================================================
# 2. Tool 1: audit_ad_dacl_abuse_paths
# ============================================================================

@pytest.mark.asyncio
async def test_audit_ad_dacl_abuse_paths_vulnerable(executor):
    """Test identification of dangerous DACL/ACE control relationships over Domain Admins."""
    acl_data = [
        {
            "principal": "CORP\\helpdesk_user",
            "target_object": "CORP\\Domain Admins",
            "target_type": "group",
            "right": "GenericAll",
        },
        {
            "principal": "CORP\\operator",
            "target_object": "CORP\\backup_service",
            "target_type": "user",
            "right": "ForceChangePassword",
        },
    ]

    result = await executor._handle_audit_ad_dacl_abuse_paths(
        domain="corp.local",
        acl_data=acl_data,
    )

    assert result["domain"] == "corp.local"
    assert result["acl_entries_analyzed"] == 2
    assert len(result["abusable_paths"]) == 2
    assert any(p["high_value_target"] for p in result["abusable_paths"])
    assert result["score"] < 50
    assert result["risk_level"] == "critical"
    assert any("Caminho de Abuso de DACL/ACL" in f["issue"] for f in result["findings"])


@pytest.mark.asyncio
async def test_audit_ad_dacl_abuse_paths_secure(executor):
    """Test clean DACL relationships with standard read-only ACEs."""
    acl_data = [
        {
            "principal": "CORP\\standard_user",
            "target_object": "CORP\\finance_folder",
            "target_type": "folder",
            "right": "ReadControl",
        },
    ]

    result = await executor._handle_audit_ad_dacl_abuse_paths(
        domain="corp.local",
        acl_data=acl_data,
    )

    assert len(result["abusable_paths"]) == 0
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"


# ============================================================================
# 3. Tool 2: audit_windows_token_privileges
# ============================================================================

@pytest.mark.asyncio
async def test_audit_windows_token_privileges_vulnerable(executor):
    """Test detection of Potato-family token privileges (SeImpersonatePrivilege, SeBackupPrivilege)."""
    whoami_priv_output = [
        "SeImpersonatePrivilege        Impersonate a client after authentication  Enabled",
        "SeBackupPrivilege             Back up files and directories              Enabled",
        "SeChangeNotifyPrivilege       Bypass traverse checking                   Enabled",
    ]

    result = await executor._handle_audit_windows_token_privileges(
        privileges_data=whoami_priv_output,
        account_name="IIS APPPOOL\\DefaultAppPool",
    )

    assert result["account_name"] == "IIS APPPOOL\\DefaultAppPool"
    assert "seimpersonateprivilege" in result["dangerous_privileges"]
    assert "sebackupprivilege" in result["dangerous_privileges"]
    assert any("Potato" in v for v in result["privesc_vectors"])
    assert result["score"] <= 30
    assert result["risk_level"] == "critical"
    assert any("SeImpersonatePrivilege" in f["issue"] or "seimpersonateprivilege" in f["issue"] for f in result["findings"])


@pytest.mark.asyncio
async def test_audit_windows_token_privileges_secure(executor):
    """Test standard unprivileged token with only safe privileges."""
    safe_privs = [
        "SeChangeNotifyPrivilege       Bypass traverse checking                   Enabled",
        "SeShutdownPrivilege           Shut down the system                       Disabled",
    ]

    result = await executor._handle_audit_windows_token_privileges(
        privileges_data=safe_privs,
        account_name="CORP\\jdoe",
    )

    assert len(result["dangerous_privileges"]) == 0
    assert len(result["privesc_vectors"]) == 0
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"


# ============================================================================
# 4. Tool 3: audit_cicd_workflow_poisoning
# ============================================================================

@pytest.mark.asyncio
async def test_audit_cicd_workflow_poisoning_vulnerable(executor):
    """Test detection of context injection and pull_request_target checkout abuse."""
    vuln_yaml = """
    name: Build & PR Triage
    on:
      pull_request_target:
        types: [opened]

    jobs:
      triage:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v2
            with:
              ref: ${{ github.event.pull_request.head.sha }}
          - name: Echo issue title
            run: |
              echo "Processing PR: ${{ github.event.issue.title }}"
              curl -s https://api.mycorp.com?t=${{ github.event.comment.body }}
          - uses: unverified-owner/custom-action@v1
    """

    result = await executor._handle_audit_cicd_workflow_poisoning(
        workflow_content=vuln_yaml,
        workflow_name="pr_triage.yml",
    )

    assert result["workflow_name"] == "pr_triage.yml"
    assert "pwn_request_target_checkout" in result["vulnerabilities_detected"]
    assert any("context_injection" in v for v in result["vulnerabilities_detected"])
    assert result["unpinned_actions_count"] >= 1
    assert result["score"] < 50
    assert result["risk_level"] == "critical"
    assert any("Injeção direta de contexto" in f["issue"] for f in result["findings"])


@pytest.mark.asyncio
async def test_audit_cicd_workflow_poisoning_secure(executor):
    """Test clean CI workflow using env mapping and commit-pinned actions."""
    safe_yaml = """
    name: Safe Build
    on:
      pull_request:
        branches: [main]

    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
          - name: Build
            env:
              TITLE: ${{ github.event.issue.title }}
            run: |
              echo "Processing safely: $TITLE"
    """

    result = await executor._handle_audit_cicd_workflow_poisoning(
        workflow_content=safe_yaml,
        workflow_name="safe_build.yml",
    )

    assert len(result["vulnerabilities_detected"]) == 0
    assert result["unpinned_actions_count"] == 0
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"


# ============================================================================
# 5. Tool 4: audit_mtls_and_mesh_security
# ============================================================================

@pytest.mark.asyncio
async def test_audit_mtls_and_mesh_security_vulnerable(executor):
    """Test service mesh proxy accepting external X-Forwarded-Client-Cert injection."""
    def mock_get_side_effect(url, headers=None, **kwargs):
        resp = MagicMock()
        hdrs = headers or {}
        if "X-Forwarded-Client-Cert" in hdrs:
            resp.status_code = 200
            resp.text = '{"authenticated": true, "user": "admin", "mesh": "InternalMesh"}'
        else:
            resp.status_code = 401
            resp.text = '{"error": "Client certificate required"}'
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.side_effect = mock_get_side_effect

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await executor._handle_audit_mtls_and_mesh_security(
            url="https://gateway.internal.corp/api/admin",
        )

    assert result["url"] == "https://gateway.internal.corp/api/admin"
    assert "X-Forwarded-Client-Cert" in result["injected_headers_accepted"]
    assert result["mtls_enforced"] is False
    assert result["score"] <= 50
    assert result["risk_level"] in ("critical", "high")
    assert any("Bypass de mTLS" in f["issue"] for f in result["findings"])


@pytest.mark.asyncio
async def test_audit_mtls_and_mesh_security_secure(executor):
    """Test service gateway properly stripping or rejecting spoofed client cert headers."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = '{"error": "mTLS mandatory at transport layer"}'

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await executor._handle_audit_mtls_and_mesh_security(
            url="https://gateway.internal.corp/api",
        )

    assert len(result["injected_headers_accepted"]) == 0
    assert result["mtls_enforced"] is True
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"


# ============================================================================
# 6. Tool 5: audit_ebpf_integrity_and_rootkits
# ============================================================================

@pytest.mark.asyncio
async def test_audit_ebpf_integrity_and_rootkits_vulnerable(executor):
    """Test detection of suspicious eBPF rootkit hooking directory listing (getdents64)."""
    progs = [
        {
            "id": 1042,
            "name": "bpfdoor_stealth",
            "type": "kprobe",
            "attached": "sys_enter_getdents64",
        },
        {
            "id": 2048,
            "name": "",  # Anonymous program
            "type": "tracepoint",
            "attached": "sys_enter_kill",
        },
    ]

    result = await executor._handle_audit_ebpf_integrity_and_rootkits(
        ebpf_programs=progs,
        host_name="k8s-worker-node-01",
    )

    assert result["host_name"] == "k8s-worker-node-01"
    assert result["total_ebpf_programs"] == 2
    assert result["suspicious_programs_count"] == 2
    assert result["score"] < 50
    assert result["risk_level"] == "critical"
    assert any("Rootkit de Kernel eBPF" in f["impact"] for f in result["findings"])


@pytest.mark.asyncio
async def test_audit_ebpf_integrity_and_rootkits_secure(executor):
    """Test legitimate eBPF programs from trusted security observability daemons (Cilium, Falco)."""
    progs = [
        {
            "id": 101,
            "name": "cilium_xdp_entry",
            "type": "xdp",
            "attached": "eth0",
        },
        {
            "id": 102,
            "name": "falco_tracepoint",
            "type": "tracepoint",
            "attached": "sys_enter_execve",
        },
    ]

    result = await executor._handle_audit_ebpf_integrity_and_rootkits(
        ebpf_programs=progs,
        host_name="prod-bastion",
    )

    assert result["suspicious_programs_count"] == 0
    assert len(result["stealth_indicators"]) == 0
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "low"
