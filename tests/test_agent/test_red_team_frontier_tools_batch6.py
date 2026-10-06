"""Tests for Batch 6 of Red Team / Frontier Security Audit Tools (Milestone: 96 Native Tools).

Tools covered:
- audit_adcs_certificate_templates
- audit_smb_signing_and_null_sessions
- audit_postmessage_messaging_security
- audit_http_parameter_pollution
- audit_container_breakout_vectors
"""

import pytest
import socket
from unittest.mock import AsyncMock, MagicMock, patch

from arcanum.agent.tools import NATIVE_TOOLS, ToolExecutor, RECON_TOOLS, ANALYSIS_TOOLS
from arcanum.agent.engine import AgentEngine


@pytest.fixture
def executor():
    return ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)


# ============================================================================
# 1. Registration & Schema Validation
# ============================================================================

def test_batch6_registrations(executor):
    """Verify all 5 tools are registered in NATIVE_TOOLS and ToolExecutor handlers."""
    assert len(NATIVE_TOOLS) >= 96

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    expected = [
        "audit_adcs_certificate_templates",
        "audit_smb_signing_and_null_sessions",
        "audit_postmessage_messaging_security",
        "audit_http_parameter_pollution",
        "audit_container_breakout_vectors",
    ]
    for name in expected:
        assert name in tool_names, f"Tool {name} should be in NATIVE_TOOLS"
        assert name in ANALYSIS_TOOLS, f"Tool {name} should be in ANALYSIS_TOOLS"

    assert "audit_smb_signing_and_null_sessions" in RECON_TOOLS
    assert "audit_postmessage_messaging_security" in RECON_TOOLS
    assert "audit_http_parameter_pollution" in RECON_TOOLS

    for name in expected:
        assert name in executor._handlers, f"Handler for {name} missing in ToolExecutor"


def test_batch6_engine_normalization_and_risk():
    """Verify engine normalizes calls, explains actions and assesses risk properly."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "corp.local"}

    batch6_tools = [
        ("audit_adcs_certificate_templates", {"domain": "corp.local"}),
        ("audit_smb_signing_and_null_sessions", {"host": "192.168.1.50"}),
        ("audit_postmessage_messaging_security", {"url": "https://corp.local/app"}),
        ("audit_http_parameter_pollution", {"url": "https://corp.local/search?q=test"}),
        ("audit_container_breakout_vectors", {"manifest_content": "privileged: true"}),
    ]

    for tool_name, args in batch6_tools:
        # Normalization
        norm = AgentEngine._normalize_tool_call_dict({"name": tool_name, "arguments": args})
        assert norm is not None
        assert norm["function"]["name"] == tool_name

        # Risk assessment
        risk = AgentEngine._assess_risk(tool_name, args)
        assert risk == "LOW"

        # Pedagogical explanation
        exp = engine._explain_tool_action(tool_name, args)
        assert "what" in exp
        assert "why" in exp
        assert "params" in exp
        assert len(exp["what"]) > 5
        assert len(exp["why"]) > 10


# ============================================================================
# 2. AD CS Certificate Templates (ESC1-ESC8)
# ============================================================================

@pytest.mark.asyncio
async def test_audit_adcs_esc1_vulnerable(executor):
    """Test AD CS template vulnerable to ESC1 (SAN abuse by low-priv users)."""
    vulnerable_templates = [
        {
            "name": "VulnUserCert",
            "client_authentication": True,
            "enrollee_supplies_subject": True,
            "requires_manager_approval": False,
            "authorized_signatures_required": 0,
            "enroll_principals": ["Domain Users"],
        }
    ]
    res = await executor._handle_audit_adcs_certificate_templates(
        domain="corp.local",
        templates_data=vulnerable_templates,
    )
    assert res["domain"] == "corp.local"
    assert "ESC1" in res["esc_vectors_detected"]
    assert res["score"] <= 15
    assert res["grade"] == "F"
    assert any("ESC1" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_adcs_esc8_web_enrollment(executor):
    """Test AD CS audit identifying HTTP Web Enrollment exposure (ESC8)."""
    templates = [
        {
            "name": "WebCA",
            "ca_web_http": True,
            "client_authentication": False,
        }
    ]
    res = await executor._handle_audit_adcs_certificate_templates(
        domain="corp.local",
        templates_data=templates,
    )
    assert "ESC8" in res["esc_vectors_detected"]
    assert any("ESC8" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_adcs_hardened(executor):
    """Test AD CS with secure template configuration."""
    secure_templates = [
        {
            "name": "SecureAdminCert",
            "client_authentication": True,
            "enrollee_supplies_subject": False,
            "requires_manager_approval": True,
            "authorized_signatures_required": 1,
            "enroll_principals": ["Enterprise Admins"],
        }
    ]
    res = await executor._handle_audit_adcs_certificate_templates(
        domain="corp.local",
        templates_data=secure_templates,
    )
    assert len(res["esc_vectors_detected"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 3. SMB Signing & Null Sessions
# ============================================================================

@pytest.mark.asyncio
async def test_audit_smb_signing_disabled(executor):
    """Test SMB server with signing disabled (vulnerable to NTLM Relay)."""
    # Create dummy SMB2 negotiate response with SecurityMode = 0x01 (Signing enabled but NOT required)
    fake_header = b"\x00\x00\x00\x50\xfeSMB" + (b"\x00" * 60)
    fake_body = b"\x24\x00\x01\x00" + (b"\x00" * 20)  # SecurityMode = 0x01 (not required)
    mock_response = fake_header + fake_body

    mock_sock = MagicMock()
    mock_sock.recv.return_value = mock_response

    with patch("socket.socket") as mock_socket_cls:
        mock_socket_cls.return_value = mock_sock
        res = await executor._handle_audit_smb_signing_and_null_sessions(
            host="192.168.1.100",
            port=445,
        )

        assert res["smb_open"] is True
        assert res["smb_signing_required"] is False
        assert res["relay_vulnerable"] is True
        assert res["score"] < 60
        assert any("SMB Signing" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_smb_port_closed(executor):
    """Test SMB probe when port 445 is closed."""
    with patch("socket.socket") as mock_socket_cls:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.error("Connection refused")
        mock_socket_cls.return_value = mock_sock

        res = await executor._handle_audit_smb_signing_and_null_sessions(
            host="10.0.0.1",
            port=445,
        )

        assert res["smb_open"] is False
        assert res["score"] == 100
        assert res["grade"] == "A"


# ============================================================================
# 4. HTML5 postMessage Messaging Security
# ============================================================================

@pytest.mark.asyncio
async def test_audit_postmessage_vulnerable_sink(executor):
    """Test postMessage handler without origin check and dangerous innerHTML sink."""
    vulnerable_script = """
    <script>
        window.addEventListener("message", function(e) {
            document.getElementById("output").innerHTML = e.data;
        });
        window.parent.postMessage({token: "secret123"}, "*");
    </script>
    """
    res = await executor._handle_audit_postmessage_messaging_security(
        url="https://corp.com.br/chat.html",
        html_or_script_content=vulnerable_script,
    )

    assert res["listeners_found"] >= 1
    assert res["unvalidated_origin_count"] >= 1
    assert res["wildcard_postmessage_count"] >= 1
    assert res["dom_xss_sink_count"] >= 1
    assert res["score"] < 50
    assert res["grade"] == "F"


@pytest.mark.asyncio
async def test_audit_postmessage_hardened(executor):
    """Test postMessage handler with strict event.origin validation."""
    secure_script = """
    <script>
        window.addEventListener("message", function(event) {
            if (event.origin !== "https://trusted.corp.com.br") {
                return;
            }
            console.log("Safe data:", event.data);
        });
    </script>
    """
    res = await executor._handle_audit_postmessage_messaging_security(
        url="https://trusted.corp.com.br/app",
        html_or_script_content=secure_script,
    )

    assert res["listeners_found"] == 1
    assert res["unvalidated_origin_count"] == 0
    assert res["wildcard_postmessage_count"] == 0
    assert res["dom_xss_sink_count"] == 0
    assert res["score"] >= 90
    assert res["grade"] == "A"


# ============================================================================
# 5. HTTP Parameter Pollution (HPP)
# ============================================================================

@pytest.mark.asyncio
async def test_audit_hpp_precedence_last_wins(executor):
    """Test HPP probe detecting 'last_wins' precedence with WAF bypass risk."""
    mock_resp = MagicMock()
    mock_resp.text = "Search results for: arcanum_hpp_val2"
    mock_resp.status_code = 200

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    with patch("httpx.AsyncClient", return_value=mock_client):
        res = await executor._handle_audit_http_parameter_pollution(
            url="https://corp.com.br/search?q=test",
            param_name="q",
        )

        assert res["hpp_detected"] is True
        assert res["precedence_behavior"] == "last_wins"
        assert res["waf_bypass_risk"] is True
        assert res["score"] < 75
        assert any("HPP" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_hpp_array_conversion(executor):
    """Test HPP probe detecting array conversion when both duplicate parameters reflect."""
    mock_resp = MagicMock()
    mock_resp.text = "Filtered items: ['arcanum_hpp_val1', 'arcanum_hpp_val2']"
    mock_resp.status_code = 200

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    with patch("httpx.AsyncClient", return_value=mock_client):
        res = await executor._handle_audit_http_parameter_pollution(
            url="https://corp.com.br/api/items?tag=tech",
            param_name="tag",
        )

        assert res["hpp_detected"] is True
        assert res["precedence_behavior"] == "array_conversion"
        assert res["waf_bypass_risk"] is True


# ============================================================================
# 6. Container Breakout Vectors
# ============================================================================

@pytest.mark.asyncio
async def test_audit_container_breakout_vulnerable(executor):
    """Test container breakout audit identifying privileged container and host mounts."""
    vulnerable_manifest = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: attack-pod
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: backdoor
        image: alpine
        securityContext:
          privileged: true
          capabilities:
            add: ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"]
        volumeMounts:
        - mountPath: /var/run/docker.sock
          name: dockersock
    """
    res = await executor._handle_audit_container_breakout_vectors(
        manifest_content=vulnerable_manifest,
        target_name="attack-pod",
    )

    assert "privileged_container" in res["breakout_vectors_found"]
    assert "cap_sys_admin" in res["breakout_vectors_found"]
    assert "cap_sys_ptrace" in res["breakout_vectors_found"]
    assert "host_pid_namespace" in res["breakout_vectors_found"]
    assert "docker_socket_mount" in res["breakout_vectors_found"]
    assert res["risk_level"] == "critical"
    assert res["score"] <= 20
    assert res["grade"] == "F"


@pytest.mark.asyncio
async def test_audit_container_breakout_hardened(executor):
    """Test hardened container manifest complying with PodSecurity Restricted standards."""
    hardened_manifest = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: secure-microservice
    spec:
      hostPID: false
      hostNetwork: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
      - name: web
        image: nginx:alpine
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
    """
    res = await executor._handle_audit_container_breakout_vectors(
        manifest_content=hardened_manifest,
        target_name="secure-microservice",
    )

    assert len(res["breakout_vectors_found"]) == 0
    assert res["risk_level"] == "low"
    assert res["score"] == 100
    assert res["grade"] == "A"
