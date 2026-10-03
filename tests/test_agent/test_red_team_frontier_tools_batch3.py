"""Unit tests for the 5 advanced Red Team frontier tools (Batch 3) in Arcanum.

Tools tested:
1. audit_grpc_api_security (gRPC Server Reflection, h2c cleartext, unauthenticated methods)
2. audit_insecure_deserialization (Java, Python Pickle, PHP, .NET serialization signatures)
3. audit_crlf_header_injection (CRLF HTTP header injection and Response Splitting)
4. audit_reverse_proxy_path_traversal (Nginx alias off-by-slash, Spring/Tomcat semicolon /..;/)
5. audit_s3_bucket_permissions_deep (IAM policy wildcard, PutObjectAcl privesc, anonymous read/write, dangling takeover)
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

def test_batch3_registrations():
    """Verify all 5 tools are registered in NATIVE_TOOLS and ToolExecutor handlers."""
    assert len(NATIVE_TOOLS) >= 81

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    expected = [
        "audit_grpc_api_security",
        "audit_insecure_deserialization",
        "audit_crlf_header_injection",
        "audit_reverse_proxy_path_traversal",
        "audit_s3_bucket_permissions_deep",
    ]
    for name in expected:
        assert name in tool_names, f"Missing tool in NATIVE_TOOLS: {name}"

    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    for name in expected:
        assert name in executor._handlers, f"Missing handler in ToolExecutor: {name}"

    assert "audit_grpc_api_security" in RECON_TOOLS
    assert "audit_s3_bucket_permissions_deep" in RECON_TOOLS

    for name in expected:
        assert name in ANALYSIS_TOOLS


def test_batch3_normalizer_and_risk_scoring():
    """Verify tool normalization and low-risk rating in AgentEngine."""
    expected = [
        "audit_grpc_api_security",
        "audit_insecure_deserialization",
        "audit_crlf_header_injection",
        "audit_reverse_proxy_path_traversal",
        "audit_s3_bucket_permissions_deep",
    ]
    for name in expected:
        norm = AgentEngine._normalize_tool_call_dict({"name": name, "arguments": {}})
        assert norm is not None, f"Failed to normalize {name}"
        assert norm["function"]["name"] == name

        risk = AgentEngine._assess_risk(name, {})
        assert risk == "LOW", f"Risk for {name} should be LOW, got {risk}"


def test_batch3_pedagogical_explanations():
    """Verify pedagogical explanations for the 5 tools in Portuguese."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "analysis"
    engine.session = {"target": "corp.com.br"}

    exp_grpc = engine._explain_tool_action("audit_grpc_api_security", {"target": "grpc.corp.com.br:50051"})
    assert "grpc" in exp_grpc["what"].lower()
    assert "reflection" in exp_grpc["why"].lower() or "tls" in exp_grpc["why"].lower()

    exp_deser = engine._explain_tool_action("audit_insecure_deserialization", {"url": "https://corp.com.br/api"})
    assert "desserialização" in exp_deser["what"].lower()
    assert "rce" in exp_deser["why"].lower() or "gadget" in exp_deser["why"].lower() or "serialização" in exp_deser["why"].lower()

    exp_crlf = engine._explain_tool_action("audit_crlf_header_injection", {"url": "https://corp.com.br/redirect?url="})
    assert "crlf" in exp_crlf["what"].lower()
    assert "cookie" in exp_crlf["why"].lower() or "splitting" in exp_crlf["why"].lower()

    exp_proxy = engine._explain_tool_action("audit_reverse_proxy_path_traversal", {"url": "https://corp.com.br", "base_path": "/static"})
    assert "proxy" in exp_proxy["what"].lower() or "traversal" in exp_proxy["what"].lower()
    assert "nginx" in exp_proxy["why"].lower() or "normalização" in exp_proxy["why"].lower()

    exp_s3 = engine._explain_tool_action("audit_s3_bucket_permissions_deep", {"bucket_name": "corp-backups"})
    assert "bucket" in exp_s3["what"].lower()
    assert "iam" in exp_s3["why"].lower() or "pública" in exp_s3["why"].lower() or "takeover" in exp_s3["why"].lower()


# ============================================================================
# 2. gRPC API Security
# ============================================================================

@pytest.mark.asyncio
async def test_audit_grpc_api_security_vulnerable():
    """Test gRPC audit detecting reflection enabled, cleartext h2c, and missing auth."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/grpc", "grpc-status": "0"}
    mock_resp.text = "reflection service data"

    with patch("socket.create_connection", side_effect=Exception("Connection refused for TLS")), \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        res = await executor._handle_audit_grpc_api_security(target="api.corp.com.br:50051", use_tls=False)

    assert res["target"] == "api.corp.com.br"
    assert res["port"] == 50051
    assert res["h2c_cleartext"] is True
    assert res["reflection_enabled"] is True
    assert res["auth_missing"] is True
    assert "grpc.reflection.v1alpha.ServerReflection" in res["exposed_services"]
    assert res["score"] < 60
    assert res["grade"] in ("C", "F")
    assert any("Server Reflection" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_grpc_api_security_clean():
    """Test gRPC audit with TLS enforced and reflection disabled."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.headers = {"content-type": "application/grpc", "grpc-status": "12"}  # UNIMPLEMENTED
    mock_resp.text = ""

    with patch("socket.create_connection") as mock_conn, \
         patch("ssl.create_default_context") as mock_ssl, \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        # mock TLS wrap_socket
        mock_ctx = MagicMock()
        mock_ssl.return_value = mock_ctx
        mock_ctx.wrap_socket.return_value.__enter__.return_value = MagicMock()

        res = await executor._handle_audit_grpc_api_security(target="secure-grpc.corp.com.br:443", use_tls=True)

    assert res["tls_enforced"] is True
    assert res["reflection_enabled"] is False
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 3. Insecure Deserialization
# ============================================================================

@pytest.mark.asyncio
async def test_audit_insecure_deserialization_positive():
    """Test detection of Java, Python Pickle, PHP, and .NET serialization signatures."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # 1. Java cookie
    res_java = await executor._handle_audit_insecure_deserialization(
        url="https://corp.com.br/admin",
        cookies={"remember_me": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAU="},
    )
    assert res_java["deserialization_detected"] is True
    assert "Java" in res_java["detected_frameworks"]
    assert res_java["score"] <= 25

    # 2. Python Pickle payload
    res_pickle = await executor._handle_audit_insecure_deserialization(
        url="https://corp.com.br/api/process",
        payload="gANjcG9zaXgKc3lzdGVtCnEAWA=="
    )
    assert res_pickle["deserialization_detected"] is True
    assert "Python Pickle" in res_pickle["detected_frameworks"]

    # 3. PHP serialized parameter
    res_php = await executor._handle_audit_insecure_deserialization(
        url="https://corp.com.br/profile?data=O:4:%22User%22:2:{s:4:%22name%22;s:5:%22admin%22;}"
    )
    assert res_php["deserialization_detected"] is True
    assert "PHP" in res_php["detected_frameworks"]

    # 4. .NET TypeNameHandling header
    res_dotnet = await executor._handle_audit_insecure_deserialization(
        url="https://corp.com.br/api/config",
        headers={"X-Custom-Data": '{"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework"}'}
    )
    assert res_dotnet["deserialization_detected"] is True
    assert ".NET" in res_dotnet["detected_frameworks"]


@pytest.mark.asyncio
async def test_audit_insecure_deserialization_clean():
    """Test clean request with benign JSON tokens and cookies."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    res = await executor._handle_audit_insecure_deserialization(
        url="https://corp.com.br/api",
        cookies={"sessionid": "3b29c9fa8d104ebfa4"},
        headers={"Content-Type": "application/json"},
        payload={"username": "alice", "action": "view_dashboard"}
    )
    assert res["deserialization_detected"] is False
    assert res["score"] == 100
    assert res["grade"] == "A"
    assert len(res["detected_frameworks"]) == 0


# ============================================================================
# 4. CRLF Header Injection
# ============================================================================

@pytest.mark.asyncio
async def test_audit_crlf_header_injection_vulnerable():
    """Test CRLF header injection detection when response header reflects injected cookie."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {
        "location": "https://corp.com.br/login",
        "set-cookie": "arcanum_crlf=1; Path=/",
    }
    mock_resp.cookies = {"arcanum_crlf": "1"}
    mock_resp.text = "Redirecting..."

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await executor._handle_audit_crlf_header_injection(
            url="https://corp.com.br/redirect",
            parameter="next",
            method="GET"
        )

    assert res["crlf_detected"] is True
    assert res["parameter"] == "next"
    assert len(res["vulnerable_payloads"]) > 0
    assert "Set-Cookie: arcanum_crlf=1" in res["injected_headers"]
    assert res["score"] <= 25
    assert res["grade"] == "F"


@pytest.mark.asyncio
async def test_audit_crlf_header_injection_clean():
    """Test clean response sanitizing CRLF sequences."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.cookies = {}
    mock_resp.text = "Normal safe page content"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await executor._handle_audit_crlf_header_injection(
            url="https://corp.com.br/search",
            parameter="q"
        )

    assert res["crlf_detected"] is False
    assert res["response_splitting_possible"] is False
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 5. Reverse Proxy Path Traversal
# ============================================================================

@pytest.mark.asyncio
async def test_audit_reverse_proxy_path_traversal_vulnerable():
    """Test detection of Nginx alias off-by-slash or Spring semicolon normalization."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # Baseline returns 404, probe returns 200 with directory listing
    mock_base = MagicMock()
    mock_base.status_code = 404
    mock_base.text = "Not Found"

    mock_probe = MagicMock()
    mock_probe.status_code = 200
    mock_probe.text = "<html><head><title>Index of /secret_files</title></head><body><h1>Index of /</h1></body></html>"

    def side_effect_get(url):
        if url.endswith("/static/"):
            return mock_base
        return mock_probe

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=side_effect_get):
        res = await executor._handle_audit_reverse_proxy_path_traversal(
            url="https://corp.com.br",
            base_path="/static"
        )

    assert res["traversal_detected"] is True
    assert len(res["vulnerable_vectors"]) > 0
    assert res["score"] <= 25
    assert res["grade"] == "F"


@pytest.mark.asyncio
async def test_audit_reverse_proxy_path_traversal_clean():
    """Test clean reverse proxy rejecting traversal attempts."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await executor._handle_audit_reverse_proxy_path_traversal(
            url="https://corp.com.br",
            base_path="/assets"
        )

    assert res["traversal_detected"] is False
    assert len(res["vulnerable_vectors"]) == 0
    assert res["score"] == 100
    assert res["grade"] == "A"


# ============================================================================
# 6. S3 Bucket Deep Permissions
# ============================================================================

@pytest.mark.asyncio
async def test_audit_s3_bucket_permissions_deep_vulnerable_policy_and_probe():
    """Test S3 audit detecting wildcard Principal, public write, and PutObjectAcl privesc."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:PutObjectAcl"
                ],
                "Resource": "arn:aws:s3:::corp-data/*"
            }
        ]
    }

    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.text = "<ListBucketResult><Name>corp-data</Name></ListBucketResult>"

    mock_options = MagicMock()
    mock_options.headers = {"access-control-allow-origin": "*"}

    mock_put = MagicMock()
    mock_put.status_code = 200

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_get), \
         patch("httpx.AsyncClient.options", new_callable=AsyncMock, return_value=mock_options), \
         patch("httpx.AsyncClient.put", new_callable=AsyncMock, return_value=mock_put):
        res = await executor._handle_audit_s3_bucket_permissions_deep(
            bucket_name="corp-data",
            cloud_provider="aws",
            policy_document=policy,
            test_anonymous_access=True
        )

    assert res["bucket_name"] == "corp-data"
    assert res["public_read"] is True
    assert res["public_write"] is True
    assert res["wildcard_principal"] is True
    assert res["acl_privesc_risk"] is True
    assert res["cors_wildcard"] is True
    assert res["score"] == 0
    assert res["grade"] == "F"
    assert any("ESCRITA PÚBLICA" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_audit_s3_bucket_permissions_deep_clean():
    """Test securely configured private bucket."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_get = MagicMock()
    mock_get.status_code = 403
    mock_get.text = "<Error><Code>AccessDenied</Code></Error>"

    mock_options = MagicMock()
    mock_options.headers = {}

    mock_put = MagicMock()
    mock_put.status_code = 403

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_get), \
         patch("httpx.AsyncClient.options", new_callable=AsyncMock, return_value=mock_options), \
         patch("httpx.AsyncClient.put", new_callable=AsyncMock, return_value=mock_put):
        res = await executor._handle_audit_s3_bucket_permissions_deep(
            bucket_name="secure-private-vault",
            cloud_provider="aws",
            test_anonymous_access=True
        )

    assert res["public_read"] is False
    assert res["public_write"] is False
    assert res["wildcard_principal"] is False
    assert res["acl_privesc_risk"] is False
    assert res["dangling_takeover_risk"] is False
    assert res["score"] == 100
    assert res["grade"] == "A"
