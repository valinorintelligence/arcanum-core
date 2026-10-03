"""Unit and integration tests for TLS/SSL audit and OpenAPI contract audit tools."""

import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from arcanum.agent.tools import (
    NATIVE_TOOLS,
    RECON_TOOLS,
    ANALYSIS_TOOLS,
    ToolExecutor,
)
from arcanum.agent.engine import AgentEngine


def test_tls_and_api_spec_tool_registrations():
    """Verify audit_tls_ssl and audit_api_spec are correctly registered."""
    tool_names = [t["function"]["name"] for t in NATIVE_TOOLS]
    assert "audit_tls_ssl" in tool_names
    assert "audit_api_spec" in tool_names

    assert "audit_tls_ssl" in RECON_TOOLS
    assert "audit_api_spec" in ANALYSIS_TOOLS


def test_engine_explanations_for_tls_and_api_spec():
    """Verify pedagogical explanations for the new audit tools."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "recon"
    engine.session = {"target": "example.com"}

    exp_tls = engine._explain_tool_action("audit_tls_ssl", {"hostname": "example.com", "port": 443})
    assert "TLS/SSL" in exp_tls["what"]
    assert "criptográfica" in exp_tls["what"]
    assert "443" in exp_tls["params"]

    engine.current_phase = "analysis"
    exp_api = engine._explain_tool_action("audit_api_spec", {"url": "https://api.example.com"})
    assert "OpenAPI/Swagger" in exp_api["what"]
    assert "contratos de API" in exp_api["what"]
    assert "api.example.com" in exp_api["params"]


@pytest.mark.asyncio
async def test_audit_tls_ssl_invalid_host():
    """Verify invalid hostname handling."""
    executor = ToolExecutor(
        sandbox=None,
        browser=None,
        workspace_dir=None,
        db=None,
    )
    res = await executor._handle_audit_tls_ssl(host="")
    assert res.get("error") == "Hostname inválido fornecido."


@pytest.mark.asyncio
async def test_audit_tls_ssl_connection_failure():
    """Verify socket error handling when host is unreachable."""
    executor = ToolExecutor(
        sandbox=None,
        browser=None,
        workspace_dir=None,
        db=None,
    )
    with patch("socket.create_connection", side_effect=OSError("Connection refused")):
        res = await executor._handle_audit_tls_ssl(host="nonexistent.local", port=443)
        assert res["score"] == 0
        assert res["grade"] == "F"
        assert "Falha na conexão TLS/SSL" in res["error"]
        assert len(res["findings"]) > 0


@pytest.mark.asyncio
async def test_audit_tls_ssl_mock_valid_certificate():
    """Verify TLS audit parsing with mocked valid TLS 1.3 handshake."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Verified Security CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com"), x509.DNSName("www.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    executor = ToolExecutor(
        sandbox=None,
        browser=None,
        workspace_dir=None,
        db=None,
    )

    with patch("asyncio.to_thread") as mock_thread:
        # returns: raw_der, cipher, proto, is_trusted_ca, cert_error
        mock_thread.return_value = (
            der_bytes,
            ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "TLSv1.3",
            True,
            None,
        )

        res = await executor._handle_audit_tls_ssl(host="example.com", port=443)
        assert res["protocol"] == "TLSv1.3"
        assert res["cipher_bits"] == 256
        assert res["score"] == 100
        assert res["grade"] == "A"
        assert res["certificate"]["common_name"] == "example.com"
        assert res["certificate"]["issuer_ca"] == "Verified Security CA"
        assert "example.com" in res["certificate"]["sans"]
        assert res["certificate"]["trusted_ca"] is True


@pytest.mark.asyncio
async def test_audit_tls_ssl_mock_expired_and_weak_cipher():
    """Verify penalties for expired cert, weak cipher and legacy protocol."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=400))
        .not_valid_after(now - datetime.timedelta(days=20))  # expired
        .sign(key, hashes.SHA256())
    )
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    executor = ToolExecutor(
        sandbox=None,
        browser=None,
        workspace_dir=None,
        db=None,
    )

    with patch("asyncio.to_thread") as mock_thread:
        # Mock legacy protocol (SSLv3) + weak cipher (RC4 64-bit) + untrusted + expired
        mock_thread.return_value = (
            der_bytes,
            ("RC4-MD5", "SSLv3", 64),
            "SSLv3",
            False,
            "Certificate expired and untrusted",
        )

        res = await executor._handle_audit_tls_ssl(host="expired.example.com", port=443)
        assert res["score"] <= 20
        assert res["grade"] in ("D", "F")
        issues = [f["issue"] for f in res["findings"]]
        assert any("obsoleto" in iss.lower() for iss in issues)
        assert any("fraca" in iss.lower() for iss in issues)
        assert any("expirado" in iss.lower() for iss in issues)


@pytest.mark.asyncio
async def test_audit_api_spec_not_found():
    """Verify audit_api_spec when no spec is exposed on candidate paths."""
    executor = ToolExecutor(
        sandbox=None,
        browser=None,
        workspace_dir=None,
        db=None,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"
    mock_resp.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_audit_api_spec(url="https://example.com")
        assert res["spec_found"] is False
        assert res["total_endpoints"] == 0


@pytest.mark.asyncio
async def test_audit_api_spec_found_with_findings():
    """Verify OpenAPI spec detection with missing auth and exposed admin routes."""
    executor = ToolExecutor(
        sandbox=None,
        browser=None,
        workspace_dir=None,
        db=None,
    )

    mock_spec = {
        "openapi": "3.0.1",
        "info": {"title": "E-Commerce Public API", "version": "2.1.0"},
        "paths": {
            "/api/v1/products": {
                "get": {"summary": "List products"}
            },
            "/api/v1/admin/users": {
                "get": {"summary": "List sensitive users"},
                "delete": {"summary": "Delete user"}
            },
            "/internal/metrics": {
                "get": {"summary": "System metrics"}
            }
        },
        "components": {}  # No securitySchemes defined
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.text = '{"openapi": "3.0.1"}'
    mock_resp.json = MagicMock(return_value=mock_spec)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_audit_api_spec(url="https://api.example.com")
        assert res["spec_found"] is True
        assert res["title"] == "E-Commerce Public API"
        assert res["total_endpoints"] == 4
        assert len(res["security_schemes"]) == 0
        assert any("/admin/users" in r for r in res["sensitive_routes_sample"])
        assert any("/metrics" in r for r in res["sensitive_routes_sample"])
        assert res["score"] < 90
        issues = [f["issue"] for f in res["findings"]]
        assert any("esquema de segurança" in iss.lower() for iss in issues)
        assert any("administração" in iss.lower() for iss in issues)
