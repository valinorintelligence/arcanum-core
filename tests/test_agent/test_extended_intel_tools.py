"""Unit and integration tests for crt.sh (Certificate Transparency), CISA KEV / EPSS, security.txt/robots.txt, and cloud storage audits."""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from arcanum.agent.tools import (
    NATIVE_TOOLS,
    RECON_TOOLS,
    ANALYSIS_TOOLS,
    ToolExecutor,
)
from arcanum.agent.engine import AgentEngine


def test_extended_intel_tool_registrations():
    """Verify tool registrations in NATIVE_TOOLS, RECON_TOOLS, and ANALYSIS_TOOLS."""
    tool_names = [t["function"]["name"] for t in NATIVE_TOOLS]
    assert "search_cert_transparency" in tool_names
    assert "enrich_cve_threat" in tool_names
    assert "audit_well_known_security" in tool_names
    assert "audit_cloud_storage" in tool_names

    assert "search_cert_transparency" in RECON_TOOLS
    assert "audit_well_known_security" in RECON_TOOLS
    assert "audit_cloud_storage" in RECON_TOOLS

    assert "enrich_cve_threat" in ANALYSIS_TOOLS
    assert "audit_well_known_security" in ANALYSIS_TOOLS
    assert "audit_cloud_storage" in ANALYSIS_TOOLS


def test_engine_explanations_for_extended_intel_tools():
    """Verify pedagogical explanations for the 4 new intelligence tools."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "recon"
    engine.session = {"target": "empresa.com.br"}

    exp_ct = engine._explain_tool_action("search_cert_transparency", {"domain": "empresa.com.br"})
    assert "Certificate Transparency" in exp_ct["what"]
    assert "crt.sh" in exp_ct["why"]

    exp_cve = engine._explain_tool_action("enrich_cve_threat", {"cve_id": "CVE-2021-44228"})
    assert "CISA KEV" in exp_cve["what"]
    assert "EPSS" in exp_cve["what"]

    exp_wk = engine._explain_tool_action("audit_well_known_security", {"url": "https://empresa.com.br"})
    assert "RFC 9116" in exp_wk["what"]
    assert "security.txt" in exp_wk["why"]
    assert "robots.txt" in exp_wk["why"]

    exp_cs = engine._explain_tool_action("audit_cloud_storage", {"target": "empresa.com.br"})
    assert "AWS S3" in exp_cs["what"]
    assert "listagem pública" in exp_cs["why"].lower()


@pytest.mark.asyncio
async def test_search_cert_transparency_success():
    """Verify crt.sh parsing, subdomain extraction and normalization."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = MagicMock(return_value=[
        {
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "empresa.com.br",
            "name_value": "*.empresa.com.br\nempresa.com.br\nvpn.empresa.com.br",
        },
        {
            "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert Global CA",
            "common_name": "dev-api.empresa.com.br",
            "name_value": "dev-api.empresa.com.br\nhomolog.empresa.com.br",
        }
    ])

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_search_cert_transparency("https://empresa.com.br")
        assert res["domain"] == "empresa.com.br"
        assert res["unique_subdomains_count"] >= 4
        assert "vpn.empresa.com.br" in res["subdomains"]
        assert "dev-api.empresa.com.br" in res["subdomains"]
        assert any("vpn" in s for s in res["interesting_subdomains"])
        assert any("dev" in s for s in res["interesting_subdomains"])


@pytest.mark.asyncio
async def test_search_cert_transparency_connection_error():
    """Verify graceful handling when crt.sh connection fails."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    with patch("httpx.AsyncClient.get", side_effect=Exception("ReadTimeout")):
        res = await executor._handle_search_cert_transparency("error-domain.com")
        assert "error" in res
        assert res["subdomains"] == []


@pytest.mark.asyncio
async def test_enrich_cve_threat_with_cisa_kev_and_epss():
    """Verify CISA KEV match with ransomware flag and high EPSS probability."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_epss_resp = MagicMock()
    mock_epss_resp.status_code = 200
    mock_epss_resp.json = MagicMock(return_value={
        "status": "OK",
        "data": [{"cve": "CVE-2021-44228", "epss": "0.97540", "percentile": "0.99910", "date": "2026-10-02"}]
    })

    mock_kev_resp = MagicMock()
    mock_kev_resp.status_code = 200
    mock_kev_resp.json = MagicMock(return_value={
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j Remote Code Execution",
                "dateAdded": "2021-12-10",
                "requiredAction": "Apply updates per vendor instructions.",
                "knownRansomwareCampaignUse": "Known",
            }
        ]
    })

    async def _mock_get(url, *args, **kwargs):
        if "first.org" in url:
            return mock_epss_resp
        return mock_kev_resp

    with patch("httpx.AsyncClient.get", side_effect=_mock_get):
        res = await executor._handle_enrich_cve_threat("CVE-2021-44228")
        assert res["cve_id"] == "CVE-2021-44228"
        assert res["in_cisa_kev"] is True
        assert res["is_active_in_the_wild"] is True
        assert "CRÍTICO" in res["threat_level"]
        assert res["cisa_kev_details"]["known_ransomware_campaign_use"] == "Known"
        assert res["epss"]["score"] == 0.9754


@pytest.mark.asyncio
async def test_enrich_cve_threat_invalid_id():
    """Verify validation of CVE format."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    res = await executor._handle_enrich_cve_threat("INVALID-CVE")
    assert "error" in res


@pytest.mark.asyncio
async def test_audit_well_known_security_with_security_txt_and_robots():
    """Verify parsing of security.txt policy and robots.txt disallowed directories."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_security_txt = MagicMock()
    mock_security_txt.status_code = 200
    mock_security_txt.text = (
        "Contact: mailto:security@empresa.com.br\n"
        "Expires: 2027-12-31T23:59:59.000Z\n"
        "Preferred-Languages: pt, en\n"
        "Policy: https://empresa.com.br/security-policy\n"
    )

    mock_robots = MagicMock()
    mock_robots.status_code = 200
    mock_robots.text = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /wp-admin/\n"
        "Disallow: /backup_2025/\n"
        "Sitemap: https://empresa.com.br/sitemap.xml\n"
    )

    mock_sitemap = MagicMock()
    mock_sitemap.status_code = 200
    mock_sitemap.headers = {"content-type": "application/xml"}
    mock_sitemap.text = "<urlset></urlset>"

    async def _mock_get(url, *args, **kwargs):
        if "security.txt" in url:
            return mock_security_txt
        elif "robots.txt" in url:
            return mock_robots
        elif "sitemap.xml" in url:
            return mock_sitemap
        resp = MagicMock()
        resp.status_code = 404
        return resp

    with patch("httpx.AsyncClient.get", side_effect=_mock_get):
        res = await executor._handle_audit_well_known_security("https://empresa.com.br")
        assert res["has_security_txt"] is True
        assert res["security_policy"]["contact"] == "mailto:security@empresa.com.br"
        assert res["robots_txt_found"] is True
        assert len(res["sensitive_disallowed_paths"]) >= 2
        assert any("admin" in p for p in res["sensitive_disallowed_paths"])
        assert res["score"] >= 80


@pytest.mark.asyncio
async def test_audit_cloud_storage_detected_open_bucket():
    """Verify detection of publicly listable cloud storage bucket."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_open_s3 = MagicMock()
    mock_open_s3.status_code = 200
    mock_open_s3.text = "<ListBucketResult><Name>empresa-backup</Name></ListBucketResult>"

    mock_private_gcs = MagicMock()
    mock_private_gcs.status_code = 403
    mock_private_gcs.text = "AccessDenied"

    async def _mock_get(url, *args, **kwargs):
        if "empresa-backup.s3.amazonaws.com" in url:
            return mock_open_s3
        elif "storage.googleapis.com/empresa" in url:
            return mock_private_gcs
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "NoSuchBucket"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=_mock_get):
        res = await executor._handle_audit_cloud_storage("empresa.com.br")
        assert res["target"] == "empresa.com.br"
        assert res["open_public_buckets_count"] >= 1
        assert res["open_public_buckets"][0]["exposure"] == "PUBLIC_LISTING_ENABLED"
        assert res["score"] == 30
        assert res["grade"] == "F"
        assert len(res["findings"]) > 0
