"""Unit and integration tests for WHOIS/RDAP (BrasilAPI), IP intelligence and Wayback Machine historical URLs."""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from arcanum.agent.tools import (
    NATIVE_TOOLS,
    RECON_TOOLS,
    ANALYSIS_TOOLS,
    ToolExecutor,
)
from arcanum.agent.engine import AgentEngine


def test_osint_tools_registration():
    """Verify query_whois_rdap, enrich_ip_intel, and search_historical_urls registrations."""
    tool_names = [t["function"]["name"] for t in NATIVE_TOOLS]
    assert "query_whois_rdap" in tool_names
    assert "enrich_ip_intel" in tool_names
    assert "search_historical_urls" in tool_names

    assert "query_whois_rdap" in RECON_TOOLS
    assert "enrich_ip_intel" in RECON_TOOLS
    assert "search_historical_urls" in RECON_TOOLS
    assert "search_historical_urls" in ANALYSIS_TOOLS


def test_engine_explanations_for_osint_tools():
    """Verify pedagogical explanations in pt-BR for OSINT tools."""
    engine = AgentEngine.__new__(AgentEngine)
    engine.current_phase = "recon"
    engine.session = {"target": "empresa.com.br"}

    exp_whois = engine._explain_tool_action("query_whois_rdap", {"domain": "empresa.com.br"})
    assert "WHOIS/RDAP" in exp_whois["what"]
    assert "BrasilAPI" in exp_whois["params"]

    exp_ip = engine._explain_tool_action("enrich_ip_intel", {"target": "104.21.5.10"})
    assert "inteligência de rede" in exp_ip["what"].lower()
    assert "ASN" in exp_ip["what"]

    exp_history = engine._explain_tool_action("search_historical_urls", {"domain": "empresa.com.br", "limit": 40})
    assert "Wayback Machine" in exp_history["what"]
    assert "AlienVault OTX" in exp_history["what"]
    assert "40" in exp_history["params"]


@pytest.mark.asyncio
async def test_query_whois_rdap_brasilapi_success():
    """Verify BrasilAPI lookup for .br domains."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = MagicMock(return_value={
        "status": "REGISTERED",
        "fqdn": "empresa.com.br",
        "hosts": ["ns1.empresa.com.br", "ns2.empresa.com.br"],
        "expires-at": "2028-10-25T00:00:00-03:00",
        "publication-status": "published",
        "suggestions": ["empresa.net.br"],
    })

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_query_whois_rdap("https://empresa.com.br/contato")
        assert res["domain"] == "empresa.com.br"
        assert res["source"] == "BrasilAPI (Registro.br)"
        assert res["registered"] is True
        assert "ns1.empresa.com.br" in res["nameservers"]
        assert res["expires_at"] == "2028-10-25T00:00:00-03:00"


@pytest.mark.asyncio
async def test_query_whois_rdap_global_rdap_success():
    """Verify RDAP lookup for international domains."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = MagicMock(return_value={
        "handle": "DOMAIN_1234",
        "status": ["active", "clientTransferProhibited"],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]]
            },
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@cloudflare.com"]]]
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2025-01-15T00:00:00Z"}
        ],
        "nameservers": [{"ldhName": "ns1.cloudflare.com"}, {"ldhName": "ns2.cloudflare.com"}]
    })

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_query_whois_rdap("target-corp.com")
        assert res["domain"] == "target-corp.com"
        assert res["source"] == "RDAP (Global)"
        assert res["registered"] is True
        assert res["registrar"] == "Cloudflare, Inc."
        assert res["abuse_email"] == "abuse@cloudflare.com"
        assert "ns1.cloudflare.com" in res["nameservers"]
        assert res["created_at"] == "2020-01-15T00:00:00Z"


@pytest.mark.asyncio
async def test_enrich_ip_intel_cdn_detection():
    """Verify IP intelligence and CDN detection."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = MagicMock(return_value={
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "regionName": "California",
        "city": "San Francisco",
        "isp": "Cloudflare, Inc",
        "org": "Cloudflare, Inc.",
        "as": "AS13335 Cloudflare, Inc.",
        "asname": "CLOUDFLARENET",
        "hosting": True,
        "query": "104.21.5.10",
    })

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await executor._handle_enrich_ip_intel("104.21.5.10")
        assert res["ip"] == "104.21.5.10"
        assert res["as_name"] == "CLOUDFLARENET"
        assert res["is_cdn_or_waf"] is True
        assert "CDN" in res["infrastructure_type"]
        assert "Anycast" in res["guidance"]


@pytest.mark.asyncio
async def test_enrich_ip_intel_with_hostname_resolution():
    """Verify IP intelligence resolves hostname and identifies cloud provider."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = MagicMock(return_value={
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "regionName": "Virginia",
        "city": "Ashburn",
        "isp": "Amazon.com, Inc.",
        "org": "AWS EC2",
        "as": "AS16509 Amazon.com, Inc.",
        "asname": "AMAZON-02",
        "hosting": True,
        "query": "52.95.110.1",
    })

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_resolve, \
         patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resolve.return_value = "52.95.110.1"
        mock_get.return_value = mock_resp

        res = await executor._handle_enrich_ip_intel("api.target.com")
        assert res["target"] == "api.target.com"
        assert res["ip"] == "52.95.110.1"
        assert res["is_cdn_or_waf"] is False
        assert "Nuvem Pública" in res["infrastructure_type"]


@pytest.mark.asyncio
async def test_search_historical_urls_wayback_and_otx():
    """Verify passive discovery of historical URLs and categorization."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_wayback_resp = MagicMock()
    mock_wayback_resp.status_code = 200
    mock_wayback_resp.json = MagicMock(return_value=[
        ["original"],
        ["https://example.com/wp-admin/login.php"],
        ["https://example.com/api/v1/users"],
        ["https://example.com/config.json"],
        ["https://example.com/search?token=secret123&redirect=home"],
    ])

    mock_otx_resp = MagicMock()
    mock_otx_resp.status_code = 200
    mock_otx_resp.json = MagicMock(return_value={
        "url_list": [
            {"url": "https://example.com/admin/dashboard"},
            {"url": "https://example.com/backup.sql"},
        ]
    })

    async def _mock_client_get(url, *args, **kwargs):
        if "web.archive.org" in url:
            return mock_wayback_resp
        return mock_otx_resp

    with patch("httpx.AsyncClient.get", side_effect=_mock_client_get):
        res = await executor._handle_search_historical_urls("example.com", limit=20)
        assert res["domain"] == "example.com"
        assert res["total_discovered"] >= 5

        endpoints = res["interesting_endpoints"]
        assert any("wp-admin" in u or "admin" in u for u in endpoints["admin_or_login"])
        assert any("/api/v1" in u for u in endpoints["api_routes"])
        assert any("config.json" in u or "backup.sql" in u for u in endpoints["sensitive_files"])
        assert any("token=" in u for u in endpoints["parameterized_urls"])
