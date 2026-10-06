import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from arcanum.agent.engine import AgentEngine
from arcanum.agent.tools import ToolExecutor, RECON_TOOLS, ANALYSIS_TOOLS


def test_tools_registered_in_phases():
    assert "audit_dns_email_security" in RECON_TOOLS
    assert "audit_dns_email_security" in ANALYSIS_TOOLS
    assert "scan_exposed_secrets" in RECON_TOOLS
    assert "scan_exposed_secrets" in ANALYSIS_TOOLS


def test_pedagogical_explanations_new_tools():
    eng = AgentEngine(llm=None, tool_executor=None,
                      session={"name": "test", "target": "example.com", "mode": "autopilot"})
    exp1 = eng._explain_tool_action("audit_dns_email_security", {"domain": "example.com"})
    assert "what" in exp1 and "dns" in exp1["what"].lower()
    assert "why" in exp1 and "dmarc" in exp1["why"].lower()

    exp2 = eng._explain_tool_action("scan_exposed_secrets", {"url": "https://example.com"})
    assert "what" in exp2 and "segredos" in exp2["what"].lower()
    assert "why" in exp2 and "api" in exp2["why"].lower()


@pytest.mark.asyncio
async def test_audit_dns_email_security_hardened():
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # Mock DoH responses for a well-configured domain
    async def mock_doh_get(url, **kwargs):
        mock_r = MagicMock()
        mock_r.status_code = 200
        if "type=TXT" in url and "_dmarc" in url:
            mock_r.json.return_value = {
                "Status": 0,
                "Answer": [{"data": '"v=DMARC1; p=reject; rua=mailto:dmarc@corp.local"'}]
            }
        elif "type=TXT" in url:
            mock_r.json.return_value = {
                "Status": 0,
                "Answer": [{"data": '"v=spf1 include:_spf.corp.local -all"'}]
            }
        elif "type=MX" in url:
            mock_r.json.return_value = {
                "Status": 0,
                "Answer": [{"data": "10 mail.corp.local."}]
            }
        elif "type=CAA" in url:
            mock_r.json.return_value = {
                "Status": 0,
                "Answer": [{"data": '0 issue "letsencrypt.org"'}]
            }
        else:
            mock_r.json.return_value = {"Status": 0, "Answer": []}
        return mock_r

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = mock_doh_get
        res = await te._handle_audit_dns_email_security("corp.local")

    assert res["domain"] == "corp.local"
    assert res["score"] >= 90
    assert res["grade"] == "A"
    assert res["dmarc"]["configured"] is True
    assert "reject" in res["dmarc"]["policy"]
    assert res["spf"]["configured"] is True
    assert "-all" in res["spf"]["qualifier"]
    assert len(res["caa_records"]) == 1


@pytest.mark.asyncio
async def test_audit_dns_email_security_vulnerable():
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    # Mock DoH responses with missing DMARC and permissive SPF (+all)
    async def mock_doh_get(url, **kwargs):
        mock_r = MagicMock()
        mock_r.status_code = 200
        if "type=TXT" in url and "_dmarc" in url:
            mock_r.json.return_value = {"Status": 0, "Answer": []}
        elif "type=TXT" in url:
            mock_r.json.return_value = {
                "Status": 0,
                "Answer": [{"data": '"v=spf1 +all"'}]
            }
        else:
            mock_r.json.return_value = {"Status": 0, "Answer": []}
        return mock_r

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = mock_doh_get
        res = await te._handle_audit_dns_email_security("vulnerable.local")

    assert res["score"] < 50
    assert res["grade"] in ("D", "F")
    assert res["dmarc"]["configured"] is False
    assert any("DMARC" in f["record"] for f in res["findings"])
    assert any("+all" in f["issue"] for f in res["findings"])


@pytest.mark.asyncio
async def test_scan_exposed_secrets_detects_and_masks():
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    html_payload = """
    <!DOCTYPE html>
    <html>
      <head>
        <script src="/static/app.js"></script>
      </head>
      <body>
        <script>
          const firebaseConfig = { databaseURL: "https://my-test-app.firebaseio.com" };
        </script>
      </body>
    </html>
    """

    js_payload = """
    // Frontend bundle
    const stripeKey = "pk_live_1234567890abcdefghijklmn";
    const awsKey = "AKIAIOSFODNN7EXAMPLE";
    const apiKey = "AIzaSyD-1234567890abcdefghijk_lmnopqrstuv";
    """

    async def mock_client_get(url, **kwargs):
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.url = httpx.URL(url)
        if url.endswith("app.js"):
            mock_r.text = js_payload
        else:
            mock_r.text = html_payload
        return mock_r

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = mock_client_get
        res = await te._handle_scan_exposed_secrets("https://demo.local")

    assert res["status"] == "secrets_exposed"
    assert res["secrets_count"] >= 3
    types = [s["type"] for s in res["secrets_found"]]
    assert "AWS Access Key" in types
    assert "Google Cloud API Key" in types
    assert "Stripe Publishable Key" in types

    # Verify all secrets are masked
    for s in res["secrets_found"]:
        assert "[masked]" in s["masked_value"]
        assert "AKIAIOSFODNN7EXAMPLE" not in s["masked_value"]


@pytest.mark.asyncio
async def test_scan_exposed_secrets_clean_page():
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL("https://clean.local")
    mock_resp.text = "<html><body><h1>Site Limpo</h1></body></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await te._handle_scan_exposed_secrets("https://clean.local")

    assert res["status"] == "clean"
    assert res["secrets_count"] == 0
    assert len(res["secrets_found"]) == 0
