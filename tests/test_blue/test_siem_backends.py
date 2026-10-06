"""F2 (b) — real SIEM deploy backends: Splunk saved-search + Microsoft Sentinel.

Exercised with a mocked httpx client (no live SIEM): we assert the backend selection,
the request shape (endpoint, auth, body) and verify/rollback routing by the prefixed
external id. Honest mock fallback and precedence are covered too.
"""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.blue.registry import DeploymentRegistry
from arcanum.blue.deployers.siem import SIEMDeployer

_FIELDS = ("elastic_url", "elastic_api_key", "splunk_mgmt_url", "splunk_mgmt_token",
           "splunk_username", "splunk_password", "sentinel_resource_id", "sentinel_token")


class _Cfg:
    def __init__(self, **kw):
        for f in _FIELDS:
            setattr(self, f, "")
        self.splunk_app = "search"
        self.sentinel_api_version = "2023-11-01"
        for k, v in kw.items():
            setattr(self, k, v)


class _Resp:
    def __init__(self, code, payload=None, text=""):
        self.status_code = code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def _fake_httpx(calls, responder):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def _do(self, method, url, **kw):
            calls.append((method, url, kw))
            return responder(method, url, kw)

        async def post(self, url, **kw):
            return await self._do("POST", url, **kw)

        async def get(self, url, **kw):
            return await self._do("GET", url, **kw)

        async def delete(self, url, **kw):
            return await self._do("DELETE", url, **kw)

        async def put(self, url, **kw):
            return await self._do("PUT", url, **kw)
    return _Client


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "siem.db")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

def test_backend_precedence_and_unconfigured():
    assert SIEMDeployer(config=_Cfg()).configured() is False
    assert SIEMDeployer(config=_Cfg(splunk_mgmt_url="https://s:8089", splunk_mgmt_token="t"))._backend() == "splunk"
    assert SIEMDeployer(config=_Cfg(sentinel_resource_id="/subscriptions/x", sentinel_token="t"))._backend() == "sentinel"
    # Elastic wins when several are set.
    both = SIEMDeployer(config=_Cfg(elastic_url="https://e", elastic_api_key="k",
                                    splunk_mgmt_url="https://s:8089", splunk_mgmt_token="t"))
    assert both._backend() == "elastic"


# ---------------------------------------------------------------------------
# Splunk saved-search
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_splunk_deploy_shape(monkeypatch):
    dep = SIEMDeployer(config=_Cfg(splunk_mgmt_url="https://splunk:8089",
                                   splunk_mgmt_token="tok", splunk_app="search"))
    calls = []
    monkeypatch.setattr("arcanum.blue.deployers.siem.httpx.AsyncClient",
                        _fake_httpx(calls, lambda m, u, kw: _Resp(201, {})))
    ext = await dep._deploy_real({"name": "R1", "spl": "index=main sourcetype=foo"})
    assert ext == "splunk:R1"
    method, url, kw = calls[0]
    assert method == "POST" and url.endswith("/servicesNS/nobody/search/saved/searches")
    assert kw["headers"]["Authorization"] == "Bearer tok"
    assert kw["data"]["search"] == "index=main sourcetype=foo" and kw["data"]["name"] == "R1"
    assert kw["data"]["is_scheduled"] == "1"


@pytest.mark.asyncio
async def test_splunk_requires_spl():
    dep = SIEMDeployer(config=_Cfg(splunk_mgmt_url="https://s:8089", splunk_mgmt_token="t"))
    with pytest.raises(RuntimeError):
        await dep._deploy_real({"name": "R1"})  # no SPL/query


@pytest.mark.asyncio
async def test_splunk_verify_and_rollback_route(monkeypatch):
    dep = SIEMDeployer(config=_Cfg(splunk_mgmt_url="https://s:8089", splunk_username="u", splunk_password="p"))
    calls = []
    monkeypatch.setattr("arcanum.blue.deployers.siem.httpx.AsyncClient",
                        _fake_httpx(calls, lambda m, u, kw: _Resp(200, {})))
    assert await dep._verify_real({"external_id": "splunk:R1", "status": "active"}) is True
    assert calls[0][0] == "GET" and calls[0][1].endswith("/saved/searches/R1?output_mode=json")
    # Basic auth used when no token.
    assert calls[0][2]["auth"] == ("u", "p")
    await dep._rollback_real({"external_id": "splunk:R1"})
    assert calls[1][0] == "DELETE"


# ---------------------------------------------------------------------------
# Microsoft Sentinel
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sentinel_deploy_shape(monkeypatch):
    scope = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
    dep = SIEMDeployer(config=_Cfg(sentinel_resource_id=scope, sentinel_token="tok"))
    calls = []
    monkeypatch.setattr("arcanum.blue.deployers.siem.httpx.AsyncClient",
                        _fake_httpx(calls, lambda m, u, kw: _Resp(200, {})))
    ext = await dep._deploy_real({"name": "R", "kql": "SecurityEvent | take 1", "rule_id": "rid-1"})
    assert ext == "sentinel:rid-1"
    method, url, kw = calls[0]
    assert method == "PUT"
    assert "providers/Microsoft.SecurityInsights/alertRules/rid-1" in url
    assert "api-version=2023-11-01" in url and url.startswith("https://management.azure.com")
    assert kw["headers"]["Authorization"] == "Bearer tok"
    assert kw["json"]["properties"]["query"] == "SecurityEvent | take 1"
    assert kw["json"]["kind"] == "Scheduled"


# ---------------------------------------------------------------------------
# End-to-end via BaseDeployer.deploy (registry + honest mock)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unconfigured_is_honest_mock(db):
    dep = SIEMDeployer(config=_Cfg(), registry=DeploymentRegistry(db))
    out = await dep.deploy({"name": "R1", "spl": "index=main"})
    assert out["mock"] is True and out["status"] == "active" and out["external_id"] is None


@pytest.mark.asyncio
async def test_configured_splunk_stores_prefixed_external_id(db, monkeypatch):
    dep = SIEMDeployer(config=_Cfg(splunk_mgmt_url="https://s:8089", splunk_mgmt_token="t"),
                       registry=DeploymentRegistry(db))
    monkeypatch.setattr("arcanum.blue.deployers.siem.httpx.AsyncClient",
                        _fake_httpx([], lambda m, u, kw: _Resp(201, {})))
    out = await dep.deploy({"name": "R1", "spl": "index=main"})
    assert out["mock"] is False and out["status"] == "active"
    assert out["external_id"] == "splunk:R1"
