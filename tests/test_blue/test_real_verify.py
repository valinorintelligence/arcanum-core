"""F2 (c) — real verify for WAF/EDR queries the external control.

Before this, a real (non-mock) deployment's ``verify`` just trusted the registry
status. Now it issues a GET to the admin endpoint by external id. Tested with a
mocked httpx client (no live WAF/EDR needed); the honest fallbacks (no external
id / non-200) are covered too.
"""

import pytest

from arcanum.blue.deployers.waf import WAFDeployer
from arcanum.blue.deployers.edr import EDRDeployer


class _Resp:
    def __init__(self, code):
        self.status_code = code


def _fake_client(status_code, sink):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            sink["url"] = url
            sink["auth"] = (headers or {}).get("Authorization")
            return _Resp(status_code)
    return _Client


@pytest.mark.asyncio
async def test_waf_verify_real_hits_endpoint(monkeypatch):
    monkeypatch.setenv("ARCANUM_WAF_ADMIN_URL", "https://waf.local")
    monkeypatch.setenv("ARCANUM_WAF_ADMIN_TOKEN", "tok")
    dep = WAFDeployer()
    assert dep.configured() is True

    sink = {}
    monkeypatch.setattr("arcanum.blue.deployers.waf.httpx.AsyncClient", _fake_client(200, sink))
    assert await dep._verify_real({"external_id": "rule-1"}) is True
    assert sink["url"] == "https://waf.local/rules/rule-1"
    assert sink["auth"] == "Bearer tok"

    # 404 => the rule is gone => not active.
    monkeypatch.setattr("arcanum.blue.deployers.waf.httpx.AsyncClient", _fake_client(404, {}))
    assert await dep._verify_real({"external_id": "rule-1"}) is False

    # No external id => cannot confirm => not active (honest).
    assert await dep._verify_real({}) is False


@pytest.mark.asyncio
async def test_edr_verify_real_hits_endpoint(monkeypatch):
    monkeypatch.setenv("ARCANUM_EDR_API_URL", "https://edr.local")
    monkeypatch.setenv("ARCANUM_EDR_API_TOKEN", "tok")
    dep = EDRDeployer()
    assert dep.configured() is True

    sink = {}
    monkeypatch.setattr("arcanum.blue.deployers.edr.httpx.AsyncClient", _fake_client(200, sink))
    assert await dep._verify_real({"external_id": "det-9"}) is True
    assert sink["url"] == "https://edr.local/detections/det-9"

    monkeypatch.setattr("arcanum.blue.deployers.edr.httpx.AsyncClient", _fake_client(500, {}))
    assert await dep._verify_real({"external_id": "det-9"}) is False
    assert await dep._verify_real({}) is False
