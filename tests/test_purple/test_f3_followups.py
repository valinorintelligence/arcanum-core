"""F3 follow-ups: multi-SIEM detection (b), real Atomic Red Team (a), CTEM Purple
scheduling (c). Network/sandbox are mocked — no live SIEM, no real attack."""

import httpx
import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.core.ctem import CTEMDaemon
from arcanum.purple.verify import DetectionVerifier
from arcanum.purple.bas import BASRunner

_SIEM_FIELDS = ("elastic_url", "elastic_api_key", "splunk_mgmt_url", "splunk_mgmt_token",
                "splunk_username", "splunk_password", "sentinel_resource_id", "sentinel_token")


class _Cfg:
    def __init__(self, **kw):
        for f in _SIEM_FIELDS:
            setattr(self, f, "")
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


def _fake_httpx(responder):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, **kw):
            return responder(url, kw)
    return _Client


# ---------------------------------------------------------------------------
# (b) multi-SIEM detection
# ---------------------------------------------------------------------------

def test_siem_backends_selection():
    assert DetectionVerifier(None, config=_Cfg())._siem_backends() == []
    assert DetectionVerifier(None, config=_Cfg(elastic_url="u", elastic_api_key="k"))._siem_backends() == ["elastic"]
    v = DetectionVerifier(None, config=_Cfg(splunk_mgmt_url="u", splunk_mgmt_token="t",
                                            sentinel_resource_id="/s", sentinel_token="t"))
    assert v._siem_backends() == ["splunk", "sentinel"]


@pytest.mark.asyncio
async def test_query_backend_splunk(monkeypatch):
    v = DetectionVerifier(None, config=_Cfg(splunk_mgmt_url="https://s:8089", splunk_mgmt_token="tok"))
    monkeypatch.setattr(httpx, "AsyncClient", _fake_httpx(lambda u, kw: _Resp(200, text='{"result":{"_raw":"hit"}}')))
    assert await v._query_backend("splunk", "ARCANUM-BAS:c:T1", 15) is True
    monkeypatch.setattr(httpx, "AsyncClient", _fake_httpx(lambda u, kw: _Resp(200, text="")))
    assert await v._query_backend("splunk", "nope", 15) is False


@pytest.mark.asyncio
async def test_query_backend_sentinel(monkeypatch):
    scope = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
    v = DetectionVerifier(None, config=_Cfg(sentinel_resource_id=scope, sentinel_token="tok"))
    captured = {}

    def responder(url, kw):
        captured["url"] = url
        captured["auth"] = kw["headers"]["Authorization"]
        return _Resp(200, payload={"tables": [{"rows": [[1]]}]})
    monkeypatch.setattr(httpx, "AsyncClient", _fake_httpx(responder))
    assert await v._query_backend("sentinel", "tag", 15) is True
    assert captured["url"].startswith("https://management.azure.com")
    assert "/query?api-version=" in captured["url"]
    assert captured["auth"] == "Bearer tok"


@pytest.mark.asyncio
async def test_query_siem_ors_backends(monkeypatch):
    v = DetectionVerifier(None, config=_Cfg(elastic_url="u", elastic_api_key="k",
                                            splunk_mgmt_url="https://s", splunk_mgmt_token="t"))

    async def fake_backend(backend, tag, window):
        return backend == "splunk"      # elastic misses, splunk hits
    monkeypatch.setattr(v, "_query_backend", fake_backend)
    assert await v._query_siem("tag", 15) is True


@pytest.mark.asyncio
async def test_query_siem_all_error_raises(monkeypatch):
    v = DetectionVerifier(None, config=_Cfg(elastic_url="u", elastic_api_key="k"))

    async def boom(*a):
        raise RuntimeError("siem down")
    monkeypatch.setattr(v, "_query_backend", boom)
    with pytest.raises(RuntimeError):
        await v._query_siem("tag", 15)


# ---------------------------------------------------------------------------
# (a) real Atomic Red Team
# ---------------------------------------------------------------------------

class _Sandbox:
    def __init__(self):
        self._active_container = "c"
        self.cmds = []

    async def create_container(self, path):
        return "c"

    async def execute(self, cid, command, timeout=120):
        self.cmds.append(command)
        return {"stdout": "ok", "exit_code": 0}


@pytest.mark.asyncio
async def test_bas_atomics_builds_invoke_atomictest(monkeypatch):
    monkeypatch.delenv("ARCANUM_ATOMIC_CMD_TEMPLATE", raising=False)
    sb = _Sandbox()
    r = await BASRunner(sandbox=sb).run("T1059.001", "c1", use_atomics=True)
    assert r["execution_status"] == "executed" and r["atomic"] is True
    assert "Invoke-AtomicTest T1059.001" in sb.cmds[0]
    assert "ARCANUM-BAS:c1:T1059.001" in sb.cmds[0]   # deconfliction tag stamped


@pytest.mark.asyncio
async def test_bas_atomics_template_override(monkeypatch):
    monkeypatch.setenv("ARCANUM_ATOMIC_CMD_TEMPLATE", "atomic-operator run --techniques {technique}")
    sb = _Sandbox()
    await BASRunner(sandbox=sb).run("T1190", "c1", use_atomics=True)
    assert "atomic-operator run --techniques T1190" in sb.cmds[0]


@pytest.mark.asyncio
async def test_bas_no_sandbox_simulates_even_with_atomics():
    r = await BASRunner(sandbox=None).run("T1190", "c1", use_atomics=True)
    assert r["execution_status"] == "simulated"


@pytest.mark.asyncio
async def test_bas_default_no_atomics_no_command_simulates():
    sb = _Sandbox()
    r = await BASRunner(sandbox=sb).run("T1190", "c1")  # backward-compat: simulate
    assert r["execution_status"] == "simulated" and sb.cmds == []


# ---------------------------------------------------------------------------
# (c) CTEM Purple scheduling
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "f3.db")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


@pytest.mark.asyncio
async def test_ctem_purple_schedule_create_list_run(db):
    daemon = CTEMDaemon(db=db)
    sched = await daemon.create_purple_schedule(["T1190", "T1059.001"], frequency_minutes=60)
    assert sched["schedule_id"].startswith("pcs-") and sched["auto_tune"] is True

    lst = await daemon.list_purple_schedules()
    assert len(lst) == 1 and lst[0]["techniques"] == ["T1190", "T1059.001"]

    res = await daemon.run_purple_schedule(sched["schedule_id"])
    assert res.get("campaign_id") and "coverage" in res

    lst2 = await daemon.list_purple_schedules()
    assert lst2[0]["total_runs"] == 1 and lst2[0]["last_campaign_id"]


@pytest.mark.asyncio
async def test_ctem_run_due_purple(db):
    daemon = CTEMDaemon(db=db)
    sched = await daemon.create_purple_schedule(["T1190"], frequency_minutes=60)
    # Force it due.
    await db.execute("UPDATE ctem_purple_schedules SET next_run_at=NULL WHERE id=?",
                     (sched["schedule_id"],))
    assert await daemon.run_due_purple_schedules() == 1
