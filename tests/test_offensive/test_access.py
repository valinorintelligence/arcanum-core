"""F1 — map_service_to_exploits + exploit_webapp (governed, delegating).

No real attack runs: a fake executor stands in for the sandbox and returns canned
tool output, so we verify the ORCHESTRATION (delegation command, success parsing,
foothold registration, compromise state, honest refusals) — never an exploit.
"""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.core.graph import GraphManager
from arcanum.redteam.sessions import SessionRegistry
from arcanum.offensive.base import OffensiveContext
from arcanum.offensive.access import map_service_to_exploits, exploit_webapp, _build_delegation


class _CVE:
    def __init__(self, id, score, desc):
        self.id, self.cvss_score, self.description = id, score, desc


class _FakeCVEKB:
    async def search(self, query, limit=10):
        return [_CVE("CVE-2021-41773", 7.5, "Apache path traversal / RCE")]


class _FakeExecutor:
    """Stands in for ToolExecutor: records delegated commands, returns canned output."""
    def __init__(self, db=None, sandbox=True, cve_kb=None, graph_mgr=None, output=""):
        self.db = db
        self.sandbox = sandbox          # truthy => has_sandbox() True
        self.cve_kb = cve_kb
        self.graph_mgr = graph_mgr
        self.session_id = "op-1"
        self.commands = []
        self._output = output

    async def execute_tool(self, tool, args):
        self.commands.append(args.get("command", ""))
        return {"success": True, "error": None,
                "output": {"stdout": self._output, "stderr": "", "exit_code": 0}}


NMAP = """Nmap scan report for target
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.49
"""


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "off.db")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


# ---------------------------------------------------------------------------
# map_service_to_exploits (ACTIVE — recon→CVE correlation, no attack)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_map_parses_services_and_correlates_cves(db):
    ex = _FakeExecutor(db=db, cve_kb=_FakeCVEKB(), graph_mgr=GraphManager(db))
    ctx = OffensiveContext(executor=ex, db=db, session_id="op-1")
    res = await map_service_to_exploits(ctx, "target", nmap_output=NMAP)
    assert res["service_count"] == 2
    http = [s for s in res["services"] if s["port"] == 80][0]
    assert http["version"] == "2.4.49"
    assert http["cve_candidates"] and http["cve_candidates"][0]["id"] == "CVE-2021-41773"


@pytest.mark.asyncio
async def test_map_requires_sandbox_when_scanning(db):
    ex = _FakeExecutor(db=db, sandbox=None)
    ctx = OffensiveContext(executor=ex, db=db, session_id="op-1")
    res = await map_service_to_exploits(ctx, "target")  # no nmap_output, no sandbox
    assert "error" in res and "Sandbox" in res["error"]


@pytest.mark.asyncio
async def test_map_scans_via_sandbox_when_available(db):
    ex = _FakeExecutor(db=db, cve_kb=_FakeCVEKB(), graph_mgr=GraphManager(db), output=NMAP)
    ctx = OffensiveContext(executor=ex, db=db, session_id="op-1")
    res = await map_service_to_exploits(ctx, "target")
    assert res["service_count"] == 2
    assert any(c.startswith("nmap -sV") for c in ex.commands)  # it delegated the scan


# ---------------------------------------------------------------------------
# _build_delegation (operator-supplied spec only; no exploit synthesized)
# ---------------------------------------------------------------------------

def test_build_delegation_metasploit_from_operator_spec():
    cmd, tool = _build_delegation("metasploit", "10.0.0.5",
                                  None, "exploit/multi/http/x", {"RPORT": "8080"})
    assert tool == "metasploit"
    assert "use exploit/multi/http/x" in cmd
    assert "set RHOSTS 10.0.0.5" in cmd and "set RPORT 8080" in cmd


def test_build_delegation_nuclei_and_command():
    cmd, tool = _build_delegation("nuclei", "https://t", None, None, {"id": "CVE-2021-41773"})
    assert tool == "nuclei" and "-id CVE-2021-41773" in cmd and "-u https://t" in cmd
    cmd, tool = _build_delegation("command", "t", "whoami", None, None)
    assert tool == "operator-command" and cmd == "whoami"
    assert _build_delegation("metasploit", "t", None, None, None)[0] is None  # no module => no command


# ---------------------------------------------------------------------------
# exploit_webapp (EXPLOIT — delegates, parses, registers foothold on real access)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exploit_refuses_without_sandbox(db):
    ex = _FakeExecutor(db=db, sandbox=None)
    ctx = OffensiveContext(executor=ex, db=db, session_id="op-1", engagement_id="e1")
    res = await exploit_webapp(ctx, "target", method="command", command="whoami")
    assert res["access_obtained"] is False and "Sandbox" in res["error"]
    assert ex.commands == []  # nothing was delegated


@pytest.mark.asyncio
async def test_exploit_session_registers_foothold_and_marks_owned(db):
    ex = _FakeExecutor(db=db, graph_mgr=GraphManager(db),
                       output="[*] Meterpreter session 1 opened")
    ctx = OffensiveContext(executor=ex, db=db, session_id="op-1", engagement_id="e1")
    res = await exploit_webapp(ctx, "10.0.0.5", method="metasploit",
                               module="exploit/multi/http/x", options={"RPORT": "8080"},
                               teardown_recipe=["rm -f /tmp/x"])
    assert res["access_obtained"] is True
    assert res["proof"]["proof_type"] == "shell"
    # Foothold registered (open) with the teardown recipe stored.
    footholds = await SessionRegistry(db).list(engagement_id="e1", status="open")
    assert len(footholds) == 1
    assert footholds[0]["metadata"]["teardown_recipe"] == ["rm -f /tmp/x"]
    # Compromise state set on the graph host node.
    rows = await db.fetch_all("SELECT owned, foothold_id FROM graph_nodes WHERE type='host'")
    assert any(r["owned"] == "user" and r["foothold_id"] for r in rows)


@pytest.mark.asyncio
async def test_exploit_vuln_confirmed_gives_proof_but_no_foothold(db):
    ex = _FakeExecutor(db=db, graph_mgr=GraphManager(db),
                       output="parameter 'id' is vulnerable")
    ctx = OffensiveContext(executor=ex, db=db, session_id="op-1", engagement_id="e1")
    res = await exploit_webapp(ctx, "https://t/app", method="command", command="sqlmap ...")
    assert res["access_obtained"] is False and res["vuln_confirmed"] is True
    assert res["proof"]["proof_type"] == "vuln_confirmation"
    assert await SessionRegistry(db).list(engagement_id="e1", status="open") == []


@pytest.mark.asyncio
async def test_exploit_no_signal_no_foothold(db):
    ex = _FakeExecutor(db=db, graph_mgr=GraphManager(db), output="connection refused")
    ctx = OffensiveContext(executor=ex, db=db, session_id="op-1", engagement_id="e1")
    res = await exploit_webapp(ctx, "t", method="command", command="whoami")
    assert res["access_obtained"] is False and not res.get("vuln_confirmed")
    assert await SessionRegistry(db).list(engagement_id="e1", status="open") == []
