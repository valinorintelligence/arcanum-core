"""Regression tests for the security hardening (Fases 1-4).

These lock in behaviours that were broken or regressed in the field:
path traversal, session-name traversal, FTS DoS, report XSS, token auth,
sandbox hardening, nmap SYN->connect downgrade, and the stagnation guard.
"""
import asyncio
import tempfile
from pathlib import Path

import pytest

from arcanum.agent.tools import ToolExecutor, _auto_repair_command
from arcanum.agent.session import validate_session_name
from arcanum.agent.engine import AgentEngine
from arcanum.core.reports import ReportEngine, ReportConfig
from arcanum.core.cve_kb import CVEKnowledgeBase, CVEEntry


# --- Path traversal -------------------------------------------------------

@pytest.mark.asyncio
async def test_read_file_absolute_path_blocked(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET")
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=ws, db=None)
    with pytest.raises(ValueError):
        await te._handle_read_file(path=str(secret))


@pytest.mark.asyncio
async def test_create_file_traversal_blocked(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=ws, db=None)
    with pytest.raises(ValueError):
        await te._handle_create_file(path="../../pwned.txt", content="x")
    # legit relative path still works
    res = await te._handle_create_file(path="output/ok.txt", content="hi")
    assert Path(res["full_path"]).exists()


# --- Session name validation ---------------------------------------------

@pytest.mark.parametrize("bad", ["../../x", "/etc/passwd", "a/b", "..", "", "a" * 65])
def test_session_name_rejects_traversal(bad):
    with pytest.raises(ValueError):
        validate_session_name(bad)


def test_session_name_accepts_valid():
    assert validate_session_name("hostinger-evo_01") == "hostinger-evo_01"


# --- CVE FTS DoS ----------------------------------------------------------

@pytest.mark.asyncio
async def test_cve_search_survives_hostile_fts_input(tmp_path):
    kb = CVEKnowledgeBase(tmp_path / "cve.db")
    await kb.connect()
    await kb.add(CVEEntry(id="CVE-2021-44228", description="apache log4j log4shell rce jndi"))
    try:
        for q in ['log4j', '"', 'a AND', 'foo*(', 'NEAR/', 'x OR (']:
            await kb.search(q)  # must not raise
        hits = await kb.search("log4shell")
        assert any(e.id == "CVE-2021-44228" for e in hits)
    finally:
        await kb.close()


# --- Report XSS -----------------------------------------------------------

def test_html_report_escapes_target_derived_content():
    eng = ReportEngine()
    finding = {
        "title": "<script>alert(1)</script>", "type": "xss", "severity": "high",
        "cvss_score": 7.5, "affected": {"url": "http://x"}, "verified": True,
        "evidence": {"request": "<b>r</b>", "response": "<i>s</i>"},
        "poc": {"command": "<script>evil()</script>"}, "remediation": "<script>x</script>",
    }
    html = eng.generate_html({"target": "t", "name": "op", "mode": "manual"}, [finding], ReportConfig())
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --- nmap SYN -> connect downgrade (unprivileged sandbox) -----------------

def test_nmap_syn_downgraded_and_pn_added():
    repaired = _auto_repair_command("nmap -sS -sV -p 80,443 example.com")
    assert "-sS" not in repaired and "-sT" in repaired and "-Pn" in repaired


def test_httpx_rewritten_to_projectdiscovery_binary():
    # /usr/bin/httpx on the sandbox is the Python HTTP client (no -u); the PD
    # pentest tool is 'httpx-toolkit'. The agent's httpx calls must target it.
    assert _auto_repair_command("httpx -u http://x -tech-detect").startswith("httpx-toolkit ")
    assert "-u" in _auto_repair_command("httpx x.com")  # bare target gets -u
    assert _auto_repair_command("httpx x.com").startswith("httpx-toolkit -u ")
    assert _auto_repair_command("httpx -l hosts.txt").startswith("httpx-toolkit -l ")


def test_nmap_without_scan_type_forces_connect():
    # Reproduces the operator's failure: no scan type -> nmap defaults to SYN
    # (raw socket) which fails as nobody. Must inject -sT.
    repaired = _auto_repair_command("nmap -Pn -sV -p 80,443,8080,8443 example.com")
    assert "-sT" in repaired and "-Pn" in repaired
    # an explicit connect scan is left intact (no double -sT)
    assert _auto_repair_command("nmap -sT -p 80 example.com").count("-sT") == 1


# --- Multi-call extractor -------------------------------------------------

def test_extractor_returns_all_inline_calls():
    text = ('{"name":"execute","arguments":{"command":"httpx a.com"}}\n'
            '{"name":"execute","arguments":{"command":"httpx b.com"}}\n'
            '{"name":"execute","arguments":{"command":"httpx c.com"}}')
    calls = AgentEngine._extract_tool_calls_from_text(text)
    assert len(calls) == 3


# --- Stagnation / feedback guard ------------------------------------------

class _RepeatLLM:
    enable_thinking = False
    async def chat(self, messages, tools=None, fmt=None):
        return {"content": '{"name":"execute","arguments":{"command":"subfinder -d x.com"}}'}


def _make_exec(exit_code, tmp_path):
    class FakeExec:
        def __init__(self):
            self.calls = 0
        async def execute_tool(self, name, args):
            self.calls += 1
            return {"success": True, "output": {"stdout": "done" if exit_code == 0 else "", "exit_code": exit_code}}
        def _get_wiki_path(self, s):
            return tmp_path / "x.md"
    return FakeExec()


@pytest.mark.asyncio
async def test_stagnation_guard_aborts_failing_command(tmp_path):
    # A command that keeps FAILING must abort the run (real failure loop).
    te = _make_exec(exit_code=1, tmp_path=tmp_path)
    eng = AgentEngine(llm=_RepeatLLM(), tool_executor=te,
                      session={"name": "op", "target": "x.com", "mode": "autopilot"})
    events = []
    async for ev in eng.run("x.com"):
        events.append(ev)
        if len(events) > 60:
            break
    assert te.calls <= 2
    assert any(e.get("type") == "error" and "falhou" in str(e.get("error", "")).lower() for e in events)


@pytest.mark.asyncio
async def test_repeated_successful_command_is_skipped_not_failed(tmp_path):
    # A command that already SUCCEEDED must not be treated as "no progress":
    # the guard skips the re-run (info) and only stops the loop after several
    # pointless repeats, never labelling it a failure.
    te = _make_exec(exit_code=0, tmp_path=tmp_path)
    eng = AgentEngine(llm=_RepeatLLM(), tool_executor=te,
                      session={"name": "op", "target": "x.com", "mode": "autopilot"})
    events = []
    async for ev in eng.run("x.com"):
        events.append(ev)
        if len(events) > 80:
            break
    # It ran once successfully, then subsequent identical proposals are skipped.
    assert te.calls == 1
    assert any(e.get("type") == "info" and "já concluído" in str(e.get("content", "")) for e in events)
    assert not any("falhou" in str(e.get("error", "")).lower() for e in events)


# --- Continuous learning (store + recall) ---------------------------------

@pytest.mark.asyncio
async def test_continuous_learning_store_and_recall(tmp_path):
    from arcanum.core.database import Database
    from arcanum.agent.tools import ToolExecutor
    db = Database(":memory:")
    await db.connect()
    await db.init_db()
    ws = tmp_path / "workspace"
    ws.mkdir()
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=ws, db=db)
    eng = AgentEngine(llm=None, tool_executor=te,
                      session={"name": "op", "target": "victim.example.com", "mode": "manual"})
    try:
        # STORE: a successful command is persisted, generalized (no host leak).
        await eng._auto_learn("nmap -sT -Pn -sV -p 80 victim.example.com",
                              {"success": True, "output": {"exit_code": 0, "stdout": "80/tcp open"}}, "recon")
        rows = await te.playbook_mgr.search("nmap", limit=5)
        assert any("TARGET" in (r.get("steps") or "") for r in rows)
        assert all("victim.example.com" not in (r.get("steps") or "") for r in rows)

        # A FAILED command is not learned.
        n_before = len(await te.playbook_mgr.search("ffuf", limit=9))
        await eng._auto_learn("ffuf -u http://x/FUZZ", {"success": True, "output": {"exit_code": 1}}, "analysis")
        assert len(await te.playbook_mgr.search("ffuf", limit=9)) == n_before

        # RECALL: with Express detected in memory and an express playbook stored,
        # the next phase is auto-enriched with the proven technique.
        await te.playbook_mgr.save("express", "express_probe", "curl TARGET/actuator", "t")
        (ws / "wiki").mkdir(parents=True, exist_ok=True)
        (ws / "wiki" / "ATTACK_SURFACE.md").write_text("httpx: Express,Node.js", encoding="utf-8")
        eng2 = AgentEngine(llm=None, tool_executor=te,
                           session={"name": "op", "target": "victim.example.com", "mode": "manual"})
        res = await eng2._consult_playbooks()
        assert res and res["count"] >= 1
        assert any("MEMÓRIA DE LONGO PRAZO" in m.get("content", "")
                   for m in eng2.messages if m.get("role") == "system")
        assert await eng2._consult_playbooks() is None  # once per phase
    finally:
        await db.close()


# --- Token auth -----------------------------------------------------------

def test_api_requires_token_and_ui_gets_it():
    from fastapi.testclient import TestClient
    import arcanum.api.main as m
    with TestClient(m.app) as client:
        tok = m.app.state.api_token
        assert tok
        assert client.get("/api/stats").status_code == 401
        assert client.get("/api/stats", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
        assert "ARCANUM_TOKEN" in client.get("/").text
