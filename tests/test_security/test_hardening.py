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


# --- Multi-call extractor -------------------------------------------------

def test_extractor_returns_all_inline_calls():
    text = ('{"name":"execute","arguments":{"command":"httpx a.com"}}\n'
            '{"name":"execute","arguments":{"command":"httpx b.com"}}\n'
            '{"name":"execute","arguments":{"command":"httpx c.com"}}')
    calls = AgentEngine._extract_tool_calls_from_text(text)
    assert len(calls) == 3


# --- Stagnation guard -----------------------------------------------------

@pytest.mark.asyncio
async def test_stagnation_guard_aborts_repeated_command(tmp_path):
    class FakeLLM:
        enable_thinking = False
        async def chat(self, messages, tools=None):
            return {"content": '{"name":"execute","arguments":{"command":"subfinder -d x.com"}}'}

    class FakeExec:
        def __init__(self):
            self.calls = 0
        async def execute_tool(self, name, args):
            self.calls += 1
            return {"success": True, "output": {"stdout": "", "exit_code": 1}}
        def _get_wiki_path(self, s):
            return tmp_path / "x.md"

    te = FakeExec()
    eng = AgentEngine(llm=FakeLLM(), tool_executor=te,
                      session={"name": "op", "target": "x.com", "mode": "autopilot"})
    events = []
    async for ev in eng.run("x.com"):
        events.append(ev)
        if len(events) > 60:
            break
    assert te.calls <= 2
    assert any(e.get("type") == "error" and "repetido" in str(e.get("error", "")) for e in events)


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
