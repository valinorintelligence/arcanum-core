"""Regression tests for the 360-degree audit fixes.

These lock in the critical correctness/security invariants discovered during the
audit so the bugs can never silently return:

- BUG N  : native-tool findings must be auto-ingested from the WRAPPED result
           ({"success","output",...}) — reading the top level yielded 0 findings
           on every real run.
- BUG K  : retest must never report a finding 'remediated' without positive proof
           (mock / still-vulnerable / inconclusive => stays open).
- Perf   : effective_num_thread() must leave CPU headroom by default.
- Skills : the 57-skill library must be seeded into the recall KB (idempotently).
"""
from pathlib import Path
import tempfile

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.core.playbooks import PlaybookManager
from arcanum.core.retest import RetestEngine
from arcanum.core.config import ArcanumConfig
from arcanum.agent.tools import ToolExecutor
from arcanum.agent.engine import AgentEngine


@pytest_asyncio.fixture
async def memory_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(db_path=Path(tmpdir) / "regress.db")
        await db.connect()
        await db.init_db()
        yield db
        await db.close()


# ---------------------------------------------------------------------------
# BUG N — auto-ingest must unwrap execute_tool's {"success","output"} envelope
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_auto_ingest_reads_wrapped_tool_output(memory_db):
    """execute_tool returns {"success","output","error"}; the finding data lives
    under 'output'. Auto-ingest must read it there (the bug read the top level)."""
    # Findings reference a session (FK), so create one first (as in real usage).
    await memory_db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        ("op-regress", "regress", "example.com"))
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=Path("."),
                      db=memory_db, session_id="op-regress")
    eng = AgentEngine.__new__(AgentEngine)
    eng.tool_executor = te
    eng.session = {"id": "op-regress", "target": "example.com"}
    eng.findings_count = 0

    wrapped = {
        "success": True,
        "error": None,
        "output": {
            "missing_headers": [
                {"header": "Content-Security-Policy", "severity": "high",
                 "remediation": "Configure CSP", "description": "x"},
                {"header": "Strict-Transport-Security", "severity": "medium",
                 "remediation": "Configure HSTS", "description": "y"},
            ],
        },
    }
    created = await eng._auto_ingest_native_findings(
        "audit_security_headers", {"url": "https://example.com"}, wrapped)
    assert len(created) >= 2, "auto-ingest must create findings from the wrapped output"

    rows = await memory_db.fetch_all(
        "SELECT title FROM findings WHERE session_id = ?", ("op-regress",))
    assert len(rows) >= 2


@pytest.mark.asyncio
async def test_auto_ingest_skips_simulated_findings(memory_db):
    """Simulated/mock results (e.g. headless browser without Playwright) must
    never be persisted as real findings."""
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=Path("."),
                      db=memory_db, session_id="op-sim")
    eng = AgentEngine.__new__(AgentEngine)
    eng.tool_executor = te
    eng.session = {"id": "op-sim", "target": "example.com"}
    eng.findings_count = 0

    simulated = {"success": True, "error": None, "output": {
        "simulated": True,
        "findings": [{"title": "IDOR Simulado", "severity": "high"}],
    }}
    created = await eng._auto_ingest_native_findings(
        "headless_web_audit", {"url": "https://example.com"}, simulated)
    assert created == [], "simulated results must not be ingested as real findings"


# ---------------------------------------------------------------------------
# BUG K — retest is conservative: never 'remediated' without positive proof
# ---------------------------------------------------------------------------

def test_retest_mock_is_not_remediated():
    re = RetestEngine(db=None)
    ok, reason = re._evaluate_probe_outcome(
        {"title": "x"}, {"status": "mock_simulated", "findings": []}, None)
    assert ok is False


def test_retest_still_vulnerable_headers_not_remediated():
    re = RetestEngine(db=None)
    ok, _ = re._evaluate_probe_outcome(
        {"title": "Missing CSP"}, {"missing_headers": [{"header": "CSP"}]}, None)
    assert ok is False


def test_retest_probe_error_not_remediated():
    re = RetestEngine(db=None)
    ok, _ = re._evaluate_probe_outcome({"title": "x"}, None, "tool not found")
    assert ok is False


def test_retest_positive_proof_remediated():
    re = RetestEngine(db=None)
    ok, _ = re._evaluate_probe_outcome({"title": "CSP"}, {"score": 95, "grade": "A"}, None)
    assert ok is True


# ---------------------------------------------------------------------------
# Perf — effective_num_thread leaves CPU headroom by default
# ---------------------------------------------------------------------------

def test_effective_num_thread_default_leaves_headroom():
    c = ArcanumConfig(ollama_num_thread=0)
    n = c.effective_num_thread()
    assert n >= 1
    # On any multi-core host it should cap below the logical core count.
    import os
    logical = os.cpu_count() or 4
    if logical >= 4:
        assert n < logical


def test_effective_num_thread_explicit_and_all_cores():
    assert ArcanumConfig(ollama_num_thread=4).effective_num_thread() == 4
    # -1 means "use all cores" -> 0 (client does not cap)
    assert ArcanumConfig(ollama_num_thread=-1).effective_num_thread() == 0


# ---------------------------------------------------------------------------
# Skills — the 57-skill library is seeded into the recall KB (idempotent)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_skill_library_seeded_into_recall(memory_db):
    pm = PlaybookManager(memory_db)
    first = await pm.ensure_skill_playbooks()
    second = await pm.ensure_skill_playbooks()
    assert first >= 50, "expected the full skill library to be seeded"
    assert second == 0, "seeding must be idempotent"

    found = await pm.search("subdomain", limit=5)
    blob = " ".join((f.get("technique", "") + " " + f.get("notes", "")) for f in found).lower()
    assert "subdomain" in blob
