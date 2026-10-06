"""Unit and Integration Tests for Closed-Loop Retest Engine & Exposure Drift (Fase 1)."""

import json
from pathlib import Path
import tempfile
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

from arcanum.core.database import Database
from arcanum.core.models import Finding, FindingStatus, Severity
from arcanum.core.retest import RetestEngine
from arcanum.core.drift import ExposureDrift


@pytest_asyncio.fixture
async def memory_db():
    """Provide an initialized SQLite database in a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_retest.db"
        db = Database(db_path=db_file)
        await db.connect()
        await db.init_db()
        yield db
        await db.close()


# ============================================================================
# 1. Finding Lifecycle & Model Evolution
# ============================================================================

def test_finding_lifecycle_model():
    """Verify Finding model supports all lifecycle statuses and retest metadata."""
    finding = Finding(
        id="f-test-01",
        session_id="sess-01",
        title="Exposed Vector Database on port 6333",
        severity=Severity.critical,
    )

    assert finding.status == FindingStatus.confirmed
    assert finding.retest_tool is None
    assert finding.retested_at is None
    assert finding.retest_proof is None

    # Test status transitions
    finding.status = FindingStatus.verifying
    assert finding.status.value == "verifying"

    finding.status = FindingStatus.remediated
    assert finding.status.value == "remediated"

    finding.status = FindingStatus.regressed
    assert finding.status.value == "regressed"


# ============================================================================
# 2. Database Schema & Migration Validation
# ============================================================================

@pytest.mark.asyncio
async def test_database_schema_and_migration(memory_db):
    """Verify database creates and migrates findings table with retest columns."""
    cursor = await memory_db.execute("PRAGMA table_info(findings)")
    cols = {row["name"] for row in await cursor.fetchall()}

    expected_cols = {"status", "retest_tool", "retest_arguments", "retested_at", "retest_proof"}
    for col in expected_cols:
        assert col in cols, f"Column '{col}' must exist in findings table"


# ============================================================================
# 3. Closed-Loop Retest Engine (1-Click Verification)
# ============================================================================

@pytest.mark.asyncio
async def test_retest_finding_remediated(memory_db):
    """Test surgical re-test confirming that a vulnerability was successfully remediated."""
    session_id = "sess-recon-01"
    await memory_db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        (session_id, "recon-target", "https://app.corp.local"),
    )

    finding_id = "f-clickjack-01"
    await memory_db.execute(
        """INSERT INTO findings (id, session_id, title, type, severity, status, affected, retest_tool, retest_arguments)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding_id,
            session_id,
            "Clickjacking UI Redressing Missing XFO",
            "web_vulnerability",
            "medium",
            "confirmed",
            json.dumps({"url": "https://app.corp.local/login"}),
            "audit_clickjacking_and_ui_redressing",
            json.dumps({"url": "https://app.corp.local/login"}),
        ),
    )

    # Mock tool executor returning clean hardened probe
    mock_executor = MagicMock()
    mock_executor.execute_tool = AsyncMock(
        return_value={
            "success": True,
            "output": {
                "frameable": False,
                "score": 100,
                "grade": "A",
                "findings": [],
            },
        }
    )

    engine = RetestEngine(db=memory_db, tool_executor=mock_executor)
    outcome = await engine.retest_finding(finding_id)

    assert outcome["success"] is True
    assert outcome["is_remediated"] is True
    assert outcome["new_status"] == "remediated"
    assert outcome["verdict"] == "REMEDIATED"

    # Verify DB persistence
    row = await memory_db.fetch_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
    assert row["status"] == "remediated"
    assert row["retested_at"] is not None
    proof = json.loads(row["retest_proof"])
    assert proof["verdict"] == "REMEDIATED"
    assert proof["remediated"] is True


@pytest.mark.asyncio
async def test_retest_finding_still_vulnerable(memory_db):
    """Test surgical re-test detecting that a vulnerability is still reproducible."""
    session_id = "sess-recon-02"
    await memory_db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        (session_id, "recon-target-2", "https://api.corp.local"),
    )

    finding_id = "f-vector-01"
    await memory_db.execute(
        """INSERT INTO findings (id, session_id, title, type, severity, status, affected, retest_tool, retest_arguments)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding_id,
            session_id,
            "Unauthenticated ChromaDB Vector Database Exposure",
            "ai_rag_exposure",
            "critical",
            "confirmed",
            json.dumps({"host": "rag.corp.local"}),
            "audit_vector_database_exposure",
            json.dumps({"host": "rag.corp.local"}),
        ),
    )

    # Mock tool executor returning vulnerability still present
    mock_executor = MagicMock()
    mock_executor.execute_tool = AsyncMock(
        return_value={
            "success": True,
            "output": {
                "exposed_databases": [{"service": "ChromaDB", "port": 8000}],
                "score": 45,
                "grade": "F",
                "findings": [{"severity": "critical", "issue": "ChromaDB exposto"}],
            },
        }
    )

    engine = RetestEngine(db=memory_db, tool_executor=mock_executor)
    outcome = await engine.retest_finding(finding_id)

    assert outcome["success"] is True
    assert outcome["is_remediated"] is False
    assert outcome["new_status"] == "confirmed"
    assert outcome["verdict"] == "CONFIRMED"

    row = await memory_db.fetch_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
    assert row["status"] == "confirmed"


@pytest.mark.asyncio
async def test_retest_finding_detects_regression(memory_db):
    """Test re-test flagging a regression when a previously remediated vulnerability resurfaces."""
    session_id = "sess-recon-03"
    await memory_db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        (session_id, "recon-target-3", "https://portal.corp.local"),
    )

    finding_id = "f-sri-01"
    await memory_db.execute(
        """INSERT INTO findings (id, session_id, title, type, severity, status, affected, retest_tool, retest_arguments)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding_id,
            session_id,
            "Missing Subresource Integrity SRI on Axios",
            "frontend_supply_chain",
            "high",
            "remediated",  # Previously fixed
            json.dumps({"url": "https://portal.corp.local"}),
            "audit_subresource_integrity_sri",
            json.dumps({"url": "https://portal.corp.local"}),
        ),
    )

    # Re-test reveals it was reintroduced by a bad deployment
    mock_executor = MagicMock()
    mock_executor.execute_tool = AsyncMock(
        return_value={
            "success": True,
            "output": {
                "scripts_missing_sri": ["https://cdn.example.com/axios.js"],
                "score": 60,
                "findings": [{"severity": "high", "issue": "Script sem SRI"}],
            },
        }
    )

    engine = RetestEngine(db=memory_db, tool_executor=mock_executor)
    outcome = await engine.retest_finding(finding_id)

    assert outcome["is_remediated"] is False
    assert outcome["new_status"] == "regressed"
    assert outcome["verdict"] == "REGRESSED"

    row = await memory_db.fetch_one("SELECT status FROM findings WHERE id = ?", (finding_id,))
    assert row["status"] == "regressed"


# ============================================================================
# 4. Exposure Drift & Assessment Delta Engine
# ============================================================================

@pytest.mark.asyncio
async def test_exposure_drift_calculation(memory_db):
    """Test calculating exposure drift between baseline and current assessments."""
    # Setup Target
    target = "https://finance.corp.local"

    # Baseline Session (Day 1)
    sess_day1 = "sess-day1"
    await memory_db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        (sess_day1, "day1-audit", target),
    )
    # Finding A: will be fixed on day 2
    await memory_db.execute(
        """INSERT INTO findings (id, session_id, title, type, severity, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("f-1", sess_day1, "Missing Security Headers", "web", "medium", "confirmed"),
    )
    # Finding B: will persist on day 2
    await memory_db.execute(
        """INSERT INTO findings (id, session_id, title, type, severity, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("f-2", sess_day1, "Weak TLS 1.0 Cipher", "tls", "high", "confirmed"),
    )

    # Current Session (Day 2)
    sess_day2 = "sess-day2"
    await memory_db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        (sess_day2, "day2-audit", target),
    )
    # Finding B persists
    await memory_db.execute(
        """INSERT INTO findings (id, session_id, title, type, severity, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("f-2-copy", sess_day2, "Weak TLS 1.0 Cipher", "tls", "high", "confirmed"),
    )
    # Finding C is new
    await memory_db.execute(
        """INSERT INTO findings (id, session_id, title, type, severity, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("f-3", sess_day2, "New Open Webhook SSRF", "ssrf", "critical", "confirmed"),
    )

    drift_engine = ExposureDrift(db=memory_db)
    drift = await drift_engine.calculate_drift(
        current_session_id=sess_day2,
        baseline_session_id=sess_day1,
    )

    assert drift["total_baseline_findings"] == 2
    assert drift["total_current_findings"] == 2
    assert drift["remediated_count"] == 1  # Finding A was fixed
    assert drift["new_count"] == 1         # Finding C is new
    assert drift["persistent_count"] == 1  # Finding B persisted
    assert drift["posture_trend"] in ("improving", "degrading", "stable")
    # Finding A remediated gives +15, Finding C critical deducts -40 -> Net delta -25
    assert drift["score_delta"] == -25.0
    assert drift["posture_trend"] == "degrading"
