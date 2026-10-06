"""Unit and Integration Tests for Continuous Threat Exposure Management (CTEM) & CISA KEV (Fase 4)."""

import json
from pathlib import Path
import tempfile
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from arcanum.core.database import Database
from arcanum.core.kev import CISAKEVEngine, BOOTSTRAP_KEV_DATA
from arcanum.core.ctem import CTEMDaemon
from arcanum.agent.tools import ToolExecutor, NATIVE_TOOLS


@pytest_asyncio.fixture
async def memory_db():
    """Provides an isolated database instance in a temporary folder."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_ctem.db"
        db = Database(db_path=db_file)
        await db.connect()
        await db.init_db()
        yield db
        await db.close()


# ============================================================================
# 1. CISA KEV Engine Tests
# ============================================================================

@pytest.mark.asyncio
async def test_cisa_kev_engine_sync_and_lookup(memory_db):
    """Test CISA KEV catalog sync, lookup and statistics."""
    kev = CISAKEVEngine(db=memory_db, mock_mode=True)
    sync_res = await kev.sync_cisa_kev()

    assert sync_res["success"] is True
    assert sync_res["total_synced"] >= len(BOOTSTRAP_KEV_DATA)

    # 1. Known KEV CVE (Log4Shell)
    assert await kev.is_cisa_kev("CVE-2021-44228") is True
    assert await kev.is_cisa_kev("cve-2021-44228") is True  # Case insensitive

    details = await kev.get_cve_details("CVE-2021-44228")
    assert details is not None
    assert "Log4j" in details["product"]
    assert details["due_date"] == "2021-12-24"

    # 2. Non-existent CVE
    assert await kev.is_cisa_kev("CVE-2099-9999") is False
    assert await kev.get_cve_details("CVE-2099-9999") is None

    # 3. Statistics
    stats = await kev.get_statistics()
    assert stats["total_cves"] >= 6
    assert stats["ransomware_linked_cves"] >= 3


@pytest.mark.asyncio
async def test_cisa_kev_finding_enrichment(memory_db):
    """Test automatic finding enrichment, critical escalation and BOD 22-01 mandate."""
    kev = CISAKEVEngine(db=memory_db, mock_mode=True)
    await kev.sync_cisa_kev()

    # 1. Finding with CISA KEV CVE (PAN-OS GlobalProtect)
    finding_kev = {
        "id": "find-pan-01",
        "title": "Command Injection in GlobalProtect Gateway",
        "severity": "medium",  # Sub-classified originally
        "cve_id": "CVE-2024-3400",
        "remediation": "Apply network isolation.",
    }
    enriched = await kev.enrich_finding(finding_kev)

    assert enriched["is_cisa_kev"] is True
    assert enriched["severity"] == "critical"  # Escalated to critical
    assert "cisa_kev" in enriched
    assert enriched["cisa_kev"]["due_date"] == "2024-04-19"
    assert "[CISA BOD 22-01 MANDATE]" in enriched["remediation"]

    # 2. Finding with non-KEV CVE
    finding_normal = {
        "id": "find-norm-01",
        "title": "Minor Information Disclosure",
        "severity": "low",
        "cve_id": "CVE-2019-12345",
        "remediation": "Update package.",
    }
    enriched_normal = await kev.enrich_finding(finding_normal)
    assert enriched_normal["is_cisa_kev"] is False
    assert enriched_normal["severity"] == "low"
    assert "[CISA BOD 22-01 MANDATE]" not in enriched_normal["remediation"]


# ============================================================================
# 2. Continuous CTEM Daemon Tests
# ============================================================================

@pytest.mark.asyncio
async def test_ctem_daemon_schedules_crud(memory_db):
    """Test CTEM schedule creation, retrieval, pause/resume and deletion."""
    daemon = CTEMDaemon(db=memory_db)
    await daemon.init_tables()

    # Seed session
    session_id = "sess-ctem-01"
    await memory_db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        (session_id, "prod-ecommerce", "https://shop.corp.local"),
    )

    # 1. Create schedule
    sched = await daemon.create_schedule(
        session_id=session_id,
        target="https://shop.corp.local",
        frequency_minutes=60,
    )
    sched_id = sched["schedule_id"]
    assert sched_id.startswith("ctem-")
    assert sched["status"] == "active"
    assert sched["frequency_minutes"] == 60

    # 2. List schedules
    schedules = await daemon.list_schedules()
    assert len(schedules) == 1
    assert schedules[0]["id"] == sched_id

    # 3. Pause & Resume
    assert await daemon.update_schedule_status(sched_id, "paused") is True
    s_paused = await daemon.get_schedule(sched_id)
    assert s_paused["status"] == "paused"

    assert await daemon.update_schedule_status(sched_id, "active") is True
    s_active = await daemon.get_schedule(sched_id)
    assert s_active["status"] == "active"

    # 4. Delete schedule
    assert await daemon.delete_schedule(sched_id) is True
    assert await daemon.get_schedule(sched_id) is None


@pytest.mark.asyncio
async def test_ctem_daemon_assessment_cycle_and_drift(memory_db):
    """Test full automated CTEM assessment cycle with finding retest and drift score."""
    session_id = "sess-continuous-01"
    await memory_db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        (session_id, "continuous-target", "https://api.corp.local"),
    )

    # Seed finding with retest metadata
    finding_id = "find-ctem-xfo"
    await memory_db.execute(
        """INSERT INTO findings (id, session_id, title, severity, status, cve_id, retest_tool, retest_arguments)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding_id,
            session_id,
            "Missing X-Frame-Options Clickjacking",
            "medium",
            "confirmed",
            "CVE-2021-44228",  # Log4Shell for KEV alert test
            "audit_security_headers",
            json.dumps({"url": "https://api.corp.local"}),
        ),
    )

    # Setup CTEM Daemon with mock hub
    mock_hub = AsyncMock()
    daemon = CTEMDaemon(db=memory_db, enterprise_hub=mock_hub)

    sched = await daemon.create_schedule(
        session_id=session_id,
        target="https://api.corp.local",
        frequency_minutes=120,
    )
    sched_id = sched["schedule_id"]

    # Run assessment cycle
    cycle_res = await daemon.run_assessment_cycle(sched_id)

    assert cycle_res["schedule_id"] == sched_id
    assert cycle_res["session_id"] == session_id
    assert cycle_res["total_runs"] == 1
    assert cycle_res["retested_count"] == 1
    assert cycle_res["kev_alert_count"] == 1
    assert "summary" in cycle_res

    # Verify run was logged in ctem_run_logs
    cursor = await memory_db.execute(
        "SELECT COUNT(*) AS total FROM ctem_run_logs WHERE schedule_id = ?",
        (sched_id,),
    )
    log_count = (await cursor.fetchone())["total"]
    assert log_count == 1


# ============================================================================
# 3. Agent Tool check_cisa_kev
# ============================================================================

@pytest.mark.asyncio
async def test_agent_tool_check_cisa_kev(memory_db):
    """Verify check_cisa_kev agent tool is registered and executes properly."""
    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    assert "check_cisa_kev" in tool_names

    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=memory_db)
    assert "check_cisa_kev" in executor._handlers

    # Test with Log4Shell (active KEV)
    res_kev = await executor.execute_tool("check_cisa_kev", {"cve_id": "CVE-2021-44228"})
    assert res_kev["success"] is True
    out_kev = res_kev["output"]
    assert out_kev["is_cisa_kev"] is True
    assert "CISA KEV ALERT" in out_kev["summary"]
    assert out_kev["details"] is not None

    # Test with non-KEV CVE
    res_non_kev = await executor.execute_tool("check_cisa_kev", {"cve_id": "CVE-1999-0001"})
    assert res_non_kev["success"] is True
    out_non_kev = res_non_kev["output"]
    assert out_non_kev["is_cisa_kev"] is False
    assert "not currently listed" in out_non_kev["summary"]
