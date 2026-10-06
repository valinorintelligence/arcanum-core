"""Unit and Integration Tests for Distributed Satellite Probes Architecture (Fase 5)."""

import json
from pathlib import Path
import tempfile
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta

from arcanum.core.database import Database
from arcanum.probes.hub import ProbeHubManager
from arcanum.probes.satellite import SatelliteProbe
from arcanum.agent.tools import ToolExecutor, NATIVE_TOOLS


@pytest_asyncio.fixture
async def memory_db():
    """Provides an isolated database instance in a temporary folder."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_probes.db"
        db = Database(db_path=db_file)
        await db.connect()
        await db.init_db()
        yield db
        await db.close()


# ============================================================================
# 1. Probe Hub Manager Lifecycle Tests
# ============================================================================

@pytest.mark.asyncio
async def test_probe_registration_and_heartbeat(memory_db):
    """Test satellite probe registration, heartbeat and liveness calculation."""
    hub = ProbeHubManager(db=memory_db)
    await hub.init_tables()

    # 1. Register Probe
    reg = await hub.register_probe(
        name="probe-aws-us-east-1",
        hostname="worker-ec2-01.internal",
        ip_address="10.0.10.55",
        tags=["aws", "vpc-prod", "internal"],
        capabilities=["execute", "audit_security_headers"],
    )
    pid = reg["probe_id"]
    assert pid.startswith("probe-")
    assert reg["status"] == "online"
    assert "vpc-prod" in reg["tags"]

    # 2. Get Probe
    probe = await hub.get_probe(pid)
    assert probe is not None
    assert probe["hostname"] == "worker-ec2-01.internal"

    # 3. Heartbeat
    hb = await hub.heartbeat(pid, status="online")
    assert hb["success"] is True

    # 4. List Probes
    probes = await hub.list_probes()
    assert len(probes) == 1
    assert probes[0]["id"] == pid
    assert probes[0]["status"] == "online"

    # 5. Filter by Tag
    aws_probes = await hub.list_probes(tag="aws")
    assert len(aws_probes) == 1

    azure_probes = await hub.list_probes(tag="azure")
    assert len(azure_probes) == 0

    # 6. Find Probe by Tag
    found = await hub.find_probe_by_tag("vpc-prod")
    assert found is not None
    assert found["id"] == pid


@pytest.mark.asyncio
async def test_probe_stale_offline_detection(memory_db):
    """Test that a probe whose last heartbeat is older than threshold is marked offline."""
    hub = ProbeHubManager(db=memory_db)
    await hub.init_tables()

    reg = await hub.register_probe(
        name="probe-stale-dc",
        tags=["onprem"],
    )
    pid = reg["probe_id"]

    # Manually backdate last_heartbeat to 10 minutes ago
    stale_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    await memory_db.execute(
        "UPDATE satellite_probes SET last_heartbeat = ? WHERE id = ?",
        (stale_time, pid),
    )

    probes = await hub.list_probes()
    assert len(probes) == 1
    assert probes[0]["status"] == "offline"


# ============================================================================
# 2. Probe Task Queue & Remote Dispatch
# ============================================================================

@pytest.mark.asyncio
async def test_probe_task_dispatch_and_execution_lifecycle(memory_db):
    """Test end-to-end task queueing, polling, execution and result submission."""
    hub = ProbeHubManager(db=memory_db)
    await hub.init_tables()

    reg = await hub.register_probe(
        name="probe-internal-dmz",
        tags=["dmz"],
    )
    pid = reg["probe_id"]

    # 1. Dispatch task to probe
    task = await hub.dispatch_task(
        probe_id=pid,
        tool_name="audit_security_headers",
        arguments={"url": "http://internal-payroll.local"},
        session_id="sess-remote-audit",
    )
    tid = task["task_id"]
    assert tid.startswith("ptask-")
    assert task["status"] == "pending"

    # 2. Probe polls for tasks
    polled = await hub.poll_tasks(probe_id=pid, limit=5)
    assert len(polled) == 1
    assert polled[0]["id"] == tid
    assert polled[0]["status"] == "assigned"
    assert polled[0]["arguments"]["url"] == "http://internal-payroll.local"

    # 3. Probe submits successful result
    remote_output = {"score": 90, "grade": "A", "verified_internal": True}
    sub_res = await hub.submit_task_result(
        task_id=tid,
        probe_id=pid,
        result=remote_output,
    )
    assert sub_res["success"] is True
    assert sub_res["status"] == "completed"

    # 4. Hub retrieves completed task
    completed_task = await hub.get_task(tid)
    assert completed_task["status"] == "completed"
    assert completed_task["result"]["verified_internal"] is True
    assert completed_task["completed_at"] is not None


# ============================================================================
# 3. SatelliteProbe Client Local Execution & Agent Tool
# ============================================================================

@pytest.mark.asyncio
async def test_satellite_probe_client_local_execution():
    """Test SatelliteProbe local tool execution logic."""
    probe = SatelliteProbe(
        hub_url="http://127.0.0.1:8000",
        token="test-token",
        name="probe-local-test",
    )
    out_cmd = await probe.execute_task_locally("execute", {"command": "whoami"})
    assert "stdout" in out_cmd
    assert out_cmd["exit_code"] == 0

    out_hdr = await probe.execute_task_locally("audit_security_headers", {"url": "https://example.com"})
    assert out_hdr["score"] == 85
    assert out_hdr["probe"] == "probe-local-test"


@pytest.mark.asyncio
async def test_agent_tool_dispatch_to_satellite_probe(memory_db):
    """Verify dispatch_to_satellite_probe agent tool queues task on target probe."""
    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    assert "dispatch_to_satellite_probe" in tool_names

    hub = ProbeHubManager(db=memory_db)
    reg = await hub.register_probe(name="probe-vlan-iot", tags=["iot-network"])
    pid = reg["probe_id"]

    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=memory_db)
    assert "dispatch_to_satellite_probe" in executor._handlers

    # Dispatch via probe_id
    res = await executor.execute_tool(
        "dispatch_to_satellite_probe",
        {
            "probe_id": pid,
            "tool_name": "execute",
            "arguments": {"command": "nmap -sP 192.168.1.0/24"},
        },
    )
    assert res["success"] is True
    out = res["output"]
    assert out["status"] == "queued_at_remote_probe"
    assert out["probe_id"] == pid

    # Dispatch via tag
    res_tag = await executor.execute_tool(
        "dispatch_to_satellite_probe",
        {
            "probe_id": "iot-network",
            "tool_name": "audit_security_headers",
            "arguments": {"url": "http://192.168.1.1"},
        },
    )
    assert res_tag["success"] is True
    assert res_tag["output"]["probe_id"] == pid
