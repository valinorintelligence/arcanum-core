"""F2 — ToolExecutor Blue handlers + F0 governance integration for Blue tools."""

from pathlib import Path

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.agent.tools import ToolExecutor
from arcanum.blue.registry import DeploymentRegistry
from arcanum.redteam.action_classes import classify, hitl_tier, ActionClass


@pytest_asyncio.fixture
async def te(tmp_path):
    db = Database(db_path=tmp_path / "blue.db")
    await db.connect()
    await db.init_db()
    ex = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path, db=db, session_id="op-blue")
    try:
        yield ex, db
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_deploy_then_verify_tool(te):
    ex, db = te
    out = await ex.execute_tool("deploy_detection_rule", {
        "rule": "title: SQLi\ndetection:\n  condition: selection",
        "rule_type": "sigma", "target_system": "siem", "name": "sqli-sigma"})
    assert out["success"] is True
    dep = out["output"]
    assert dep["status"] == "active" and dep["mock"] is True
    did = dep["id"]

    v = await ex.execute_tool("verify_detection_active", {"deployment_id": did})
    assert v["success"] is True and v["output"]["active"] is True

    # rollback via registry, then verify flips to inactive
    assert await DeploymentRegistry(db).mark_rolled_back(did) is True
    v2 = await ex.execute_tool("verify_detection_active", {"deployment_id": did})
    assert v2["output"]["active"] is False


@pytest.mark.asyncio
async def test_deploy_rejects_bad_target(te):
    ex, _ = te
    out = await ex.execute_tool("deploy_detection_rule", {"rule": "x", "target_system": "mainframe"})
    assert out["success"] is True and "error" in out["output"]


@pytest.mark.asyncio
async def test_apply_hardening_dry_run_default(te):
    ex, db = te
    # Default must be dry-run: nothing applied.
    out = await ex.execute_tool("apply_hardening", {
        "config_file": "/etc/nginx/conf.d/h.conf", "snippet": "server_tokens off;"})
    assert out["success"] is True
    res = out["output"]
    assert res["status"] == "dry_run" and res["applied"] is False
    # Explicit apply records an active, reversible change.
    out2 = await ex.execute_tool("apply_hardening", {
        "config_file": "/etc/nginx/conf.d/h.conf", "snippet": "server_tokens off;", "dry_run": False})
    assert out2["output"]["applied"] is True


@pytest.mark.asyncio
async def test_apply_hardening_consumes_generator_output(te):
    """apply_hardening must accept the real generate_hardening_baseline output
    shape (target_config_file / hardening_snippet), not just flat config_file/snippet."""
    ex, _ = te
    hb = (await ex.execute_tool("generate_hardening_baseline", {"target_technology": "nginx"}))["output"]
    assert "hardening_snippet" in hb and "target_config_file" in hb
    out = await ex.execute_tool("apply_hardening", {"baseline": hb})
    assert out["success"] is True
    res = out["output"]
    assert res.get("status") == "dry_run", res
    assert res["config_file"] == hb["target_config_file"]


@pytest.mark.asyncio
async def test_ir_contain_tool_and_revert(te):
    ex, _ = te
    out = await ex.execute_tool("ir_contain", {"action": "block_ip", "target": "1.2.3.4"})
    assert out["success"] is True and out["output"]["status"] == "active"
    did = out["output"]["id"]
    rev = await ex.execute_tool("ir_contain", {"revert": True, "deployment_id": did})
    assert rev["output"]["success"] is True


def test_blue_tools_action_classes_and_tiers():
    # Governance (F0): Blue changes are ACTIVE (single approval); verify is PASSIVE.
    assert classify("deploy_detection_rule", {}) == ActionClass.ACTIVE
    assert classify("apply_hardening", {}) == ActionClass.ACTIVE
    assert classify("ir_contain", {}) == ActionClass.ACTIVE
    assert classify("verify_detection_active", {}) == ActionClass.PASSIVE
    assert hitl_tier(ActionClass.ACTIVE) == "approve"
