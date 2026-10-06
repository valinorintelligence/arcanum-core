"""F2 — hardening applier (dry-run→apply→verify→rollback) + IR containment."""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.blue.registry import DeploymentRegistry
from arcanum.blue.hardening import HardeningApplier
from arcanum.blue.response import IncidentResponder


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "blue.db")
    await d.connect()
    await d.init_db()
    try:
        yield d
    finally:
        await d.close()


BASELINE = {
    "benchmark": "CIS Nginx Benchmark v2.0",
    "config_file": "/etc/nginx/conf.d/hardening.conf",
    "snippet": "server_tokens off;\nadd_header X-Frame-Options \"DENY\" always;\n",
}


@pytest.mark.asyncio
async def test_hardening_dry_run_changes_nothing(db):
    reg = DeploymentRegistry(db)
    applier = HardeningApplier(config=None, registry=reg)
    res = await applier.apply(BASELINE, target="web01", dry_run=True)
    assert res["status"] == "dry_run" and res["applied"] is False
    assert "server_tokens off;" in res["diff"]
    # dry-run is recorded (auditable) but NOT active
    rec = await reg.get(res["id"])
    assert rec["status"] == "dry_run"
    v = await applier.verify(res["id"])
    assert v["active"] is False


@pytest.mark.asyncio
async def test_hardening_apply_then_rollback(db):
    reg = DeploymentRegistry(db)
    applier = HardeningApplier(config=None, registry=reg)
    res = await applier.apply(BASELINE, target="web01", dry_run=False)
    assert res["applied"] is True and res["status"] == "active" and res["mock"] is True
    assert (await applier.verify(res["id"]))["active"] is True
    rb = await applier.rollback(res["id"])
    assert rb["success"] is True
    assert (await applier.verify(res["id"]))["active"] is False


@pytest.mark.asyncio
async def test_ir_contain_and_revert(db):
    reg = DeploymentRegistry(db)
    ir = IncidentResponder(config=None, registry=reg)
    res = await ir.contain("isolate_host", "10.0.0.5")
    assert res["status"] == "active" and res["mock"] is True and res["reversible"] is True
    rec = await reg.get(res["id"])
    assert rec["kind"] == "ir_action" and rec["target_system"] == "host"
    rev = await ir.revert(res["id"])
    assert rev["success"] is True and rev["status"] == "reverted"
    assert (await reg.get(res["id"]))["status"] == "rolled_back"


@pytest.mark.asyncio
async def test_ir_rejects_unknown_action(db):
    ir = IncidentResponder(config=None, registry=DeploymentRegistry(db))
    res = await ir.contain("nuke_everything", "10.0.0.5")
    assert res["success"] is False and "unknown" in res["error"].lower()
