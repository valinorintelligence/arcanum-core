"""F2 — SIEM/WAF/EDR deployers + rollback registry (honest mock, no credentials)."""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.blue.registry import DeploymentRegistry
from arcanum.blue.deployers.siem import SIEMDeployer
from arcanum.blue.deployers.waf import WAFDeployer
from arcanum.blue.deployers.edr import EDRDeployer


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "blue.db")
    await d.connect()
    await d.init_db()
    try:
        yield d
    finally:
        await d.close()


@pytest.mark.asyncio
async def test_blue_table_exists(db):
    row = await db.fetch_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='blue_deployments'")
    assert row is not None


@pytest.mark.parametrize("Deployer,ts,rule_type,body", [
    (SIEMDeployer, "siem", "sigma", "title: Test\ndetection:\n  condition: selection"),
    (WAFDeployer, "waf", "modsecurity", 'SecRule REQUEST_URI "@contains /x" "id:1,deny"'),
    (EDRDeployer, "edr", "ioc", "md5:deadbeef"),
])
@pytest.mark.asyncio
async def test_deploy_verify_rollback_mock(db, Deployer, ts, rule_type, body):
    reg = DeploymentRegistry(db)
    d = Deployer(config=None, registry=reg)           # no config => honest mock
    assert d.mock_mode is True

    dep = await d.deploy({"rule_type": rule_type, "name": f"t-{ts}",
                          "body": body, "modsecurity": body, "sigma": body, "indicator": body})
    assert dep["status"] == "active" and dep["mock"] is True and dep["target_system"] == ts
    did = dep["id"]

    # Registry persisted it.
    rec = await reg.get(did)
    assert rec and rec["status"] == "active" and rec["kind"] == "detection_rule"

    # Verify => active.
    v = await d.verify(did)
    assert v["active"] is True and v["status"] == "active"

    # Rollback => no longer active; registry reflects it.
    rb = await d.rollback(did)
    assert rb["success"] is True and rb["status"] == "rolled_back"
    v2 = await d.verify(did)
    assert v2["active"] is False
    assert (await reg.get(did))["status"] == "rolled_back"


@pytest.mark.asyncio
async def test_verify_unknown_deployment(db):
    d = SIEMDeployer(config=None, registry=DeploymentRegistry(db))
    v = await d.verify("dep-nope")
    assert v["active"] is False and v["status"] == "not_found"


@pytest.mark.asyncio
async def test_rollback_is_idempotent(db):
    reg = DeploymentRegistry(db)
    d = WAFDeployer(config=None, registry=reg)
    dep = await d.deploy({"rule_type": "modsecurity", "body": "x"})
    await d.rollback(dep["id"])
    again = await d.rollback(dep["id"])
    assert again["success"] is True and again["status"] == "rolled_back"


@pytest.mark.asyncio
async def test_siem_without_creds_is_mock(db):
    # No elastic/splunk/datadog creds => mock mode (never a fake real deploy).
    class Cfg:  # bare config with empty creds
        elastic_url = elastic_api_key = splunk_hec_url = splunk_hec_token = datadog_api_key = ""
    d = SIEMDeployer(config=Cfg(), registry=DeploymentRegistry(db))
    assert d.configured() is False and d.mock_mode is True
    dep = await d.deploy({"rule_type": "sigma", "body": "x"})
    assert dep["mock"] is True
