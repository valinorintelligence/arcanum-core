"""F3 — BAS runner, detection verifier, result store, closed loop, efficacy."""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.purple.store import PurpleResultStore
from arcanum.purple.bas import BASRunner, deconfliction_tag
from arcanum.purple.verify import DetectionVerifier
from arcanum.purple.loop import PurpleLoop, build_detection_rule
from arcanum.purple.efficacy import measured_efficacy_report, apply_measured_results


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "purple.db")
    await d.connect()
    await d.init_db()
    try:
        yield d
    finally:
        await d.close()


@pytest.mark.asyncio
async def test_purple_table_exists(db):
    row = await db.fetch_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='purple_results'")
    assert row is not None


@pytest.mark.asyncio
async def test_bas_simulates_without_sandbox_and_tags(db):
    runner = BASRunner(sandbox=None)
    run = await runner.run("T1190", "camp-1", tactic="initial-access")
    # honest: nothing real executed, clearly marked, deconfliction-tagged
    assert run["executed"] is True and run["execution_status"] == "simulated"
    assert run["sandbox"] is False
    assert run["deconfliction_tag"] == deconfliction_tag("camp-1", "T1190")


@pytest.mark.asyncio
async def test_verifier_miss_then_simulated_hit_after_mock_rule(db):
    """Honesty (F3 review): a MOCK deploy (no creds) is SIMULATED coverage, not a
    real detection — flagged simulated=True, source='deployed_rule_simulated'."""
    from arcanum.blue.registry import DeploymentRegistry
    from arcanum.blue.deployers.siem import SIEMDeployer
    v = DetectionVerifier(db, config=None)
    before = await v.was_detected("T1059.001")
    assert before["detected"] is False and before["source"] == "none" and before["simulated"] is False
    # Deploy a covering rule WITHOUT creds => mock => simulated coverage.
    reg = DeploymentRegistry(db)
    await SIEMDeployer(config=None, registry=reg).deploy(build_detection_rule("T1059.001", "execution"))
    after = await v.was_detected("T1059.001")
    assert after["detected"] is True
    assert after["simulated"] is True and after["source"] == "deployed_rule_simulated"


@pytest.mark.asyncio
async def test_verifier_real_deploy_is_not_simulated(db):
    """A rule deployed to a REAL control (mock=False) counts as real detection."""
    from arcanum.blue.registry import DeploymentRegistry
    reg = DeploymentRegistry(db)
    # Record a non-mock active detection rule covering the technique.
    await reg.record(kind="detection_rule", target_system="siem", rule_type="sigma",
                     name="purple-T1190", status="active", mock=False,
                     payload={"technique_id": "T1190"})
    v = DetectionVerifier(db, config=None)
    res = await v.was_detected("T1190")
    assert res["detected"] is True and res["simulated"] is False and res["source"] == "deployed_rule"


@pytest.mark.asyncio
async def test_verifier_prefers_real_over_simulated(db):
    from arcanum.blue.registry import DeploymentRegistry
    reg = DeploymentRegistry(db)
    await reg.record(kind="detection_rule", target_system="siem", rule_type="sigma",
                     name="purple-T1190-mock", status="active", mock=True,
                     payload={"technique_id": "T1190"})
    await reg.record(kind="detection_rule", target_system="siem", rule_type="sigma",
                     name="purple-T1190-real", status="active", mock=False,
                     payload={"technique_id": "T1190"})
    res = await DetectionVerifier(db, config=None).was_detected("T1190")
    assert res["simulated"] is False and res["source"] == "deployed_rule"


@pytest.mark.asyncio
async def test_verifier_real_siem_query_source(db, monkeypatch):
    """With SIEM creds and no covering rule, a real SIEM hit => source='siem'."""
    class Cfg:
        elastic_url = "https://elastic.example.com"
        elastic_api_key = "key"
    v = DetectionVerifier(db, config=Cfg())

    async def _fake_query(tag, window):
        return True
    monkeypatch.setattr(v, "_query_siem", _fake_query)
    res = await v.was_detected("T1003.001", tag="ARCANUM-BAS:c:T1003.001")
    assert res["detected"] is True and res["source"] == "siem" and res["simulated"] is False


@pytest.mark.asyncio
async def test_closed_loop_detect_tune_validate_simulated(db):
    loop = PurpleLoop(db, config=None, sandbox=None)
    res = await loop.close_gap("T1110.003", tactic="credential-access", auto_tune=True)
    # Starts missed, gets tuned (rule deployed). Without creds the deploy is MOCK,
    # so the re-measure is SIMULATED coverage — honestly labeled, not real.
    assert res["before"]["detected"] is False
    assert res["tuned"] is True and res["deployment"]["status"] == "active"
    assert res["after"]["detected"] is True and res["after"]["simulated"] is True
    assert res["status"] == "tuned_simulated"

    cov = await PurpleResultStore(db).coverage(res["campaign_id"])
    # Inclusive coverage is 100% (a rule covers it) but REAL coverage is 0%.
    assert cov["coverage_percent"] == 100.0 and cov["gaps"] == []
    assert cov["coverage_percent_real"] == 0.0
    assert cov["detected_simulated"] == 1 and cov["detected_real"] == 0
    assert cov["simulated_gaps"] == ["T1110.003"]


@pytest.mark.asyncio
async def test_closed_loop_no_autotune_stays_missed(db):
    loop = PurpleLoop(db, config=None, sandbox=None)
    res = await loop.close_gap("T1087.002", auto_tune=False)
    assert res["status"] == "missed" and res["tuned"] is False
    cov = await PurpleResultStore(db).coverage(res["campaign_id"])
    assert cov["coverage_percent"] == 0.0 and cov["gaps"] == ["T1087.002"]


@pytest.mark.asyncio
async def test_measured_efficacy_separates_real_from_simulated(db):
    loop = PurpleLoop(db, config=None, sandbox=None)
    await loop.close_gap("T1190", campaign_id="c-eff", auto_tune=True)       # -> simulated hit
    await loop.close_gap("T1071.001", campaign_id="c-eff", auto_tune=False)  # -> real miss
    results = await PurpleResultStore(db).list("c-eff")
    rep = measured_efficacy_report(results)
    assert rep["source"] == "measured" and rep["executed"] == 2
    # Honesty: the only "detection" is simulated → real rate is 0.
    assert rep["detected"] == 1 and rep["detected_real"] == 0 and rep["detected_simulated"] == 1
    assert rep["detection_rate_real"] == 0.0 and rep["coverage_simulated"] == 50.0
    assert rep["gaps"] == ["T1071.001"] and rep["simulated_gaps"] == ["T1190"]


def test_apply_measured_results_real_detected_vs_simulated():
    from arcanum.mitre.engine import MitreEfficacyEngine
    from arcanum.mitre.models import DefenseStatus
    engine = MitreEfficacyEngine()
    # Real detection => DETECTED; simulated-only => MISSED (not painted as real).
    results = [
        {"technique_id": "T1190", "executed": True, "detected": True,
         "detection_simulated": False, "detection_source": "deployed_rule",
         "created_at": "2026-10-04T00:00:00Z"},
        {"technique_id": "T1059.001", "executed": True, "detected": True,
         "detection_simulated": True, "detection_source": "deployed_rule_simulated",
         "created_at": "2026-10-04T00:00:01Z"},
    ]
    out = apply_measured_results(engine, results)
    assert out["applied"] == 2 and out["simulated"] == 1
    assert engine.get_technique("T1190").status == DefenseStatus.DETECTED
    assert engine.get_technique("T1059.001").status == DefenseStatus.MISSED
