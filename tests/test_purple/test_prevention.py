"""F3 (d) — PREVENTION (BLOCKED) measured separately from DETECTION.

Prevention = the attack was blocked by a control; detection = it was alerted/logged.
They map to the distinct MITRE statuses BLOCKED vs DETECTED, keep the same
real-vs-simulated honesty split, and prevention never silently counts as detection.
"""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.blue.registry import DeploymentRegistry
from arcanum.purple.verify import DetectionVerifier
from arcanum.purple.store import PurpleResultStore
from arcanum.purple.loop import PurpleLoop
from arcanum.purple.efficacy import measured_efficacy_report, apply_measured_results
from arcanum.mitre.models import DefenseStatus


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "prev.db")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


class _FakeMitre:
    def __init__(self):
        self.calls = {}

    def evaluate_technique(self, technique_id, status, execution_log=None):
        self.calls[technique_id] = status
        return True


# ---------------------------------------------------------------------------
# verify.was_prevented
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_prevention_real_from_blocked_run(db):
    v = DetectionVerifier(db)
    res = await v.was_prevented("T1190", run={"execution_status": "blocked"})
    assert res["prevented"] is True
    assert res["source"] == "bas_blocked" and res["simulated"] is False


@pytest.mark.asyncio
async def test_prevention_mock_deploy_is_simulated(db):
    reg = DeploymentRegistry(db)
    # A WAF rule deployed in mock mode (no creds) → SIMULATED prevention only.
    await reg.record(kind="detection_rule", target_system="waf", name="waf-T1190",
                     status="active", mock=True)
    v = DetectionVerifier(db)
    res = await v.was_prevented("T1190", run={"execution_status": "simulated"})
    assert res["prevented"] is True
    assert res["simulated"] is True and res["source"] == "deployed_control_simulated"


@pytest.mark.asyncio
async def test_prevention_real_control_beats_mock(db):
    reg = DeploymentRegistry(db)
    await reg.record(kind="detection_rule", target_system="waf", name="waf-T1190",
                     status="active", mock=True)
    await reg.record(kind="ir_action", target_system="firewall", name="block-T1190",
                     status="active", mock=False)
    v = DetectionVerifier(db)
    res = await v.was_prevented("T1190", run={"execution_status": "simulated"})
    assert res["prevented"] is True
    assert res["simulated"] is False and res["source"] == "deployed_control"


@pytest.mark.asyncio
async def test_siem_detection_rule_is_not_prevention(db):
    # A SIEM detection rule alerts; it does not BLOCK → not prevention.
    reg = DeploymentRegistry(db)
    await reg.record(kind="detection_rule", target_system="siem", name="siem-T1200",
                     status="active", mock=True)
    v = DetectionVerifier(db)
    res = await v.was_prevented("T1200", run={"execution_status": "simulated"})
    assert res["prevented"] is False and res["source"] == "none"


# ---------------------------------------------------------------------------
# store coverage splits prevention real vs simulated
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_coverage_splits_prevention(db):
    store = PurpleResultStore(db)
    await store.record(campaign_id="c1", technique_id="T1", executed=True,
                       detected=False, prevented=True, prevention_simulated=False)
    await store.record(campaign_id="c1", technique_id="T2", executed=True,
                       detected=False, prevented=True, prevention_simulated=True)
    cov = await store.coverage("c1")
    assert cov["prevented"] == 2
    assert cov["prevented_real"] == 1 and cov["prevented_simulated"] == 1
    assert cov["prevention_percent"] == 100.0
    assert cov["prevention_percent_real"] == 50.0


# ---------------------------------------------------------------------------
# efficacy: BLOCKED > DETECTED > MISSED; simulated never counts as real
# ---------------------------------------------------------------------------

def test_apply_measured_results_precedence():
    results = [
        {"technique_id": "TP", "executed": True, "detected": False,
         "prevented": True, "prevention_simulated": False, "created_at": "1"},
        {"technique_id": "TD", "executed": True, "detected": True,
         "detection_simulated": False, "prevented": False, "created_at": "1"},
        {"technique_id": "TS", "executed": True, "detected": True,
         "detection_simulated": True, "prevented": False, "created_at": "1"},
        {"technique_id": "TPS", "executed": True, "detected": False,
         "prevented": True, "prevention_simulated": True, "created_at": "1"},
    ]
    eng = _FakeMitre()
    out = apply_measured_results(eng, results)
    assert eng.calls["TP"] == DefenseStatus.BLOCKED       # real prevention
    assert eng.calls["TD"] == DefenseStatus.DETECTED      # real detection
    assert eng.calls["TS"] == DefenseStatus.MISSED        # simulated detection => gap
    assert eng.calls["TPS"] == DefenseStatus.MISSED       # simulated prevention => gap
    assert out["prevented"] == 1 and out["simulated"] == 2


def test_measured_report_prevention_rates():
    results = [
        {"technique_id": "TP", "executed": True, "detected": False,
         "prevented": True, "prevention_simulated": False, "created_at": "1"},
        {"technique_id": "TD", "executed": True, "detected": True,
         "detection_simulated": False, "prevented": False, "created_at": "1"},
        {"technique_id": "TS", "executed": True, "detected": True,
         "detection_simulated": True, "prevented": False, "created_at": "1"},
        {"technique_id": "TPS", "executed": True, "detected": False,
         "prevented": True, "prevention_simulated": True, "created_at": "1"},
    ]
    rep = measured_efficacy_report(results)
    assert rep["prevented"] == 2 and rep["prevented_real"] == 1
    assert rep["prevention_rate_real"] == 25.0
    assert rep["detection_rate_real"] == 25.0


# ---------------------------------------------------------------------------
# loop: a blocked run is recorded as (real) prevention, not a detection gap
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_close_gap_blocked_run_is_prevented(db):
    loop = PurpleLoop(db)

    async def fake_run(tid, cid, tactic=None, command=None, **kwargs):
        return {"technique_id": tid, "executed": True, "execution_status": "blocked",
                "deconfliction_tag": f"ARCANUM-BAS:{cid}:{tid}"}
    loop.bas.run = fake_run

    res = await loop.close_gap("T1190", campaign_id="c1")
    assert res["status"] == "prevented"
    assert res["before_prevention"]["prevented"] is True
    assert res["before_prevention"]["simulated"] is False
    assert res["tuned"] is False  # no need to tune: already covered by prevention

    rows = await PurpleResultStore(db).list("c1")
    assert any(r["prevented"] is True for r in rows)
