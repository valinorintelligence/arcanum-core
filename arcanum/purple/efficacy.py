"""Measured efficacy (F3): efficacy from measurement, not the static seed —
and REAL detection kept apart from SIMULATED (mock-deploy) coverage.

``measured_efficacy_report`` computes detection efficacy purely from measured BAS
results, exposing the real detection rate separately from simulated coverage so a
mock deploy never inflates the real number. ``apply_measured_results`` pushes those
verdicts into the existing :class:`~arcanum.mitre.engine.MitreEfficacyEngine`,
marking a technique DETECTED only when detection was REAL — a simulated-only
"detection" (a rule deployed to a mock control) counts as MISSED on the heatmap,
with an execution log that says so.
"""
from __future__ import annotations

from typing import Any


def measured_efficacy_report(results: list[dict]) -> dict:
    """Derive a detection-efficacy report from measured results (latest per technique).

    Real vs simulated are split: ``detection_rate_real`` reflects REAL controls
    only; ``coverage_simulated`` is mock-deploy coverage (not real detection).
    """
    latest: dict[str, dict] = {}
    for r in sorted(results, key=lambda x: x.get("created_at", "")):
        latest[r["technique_id"]] = r
    techs = list(latest.values())
    executed = [t for t in techs if t.get("executed")]
    detected = [t for t in executed if t.get("detected") is True]
    detected_real = [t for t in detected if not t.get("detection_simulated")]
    detected_sim = [t for t in detected if t.get("detection_simulated")]
    prevented = [t for t in executed if t.get("prevented") is True]
    prevented_real = [t for t in prevented if not t.get("prevention_simulated")]
    prevented_sim = [t for t in prevented if t.get("prevention_simulated")]
    missed = [t for t in executed if t.get("detected") is False]
    ne = len(executed)
    return {
        "source": "measured",
        "total_techniques": len(techs),
        "executed": ne,
        "detected": len(detected),                 # total (real + simulated)
        "detected_real": len(detected_real),
        "detected_simulated": len(detected_sim),
        "prevented": len(prevented),               # BLOCKED, distinct from detected
        "prevented_real": len(prevented_real),
        "prevented_simulated": len(prevented_sim),
        "missed": len(missed),
        "detection_rate": round((len(detected) / ne) * 100.0, 1) if ne else 0.0,
        "detection_rate_real": round((len(detected_real) / ne) * 100.0, 1) if ne else 0.0,
        "prevention_rate": round((len(prevented) / ne) * 100.0, 1) if ne else 0.0,
        "prevention_rate_real": round((len(prevented_real) / ne) * 100.0, 1) if ne else 0.0,
        "coverage_simulated": round((len(detected_sim) / ne) * 100.0, 1) if ne else 0.0,
        "gaps": [t["technique_id"] for t in missed],
        # Techniques "covered" only by a mock deploy are still real gaps.
        "simulated_gaps": [t["technique_id"] for t in detected_sim],
    }


def apply_measured_results(engine: Any, results: list[dict]) -> dict:
    """Feed measured verdicts into a MitreEfficacyEngine (measured > seed).

    Precedence per technique: **BLOCKED** (real prevention) > **DETECTED** (real
    detection) > **MISSED**. A simulated-only prevention or detection (mock deploy,
    no real control) is recorded as MISSED with a clear log — simulated never counts
    as a real control outcome. Returns {applied, unknown, simulated, prevented}.
    """
    try:
        from ..mitre.models import DefenseStatus
    except Exception:
        return {"applied": 0, "unknown": 0, "simulated": 0, "prevented": 0}

    latest: dict[str, dict] = {}
    for r in sorted(results, key=lambda x: x.get("created_at", "")):
        latest[r["technique_id"]] = r

    applied = unknown = simulated = prevented = 0
    for tid, r in latest.items():
        if not r.get("executed"):
            continue
        real_prevented = r.get("prevented") is True and not r.get("prevention_simulated")
        real_detected = r.get("detected") is True and not r.get("detection_simulated")
        if real_prevented:
            status = DefenseStatus.BLOCKED
            prevented += 1
            log = f"Medido via BAS — PREVENÇÃO REAL / bloqueado (fonte: {r.get('prevention_source')})."
        elif real_detected:
            status = DefenseStatus.DETECTED
            log = f"Medido via BAS — detecção REAL (fonte: {r.get('detection_source')})."
        else:
            status = DefenseStatus.MISSED
            sim_prev = r.get("prevented") and r.get("prevention_simulated")
            sim_det = r.get("detected") and r.get("detection_simulated")
            if sim_prev or sim_det:
                simulated += 1
                log = ("Medido via BAS — cobertura SIMULADA (deploy mock, sem controle real); "
                       "conta como LACUNA até implantar em um controle real.")
            else:
                log = "Medido via BAS — não detectado nem prevenido (lacuna)."
        updated = engine.evaluate_technique(technique_id=tid, status=status, execution_log=log)
        if updated:
            applied += 1
        else:
            unknown += 1
    return {"applied": applied, "unknown": unknown, "simulated": simulated, "prevented": prevented}
