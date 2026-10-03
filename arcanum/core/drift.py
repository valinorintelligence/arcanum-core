"""Exposure Drift & Assessment Delta Engine.

Calculates the operational delta between security assessments, tracking remediated
vulnerabilities, new attack surfaces, regressed exposures, and overall posture trend.
"""

from __future__ import annotations

import json
from typing import Any, Optional


def _finding_fingerprint(finding: dict[str, Any]) -> str:
    """Generate a stable fingerprint for finding deduplication across sessions."""
    title = (finding.get("title") or "").strip().lower()
    ftype = (finding.get("type") or "").strip().lower()
    affected = finding.get("affected") or {}
    aff_str = json.dumps(affected, sort_keys=True) if isinstance(affected, dict) else str(affected).lower()
    return f"{title}::{ftype}::{aff_str}"


class ExposureDrift:
    """Calculates security exposure drift between sessions or snapshots."""

    def __init__(self, db: Any):
        self.db = db

    async def calculate_drift(
        self,
        current_session_id: str,
        baseline_session_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Calculate the exposure drift between two assessment sessions."""
        # 1. Fetch current session findings
        current_rows = await self.db.fetch_all(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at ASC",
            (current_session_id,),
        )
        current_findings = [dict(r) for r in current_rows]

        # 2. Determine baseline session if not provided
        if not baseline_session_id:
            # Look for the immediate predecessor session for the same target
            curr_sess = await self.db.fetch_one("SELECT * FROM sessions WHERE id = ?", (current_session_id,))
            if curr_sess and curr_sess.get("target"):
                prev_sess = await self.db.fetch_one(
                    "SELECT id FROM sessions WHERE target = ? AND id != ? ORDER BY created_at DESC LIMIT 1",
                    (curr_sess["target"], current_session_id),
                )
                if prev_sess:
                    baseline_session_id = prev_sess["id"]

        baseline_findings = []
        if baseline_session_id:
            base_rows = await self.db.fetch_all(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at ASC",
                (baseline_session_id,),
            )
            baseline_findings = [dict(r) for r in base_rows]

        # 3. Build index maps
        base_map = {_finding_fingerprint(f): f for f in baseline_findings}
        curr_map = {_finding_fingerprint(f): f for f in current_findings}

        remediated: list[dict[str, Any]] = []
        new_findings: list[dict[str, Any]] = []
        regressed: list[dict[str, Any]] = []
        persistent: list[dict[str, Any]] = []

        # Analyze current findings against baseline
        for fp, curr_f in curr_map.items():
            base_f = base_map.get(fp)
            c_status = curr_f.get("status") or "confirmed"

            if c_status == "remediated":
                remediated.append(curr_f)
            elif base_f:
                b_status = base_f.get("status") or "confirmed"
                if b_status == "remediated" and c_status in ("confirmed", "regressed"):
                    regressed.append(curr_f)
                else:
                    persistent.append(curr_f)
            else:
                new_findings.append(curr_f)

        # Baseline findings not present in current session at all are considered remediated
        for fp, base_f in base_map.items():
            if fp not in curr_map:
                b_status = base_f.get("status") or "confirmed"
                if b_status != "remediated":
                    remediated_entry = dict(base_f)
                    remediated_entry["status"] = "remediated"
                    remediated.append(remediated_entry)

        # 4. Compute posture score delta
        # Remediation gives positive points; new findings and regressions deduct points
        severity_weights = {"critical": 40, "high": 25, "medium": 15, "low": 5, "info": 0}
        score_delta = 0

        for f in remediated:
            sev = (f.get("severity") or "medium").lower()
            score_delta += severity_weights.get(sev, 15)

        for f in new_findings:
            sev = (f.get("severity") or "medium").lower()
            score_delta -= severity_weights.get(sev, 15)

        for f in regressed:
            sev = (f.get("severity") or "medium").lower()
            score_delta -= severity_weights.get(sev, 15) * 1.5

        if score_delta > 0:
            trend = "improving"
        elif score_delta < 0:
            trend = "degrading"
        else:
            trend = "stable"

        return {
            "current_session_id": current_session_id,
            "baseline_session_id": baseline_session_id,
            "total_current_findings": len(current_findings),
            "total_baseline_findings": len(baseline_findings),
            "remediated_count": len(remediated),
            "new_count": len(new_findings),
            "regressed_count": len(regressed),
            "persistent_count": len(persistent),
            "score_delta": round(score_delta, 1),
            "posture_trend": trend,
            "remediated_findings": remediated,
            "new_findings": new_findings,
            "regressed_findings": regressed,
            "persistent_findings": persistent,
        }
