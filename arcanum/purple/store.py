"""Measured BAS result store (F3).

Persists every technique run + detection verdict so coverage/efficacy are derived
from **measurement** (not the static MITRE seed), and so the closed loop is
auditable end to end.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PurpleResultStore:
    def __init__(self, db: Any):
        self.db = db

    async def record(
        self,
        *,
        campaign_id: str,
        technique_id: str,
        tactic: str | None = None,
        deconfliction_tag: str | None = None,
        executed: bool = False,
        execution_status: str = "simulated",
        detected: bool | None = None,
        detection_source: str | None = None,
        detection_simulated: bool = False,
        tuned: bool = False,
        deployment_id: str | None = None,
        session_id: str | None = None,
        engagement_id: str | None = None,
    ) -> dict:
        rid = "pr-" + uuid.uuid4().hex[:12]
        await self.db.execute(
            """INSERT INTO purple_results
               (id, campaign_id, technique_id, tactic, deconfliction_tag, executed,
                execution_status, detected, detection_source, detection_simulated,
                tuned, deployment_id, session_id, engagement_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (rid, campaign_id, technique_id, tactic, deconfliction_tag,
             1 if executed else 0, execution_status,
             (None if detected is None else (1 if detected else 0)),
             detection_source, 1 if detection_simulated else 0,
             1 if tuned else 0, deployment_id,
             session_id, engagement_id, _now()),
        )
        return await self.get(rid)

    async def get(self, result_id: str) -> dict | None:
        row = await self.db.fetch_one("SELECT * FROM purple_results WHERE id = ?", (result_id,))
        return self._decorate(row) if row else None

    async def list(self, campaign_id: str | None = None) -> list[dict]:
        if campaign_id:
            rows = await self.db.fetch_all(
                "SELECT * FROM purple_results WHERE campaign_id = ? ORDER BY created_at", (campaign_id,))
        else:
            rows = await self.db.fetch_all("SELECT * FROM purple_results ORDER BY created_at DESC")
        return [self._decorate(r) for r in rows]

    async def coverage(self, campaign_id: str) -> dict:
        """Compute measured coverage for a campaign, splitting REAL detection from
        SIMULATED (mock-deploy) coverage so the latter never inflates the real
        rate. Uses the LATEST result per technique (post-tuning wins).

        - ``coverage_percent``      : techniques with any covering rule (real or
                                      simulated) — "configured" coverage.
        - ``coverage_percent_real`` : techniques detected by a REAL control only.
        """
        rows = await self.list(campaign_id)
        latest: dict[str, dict] = {}
        for r in rows:  # ordered by created_at ascending → last write wins
            latest[r["technique_id"]] = r
        techniques = list(latest.values())
        executed = [t for t in techniques if t["executed"]]
        detected = [t for t in executed if t["detected"] is True]
        detected_real = [t for t in detected if not t.get("detection_simulated")]
        detected_sim = [t for t in detected if t.get("detection_simulated")]
        missed = [t for t in executed if t["detected"] is False]
        total = len(techniques)
        ne = len(executed)
        pct = round((len(detected) / ne) * 100.0, 1) if ne else 0.0
        pct_real = round((len(detected_real) / ne) * 100.0, 1) if ne else 0.0
        return {
            "campaign_id": campaign_id,
            "total_techniques": total,
            "executed": ne,
            "detected": len(detected),
            "detected_real": len(detected_real),
            "detected_simulated": len(detected_sim),
            "missed": len(missed),
            "coverage_percent": pct,
            "coverage_percent_real": pct_real,
            "simulated_coverage": len(detected_sim) > 0 and len(detected_real) < len(detected),
            "gaps": [t["technique_id"] for t in missed],
            "simulated_gaps": [t["technique_id"] for t in detected_sim],
            "techniques": techniques,
        }

    @staticmethod
    def _decorate(row: dict) -> dict:
        d = dict(row)
        d["executed"] = bool(d.get("executed"))
        d["tuned"] = bool(d.get("tuned"))
        d["detection_simulated"] = bool(d.get("detection_simulated"))
        det = d.get("detected")
        d["detected"] = None if det is None else bool(det)
        return d
