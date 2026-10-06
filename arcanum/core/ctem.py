"""Continuous Threat Exposure Management (CTEM) Daemon.

Performs 24/7 continuous attack surface monitoring, automated re-testing cycles,
drift calculation, and triggerable SOAR alerts when critical regressions occur.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import uuid

from arcanum.core.database import Database
from arcanum.core.drift import ExposureDrift
from arcanum.core.kev import CISAKEVEngine
from arcanum.core.retest import RetestEngine

logger = logging.getLogger(__name__)


class CTEMDaemon:
    """Daemon for Continuous Threat Exposure Management (CTEM) operations."""

    def __init__(
        self,
        db: Database,
        kev_engine: CISAKEVEngine | None = None,
        retest_engine: RetestEngine | None = None,
        enterprise_hub: Any | None = None,
        check_interval_seconds: int = 60,
    ) -> None:
        self.db = db
        self.kev_engine = kev_engine or CISAKEVEngine(db=db)
        self.retest_engine = retest_engine or RetestEngine(db=db)
        self.enterprise_hub = enterprise_hub
        self.check_interval_seconds = check_interval_seconds
        self._running = False
        self._task: asyncio.Task | None = None

    async def init_tables(self) -> None:
        """Initializes tables for CTEM schedules and execution history."""
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS ctem_schedules (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                target TEXT NOT NULL,
                frequency_minutes INTEGER DEFAULT 1440,
                status TEXT DEFAULT 'active',
                last_run_at DATETIME,
                next_run_at DATETIME,
                total_runs INTEGER DEFAULT 0,
                last_drift_summary TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )"""
        )
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS ctem_run_logs (
                id TEXT PRIMARY KEY,
                schedule_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                executed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                retested_count INTEGER DEFAULT 0,
                remediated_count INTEGER DEFAULT 0,
                regressed_count INTEGER DEFAULT 0,
                kev_alert_count INTEGER DEFAULT 0,
                drift_score REAL DEFAULT 0.0,
                status TEXT DEFAULT 'success',
                details TEXT,
                FOREIGN KEY (schedule_id) REFERENCES ctem_schedules(id) ON DELETE CASCADE
            )"""
        )

    async def create_schedule(
        self,
        session_id: str,
        target: str,
        frequency_minutes: int = 1440,
    ) -> dict[str, Any]:
        """Creates a continuous exposure monitoring schedule for a target."""
        await self.init_tables()
        schedule_id = f"ctem-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)
        next_run = now + timedelta(minutes=frequency_minutes)

        await self.db.execute(
            """INSERT INTO ctem_schedules
               (id, session_id, target, frequency_minutes, status, next_run_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                schedule_id,
                session_id,
                target,
                frequency_minutes,
                "active",
                next_run.isoformat(),
                now.isoformat(),
                now.isoformat(),
            ),
        )

        return {
            "schedule_id": schedule_id,
            "session_id": session_id,
            "target": target,
            "frequency_minutes": frequency_minutes,
            "status": "active",
            "next_run_at": next_run.isoformat(),
        }

    async def list_schedules(self) -> list[dict[str, Any]]:
        """Lists all configured CTEM continuous monitoring schedules."""
        await self.init_tables()
        cursor = await self.db.execute(
            """SELECT id, session_id, target, frequency_minutes, status,
                      last_run_at, next_run_at, total_runs, last_drift_summary, created_at
               FROM ctem_schedules ORDER BY created_at DESC"""
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_schedule(self, schedule_id: str) -> dict[str, Any] | None:
        """Retrieves a single CTEM schedule by ID."""
        await self.init_tables()
        cursor = await self.db.execute(
            """SELECT id, session_id, target, frequency_minutes, status,
                      last_run_at, next_run_at, total_runs, last_drift_summary, created_at
               FROM ctem_schedules WHERE id = ?""",
            (schedule_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def delete_schedule(self, schedule_id: str) -> bool:
        """Deletes a CTEM schedule."""
        await self.init_tables()
        cursor = await self.db.execute("DELETE FROM ctem_schedules WHERE id = ?", (schedule_id,))
        return cursor.rowcount > 0

    async def update_schedule_status(self, schedule_id: str, status: str) -> bool:
        """Pauses or resumes a schedule ('active' or 'paused')."""
        await self.init_tables()
        cursor = await self.db.execute(
            "UPDATE ctem_schedules SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (status, schedule_id),
        )
        return cursor.rowcount > 0

    async def run_assessment_cycle(self, schedule_id: str) -> dict[str, Any]:
        """Executes a single CTEM verification cycle for a schedule."""
        await self.init_tables()
        sched = await self.get_schedule(schedule_id)
        if not sched:
            raise ValueError(f"Schedule '{schedule_id}' not found.")

        session_id = sched["session_id"]
        target = sched["target"]
        now = datetime.now(timezone.utc)

        # 1. Fetch all findings in this session
        cursor = await self.db.execute(
            "SELECT id, title, severity, status, cve_id, retest_tool, retest_arguments FROM findings WHERE session_id = ?",
            (session_id,),
        )
        findings_rows = await cursor.fetchall()

        retested_count = 0
        remediated_count = 0
        regressed_count = 0
        kev_alerts = 0

        # 2. Closed-Loop Retest of findings
        for f in findings_rows:
            f_dict = dict(f)
            fid = f_dict["id"]
            cve = f_dict.get("cve_id")

            # Check CISA KEV status
            if cve and await self.kev_engine.is_cisa_kev(cve):
                kev_alerts += 1

            # If retest tool is available, re-test surgically
            if f_dict.get("retest_tool"):
                try:
                    res = await self.retest_engine.retest_finding(fid)
                    retested_count += 1
                    status = res.get("status")
                    if status == "remediated":
                        remediated_count += 1
                    elif status == "regressed":
                        regressed_count += 1
                        # Broadcast critical regression to SOAR if hub is wired
                        if self.enterprise_hub:
                            await self.enterprise_hub.broadcast_finding(
                                finding=res["finding"],
                                session_name=session_id,
                                channels=["siem", "slack"],
                            )
                except Exception as e:
                    logger.warning(f"CTEM re-test error on finding {fid}: {e}")

        # 3. Calculate Exposure Drift for session
        drift_engine = ExposureDrift(db=self.db)
        drift_report = await drift_engine.calculate_drift(session_id, session_id)

        # 4. Schedule next run time
        freq = sched["frequency_minutes"] or 1440
        next_run = now + timedelta(minutes=freq)
        total_runs = (sched["total_runs"] or 0) + 1

        summary_text = (
            f"Retested: {retested_count} | Remediated: {remediated_count} | "
            f"Regressed: {regressed_count} | CISA KEV Active: {kev_alerts}"
        )

        await self.db.execute(
            """UPDATE ctem_schedules
               SET last_run_at = ?, next_run_at = ?, total_runs = ?, last_drift_summary = ?, updated_at = ?
               WHERE id = ?""",
            (
                now.isoformat(),
                next_run.isoformat(),
                total_runs,
                summary_text,
                now.isoformat(),
                schedule_id,
            ),
        )

        # 5. Record run log
        log_id = f"run-{uuid.uuid4().hex[:8]}"
        await self.db.execute(
            """INSERT INTO ctem_run_logs
               (id, schedule_id, session_id, executed_at, retested_count, remediated_count,
                regressed_count, kev_alert_count, drift_score, status, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                log_id,
                schedule_id,
                session_id,
                now.isoformat(),
                retested_count,
                remediated_count,
                regressed_count,
                kev_alerts,
                drift_report.get("net_risk_reduction_score", 0.0),
                "success",
                summary_text,
            ),
        )

        return {
            "schedule_id": schedule_id,
            "session_id": session_id,
            "target": target,
            "executed_at": now.isoformat(),
            "next_run_at": next_run.isoformat(),
            "total_runs": total_runs,
            "retested_count": retested_count,
            "remediated_count": remediated_count,
            "regressed_count": regressed_count,
            "kev_alert_count": kev_alerts,
            "summary": summary_text,
            "drift": drift_report,
        }

    async def run_due_schedules(self) -> int:
        """Finds all active schedules where next_run_at <= now, and runs them."""
        await self.init_tables()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = await self.db.execute(
            "SELECT id FROM ctem_schedules WHERE status = 'active' AND (next_run_at IS NULL OR next_run_at <= ?)",
            (now_iso,),
        )
        due_rows = await cursor.fetchall()
        executed = 0
        for row in due_rows:
            try:
                await self.run_assessment_cycle(row["id"])
                executed += 1
            except Exception as e:
                logger.error(f"Error running CTEM schedule {row['id']}: {e}")
        return executed

    # -- Purple campaign scheduling (F3 c) ----------------------------------

    async def init_purple_tables(self) -> None:
        """Table for recurring Purple campaigns (continuous coverage measurement)."""
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS ctem_purple_schedules (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                techniques TEXT NOT NULL,        -- JSON list of ATT&CK technique ids
                frequency_minutes INTEGER DEFAULT 1440,
                auto_tune INTEGER DEFAULT 1,
                status TEXT DEFAULT 'active',
                last_run_at DATETIME,
                next_run_at DATETIME,
                total_runs INTEGER DEFAULT 0,
                last_campaign_id TEXT,
                last_coverage TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )

    async def create_purple_schedule(self, techniques, frequency_minutes: int = 1440,
                                      session_id: str | None = None,
                                      auto_tune: bool = True) -> dict[str, Any]:
        """Schedule a recurring Purple campaign. Runs UNATTENDED, so it measures
        coverage via simulation (no sandbox/atomics) — never launches real attacks."""
        import json as _json
        await self.init_purple_tables()
        if isinstance(techniques, str):
            techniques = [t.strip() for t in techniques.replace(";", ",").split(",") if t.strip()]
        if not techniques:
            raise ValueError("techniques required (list of ATT&CK ids, e.g. ['T1190','T1059.001'])")
        sid = f"pcs-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)
        nxt = now + timedelta(minutes=frequency_minutes)
        await self.db.execute(
            """INSERT INTO ctem_purple_schedules
               (id, session_id, techniques, frequency_minutes, auto_tune, status, next_run_at, created_at)
               VALUES (?, ?, ?, ?, ?, 'active', ?, ?)""",
            (sid, session_id, _json.dumps(techniques), frequency_minutes,
             1 if auto_tune else 0, nxt.isoformat(), now.isoformat()))
        return {"schedule_id": sid, "techniques": techniques, "frequency_minutes": frequency_minutes,
                "auto_tune": bool(auto_tune), "status": "active", "next_run_at": nxt.isoformat()}

    async def list_purple_schedules(self) -> list[dict[str, Any]]:
        import json as _json
        await self.init_purple_tables()
        cursor = await self.db.execute(
            "SELECT * FROM ctem_purple_schedules ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["techniques"] = _json.loads(d.get("techniques") or "[]")
            except Exception:
                d["techniques"] = []
            d["auto_tune"] = bool(d.get("auto_tune"))
            if d.get("last_coverage"):
                try:
                    d["last_coverage"] = _json.loads(d["last_coverage"])
                except Exception:
                    pass
            out.append(d)
        return out

    async def run_purple_schedule(self, schedule_id: str) -> dict[str, Any]:
        """Run one scheduled Purple campaign (simulation/measurement, unattended)."""
        import json as _json
        await self.init_purple_tables()
        row = await self.db.fetch_one(
            "SELECT * FROM ctem_purple_schedules WHERE id = ?", (schedule_id,))
        if not row:
            return {"error": "schedule not found", "schedule_id": schedule_id}
        techniques = _json.loads(row["techniques"] or "[]")
        auto_tune = bool(row["auto_tune"])
        from arcanum.purple.campaign import PurpleCampaign
        try:
            from arcanum.core.config import get_config
            cfg = get_config()
        except Exception:
            cfg = None
        # Unattended ⇒ simulation only (sandbox=None, no atomics): measures detection
        # coverage from deployed rules over time; never runs real attacks on a schedule.
        camp = PurpleCampaign(self.db, config=cfg, sandbox=None, session_id=row["session_id"])
        result = await camp.run(techniques, auto_tune=auto_tune)
        cov = result.get("coverage", {}) or {}
        now = datetime.now(timezone.utc)
        nxt = now + timedelta(minutes=int(row["frequency_minutes"] or 1440))
        await self.db.execute(
            """UPDATE ctem_purple_schedules SET last_run_at=?, next_run_at=?,
               total_runs=total_runs+1, last_campaign_id=?, last_coverage=? WHERE id=?""",
            (now.isoformat(), nxt.isoformat(), result.get("campaign_id"),
             _json.dumps({"coverage_percent": cov.get("coverage_percent"),
                          "coverage_percent_real": cov.get("coverage_percent_real"),
                          "prevention_percent_real": cov.get("prevention_percent_real")}),
             schedule_id))
        return {"schedule_id": schedule_id, "campaign_id": result.get("campaign_id"),
                "coverage": cov, "next_run_at": nxt.isoformat()}

    async def run_due_purple_schedules(self) -> int:
        await self.init_purple_tables()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = await self.db.execute(
            "SELECT id FROM ctem_purple_schedules WHERE status='active' "
            "AND (next_run_at IS NULL OR next_run_at <= ?)", (now_iso,))
        due = await cursor.fetchall()
        executed = 0
        for row in due:
            try:
                await self.run_purple_schedule(row["id"])
                executed += 1
            except Exception as e:
                logger.error(f"Error running purple schedule {row['id']}: {e}")
        return executed

    async def _daemon_loop(self) -> None:
        """Internal background loop checking for due schedules."""
        logger.info("CTEM Daemon background worker started.")
        while self._running:
            try:
                await self.run_due_schedules()
                await self.run_due_purple_schedules()
            except Exception as e:
                logger.error(f"CTEM daemon tick error: {e}")
            await asyncio.sleep(self.check_interval_seconds)

    def start(self) -> None:
        """Starts the CTEM background daemon."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._daemon_loop())

    async def stop(self) -> None:
        """Stops the CTEM background daemon."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        logger.info("CTEM Daemon background worker stopped.")
