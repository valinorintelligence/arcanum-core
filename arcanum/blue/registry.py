"""Rollback registry for Blue Team actions (F2).

Every defensive change — a deployed detection rule, an applied hardening item, an
IR containment — is recorded here so it can be **verified** and **reversed**. This
is the backbone that lets `rollback` and the kill-switch undo real changes, and
that keeps `verify` honest (a rolled-back deployment is no longer active).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeploymentRegistry:
    """CRUD over ``blue_deployments`` — the single source of truth for what Blue
    Team has changed and whether it is still live."""

    def __init__(self, db: Any):
        self.db = db

    async def record(
        self,
        *,
        kind: str,
        target_system: str,
        rule_type: str | None = None,
        name: str | None = None,
        status: str = "active",
        mock: bool = False,
        reversible: bool = True,
        payload: dict | None = None,
        external_id: str | None = None,
        session_id: str | None = None,
        engagement_id: str | None = None,
    ) -> dict:
        did = "dep-" + uuid.uuid4().hex[:12]
        await self.db.execute(
            """INSERT INTO blue_deployments
               (id, kind, target_system, rule_type, name, status, mock, reversible,
                payload, external_id, session_id, engagement_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (did, kind, target_system, rule_type, name, status, 1 if mock else 0,
             1 if reversible else 0, json.dumps(payload or {}), external_id,
             session_id, engagement_id, _now()),
        )
        return await self.get(did)

    async def get(self, deployment_id: str) -> dict | None:
        row = await self.db.fetch_one("SELECT * FROM blue_deployments WHERE id = ?", (deployment_id,))
        return self._decorate(row) if row else None

    async def list(self, kind: str | None = None, status: str | None = None,
                   target_system: str | None = None) -> list[dict]:
        clauses, params = [], []
        if kind:
            clauses.append("kind = ?"); params.append(kind)
        if status:
            clauses.append("status = ?"); params.append(status)
        if target_system:
            clauses.append("target_system = ?"); params.append(target_system)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = await self.db.fetch_all(
            f"SELECT * FROM blue_deployments{where} ORDER BY created_at DESC", tuple(params))
        return [self._decorate(r) for r in rows]

    async def mark_verified(self, deployment_id: str, active: bool) -> None:
        await self.db.execute(
            "UPDATE blue_deployments SET verified_at = ? WHERE id = ?",
            (_now(), deployment_id))

    async def set_status(self, deployment_id: str, status: str) -> None:
        await self.db.execute(
            "UPDATE blue_deployments SET status = ? WHERE id = ?", (status, deployment_id))

    async def mark_rolled_back(self, deployment_id: str) -> bool:
        row = await self.get(deployment_id)
        if not row:
            return False
        await self.db.execute(
            "UPDATE blue_deployments SET status = 'rolled_back', rolled_back_at = ? WHERE id = ?",
            (_now(), deployment_id))
        return True

    @staticmethod
    def _decorate(row: dict) -> dict:
        d = dict(row)
        d["mock"] = bool(d.get("mock"))
        d["reversible"] = bool(d.get("reversible"))
        v = d.get("payload")
        if isinstance(v, str):
            try:
                d["payload"] = json.loads(v) if v else {}
            except Exception:
                d["payload"] = {}
        elif v is None:
            d["payload"] = {}
        return d
