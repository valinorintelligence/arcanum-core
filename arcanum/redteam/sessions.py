"""Registry of footholds / implants with guaranteed cleanup (F0).

Tracks every established access (foothold), implant, pivot and test account so
that nothing is ever left behind: :meth:`SessionRegistry.cleanup` marks all open
entries as cleaned at the end of an engagement (or on the global kill-switch).

F0 provides the *registry and cleanup bookkeeping* only — the actual creation of
footholds is the job of the governed offensive wrappers (F1/F4), which do not
exist yet. ``create_foothold`` is here so those wrappers have a safe home to
register into, and so the kill-switch has something to tear down.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionRegistry:
    """CRUD over ``redteam_sessions`` (footholds/implants) + cleanup."""

    def __init__(self, db: Any):
        self.db = db

    async def create_foothold(
        self,
        *,
        engagement_id: str | None,
        session_id: str | None = None,
        host: str | None = None,
        access_level: str = "user",
        implant_type: str = "shell",
        parent_id: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        fid = "fh-" + uuid.uuid4().hex[:12]
        await self.db.execute(
            """INSERT INTO redteam_sessions
               (id, engagement_id, session_id, host, access_level, implant_type,
                parent_id, status, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
            (fid, engagement_id, session_id, host, access_level, implant_type,
             parent_id, json.dumps(metadata or {}), _now()),
        )
        return await self.get(fid)

    async def get(self, foothold_id: str) -> dict | None:
        row = await self.db.fetch_one("SELECT * FROM redteam_sessions WHERE id = ?", (foothold_id,))
        return self._decorate(row) if row else None

    async def list(self, engagement_id: str | None = None, status: str | None = "open") -> list[dict]:
        clauses, params = [], []
        if engagement_id:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = await self.db.fetch_all(
            f"SELECT * FROM redteam_sessions{where} ORDER BY created_at DESC", tuple(params))
        return [self._decorate(r) for r in rows]

    async def close(self, foothold_id: str, status: str = "closed") -> bool:
        row = await self.get(foothold_id)
        if not row:
            return False
        await self.db.execute(
            "UPDATE redteam_sessions SET status = ?, closed_at = ? WHERE id = ?",
            (status, _now(), foothold_id))
        return True

    async def cleanup(self, engagement_id: str | None = None) -> dict:
        """Mark every open foothold/implant as 'cleaned' (cleanup obligation).

        Returns ``{"cleaned": n, "ids": [...]}``. With ``engagement_id=None`` it
        cleans *all* open entries (used by the global kill-switch).
        """
        open_rows = await self.list(engagement_id=engagement_id, status="open")
        ids = [r["id"] for r in open_rows]
        now = _now()
        for fid in ids:
            await self.db.execute(
                "UPDATE redteam_sessions SET status = 'cleaned', closed_at = ? WHERE id = ?",
                (now, fid))
        return {"cleaned": len(ids), "ids": ids}

    @staticmethod
    def _decorate(row: dict) -> dict:
        d = dict(row)
        v = d.get("metadata")
        if isinstance(v, str):
            try:
                d["metadata"] = json.loads(v) if v else {}
            except Exception:
                d["metadata"] = {}
        elif v is None:
            d["metadata"] = {}
        return d
