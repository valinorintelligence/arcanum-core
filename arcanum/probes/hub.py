"""Arcanum Probe Hub Manager.

Coordinates distributed Satellite Probes, manages task queues, handles
heartbeats, and routes assessment jobs to target network segments.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from arcanum.core.database import Database

logger = logging.getLogger(__name__)

OFFLINE_THRESHOLD_SECONDS = 180


class ProbeHubManager:
    """Manages distributed Satellite Probes and their remote task dispatch queues."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def init_tables(self) -> None:
        """Ensures probe and task tables exist in the database."""
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS satellite_probes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                hostname TEXT,
                ip_address TEXT,
                status TEXT DEFAULT 'online',
                tags TEXT,
                capabilities TEXT,
                version TEXT DEFAULT '3.0.0',
                last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
                registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS probe_tasks (
                id TEXT PRIMARY KEY,
                probe_id TEXT NOT NULL,
                session_id TEXT,
                tool_name TEXT NOT NULL,
                arguments TEXT,
                status TEXT DEFAULT 'pending',
                result TEXT,
                error TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                assigned_at DATETIME,
                completed_at DATETIME,
                FOREIGN KEY (probe_id) REFERENCES satellite_probes(id) ON DELETE CASCADE
            )"""
        )
        await self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_probe_tasks_probe ON probe_tasks(probe_id, status)"
        )

    async def register_probe(
        self,
        name: str,
        hostname: str = "",
        ip_address: str = "",
        tags: list[str] | None = None,
        capabilities: list[str] | None = None,
        probe_id: str | None = None,
        version: str = "3.0.0",
    ) -> dict[str, Any]:
        """Registers or updates a satellite probe."""
        await self.init_tables()
        pid = probe_id or f"probe-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        tags_json = json.dumps(tags or ["internal"])
        caps_json = json.dumps(capabilities or ["all"])

        await self.db.execute(
            """INSERT OR REPLACE INTO satellite_probes
               (id, name, hostname, ip_address, status, tags, capabilities, version, last_heartbeat, registered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                pid,
                name,
                hostname,
                ip_address,
                "online",
                tags_json,
                caps_json,
                version,
                now_iso,
                now_iso,
            ),
        )

        return {
            "probe_id": pid,
            "name": name,
            "hostname": hostname,
            "ip_address": ip_address,
            "status": "online",
            "tags": tags or ["internal"],
            "capabilities": capabilities or ["all"],
            "version": version,
            "registered_at": now_iso,
        }

    async def heartbeat(self, probe_id: str, status: str = "online") -> dict[str, Any]:
        """Records a heartbeat from an active satellite probe."""
        await self.init_tables()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = await self.db.execute(
            "UPDATE satellite_probes SET status = ?, last_heartbeat = ? WHERE id = ?",
            (status, now_iso, probe_id),
        )
        if cursor.rowcount == 0:
            return {"success": False, "error": f"Probe '{probe_id}' not found"}

        return {
            "success": True,
            "probe_id": probe_id,
            "status": status,
            "last_heartbeat": now_iso,
        }

    async def list_probes(self, tag: str | None = None) -> list[dict[str, Any]]:
        """Lists registered satellite probes with dynamic online/offline resolution."""
        await self.init_tables()
        cursor = await self.db.execute(
            "SELECT id, name, hostname, ip_address, status, tags, capabilities, version, last_heartbeat, registered_at FROM satellite_probes ORDER BY registered_at DESC"
        )
        rows = await cursor.fetchall()
        now = datetime.now(timezone.utc)
        result = []

        for r in rows:
            p = dict(r)
            try:
                p["tags"] = json.loads(p.get("tags") or "[]")
            except Exception:
                p["tags"] = []

            try:
                p["capabilities"] = json.loads(p.get("capabilities") or "[]")
            except Exception:
                p["capabilities"] = []

            # Check heartbeat staleness
            last_hb_str = p.get("last_heartbeat")
            if last_hb_str:
                try:
                    last_hb = datetime.fromisoformat(last_hb_str.replace("Z", "+00:00"))
                    if (now - last_hb).total_seconds() > OFFLINE_THRESHOLD_SECONDS:
                        p["status"] = "offline"
                except Exception:
                    pass

            if tag:
                if tag.lower() not in [t.lower() for t in p["tags"]]:
                    continue

            result.append(p)

        return result

    async def get_probe(self, probe_id: str) -> dict[str, Any] | None:
        """Retrieves a single probe by ID."""
        await self.init_tables()
        cursor = await self.db.execute(
            "SELECT id, name, hostname, ip_address, status, tags, capabilities, version, last_heartbeat, registered_at FROM satellite_probes WHERE id = ?",
            (probe_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        p = dict(row)
        try:
            p["tags"] = json.loads(p.get("tags") or "[]")
            p["capabilities"] = json.loads(p.get("capabilities") or "[]")
        except Exception:
            pass
        return p

    async def deregister_probe(self, probe_id: str) -> bool:
        """Removes a satellite probe."""
        await self.init_tables()
        cursor = await self.db.execute("DELETE FROM satellite_probes WHERE id = ?", (probe_id,))
        return cursor.rowcount > 0

    async def find_probe_by_tag(self, tag: str) -> dict[str, Any] | None:
        """Finds the first available online probe carrying a specific tag."""
        probes = await self.list_probes(tag=tag)
        for p in probes:
            if p["status"] == "online":
                return p
        return probes[0] if probes else None

    # -------------------------------------------------------------------------
    # Task Queue Management
    # -------------------------------------------------------------------------

    async def dispatch_task(
        self,
        probe_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str = "",
    ) -> dict[str, Any]:
        """Dispatches an assessment tool job to a satellite probe queue."""
        await self.init_tables()
        probe = await self.get_probe(probe_id)
        if not probe:
            raise ValueError(f"Target probe '{probe_id}' is not registered.")

        task_id = f"ptask-{uuid.uuid4().hex[:10]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        await self.db.execute(
            """INSERT INTO probe_tasks
               (id, probe_id, session_id, tool_name, arguments, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                task_id,
                probe_id,
                session_id,
                tool_name,
                json.dumps(arguments),
                "pending",
                now_iso,
            ),
        )

        return {
            "task_id": task_id,
            "probe_id": probe_id,
            "session_id": session_id,
            "tool_name": tool_name,
            "status": "pending",
            "created_at": now_iso,
        }

    async def poll_tasks(self, probe_id: str, limit: int = 5) -> list[dict[str, Any]]:
        """Satellite probe pulls pending tasks assigned to it, marking them as assigned."""
        await self.init_tables()
        cursor = await self.db.execute(
            """SELECT id, probe_id, session_id, tool_name, arguments, status, created_at
               FROM probe_tasks
               WHERE probe_id = ? AND status = 'pending'
               ORDER BY created_at ASC LIMIT ?""",
            (probe_id, limit),
        )
        rows = await cursor.fetchall()
        now_iso = datetime.now(timezone.utc).isoformat()
        tasks = []

        for r in rows:
            t = dict(r)
            try:
                t["arguments"] = json.loads(t.get("arguments") or "{}")
            except Exception:
                t["arguments"] = {}

            # Mark assigned
            await self.db.execute(
                "UPDATE probe_tasks SET status = 'assigned', assigned_at = ? WHERE id = ?",
                (now_iso, t["id"]),
            )
            t["status"] = "assigned"
            tasks.append(t)

        return tasks

    async def submit_task_result(
        self,
        task_id: str,
        probe_id: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Saves remote execution result submitted by satellite probe."""
        await self.init_tables()
        now_iso = datetime.now(timezone.utc).isoformat()
        status = "failed" if error else "completed"

        cursor = await self.db.execute(
            """UPDATE probe_tasks
               SET status = ?, result = ?, error = ?, completed_at = ?
               WHERE id = ? AND probe_id = ?""",
            (
                status,
                json.dumps(result or {}),
                error,
                now_iso,
                task_id,
                probe_id,
            ),
        )

        if cursor.rowcount == 0:
            return {"success": False, "error": f"Task '{task_id}' for probe '{probe_id}' not found"}

        return {
            "success": True,
            "task_id": task_id,
            "probe_id": probe_id,
            "status": status,
            "completed_at": now_iso,
        }

    async def get_task(self, task_id: str) -> dict[str, Any] | None:
        """Retrieves task details and its execution result."""
        await self.init_tables()
        cursor = await self.db.execute(
            """SELECT id, probe_id, session_id, tool_name, arguments, status,
                      result, error, created_at, assigned_at, completed_at
               FROM probe_tasks WHERE id = ?""",
            (task_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        t = dict(row)
        try:
            t["arguments"] = json.loads(t.get("arguments") or "{}")
            t["result"] = json.loads(t.get("result") or "{}")
        except Exception:
            pass
        return t
