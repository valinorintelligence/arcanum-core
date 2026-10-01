"""Session management for Arcanum operations with SQLite persistence."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


import re

_SESSION_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def validate_session_name(name: str) -> str:
    """Enforce a safe, filesystem-only session name. The name becomes a path
    component under ops_dir, so ``..`` / slashes / absolute paths are rejected
    (validated as directory traversal before this guard)."""
    name = (name or "").strip()
    if not _SESSION_NAME_RE.match(name) or name in (".", ".."):
        raise ValueError(
            "Invalid session name: use 1-64 chars of letters, digits, '.', '_' or '-'"
        )
    return name


def init_session_workspace(name: str, target: str = None, mode: str = "manual", scope: dict = None) -> Path:
    """Initialize workspace directories and episodic wiki templates."""
    from ..core.config import get_config
    name = validate_session_name(name)
    config = get_config()
    op_dir = config.ops_dir / name
    for subdir in ["workspace/wiki", "workspace/output", "workspace/tools", "workspace/evidence", "findings", "reports"]:
        (op_dir / subdir).mkdir(parents=True, exist_ok=True)

    wiki_dir = op_dir / "workspace" / "wiki"
    target_map = wiki_dir / "TARGET_MAP.md"
    if not target_map.exists():
        target_map.write_text(f"""# Target Map — Operation: {name}
- Target: {target or 'N/A'}
- Mode: {mode}
- Scope: {json.dumps(scope) if scope else 'All authorized assets'}

## Discovered Hosts & Ports
| Host / IP | Port | Service | Product / Version | Notes |
| :--- | :--- | :--- | :--- | :--- |
| {target or 'target'} | - | - | - | Initial Target |
""", encoding="utf-8")

    attack_surface = wiki_dir / "ATTACK_SURFACE.md"
    if not attack_surface.exists():
        attack_surface.write_text(f"""# Attack Surface — Operation: {name}

## Discovered Endpoints & Parameters
| URL / Endpoint | Method | Parameters | Auth Required | Status |
| :--- | :--- | :--- | :--- | :--- |

## Technologies Detected
- Target: {target or 'N/A'}
""", encoding="utf-8")

    operation_log = wiki_dir / "OPERATION_LOG.md"
    if not operation_log.exists():
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        operation_log.write_text(f"""# Operation Log — Operation: {name}

## Chronological Milestones
- [{now}] Operation initialized against target: {target or 'N/A'}.
""", encoding="utf-8")

    return op_dir


class SessionManager:
    """Create, retrieve, update, and delete operation sessions (persisted to SQLite)."""

    def __init__(self, db: Any):
        self.db = db

    def _generate_id(self) -> str:
        return f"op-{uuid.uuid4().hex[:12]}"

    async def create_session(
        self,
        name: str,
        target: str = None,
        mode: str = "manual",
        scope: dict = None,
    ) -> dict:
        name = validate_session_name(name)
        session_id = self._generate_id()
        now = datetime.now(timezone.utc).isoformat()
        await self.db.execute(
            """INSERT INTO sessions (id, name, target, mode, status, scope, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, name, target, mode, "created", json.dumps(scope) if scope else None, now, now),
        )
        # Initialize operation workspace & episodic wiki
        init_session_workspace(name=name, target=target, mode=mode, scope=scope)

        return {
            "id": session_id, "name": name, "target": target,
            "mode": mode, "status": "created", "scope": scope,
            "findings_count": 0, "created_at": now, "updated_at": now,
        }

    async def get_session(self, name: str) -> dict | None:
        row = await self.db.fetch_one("SELECT * FROM sessions WHERE name = ?", (name,))
        if not row:
            # Try by ID
            row = await self.db.fetch_one("SELECT * FROM sessions WHERE id = ?", (name,))
        return dict(row) if row else None

    async def list_sessions(self) -> list[dict]:
        rows = await self.db.fetch_all("SELECT * FROM sessions ORDER BY updated_at DESC")
        return [dict(r) for r in rows]

    async def update_session(self, name: str, **kwargs: Any) -> dict | None:
        session = await self.get_session(name)
        if not session:
            return None
        sets = []
        values = []
        for key, value in kwargs.items():
            if key in ("target", "mode", "status", "scope", "progress", "assets"):
                if key in ("scope", "progress", "assets") and isinstance(value, dict):
                    value = json.dumps(value)
                sets.append(f"{key} = ?")
                values.append(value)
        if sets:
            sets.append("updated_at = ?")
            values.append(datetime.now(timezone.utc).isoformat())
            values.append(session["id"])
            await self.db.execute(
                f"UPDATE sessions SET {', '.join(sets)} WHERE id = ?", tuple(values),
            )
        return await self.get_session(name)

    async def delete_session(self, name: str) -> bool:
        session = await self.get_session(name)
        if not session:
            return False
        await self.db.execute("DELETE FROM findings WHERE session_id = ?", (session["id"],))
        await self.db.execute("DELETE FROM sessions WHERE id = ?", (session["id"],))
        return True

    async def get_session_findings(self, session_id: str) -> list[dict]:
        rows = await self.db.fetch_all(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at DESC", (session_id,),
        )
        return [dict(r) for r in rows]
