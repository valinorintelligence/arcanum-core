"""Registry of footholds / implants with guaranteed cleanup (F0).

Tracks every established access (foothold), implant, pivot and test account so
that nothing is ever left behind: :meth:`SessionRegistry.cleanup` marks all open
entries as cleaned at the end of an engagement (or on the global kill-switch).

``create_foothold`` records an optional **teardown recipe** (the commands/steps
that remove the implant or persistence). :meth:`SessionRegistry.cleanup` then
*executes* that recipe through a provided executor (the sandbox) so cleanup is a
real teardown, not just a status flip (follow-up #5). Honesty rule: a foothold
that HAS a teardown recipe but is given NO executor is left ``cleanup_pending``
(never silently marked cleaned); a teardown whose commands fail is left
``cleanup_failed`` and stays visible so it is not forgotten. A foothold with no
recipe is bookkeeping-only and marked ``cleaned``.

F0 provides the registry + cleanup machinery; the actual creation of footholds is
the job of the governed offensive wrappers (F1/F4), which register here with their
teardown recipe so the kill-switch has something concrete to tear down.
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
        teardown_recipe: list[str] | None = None,
    ) -> dict:
        """Register a foothold/implant. ``teardown_recipe`` is the ordered list of
        shell commands that remove it (e.g. delete a webshell, remove a cron entry,
        kill a listener); it is stored in metadata and executed by :meth:`cleanup`."""
        fid = "fh-" + uuid.uuid4().hex[:12]
        meta = dict(metadata or {})
        if teardown_recipe:
            # Keep only non-empty string commands (defensive).
            meta["teardown_recipe"] = [str(c) for c in teardown_recipe if str(c).strip()]
        await self.db.execute(
            """INSERT INTO redteam_sessions
               (id, engagement_id, session_id, host, access_level, implant_type,
                parent_id, status, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
            (fid, engagement_id, session_id, host, access_level, implant_type,
             parent_id, json.dumps(meta), _now()),
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

    async def cleanup(self, engagement_id: str | None = None, executor: Any = None) -> dict:
        """Tear down every open foothold/implant (cleanup obligation).

        For each open foothold:
          * **no teardown recipe** → bookkeeping only → ``status='cleaned'``.
          * **recipe + executor** → run the recipe through ``executor``; all steps OK
            → ``status='cleaned'``; any step fails → ``status='cleanup_failed'``
            (kept visible, NOT marked cleaned).
          * **recipe + no executor** → cannot really remove it → ``status='cleanup_pending'``
            (honest: never flipped to 'cleaned' without actually tearing down).

        ``executor`` is any object exposing async ``execute_tool(tool, args)`` (the
        sandbox tool executor) or an async callable ``executor(command)->result``.
        With ``engagement_id=None`` it cleans *all* open entries (global kill-switch).

        Returns ``{"cleaned": n, "pending": [...], "failed": [...], "ids": [...],
        "results": [per-foothold outcome]}``.

        Re-running cleanup also retries footholds left ``cleanup_pending`` or
        ``cleanup_failed`` by a previous pass, so nothing stays stranded.
        """
        clauses = ["status IN ('open', 'cleanup_pending', 'cleanup_failed')"]
        params: list[Any] = []
        if engagement_id:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        rows = await self.db.fetch_all(
            f"SELECT * FROM redteam_sessions WHERE {' AND '.join(clauses)} ORDER BY created_at DESC",
            tuple(params))
        open_rows = [self._decorate(r) for r in rows]
        now = _now()
        cleaned, pending, failed, results = [], [], [], []
        for row in open_rows:
            fid = row["id"]
            recipe = (row.get("metadata") or {}).get("teardown_recipe") or []
            if not recipe:
                await self.db.execute(
                    "UPDATE redteam_sessions SET status = 'cleaned', closed_at = ? WHERE id = ?",
                    (now, fid))
                cleaned.append(fid)
                results.append({"id": fid, "teardown": "none"})
                continue
            if executor is None:
                # Honest: there is real teardown to do but no way to do it now.
                await self.db.execute(
                    "UPDATE redteam_sessions SET status = 'cleanup_pending' WHERE id = ?",
                    (fid,))
                pending.append(fid)
                results.append({"id": fid, "teardown": "skipped_no_executor",
                                "steps": len(recipe)})
                continue
            errors = await self._run_teardown(executor, recipe)
            if errors:
                await self.db.execute(
                    "UPDATE redteam_sessions SET status = 'cleanup_failed' WHERE id = ?",
                    (fid,))
                failed.append(fid)
                results.append({"id": fid, "teardown": "failed", "errors": errors})
            else:
                await self.db.execute(
                    "UPDATE redteam_sessions SET status = 'cleaned', closed_at = ? WHERE id = ?",
                    (now, fid))
                cleaned.append(fid)
                results.append({"id": fid, "teardown": "executed", "steps": len(recipe)})
        return {
            "cleaned": len(cleaned), "pending": pending, "failed": failed,
            "ids": cleaned + pending + failed, "results": results,
        }

    @staticmethod
    async def _run_teardown(executor: Any, recipe: list[str]) -> list[str]:
        """Run each teardown command through the executor. Returns a list of error
        strings (empty = all succeeded). Any exception or non-success result is an
        error, so a foothold is only marked cleaned when every step truly succeeded."""
        errors: list[str] = []
        for cmd in recipe:
            try:
                if hasattr(executor, "execute_tool"):
                    res = await executor.execute_tool("execute", {"command": cmd})
                elif callable(executor):
                    res = await executor(cmd)
                else:
                    errors.append(f"{cmd}: executor não suporta execução")
                    continue
                # Treat the standard {"success": bool, ...} envelope as authoritative;
                # absence of an explicit success flag is treated as success only when
                # there is no error field.
                if isinstance(res, dict):
                    ok = res.get("success", res.get("error") is None)
                    if not ok:
                        errors.append(f"{cmd}: {res.get('error') or 'falhou'}")
            except Exception as exc:
                errors.append(f"{cmd}: {exc}")
        return errors

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
