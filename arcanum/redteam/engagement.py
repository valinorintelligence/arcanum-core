"""Engagement / Rules-of-Engagement (ROE) management (F0).

An engagement is the signed authorization contract that makes real actions
legal: it declares the **scope** (hosts/CIDRs), the **time window**, and the
**allowed action classes**. Every offensive/active action is checked against the
active engagement *deterministically* before it runs.

Backward-compatibility invariant (roadmap §10): when **no** engagement is active
for a session, class-based blocking is a no-op — the platform keeps its current
behavior (operator-driven, with the existing deterministic scope enforcement in
the engine still applying). An engagement only ever *restricts* further.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .action_classes import ActionClass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        s = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _norm_class(c: Any) -> str:
    """Normalize an action class (enum or string) to its string value."""
    if isinstance(c, ActionClass):
        return c.value
    return str(c or "").strip().lower()


def deconfliction_tag(engagement_id: str) -> str:
    """Stable tag stamped on every action so the Blue team can distinguish
    Arcanum activity from a real attacker (essential for Purple)."""
    return "ARC-" + (engagement_id or "none")[:8].upper()


class EngagementManager:
    """CRUD + authorization checks over the ``engagements`` table."""

    def __init__(self, db: Any):
        self.db = db

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def compute_roe_hash(name: str, scope: list, allowed_classes: list,
                         window_start: Any, window_end: Any, auto_approve: bool = False) -> str:
        """Deterministic hash of the ROE contract (tamper-evidence). ``auto_approve``
        is part of the contract (it waives the per-action HITL pause), so it is covered."""
        payload = json.dumps(
            {
                "name": name or "",
                "scope": sorted([str(s).lower() for s in (scope or [])]),
                "allowed_classes": sorted([_norm_class(c) for c in (allowed_classes or [])]),
                "window_start": str(window_start or ""),
                "window_end": str(window_end or ""),
                "auto_approve": bool(auto_approve),
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # -- CRUD ---------------------------------------------------------------

    async def create(
        self,
        name: str,
        scope: list | None = None,
        allowed_classes: list | None = None,
        window: tuple | dict | None = None,
        session_id: str | None = None,
        operator: str | None = None,
        auto_approve: bool = False,
    ) -> dict:
        """Create (and activate) an engagement, returning its row as a dict.

        ``auto_approve=True`` marks a full-scope LAB ROE: the signed engagement
        pre-authorizes its allowed classes, so the engine waives the per-action HITL
        pause (audit/scope/cleanup/deconfliction still apply). Only for a lab the
        operator owns; DESTRUCTIVE additionally requires ``allow_destructive_testing``."""
        scope = [str(s).strip() for s in (scope or []) if str(s).strip()]
        # Default to the two non-offensive classes if unspecified (safe baseline).
        classes = [_norm_class(c) for c in (allowed_classes or [ActionClass.PASSIVE, ActionClass.ACTIVE])]
        classes = [c for c in classes if c]

        window_start = window_end = None
        if isinstance(window, dict):
            window_start, window_end = window.get("start"), window.get("end")
        elif isinstance(window, (tuple, list)) and len(window) == 2:
            window_start, window_end = window[0], window[1]

        ws = _parse_dt(window_start)
        we = _parse_dt(window_end)
        eid = "eng-" + uuid.uuid4().hex[:12]
        roe_hash = self.compute_roe_hash(
            name, scope, classes, ws.isoformat() if ws else "", we.isoformat() if we else "",
            auto_approve=bool(auto_approve))
        now = _now().isoformat()

        await self.db.execute(
            """INSERT INTO engagements
               (id, name, session_id, scope, allowed_classes, window_start, window_end,
                roe_hash, status, operator, auto_approve, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
            (
                eid, name, session_id, json.dumps(scope), json.dumps(classes),
                ws.isoformat() if ws else None, we.isoformat() if we else None,
                roe_hash, operator, 1 if auto_approve else 0, now,
            ),
        )
        return await self.get(eid)

    async def create_lab_preset(
        self,
        name: str,
        scope: list,
        window: tuple | dict | None = None,
        session_id: str | None = None,
        operator: str | None = None,
        auto_approve: bool = True,
        include_destructive: bool = False,
    ) -> dict:
        """Full-scope LAB ROE preset: pre-authorizes ALL non-destructive classes
        (PASSIVE→POST_EXPLOIT) — plus DESTRUCTIVE when ``include_destructive`` — for a
        scope the operator owns, with ``auto_approve`` so the engagement itself is the
        authorization (no per-action human pause). **Scope is REQUIRED** so this can
        never pre-authorize the whole internet. The rails stay: every action is still
        audited, scope-enforced, deconflicted and reversible, and DESTRUCTIVE still
        honors ``allow_destructive_testing``.
        """
        scope = [str(s).strip() for s in (scope or []) if str(s).strip()]
        if not scope:
            raise ValueError("create_lab_preset requires an explicit scope (your authorized lab) — "
                             "a full-scope preset must never be unscoped.")
        classes = [ActionClass.PASSIVE, ActionClass.ACTIVE, ActionClass.EXPLOIT,
                   ActionClass.POST_EXPLOIT]
        if include_destructive:
            classes.append(ActionClass.DESTRUCTIVE)
        return await self.create(
            name=name, scope=scope, allowed_classes=classes, window=window,
            session_id=session_id, operator=operator, auto_approve=auto_approve)

    async def get(self, engagement_id: str) -> dict | None:
        row = await self.db.fetch_one("SELECT * FROM engagements WHERE id = ?", (engagement_id,))
        return self._decorate(row) if row else None

    async def list(self, status: str | None = None) -> list[dict]:
        if status:
            rows = await self.db.fetch_all(
                "SELECT * FROM engagements WHERE status = ? ORDER BY created_at DESC", (status,))
        else:
            rows = await self.db.fetch_all(
                "SELECT * FROM engagements ORDER BY created_at DESC")
        return [self._decorate(r) for r in rows]

    async def active_for(self, session_id: str | None = None) -> dict | None:
        """Return the active, non-expired engagement for a session.

        Prefers a session-specific engagement; falls back to a global one
        (``session_id IS NULL``). Returns None when nothing applies (legacy mode).
        """
        rows = await self.db.fetch_all(
            "SELECT * FROM engagements WHERE status = 'active' ORDER BY created_at DESC")
        candidates = [self._decorate(r) for r in rows]
        # non-expired only
        live = [e for e in candidates if not self.is_expired(e)]
        if session_id:
            for e in live:
                if e.get("session_id") == session_id:
                    return e
        for e in live:
            if not e.get("session_id"):
                return e
        return None

    async def close(self, engagement_id: str) -> bool:
        eng = await self.get(engagement_id)
        if not eng:
            return False
        await self.db.execute(
            "UPDATE engagements SET status = 'closed', closed_at = ? WHERE id = ?",
            (_now().isoformat(), engagement_id))
        return True

    # -- authorization ------------------------------------------------------

    @staticmethod
    def is_expired(engagement: dict) -> bool:
        we = _parse_dt(engagement.get("window_end"))
        ws = _parse_dt(engagement.get("window_start"))
        now = _now()
        if ws and now < ws:
            return True   # window hasn't opened yet → treat as not-usable
        if we and now > we:
            return True
        return False

    def is_allowed(self, engagement: dict | None, cls: ActionClass | str,
                   target: str | None = None) -> tuple[bool, str]:
        """Decide whether an action of class ``cls`` against ``target`` is
        permitted by ``engagement``. Pure (no DB) for easy testing.

        Returns ``(allowed, reason)``. With no engagement, everything is allowed
        (legacy/no-ROE mode) — the engine's own deterministic scope check still
        applies separately.
        """
        if not engagement:
            return True, "no active engagement (legacy mode)"

        if engagement.get("status") and engagement["status"] != "active":
            return False, f"engagement {engagement.get('id')} is {engagement['status']}"

        if self.is_expired(engagement):
            return False, "engagement window is closed/expired"

        wanted = _norm_class(cls)
        allowed_classes = engagement.get("allowed_classes") or []
        if isinstance(allowed_classes, str):
            try:
                allowed_classes = json.loads(allowed_classes)
            except Exception:
                allowed_classes = []
        allowed_norm = {_norm_class(c) for c in allowed_classes}
        if wanted not in allowed_norm:
            return False, (
                f"action class '{wanted}' not in engagement's allowed classes "
                f"({', '.join(sorted(allowed_norm)) or 'none'})")

        # Scope check (best-effort, lenient when target unknown). The engine's
        # _scope_violation does the authoritative host-level enforcement; here we
        # only reject an obvious out-of-ROE host when scope is declared.
        scope = engagement.get("scope") or []
        if isinstance(scope, str):
            try:
                scope = json.loads(scope)
            except Exception:
                scope = []
        if scope and target:
            host = self._host_of(target)
            if host and not self._host_in_scope(host, scope):
                return False, f"target '{host}' is outside the engagement scope"

        return True, "authorized"

    @staticmethod
    def _host_of(target: str) -> str:
        import re
        t = re.sub(r"^\w+://", "", str(target).strip().lower())
        return t.split("/")[0].split(":")[0].strip()

    @staticmethod
    def _host_in_scope(host: str, scope: list) -> bool:
        host = host.lower()
        for entry in scope:
            e = str(entry).strip().lower()
            if not e:
                continue
            e_host = EngagementManager._host_of(e) if "://" in e else e
            if host == e_host:
                return True
            # suffix match for wildcard-style scope (e.g. "example.com" covers
            # "api.example.com"); CIDR/IP handled by the engine's scope check.
            if e_host.startswith("*."):
                if host.endswith(e_host[1:]):
                    return True
            elif host.endswith("." + e_host):
                return True
        return False

    # -- internal -----------------------------------------------------------

    @staticmethod
    def _decorate(row: dict) -> dict:
        d = dict(row)
        for key in ("scope", "allowed_classes"):
            v = d.get(key)
            if isinstance(v, str):
                try:
                    d[key] = json.loads(v) if v else []
                except Exception:
                    d[key] = []
            elif v is None:
                d[key] = []
        d["auto_approve"] = bool(d.get("auto_approve"))
        d["deconfliction_tag"] = deconfliction_tag(d.get("id", ""))
        return d
