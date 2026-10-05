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
import hmac
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .action_classes import ActionClass

logger = logging.getLogger("arcanum")

_ROE_SECRET_CACHE: str | None = None


def _resolve_roe_secret() -> str:
    """Resolve the server ROE signing secret (F0 #6), cached per process.

    Order: config.roe_secret / ARCANUM_ROE_SECRET env → persisted
    ``~/.arcanum/roe_secret.txt`` (generated once) → a process-ephemeral secret as a
    last resort. The secret never leaves the server; without it a ROE signature cannot
    be forged."""
    global _ROE_SECRET_CACHE
    if _ROE_SECRET_CACHE:
        return _ROE_SECRET_CACHE
    secret = ""
    try:
        from ..core.config import get_config
        secret = (get_config().roe_secret or "").strip()
    except Exception:
        secret = ""
    if not secret:
        secret = os.environ.get("ARCANUM_ROE_SECRET", "").strip()
    if not secret:
        path = Path.home() / ".arcanum" / "roe_secret.txt"
        try:
            if path.exists():
                secret = path.read_text(encoding="utf-8").strip()
            if not secret:
                secret = secrets.token_urlsafe(48)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(secret, encoding="utf-8")
        except Exception:
            if not secret:
                secret = secrets.token_urlsafe(48)  # ephemeral, still unforgeable in-process
    _ROE_SECRET_CACHE = secret
    return secret


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
    def _roe_payload(name: str, scope: list, allowed_classes: list,
                     window_start: Any, window_end: Any, auto_approve: bool = False) -> str:
        """Canonical JSON of the ROE contract (shared by the content hash and the HMAC
        signature so they can never drift). ``auto_approve`` is part of the contract."""
        return json.dumps(
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

    @staticmethod
    def compute_roe_hash(name: str, scope: list, allowed_classes: list,
                         window_start: Any, window_end: Any, auto_approve: bool = False) -> str:
        """Deterministic CONTENT hash of the ROE contract (tamper-evidence). Anyone can
        recompute it — for unforgeability use :meth:`compute_roe_sig` (F0 #6)."""
        payload = EngagementManager._roe_payload(
            name, scope, allowed_classes, window_start, window_end, auto_approve)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_roe_sig(name: str, scope: list, allowed_classes: list,
                        window_start: Any, window_end: Any, auto_approve: bool = False,
                        secret: str | None = None) -> str:
        """HMAC-SHA256 signature of the ROE contract (F0 #6). Unforgeable without the
        server secret, so a ROE row cannot be fabricated or altered and still verify."""
        payload = EngagementManager._roe_payload(
            name, scope, allowed_classes, window_start, window_end, auto_approve)
        key = (secret if secret is not None else _resolve_roe_secret()).encode("utf-8")
        return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_signature(engagement: dict | None) -> str:
        """Return ``'valid'`` | ``'invalid'`` | ``'unsigned'`` for an engagement's HMAC
        signature. Recomputes from the stored fields and compares in constant time."""
        if not engagement:
            return "unsigned"
        sig = engagement.get("roe_sig")
        if not sig:
            return "unsigned"
        expected = EngagementManager.compute_roe_sig(
            engagement.get("name"), engagement.get("scope"), engagement.get("allowed_classes"),
            engagement.get("window_start"), engagement.get("window_end"),
            bool(engagement.get("auto_approve")))
        return "valid" if hmac.compare_digest(str(sig), expected) else "invalid"

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
        wsi = ws.isoformat() if ws else ""
        wei = we.isoformat() if we else ""
        roe_hash = self.compute_roe_hash(name, scope, classes, wsi, wei, auto_approve=bool(auto_approve))
        roe_sig = self.compute_roe_sig(name, scope, classes, wsi, wei, auto_approve=bool(auto_approve))
        now = _now().isoformat()

        await self.db.execute(
            """INSERT INTO engagements
               (id, name, session_id, scope, allowed_classes, window_start, window_end,
                roe_hash, roe_sig, status, operator, auto_approve, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
            (
                eid, name, session_id, json.dumps(scope), json.dumps(classes),
                ws.isoformat() if ws else None, we.isoformat() if we else None,
                roe_hash, roe_sig, operator, 1 if auto_approve else 0, now,
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
        # ROE signature enforcement (F0 #6): a tampered/forged signature is NEVER
        # trusted; unsigned legacy engagements are honored unless require_signed_roe.
        require_signed = False
        try:
            from ..core.config import get_config
            require_signed = bool(get_config().require_signed_roe)
        except Exception:
            require_signed = False
        kept = []
        for e in live:
            status = self.verify_signature(e)
            if status == "invalid":
                logger.warning("Engagement %s rejected: ROE signature invalid (tampered/forged).",
                               e.get("id"))
                continue
            if status == "unsigned" and require_signed:
                logger.warning("Engagement %s rejected: unsigned ROE and require_signed_roe is on.",
                               e.get("id"))
                continue
            kept.append(e)
        live = kept
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
