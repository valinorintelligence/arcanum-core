"""Immutable action audit trail (F0).

Every real action is appended to ``actions_log`` as a hash-chained record:
``entry_hash = sha256(prev_hash + payload)``. Any tampering with an earlier row
breaks the chain and is caught by :meth:`ActionAuditLog.verify_chain`. The log
is append-only (no update/delete API) and exportable for the client's kill-chain
narrative.

Arguments are masked before they ever reach the log (see :func:`mask_arguments`)
so secrets/credentials are never persisted in clear text.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any


_SENSITIVE_KEY_MARKERS = (
    "password", "passwd", "secret", "token", "apikey", "api_key", "authorization",
    "auth", "credential", "cred", "private_key", "privatekey", "session_key",
    "access_key", "secret_key", "bearer", "cookie",
)
_REDACTED = "***REDACTED***"
_MAX_STR = 512

# Key-based masking only catches secrets that sit under a secret-named key. A
# password passed INLINE in a value (notably in an `execute` command, or a URL)
# would otherwise leak into the immutable log. These scrubbers redact the most
# common inline-credential shapes from string values, WITHOUT destroying benign
# data: generic short -p/-P is only touched for known credential CLIs, and
# numeric/port-like values (e.g. `nmap -p 80,443`) are preserved.
_CRED_CLI = r"(?:mysql|mysqladmin|psql|mariadb|redis-cli|mongo|mongosh|smbclient|hydra|medusa|ncrack|rsync)"
_LONG_FLAG = re.compile(
    r"(--(?:password|passwd|pass|secret|token|api[-_]?key|access[-_]?key|secret[-_]?key|auth[-_]?token)\s*[=\s]\s*)(\S+)",
    re.IGNORECASE)
_SSHPASS = re.compile(r"(\bsshpass\b[^\n]*?\s-[pP]\s*)(\S+)", re.IGNORECASE)
_URL_USERINFO = re.compile(r"([a-zA-Z][\w+.\-]*://[^\s:/@]+:)([^\s/@]+)(@)")
_BEARER = re.compile(r"(\bBearer\s+)([A-Za-z0-9._\-]{8,})", re.IGNORECASE)
_AUTH_HEADER = re.compile(r"(\bAuthorization\s*:\s*\S+\s+)(\S+)", re.IGNORECASE)
_SHORT_PW = re.compile(r"(-[pP])\s*([^\s-]\S*)")


def _scrub_credentials_in_text(s: str) -> str:
    """Redact inline credentials from a free-text string (e.g. a shell command)."""
    out = _LONG_FLAG.sub(r"\1" + _REDACTED, s)
    out = _SSHPASS.sub(r"\1" + _REDACTED, out)
    # Generic short password flags only for known credential CLIs, and never for
    # pure port/range/mapping values (so `nmap -p 80` survives).
    if re.search(r"\b" + _CRED_CLI + r"\b", out, re.IGNORECASE):
        out = _SHORT_PW.sub(
            lambda m: (m.group(1) + " " + _REDACTED)
            if not re.fullmatch(r"[\d,\-:]+", m.group(2)) else m.group(0),
            out)
    out = _URL_USERINFO.sub(r"\1" + _REDACTED + r"\3", out)
    out = _BEARER.sub(r"\1" + _REDACTED, out)
    out = _AUTH_HEADER.sub(r"\1" + _REDACTED, out)
    return out


def _mask_scalar(value: Any) -> Any:
    if isinstance(value, str):
        value = _scrub_credentials_in_text(value)
        if len(value) > _MAX_STR:
            return value[:_MAX_STR] + "…<truncated>"
    return value


def mask_arguments(args: Any) -> Any:
    """Return a copy of ``args`` with secret-looking values redacted and long
    strings truncated. Safe to persist / return over the API."""
    if isinstance(args, dict):
        out: dict[str, Any] = {}
        for k, v in args.items():
            if any(m in str(k).lower() for m in _SENSITIVE_KEY_MARKERS):
                out[k] = _REDACTED
            elif isinstance(v, dict):
                out[k] = mask_arguments(v)
            elif isinstance(v, list):
                out[k] = [mask_arguments(x) if isinstance(x, (dict, list)) else _mask_scalar(x) for x in v]
            else:
                out[k] = _mask_scalar(v)
        return out
    if isinstance(args, list):
        return [mask_arguments(x) if isinstance(x, (dict, list)) else _mask_scalar(x) for x in args]
    return _mask_scalar(args)


def summarize_result(result: Any, limit: int = 400) -> str:
    """Produce a short, safe one-line summary of a tool result for the log."""
    if result is None:
        return ""
    try:
        if isinstance(result, dict):
            # ToolExecutor envelope {"success","output","error"}
            if "success" in result or "output" in result:
                ok = result.get("success")
                err = result.get("error")
                inner = result.get("output", None)
                head = "ok" if ok else "fail"
                if err:
                    return f"{head}: {str(err)[:limit]}"
                if isinstance(inner, dict):
                    keys = ", ".join(list(inner.keys())[:8])
                    return f"{head}: {{{keys}}}"
                s = json.dumps(inner, default=str, ensure_ascii=False) if inner is not None else ""
                return f"{head}: {s[:limit]}"
            s = json.dumps(result, default=str, ensure_ascii=False)
            return s[:limit]
        return str(result)[:limit]
    except Exception:
        return str(result)[:limit]


class ActionAuditLog:
    """Append-only, hash-chained action trail over ``actions_log``."""

    def __init__(self, db: Any):
        self.db = db

    def _lock(self) -> asyncio.Lock:
        """Per-connection append lock so the read-last-hash + insert critical
        section is atomic even when two sessions share one DB connection (the
        app-level Database is shared). Lazily attached to the connection and
        bound to the running loop on first use, so it works across the fresh
        event loops pytest creates per test."""
        lock = getattr(self.db, "_audit_append_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            try:
                self.db._audit_append_lock = lock
            except Exception:
                pass
        return lock

    async def _last_hash(self) -> str:
        row = await self.db.fetch_one(
            "SELECT entry_hash FROM actions_log ORDER BY id DESC LIMIT 1")
        return (row or {}).get("entry_hash") or ""

    async def record(
        self,
        *,
        tool: str,
        action_class: str,
        decision: str,
        target: str | None = None,
        risk: str | None = None,
        arguments: Any = None,
        result_summary: str | None = None,
        engagement_id: str | None = None,
        session_id: str | None = None,
        operator: str | None = None,
        deconfliction_tag: str | None = None,
    ) -> dict:
        """Append one immutable record and return it (with its chain hashes)."""
        ts = datetime.now(timezone.utc).isoformat()
        # The payload is the exact JSON that is hashed, so verify_chain can
        # recompute it byte-for-byte from the stored column.
        payload_obj = {
            "ts": ts,
            "tool": tool,
            "action_class": action_class,
            "decision": decision,
            "target": target,
            "risk": risk,
            "arguments": mask_arguments(arguments) if arguments is not None else None,
            "result_summary": result_summary,
            "engagement_id": engagement_id,
            "session_id": session_id,
            "operator": operator,
            "deconfliction_tag": deconfliction_tag,
        }
        payload = json.dumps(payload_obj, sort_keys=True, ensure_ascii=False, default=str)

        async with self._lock():
            prev_hash = await self._last_hash()
            entry_hash = hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()
            cur = await self.db.execute(
                """INSERT INTO actions_log
                   (engagement_id, session_id, tool, action_class, target, decision, risk,
                    arguments, result_summary, operator, deconfliction_tag,
                    prev_hash, entry_hash, payload, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    engagement_id, session_id, tool, action_class, target, decision, risk,
                    json.dumps(payload_obj["arguments"], ensure_ascii=False, default=str),
                    result_summary, operator, deconfliction_tag,
                    prev_hash, entry_hash, payload, ts,
                ),
            )
        return {
            "id": getattr(cur, "lastrowid", None),
            "entry_hash": entry_hash,
            "prev_hash": prev_hash,
            "tool": tool,
            "action_class": action_class,
            "decision": decision,
            "ts": ts,
        }

    async def list(self, limit: int = 200, engagement_id: str | None = None) -> list[dict]:
        if engagement_id:
            rows = await self.db.fetch_all(
                "SELECT id, engagement_id, session_id, tool, action_class, target, decision, "
                "risk, arguments, result_summary, operator, deconfliction_tag, prev_hash, "
                "entry_hash, created_at FROM actions_log WHERE engagement_id = ? "
                "ORDER BY id DESC LIMIT ?",
                (engagement_id, limit))
        else:
            rows = await self.db.fetch_all(
                "SELECT id, engagement_id, session_id, tool, action_class, target, decision, "
                "risk, arguments, result_summary, operator, deconfliction_tag, prev_hash, "
                "entry_hash, created_at FROM actions_log ORDER BY id DESC LIMIT ?",
                (limit,))
        out = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("arguments"), str):
                try:
                    d["arguments"] = json.loads(d["arguments"])
                except Exception:
                    pass
            out.append(d)
        return out

    async def verify_chain(self) -> dict:
        """Recompute the hash chain from the stored payloads and detect tampering.

        Returns ``{"valid": bool, "length": n, "broken_at": id|None}``.
        """
        rows = await self.db.fetch_all(
            "SELECT id, prev_hash, entry_hash, payload FROM actions_log ORDER BY id ASC")
        prev = ""
        for r in rows:
            payload = r.get("payload") or ""
            expected = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
            if r.get("prev_hash") != prev or r.get("entry_hash") != expected:
                return {"valid": False, "length": len(rows), "broken_at": r.get("id")}
            prev = r.get("entry_hash") or ""
        return {"valid": True, "length": len(rows), "broken_at": None}
