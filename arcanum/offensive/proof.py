"""Proof capture + access-signal detection for offensive actions (F1+).

Two honest primitives, no attack logic:

* :func:`detect_access` reads the output of a (gated, authorized) delegated tool and
  decides whether it actually produced access — a **session/shell** (⇒ a foothold is
  justified) or merely a **confirmed vulnerability** (⇒ proof, but NOT a foothold).
  A foothold is thus only ever registered on real evidence, never assumed.
* :func:`build_proof` standardizes evidence into a masked, hash-stamped record.
  Credentials are scrubbed from the stored evidence; the sha256 is over the original
  text so integrity is still verifiable.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from ..redteam.audit import _scrub_credentials_in_text

# A match means the delegated tool reported a real interactive foothold.
_SESSION_SIGNALS: list[tuple[str, re.Pattern]] = [
    ("meterpreter_session", re.compile(r"meterpreter session \d+ opened", re.I)),
    ("command_shell_session", re.compile(r"command shell session \d+ opened", re.I)),
    ("generic_session", re.compile(r"\bsession \d+ (?:opened|created)\b", re.I)),
    # `id` output from a confirmed shell: uid=0(root) gid=0(root)
    ("shell_id_output", re.compile(r"\buid=\d+\([^)]*\)\s+gid=\d+\(", re.I)),
]

# A match means a vulnerability was CONFIRMED but no shell was obtained.
_VULN_SIGNALS: list[tuple[str, re.Pattern]] = [
    ("sqlmap_vulnerable", re.compile(r"parameter '[^']+' is vulnerable|back-end DBMS:", re.I)),
    ("nuclei_match", re.compile(r"\[(?:critical|high|medium)\]\s*\[(?:http|network|dns|tcp)\]", re.I)),
    ("generic_exploit_ok", re.compile(r"\bexploit completed\b|\bvulnerable\b", re.I)),
]


def detect_access(output: str) -> dict | None:
    """Classify a delegated tool's output.

    Returns ``{"level": "session"|"vuln_confirmed", "signal": str, "excerpt": str}``
    or ``None`` when nothing indicates success. ``session`` justifies a foothold;
    ``vuln_confirmed`` justifies proof + a finding, but NOT a foothold.
    """
    if not output:
        return None
    for name, rx in _SESSION_SIGNALS:
        m = rx.search(output)
        if m:
            return {"level": "session", "signal": name, "excerpt": _excerpt(output, m)}
    for name, rx in _VULN_SIGNALS:
        m = rx.search(output)
        if m:
            return {"level": "vuln_confirmed", "signal": name, "excerpt": _excerpt(output, m)}
    return None


def _excerpt(text: str, m: re.Match, pad: int = 60) -> str:
    start = max(0, m.start() - pad)
    end = min(len(text), m.end() + pad)
    return text[start:end].strip()[:300]


def mask_secret(secret: str, keep: int = 4) -> str:
    """Mask a secret/hash, keeping only the last ``keep`` chars for correlation."""
    s = str(secret)
    if len(s) <= keep:
        return "****"
    return "****" + s[-keep:]


# user:[rid:]secret  — secretsdump/hashcat/shadow style credential lines.
_CRED_LINE = re.compile(r"^([A-Za-z0-9._\\$@-]{1,64}):(?:\d+:)?([0-9a-fA-F]{16,}|\$[0-9a-z]+\$\S+|[^\s:]{3,})")


def _guess_cred_type(secret: str) -> str:
    s = str(secret)
    if re.fullmatch(r"[0-9a-fA-F]{32}", s):
        return "ntlm_hash"
    if re.fullmatch(r"[0-9a-fA-F]{40,}", s):
        return "hash"
    if s.startswith("$"):
        return "crypt_hash"
    return "password"


def extract_masked_credentials(output: str, max_items: int = 50) -> list[dict]:
    """Parse credential-bearing lines from a dump tool's output and return them
    **masked** — the raw secret is never included, so nothing sensitive reaches the
    log, the graph or the tool result. The operator keeps the raw in their own tool
    session; Arcanum records only a masked reference + type (AGENTS §5: creds masked)."""
    creds: list[dict] = []
    for line in (output or "").splitlines():
        m = _CRED_LINE.match(line.strip())
        if not m:
            continue
        user, secret = m.group(1), m.group(2)
        creds.append({"user": user, "secret_masked": mask_secret(secret),
                      "type": _guess_cred_type(secret)})
        if len(creds) >= max_items:
            break
    return creds


def build_proof(proof_type: str, raw, note: str | None = None,
                deconfliction_tag: str | None = None) -> dict:
    """Standardize evidence into a masked, auditable record.

    ``proof_type``: ``shell`` | ``output`` | ``vuln_confirmation`` | ``sample``.
    Secrets are scrubbed from the stored ``evidence``; the ``sha256`` is computed over
    the ORIGINAL text so the untampered evidence can still be integrity-checked.
    """
    text = raw if isinstance(raw, str) else json.dumps(raw, default=str, ensure_ascii=False)
    masked = _scrub_credentials_in_text(text)[:4000]
    return {
        "proof_type": proof_type,
        "summary": note or proof_type,
        "evidence": masked,
        "sha256": hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest(),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "deconfliction_tag": deconfliction_tag,
    }
