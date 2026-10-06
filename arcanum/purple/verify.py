"""Detection verifier (F3): was a technique detected?

Measures detection HONESTLY, from real signals — never a fabricated verdict, and
never a simulated signal painted as real:

1. **Deployed detection rules** (F2 registry): an *active* detection rule covering
   the technique makes it detectable. BUT a rule deployed WITHOUT credentials is a
   **mock** deploy (nothing reached a real control), so it is reported as
   ``source="deployed_rule_simulated"`` with ``simulated=True`` — SIMULATED
   coverage, which must NOT count toward the real detection rate. A rule deployed
   to a real control (``mock=False``) is ``source="deployed_rule"``,
   ``simulated=False``. A real match is preferred over a mock one.
2. **Real SIEM query** (optional, F3 b — MULTI-SIEM): when SIEM credentials are
   configured, query EVERY configured backend (Elastic, Splunk, Microsoft Sentinel)
   for an alert carrying the deconfliction tag in the window; a hit from any real
   control ⇒ ``source="siem"``, ``simulated=False``. All backends erroring ⇒ honest
   ``siem_error``.

If nothing covers the technique, the verdict is MISS (``detected=False``), not
unknown. This is the invariant from AGENTS §5: never report simulated as real.

PREVENTION vs DETECTION (F3 (d)): detection means an alert/log fired; **prevention**
means the attack was BLOCKED by a control (WAF/EDR/firewall/IR/hardening). They are
measured separately — :meth:`DetectionVerifier.was_prevented` — and map to the
distinct MITRE statuses BLOCKED (prevented) vs DETECTED. Real prevention comes from
a BAS run that was actually blocked (``execution_status='blocked'``); a mock
preventive deployment is SIMULATED prevention (never counted as real), same honesty
rule as detection.
"""
from __future__ import annotations

import json
from typing import Any

from ..blue.registry import DeploymentRegistry

_ARM = "https://management.azure.com"

# Deployed controls that BLOCK (prevent) rather than merely alert. Used only for the
# SIMULATED prevention signal; real prevention is the BAS run being blocked.
_PREVENTIVE_SYSTEMS = {"waf", "edr", "firewall"}
_PREVENTIVE_KINDS = {"ir_action", "hardening"}


class DetectionVerifier:
    def __init__(self, db: Any, config: Any = None):
        self.db = db
        self.config = config
        self.registry = DeploymentRegistry(db)

    async def was_detected(self, technique_id: str, tag: str | None = None,
                           window: int | None = None) -> dict:
        # 1) Active deployed detection rule covering this technique? A REAL deploy
        #    wins over a MOCK one; a mock-only match is SIMULATED coverage.
        deployments = await self.registry.list(kind="detection_rule", status="active")
        mock_match = None
        for d in deployments:
            if self._covers(d, technique_id):
                if not d.get("mock"):
                    return {"detected": True, "source": "deployed_rule",
                            "simulated": False, "technique_id": technique_id,
                            "deployment_id": d["id"]}
                if mock_match is None:
                    mock_match = d
        if mock_match is not None:
            return {"detected": True, "source": "deployed_rule_simulated",
                    "simulated": True, "technique_id": technique_id,
                    "deployment_id": mock_match["id"]}

        # 2) Optional real SIEM query (Elastic) for an alert with the tag.
        if self._siem_configured():
            try:
                hit = await self._query_siem(tag, window)
                return {"detected": bool(hit), "source": "siem", "simulated": False,
                        "technique_id": technique_id}
            except Exception as exc:
                return {"detected": False, "source": "siem_error", "simulated": False,
                        "technique_id": technique_id, "error": str(exc)}

        # 3) No coverage → honest MISS.
        return {"detected": False, "source": "none", "simulated": False,
                "technique_id": technique_id}

    async def was_prevented(self, technique_id: str, run: dict | None = None) -> dict:
        """Was the technique BLOCKED (prevented), as opposed to merely detected?

        Real prevention (``simulated=False``) comes only from a BAS run that was
        actually blocked by a control (``execution_status='blocked'``). A mock
        preventive deployment covering the technique is SIMULATED prevention
        (``simulated=True``) — coverage that must NOT count as real prevention.
        Returns ``{prevented, source, simulated, technique_id}``."""
        # 1) Ground truth: the attack run was blocked at execution time.
        if run and run.get("execution_status") == "blocked":
            return {"prevented": True, "source": "bas_blocked", "simulated": False,
                    "technique_id": technique_id}
        # 2) An active deployed PREVENTIVE control covering the technique. A real
        #    control wins over a mock one; a mock-only match is SIMULATED prevention.
        deployments = await self.registry.list(status="active")
        mock_match = None
        for d in deployments:
            if self._is_preventive(d) and self._covers(d, technique_id):
                if not d.get("mock"):
                    return {"prevented": True, "source": "deployed_control",
                            "simulated": False, "technique_id": technique_id,
                            "deployment_id": d["id"]}
                if mock_match is None:
                    mock_match = d
        if mock_match is not None:
            return {"prevented": True, "source": "deployed_control_simulated",
                    "simulated": True, "technique_id": technique_id,
                    "deployment_id": mock_match["id"]}
        return {"prevented": False, "source": "none", "simulated": False,
                "technique_id": technique_id}

    @staticmethod
    def _is_preventive(deployment: dict) -> bool:
        """A deployment that BLOCKS rather than only alerts: IR/hardening actions,
        or a detection rule deployed to a blocking control (WAF/EDR/firewall)."""
        kind = (deployment.get("kind") or "").lower()
        if kind in _PREVENTIVE_KINDS:
            return True
        if kind == "detection_rule":
            return (deployment.get("target_system") or "").lower() in _PREVENTIVE_SYSTEMS
        return False

    @staticmethod
    def _covers(deployment: dict, technique_id: str) -> bool:
        tid = (technique_id or "").lower()
        if not tid:
            return False
        if tid in (deployment.get("name") or "").lower():
            return True
        try:
            blob = json.dumps(deployment.get("payload") or {}, default=str).lower()
        except Exception:
            blob = ""
        return tid in blob

    def _cfg(self, name: str, default: str = "") -> str:
        return getattr(self.config, name, default) if self.config else default

    def _siem_backends(self) -> list[str]:
        """Which real SIEM backends have credentials (F3 b — multi-SIEM)."""
        out = []
        if self._cfg("elastic_url") and self._cfg("elastic_api_key"):
            out.append("elastic")
        if self._cfg("splunk_mgmt_url") and (
                self._cfg("splunk_mgmt_token")
                or (self._cfg("splunk_username") and self._cfg("splunk_password"))):
            out.append("splunk")
        if self._cfg("sentinel_resource_id") and self._cfg("sentinel_token"):
            out.append("sentinel")
        return out

    def _siem_configured(self) -> bool:
        return bool(self._siem_backends())

    async def _query_siem(self, tag: str | None, window: int | None) -> bool:
        """Query EVERY configured SIEM for an alert/event carrying the deconfliction
        tag in the window; True if ANY real control saw it (F3 b). Raises only when all
        configured backends errored (so was_detected reports an honest siem_error)."""
        last_error = None
        answered = False
        for backend in self._siem_backends():
            try:
                if await self._query_backend(backend, tag, window):
                    return True
                answered = True
            except Exception as exc:
                last_error = str(exc)
        if not answered and last_error:
            raise RuntimeError(last_error)
        return False

    async def _query_backend(self, backend: str, tag: str | None, window: int | None) -> bool:
        import httpx
        tag = tag or ""
        win = int(window or 15)
        if backend == "elastic":
            url = self._cfg("elastic_url").rstrip("/")
            headers = {"Authorization": f"ApiKey {self._cfg('elastic_api_key')}",
                       "Content-Type": "application/json"}
            query = {"query": {"match": {"message": tag}}, "size": 1}
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(f"{url}/_search", json=query, headers=headers)
                if resp.status_code != 200:
                    raise RuntimeError(f"Elastic query {resp.status_code}")
                hits = resp.json().get("hits", {}).get("total", {})
                n = hits.get("value", 0) if isinstance(hits, dict) else hits
                return bool(n)
        if backend == "splunk":
            url = self._cfg("splunk_mgmt_url").rstrip("/")
            token = self._cfg("splunk_mgmt_token")
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            auth = None if token else (self._cfg("splunk_username"), self._cfg("splunk_password"))
            data = {"search": f'search "{tag}" earliest=-{win}m', "output_mode": "json",
                    "exec_mode": "oneshot"}
            async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
                resp = await client.post(f"{url}/services/search/jobs/export",
                                         data=data, headers=headers, auth=auth)
                if resp.status_code != 200:
                    raise RuntimeError(f"Splunk query {resp.status_code}")
                # A oneshot export streams one JSON object per matching result row.
                return '"result"' in resp.text or (bool(tag) and tag in resp.text)
        if backend == "sentinel":
            scope = self._cfg("sentinel_resource_id").rstrip("/")
            headers = {"Authorization": f"Bearer {self._cfg('sentinel_token')}",
                       "Content-Type": "application/json"}
            body = {"query": f'search "{tag}" | take 1'}
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(f"{_ARM}{scope}/query?api-version=2017-10-01",
                                         json=body, headers=headers)
                if resp.status_code != 200:
                    raise RuntimeError(f"Sentinel query {resp.status_code}")
                tables = resp.json().get("tables", [])
                return any(t.get("rows") for t in tables)
        raise RuntimeError(f"unknown SIEM backend {backend}")
