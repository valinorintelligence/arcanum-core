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
2. **Real SIEM query** (optional): when SIEM credentials are configured, query the
   SIEM for an alert carrying the deconfliction tag in the window
   (``source="siem"``, ``simulated=False``).

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

    def _siem_configured(self) -> bool:
        c = self.config
        return bool(c and getattr(c, "elastic_url", "") and getattr(c, "elastic_api_key", ""))

    async def _query_siem(self, tag: str | None, window: int | None) -> bool:
        import httpx
        url = getattr(self.config, "elastic_url", "").rstrip("/")
        key = getattr(self.config, "elastic_api_key", "")
        headers = {"Authorization": f"ApiKey {key}", "Content-Type": "application/json"}
        query = {"query": {"match": {"message": tag or ""}}, "size": 1}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{url}/_search", json=query, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"SIEM query {resp.status_code}")
            hits = resp.json().get("hits", {}).get("total", {})
            n = hits.get("value", 0) if isinstance(hits, dict) else hits
            return bool(n)
