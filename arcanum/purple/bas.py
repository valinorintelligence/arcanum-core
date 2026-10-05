"""Breach-and-Attack-Simulation runner (F3).

Executes an ATT&CK technique as an Atomic-Red-Team-style test, stamped with a
deconfliction tag so the Blue team can tell Arcanum apart from a real attacker.

Real execution requires the Kali sandbox (and installed atomics); without it the
runner performs an **honest simulation** — it records that the technique was
*attempted* (``execution_status='simulated'``) and NEVER claims a real execution
happened or fabricates attacker artifacts. The actual offensive execution is
governed by F0 (the ``run_bas_test`` tool is classified EXPLOIT).
"""
from __future__ import annotations

from typing import Any


def deconfliction_tag(campaign_id: str, technique_id: str) -> str:
    return f"ARCANUM-BAS:{campaign_id}:{technique_id}"


class BASRunner:
    def __init__(self, sandbox: Any = None, session_id: str | None = None,
                 engagement_id: str | None = None):
        self.sandbox = sandbox
        self.session_id = session_id
        self.engagement_id = engagement_id

    async def run(self, technique_id: str, campaign_id: str,
                  tactic: str | None = None, command: str | None = None) -> dict:
        """Run (or honestly simulate) a technique. Returns an execution record."""
        tag = deconfliction_tag(campaign_id, technique_id)
        if self.sandbox is not None and command:
            # Real execution path: delegate the atomic test to the sandbox. The
            # concrete atomics live in the authorized lab image, not this repo.
            try:
                result = await self._run_real(command)
                return {
                    "technique_id": technique_id, "tactic": tactic,
                    "executed": True, "execution_status": "executed",
                    "deconfliction_tag": tag, "sandbox": True,
                    "output": result,
                }
            except Exception as exc:
                return {
                    "technique_id": technique_id, "tactic": tactic,
                    "executed": False, "execution_status": "error",
                    "deconfliction_tag": tag, "error": str(exc),
                }
        # Honest simulation (no sandbox): nothing real is executed.
        return {
            "technique_id": technique_id, "tactic": tactic,
            "executed": True, "execution_status": "simulated",
            "deconfliction_tag": tag, "sandbox": False,
            "note": ("Sandbox indisponível — execução SIMULADA (nenhum ataque real "
                     "foi executado). Para execução real, forneça sandbox autorizado + atomics."),
        }

    async def _run_real(self, command: str) -> dict:
        container_id = getattr(self.sandbox, "_active_container", None)
        if not container_id:
            container_id = await self.sandbox.create_container(".")
        return await self.sandbox.execute(container_id, command, timeout=120)
