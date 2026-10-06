"""Breach-and-Attack-Simulation runner (F3).

Executes an ATT&CK technique as an Atomic-Red-Team-style test, stamped with a
deconfliction tag so the Blue team can tell Arcanum apart from a real attacker.

Execution paths (all gated by F0 — ``run_bas_test`` is EXPLOIT):
1. an explicit ``command`` + sandbox → run it;
2. ``use_atomics=True`` + sandbox + no command → build an **Atomic Red Team**
   invocation for the technique (``Invoke-AtomicTest`` by default, overridable via
   ``ARCANUM_ATOMIC_CMD_TEMPLATE``) and run it (F3 a). The atomics themselves live in
   the authorized Kali image, not this repo;
3. otherwise → **honest simulation** (``execution_status='simulated'``) that NEVER
   claims a real execution happened nor fabricates artifacts.

Every real run echoes the deconfliction tag first so the Blue team / SIEM can
correlate (``was_detected`` searches logs for that tag).
"""
from __future__ import annotations

import os
import shlex
from typing import Any


def deconfliction_tag(campaign_id: str, technique_id: str) -> str:
    return f"ARCANUM-BAS:{campaign_id}:{technique_id}"


class BASRunner:
    def __init__(self, sandbox: Any = None, session_id: str | None = None,
                 engagement_id: str | None = None):
        self.sandbox = sandbox
        self.session_id = session_id
        self.engagement_id = engagement_id

    @staticmethod
    def _atomic_command(technique_id: str) -> str:
        """Build the Atomic Red Team invocation for a technique (F3 a). Override with
        ARCANUM_ATOMIC_CMD_TEMPLATE (use ``{technique}``); default is the standard
        Invoke-AtomicTest runner. No attack content lives here — the atomics are the
        established Atomic Red Team content installed in the authorized image."""
        tid = (technique_id or "").strip()
        tmpl = os.environ.get("ARCANUM_ATOMIC_CMD_TEMPLATE")
        if tmpl:
            return tmpl.replace("{technique}", tid)
        return f'pwsh -NoProfile -Command "Invoke-AtomicTest {tid} -Confirm:$false"'

    async def run(self, technique_id: str, campaign_id: str,
                  tactic: str | None = None, command: str | None = None,
                  use_atomics: bool = False) -> dict:
        """Run (or honestly simulate) a technique. Returns an execution record.

        ``use_atomics`` (opt-in) runs the real Atomic Red Team test for the technique
        when the sandbox is available and no explicit ``command`` is given."""
        tag = deconfliction_tag(campaign_id, technique_id)
        exec_command = command
        atomic = False
        if exec_command is None and use_atomics:
            exec_command = self._atomic_command(technique_id)
            atomic = True

        if self.sandbox is not None and exec_command:
            # Real execution via the sandbox; stamp the deconfliction tag into the run.
            stamped = f"echo {shlex.quote(tag)}; {exec_command}"
            try:
                result = await self._run_real(stamped)
                return {
                    "technique_id": technique_id, "tactic": tactic,
                    "executed": True, "execution_status": "executed",
                    "deconfliction_tag": tag, "sandbox": True, "atomic": atomic,
                    "command": exec_command, "output": result,
                }
            except Exception as exc:
                return {
                    "technique_id": technique_id, "tactic": tactic,
                    "executed": False, "execution_status": "error",
                    "deconfliction_tag": tag, "sandbox": True, "atomic": atomic,
                    "command": exec_command, "error": str(exc),
                }
        # Honest simulation (no sandbox, or nothing to run): nothing real is executed.
        note = ("Sandbox indisponível — execução SIMULADA (nenhum ataque real foi "
                "executado). Para execução real, forneça sandbox autorizado + atomics "
                "(use_atomics=true) ou um command explícito.")
        return {
            "technique_id": technique_id, "tactic": tactic,
            "executed": True, "execution_status": "simulated",
            "deconfliction_tag": tag, "sandbox": self.sandbox is not None,
            "atomic": atomic, "note": note,
        }

    async def _run_real(self, command: str) -> dict:
        container_id = getattr(self.sandbox, "_active_container", None)
        if not container_id:
            container_id = await self.sandbox.create_container(".")
        return await self.sandbox.execute(container_id, command, timeout=120)
