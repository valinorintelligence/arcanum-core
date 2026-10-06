"""Common contract for governed offensive actions (F1+).

:class:`OffensiveContext` is the single home for the shared offensive plumbing the
roadmap (§11) requires every offensive wrapper to use:

* **one delegation path** — :meth:`delegate` runs an operator/tool-supplied command
  in the authorized sandbox through the governed ``execute`` tool (no exploit logic
  lives here);
* **foothold registration with a teardown recipe** so cleanup is real (F0 #5);
* **compromise-state update** on the knowledge graph (``owned``/``foothold_id``).

Audit, ROE enforcement and HITL are applied by the engine BEFORE a wrapper runs
(the tool is classified EXPLOIT/ACTIVE in ``redteam/action_classes``), so the
wrappers focus on delegation + proof + state.
"""
from __future__ import annotations

from typing import Any


class OffensiveContext:
    def __init__(self, *, executor: Any, db: Any = None,
                 session_id: str | None = None, engagement_id: str | None = None):
        self.executor = executor
        self.db = db if db is not None else getattr(executor, "db", None)
        self.session_id = session_id if session_id is not None else getattr(executor, "session_id", None)
        self.engagement_id = engagement_id
        self._registry = None

    # -- capabilities -------------------------------------------------------

    def has_sandbox(self) -> bool:
        return getattr(self.executor, "sandbox", None) is not None

    @property
    def registry(self):
        if self._registry is None and self.db is not None:
            from ..redteam.sessions import SessionRegistry
            self._registry = SessionRegistry(self.db)
        return self._registry

    @property
    def graph(self):
        return getattr(self.executor, "graph_mgr", None)

    @property
    def cve_kb(self):
        return getattr(self.executor, "cve_kb", None)

    # -- the single delegation path ----------------------------------------

    async def delegate(self, command: str, timeout: int = 300) -> dict:
        """Run an operator/tool-supplied command in the authorized sandbox via the
        governed ``execute`` tool. Returns the unwrapped ``{stdout, stderr,
        exit_code, ...}``. This is the ONLY way an offensive wrapper touches a
        target — and it contains no exploit logic of its own."""
        res = await self.executor.execute_tool("execute", {"command": command, "timeout": timeout})
        if isinstance(res, dict):
            out = res.get("output")
            if isinstance(out, dict):
                return out
            if res.get("error"):
                return {"stdout": "", "stderr": str(res.get("error")), "exit_code": -1}
        return {"stdout": "", "stderr": "", "exit_code": -1}

    # -- state ---------------------------------------------------------------

    async def register_foothold(self, *, host: str, access_level: str = "user",
                                implant_type: str = "shell",
                                teardown_recipe: list[str] | None = None,
                                metadata: dict | None = None) -> dict | None:
        if self.registry is None:
            return None
        return await self.registry.create_foothold(
            engagement_id=self.engagement_id, session_id=self.session_id,
            host=host, access_level=access_level, implant_type=implant_type,
            teardown_recipe=teardown_recipe, metadata=metadata)

    async def mark_owned(self, host: str, owned: str = "user",
                         foothold_id: str | None = None) -> None:
        g = self.graph
        if g is None or not hasattr(g, "mark_compromised"):
            return
        try:
            await g.mark_compromised(self.session_id, host, owned=owned, foothold_id=foothold_id)
        except Exception:
            pass

    async def get_foothold(self, foothold_id: str) -> dict | None:
        if self.registry is None or not foothold_id:
            return None
        return await self.registry.get(foothold_id)

    async def register_implant(self, *, host: str, implant_type: str,
                               teardown_recipe: list[str] | None = None,
                               metadata: dict | None = None, parent_id: str | None = None,
                               access_level: str = "user") -> dict | None:
        """Register an implant/pivot/C2/foothold created through post-exploitation,
        linked to its parent foothold, with its teardown recipe for guaranteed cleanup."""
        if self.registry is None:
            return None
        return await self.registry.create_foothold(
            engagement_id=self.engagement_id, session_id=self.session_id, host=host,
            access_level=access_level, implant_type=implant_type, parent_id=parent_id,
            teardown_recipe=teardown_recipe, metadata=metadata)

    async def add_cred(self, masked_label: str, for_host: str | None = None) -> None:
        """Record a captured credential as a MASKED graph node (never the secret)."""
        g = self.graph
        if g is None or not hasattr(g, "add_cred"):
            return
        try:
            await g.add_cred(self.session_id, masked_label, for_host=for_host)
        except Exception:
            pass
