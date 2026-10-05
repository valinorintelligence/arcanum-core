"""Hardening applier (F2): apply a hardening baseline safely, reversibly.

Flow: **dry-run → diff → (approve) → apply → verify**, with rollback. Input is the
output of ``generate_hardening_baseline`` (``config_file`` + ``snippet``).

Dry-run (the default) records the proposed change as ``dry_run`` WITHOUT touching
anything. A real apply (F2 a) uses an **SSH backend** (`ARCANUM_HARDENING_SSH_TARGET`
+ creds, requires `paramiko`): it backs up the file and appends the snippet inside
``# ARCANUM-HARDENING <id> START/END`` markers, so rollback removes exactly that block
(or restores the backup). With no backend configured the apply is an **honest mock**
(``mock=True``) — tracked for rollback but never claims it mutated a live host.
"""
from __future__ import annotations

import os
import shlex
import uuid
from typing import Any


class HardeningApplier:
    def __init__(self, config: Any = None, registry: Any = None,
                 session_id: str | None = None, engagement_id: str | None = None,
                 ssh_runner: Any = None):
        self.config = config
        self.registry = registry
        self.session_id = session_id
        self.engagement_id = engagement_id
        # Injectable async SSH runner `ssh_runner(target, commands) -> {ok, error, ...}`
        # for tests / custom backends; when set it replaces the paramiko path.
        self._ssh_runner = ssh_runner

    # -- SSH backend --------------------------------------------------------

    def _ssh_params(self) -> dict:
        c = self.config

        def cfg(name, default=""):
            return getattr(c, name, default) if c else default
        return {
            "target": cfg("hardening_ssh_target") or os.environ.get("ARCANUM_HARDENING_SSH_TARGET", ""),
            "user": cfg("hardening_ssh_user") or os.environ.get("ARCANUM_HARDENING_SSH_USER", ""),
            "key": cfg("hardening_ssh_key") or os.environ.get("ARCANUM_HARDENING_SSH_KEY", ""),
            "password": cfg("hardening_ssh_password") or os.environ.get("ARCANUM_HARDENING_SSH_PASSWORD", ""),
            "port": int(cfg("hardening_ssh_port", 22) or os.environ.get("ARCANUM_HARDENING_SSH_PORT", 22) or 22),
        }

    def _apply_backend_configured(self) -> bool:
        if self._ssh_runner is not None:
            return True
        return bool(self._ssh_params()["target"])

    async def _ssh(self, target: str, commands: list[str]) -> dict:
        if self._ssh_runner is not None:
            return await self._ssh_runner(target, commands)
        import asyncio
        return await asyncio.to_thread(self._ssh_sync, target, commands)

    def _ssh_sync(self, target: str, commands: list[str]) -> dict:
        try:
            import paramiko
        except Exception:
            return {"ok": False, "error": "SSH backend requires paramiko (pip install paramiko)"}
        p = self._ssh_params()
        host = target or p["target"]
        if not host:
            return {"ok": False, "error": "no SSH target configured (ARCANUM_HARDENING_SSH_TARGET)"}
        user = p["user"]
        if "@" in host and not user:
            user, host = host.split("@", 1)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            kwargs = {"hostname": host, "port": p["port"], "timeout": 20}
            if user:
                kwargs["username"] = user
            if p["key"]:
                kwargs["key_filename"] = p["key"]
            if p["password"]:
                kwargs["password"] = p["password"]
            client.connect(**kwargs)
            steps = []
            for cmd in commands:
                _in, out, err = client.exec_command(cmd, timeout=60)
                rc = out.channel.recv_exit_status()
                steps.append({"cmd": cmd, "rc": rc,
                              "stdout": out.read().decode("utf-8", "ignore")[:2000],
                              "stderr": err.read().decode("utf-8", "ignore")[:2000]})
                if rc != 0:
                    return {"ok": False, "error": f"command failed (rc={rc}): {steps[-1]['stderr'][:300]}",
                            "steps": steps}
            return {"ok": True, "steps": steps}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            try:
                client.close()
            except Exception:
                pass

    # -- diff / apply / verify / rollback -----------------------------------

    @staticmethod
    def _build_diff(config_file: str, snippet: str) -> str:
        lines = [f"--- {config_file} (current)",
                 f"+++ {config_file} (proposed by Arcanum hardening)"]
        for ln in (snippet or "").splitlines():
            lines.append(f"+{ln}")
        return "\n".join(lines)

    async def apply(self, baseline: dict, target: str = "", dry_run: bool = True) -> dict:
        config_file = baseline.get("config_file") or "/etc/hardening.conf"
        snippet = baseline.get("snippet") or baseline.get("content") or ""
        benchmark = baseline.get("benchmark") or "custom"
        diff = self._build_diff(config_file, snippet)
        name = f"{benchmark} → {config_file}"
        eff_target = target or self._ssh_params()["target"]

        if dry_run:
            rec = await self.registry.record(
                kind="hardening", target_system="host", rule_type="host-hardening",
                name=name, status="dry_run", mock=True,
                payload={"config_file": config_file, "snippet": snippet, "diff": diff,
                         "target": eff_target, "benchmark": benchmark},
                session_id=self.session_id, engagement_id=self.engagement_id)
            return {"id": rec["id"], "status": "dry_run", "applied": False, "mock": True,
                    "config_file": config_file, "diff": diff, "benchmark": benchmark,
                    "note": "Dry-run: nada foi alterado. Aprove e chame com dry_run=false para aplicar."}

        mock = not self._apply_backend_configured()
        status = "active"
        error = None
        apply_meta: dict = {}
        marker = uuid.uuid4().hex[:12]
        if not mock:
            try:
                apply_meta = await self._apply_real(config_file, snippet, eff_target, marker) or {}
            except Exception as exc:
                status, error = "failed", str(exc)
        rec = await self.registry.record(
            kind="hardening", target_system="host", rule_type="host-hardening",
            name=name, status=status, mock=mock,
            payload={"config_file": config_file, "snippet": snippet, "diff": diff,
                     "target": eff_target, "benchmark": benchmark, "error": error,
                     "marker": apply_meta.get("marker"), "backup": apply_meta.get("backup")},
            session_id=self.session_id, engagement_id=self.engagement_id)
        out = {"id": rec["id"], "status": status, "applied": status == "active",
               "mock": mock, "config_file": config_file, "benchmark": benchmark}
        if error:
            out["error"] = error
        return out

    async def verify(self, deployment_id: str) -> dict:
        rec = await self.registry.get(deployment_id)
        if not rec:
            return {"active": False, "status": "not_found", "deployment_id": deployment_id}
        active = rec["status"] == "active"
        await self.registry.mark_verified(deployment_id, active)
        return {"active": active, "status": rec["status"], "mock": rec["mock"],
                "deployment_id": deployment_id}

    async def rollback(self, deployment_id: str) -> dict:
        rec = await self.registry.get(deployment_id)
        if not rec:
            return {"success": False, "status": "not_found", "deployment_id": deployment_id}
        if not rec["mock"]:
            try:
                await self._rollback_real(rec)
            except Exception as exc:
                return {"success": False, "error": str(exc), "deployment_id": deployment_id}
        await self.registry.mark_rolled_back(deployment_id)
        return {"success": True, "status": "rolled_back", "mock": rec["mock"],
                "deployment_id": deployment_id}

    async def _apply_real(self, config_file: str, snippet: str, target: str, marker: str) -> dict:
        """Back up the file and append the snippet inside removable markers (reversible).
        Returns rollback metadata {marker, backup}. Raises on SSH failure (never fakes)."""
        backup = f"{config_file}.arcanum-{marker}.bak"
        block = (f"\n# ARCANUM-HARDENING {marker} START\n{snippet}\n"
                 f"# ARCANUM-HARDENING {marker} END\n")
        cmds = [
            f"cp -n {shlex.quote(config_file)} {shlex.quote(backup)} 2>/dev/null || true",
            f"printf %s {shlex.quote(block)} >> {shlex.quote(config_file)}",
        ]
        res = await self._ssh(target, cmds)
        if not res.get("ok"):
            raise RuntimeError(res.get("error") or "SSH hardening apply failed")
        return {"marker": marker, "backup": backup}

    async def _rollback_real(self, rec: dict) -> None:
        payload = rec.get("payload") or {}
        cfg = payload.get("config_file")
        marker = payload.get("marker")
        target = payload.get("target")
        if not cfg:
            raise RuntimeError("no config_file in deployment payload for rollback")
        if marker:
            cmd = (f"sed -i '/# ARCANUM-HARDENING {marker} START/,"
                   f"/# ARCANUM-HARDENING {marker} END/d' {shlex.quote(cfg)}")
        elif payload.get("backup"):
            cmd = f"cp {shlex.quote(payload['backup'])} {shlex.quote(cfg)}"
        else:
            raise RuntimeError("no rollback metadata (marker/backup) in payload")
        res = await self._ssh(target, [cmd])
        if not res.get("ok"):
            raise RuntimeError(res.get("error") or "SSH hardening rollback failed")
