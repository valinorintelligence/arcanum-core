"""F2 (a) — real hardening apply/rollback over SSH (reversible, honest).

Exercised with an injected ssh_runner (no live host / paramiko): we assert the apply
backs up + appends inside removable markers, rollback removes exactly that block, a
failed SSH is reported honestly (never faked), dry-run touches nothing, and no backend
falls back to an honest mock.
"""

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.blue.registry import DeploymentRegistry
from arcanum.blue.hardening import HardeningApplier


class _SSH:
    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []

    async def __call__(self, target, commands):
        self.calls.append((target, commands))
        return {"ok": self.ok, "error": None if self.ok else "ssh boom"}


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "hard.db")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


@pytest.mark.asyncio
async def test_apply_real_backs_up_and_marks_then_rollback_removes(db):
    ssh = _SSH(ok=True)
    applier = HardeningApplier(config=None, registry=DeploymentRegistry(db),
                               session_id="s1", ssh_runner=ssh)
    assert applier._apply_backend_configured() is True  # ssh_runner present
    res = await applier.apply(
        {"config_file": "/etc/ssh/sshd_config", "snippet": "PermitRootLogin no", "benchmark": "CIS"},
        target="10.0.0.9", dry_run=False)
    assert res["mock"] is False and res["status"] == "active" and res["applied"] is True

    target, cmds = ssh.calls[0]
    assert target == "10.0.0.9"
    assert any("cp -n" in c and "sshd_config" in c for c in cmds)              # backup
    assert any("ARCANUM-HARDENING" in c and "printf" in c for c in cmds)        # marked append

    rb = await applier.rollback(res["id"])
    assert rb["success"] is True
    _, rb_cmds = ssh.calls[1]
    assert any("sed -i" in c and "ARCANUM-HARDENING" in c and "sshd_config" in c for c in rb_cmds)


@pytest.mark.asyncio
async def test_failed_ssh_is_honest_not_faked(db):
    ssh = _SSH(ok=False)
    applier = HardeningApplier(config=None, registry=DeploymentRegistry(db), ssh_runner=ssh)
    res = await applier.apply({"config_file": "/etc/x", "snippet": "foo"}, dry_run=False)
    assert res["status"] == "failed" and res["applied"] is False
    assert "error" in res


@pytest.mark.asyncio
async def test_dry_run_default_touches_nothing(db):
    ssh = _SSH()
    applier = HardeningApplier(config=None, registry=DeploymentRegistry(db), ssh_runner=ssh)
    res = await applier.apply({"config_file": "/etc/x", "snippet": "foo"})  # dry_run defaults True
    assert res["status"] == "dry_run" and res["mock"] is True
    assert ssh.calls == []  # nothing was executed


@pytest.mark.asyncio
async def test_no_backend_is_honest_mock(db, monkeypatch):
    monkeypatch.delenv("ARCANUM_HARDENING_SSH_TARGET", raising=False)
    applier = HardeningApplier(config=None, registry=DeploymentRegistry(db))  # no ssh_runner, no target
    assert applier._apply_backend_configured() is False
    res = await applier.apply({"config_file": "/etc/x", "snippet": "foo"}, dry_run=False)
    assert res["mock"] is True and res["status"] == "active"  # tracked for rollback, never claims real
