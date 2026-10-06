"""Unit tests for SandboxManager.execute_stream — the incremental (live) execution
path used by the direct operator console's WebSocket. No Docker needed: the
subprocess is faked so we exercise the queue/sentinel/exit plumbing and the
timeout -> kill path deterministically."""

import asyncio

import pytest

from arcanum.sandbox import docker as docker_mod
from arcanum.sandbox.docker import SandboxManager


class _FakeStream:
    """Yields the given byte chunks once, then EOF (empty bytes)."""
    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, n=-1):
        await asyncio.sleep(0)
        return self._chunks.pop(0) if self._chunks else b""


class _BlockStream:
    """Never produces output in time — forces the timeout branch."""
    async def read(self, n=-1):
        await asyncio.sleep(10)
        return b""


class _FakeProc:
    def __init__(self, out, err, rc=0):
        self.stdout = _FakeStream(out)
        self.stderr = _FakeStream(err)
        self.returncode = None
        self._rc = rc

    def kill(self):
        self.returncode = -9

    async def wait(self):
        self.returncode = self._rc
        return self._rc


@pytest.mark.asyncio
async def test_execute_stream_yields_chunks_then_exit(monkeypatch):
    async def fake_exec(*args, **kwargs):
        return _FakeProc([b"hello\n", b"world\n"], [b"warn\n"], rc=0)

    monkeypatch.setattr(docker_mod.asyncio, "create_subprocess_exec", fake_exec)

    sb = SandboxManager()
    pieces = [p async for p in sb.execute_stream("c1", "echo hi", timeout=5)]

    assert pieces[-1]["stream"] == "exit"
    assert pieces[-1]["exit_code"] == 0
    assert not pieces[-1].get("timed_out")
    out = "".join(p["data"] for p in pieces if p["stream"] == "stdout")
    err = "".join(p["data"] for p in pieces if p["stream"] == "stderr")
    assert "hello" in out and "world" in out
    assert "warn" in err


@pytest.mark.asyncio
async def test_execute_stream_timeout_kills_and_flags(monkeypatch):
    proc = _FakeProc([], [])
    proc.stdout = _BlockStream()
    proc.stderr = _BlockStream()

    async def fake_exec(*args, **kwargs):
        return proc

    killed = {}

    async def fake_kill(self, p, cid, cmd):
        killed["yes"] = True
        p.returncode = -9

    monkeypatch.setattr(docker_mod.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(SandboxManager, "_kill_exec", fake_kill)

    sb = SandboxManager()
    pieces = [p async for p in sb.execute_stream("c1", "sleep 99", timeout=1)]

    assert pieces[-1]["stream"] == "exit"
    assert pieces[-1]["exit_code"] == -1
    assert pieces[-1].get("timed_out") is True
    assert killed.get("yes") is True
