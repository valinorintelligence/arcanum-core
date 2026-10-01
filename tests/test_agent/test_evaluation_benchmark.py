"""Comprehensive Evaluation Benchmark Test Suite for Arcanum Agent and Tools."""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

from arcanum.agent.tools import _auto_repair_command, ToolExecutor
from arcanum.agent.engine import AgentEngine
from arcanum.sandbox.docker import SandboxManager


# ===========================================================================
# 1. EVALUATION: CLI Syntax Auto-Repair Engine
# ===========================================================================

def test_eval_auto_repair_subfinder():
    # Target without -d
    cmd = "subfinder smartia-n8n-evolution-api.dvw0ld.easypanel.host"
    repaired = _auto_repair_command(cmd)
    assert repaired == "subfinder -d smartia-n8n-evolution-api.dvw0ld.easypanel.host"

    # Already has -d
    cmd_with_d = "subfinder -d example.com"
    assert _auto_repair_command(cmd_with_d) == "subfinder -d example.com"

    # With extra arguments
    cmd_all = "subfinder target.com -all -silent"
    assert _auto_repair_command(cmd_all) == "subfinder -d target.com -all -silent"


def test_eval_auto_repair_httpx():
    # Target without -u
    cmd = "httpx example.com"
    repaired = _auto_repair_command(cmd)
    assert repaired == "httpx -u example.com"

    # Already has -u
    cmd_u = "httpx -u https://example.com -status-code"
    assert _auto_repair_command(cmd_u) == "httpx -u https://example.com -status-code"


def test_eval_auto_repair_nuclei():
    # Target without -u
    cmd = "nuclei example.com -severity critical,high"
    repaired = _auto_repair_command(cmd)
    assert repaired == "nuclei -u example.com -severity critical,high"


def test_eval_auto_repair_katana():
    # Target without -u
    cmd = "katana http://example.com"
    repaired = _auto_repair_command(cmd)
    assert repaired == "katana -u http://example.com"


def test_eval_auto_repair_nmap_pn():
    # Nmap without -Pn gets -Pn (firewall ping-drop false negatives) AND, when
    # no scan type is given, -sT (the unprivileged sandbox can't open raw
    # sockets, so nmap's default SYN scan fails with "Operation not permitted").
    cmd = "nmap -sV -p 80,443 example.com"
    repaired = _auto_repair_command(cmd)
    assert "-Pn" in repaired
    assert "-sT" in repaired  # forced connect scan (no raw sockets as nobody)
    assert "80,443" in repaired

    # Already has -Pn: still forces -sT since no scan type was specified
    repaired_pn = _auto_repair_command("nmap -Pn -sV -p 80 example.com")
    assert "-sT" in repaired_pn and "-Pn" in repaired_pn
    assert repaired_pn.count("-Pn") == 1  # not duplicated


# ===========================================================================
# 2. EVALUATION: LLM Tool Call Normalizer & Text Fallback Extractor
# ===========================================================================

def test_eval_extract_tool_call_run_alias():
    sample = """Entendido, vamos iniciar o reconhecimento.
```json
{"name": "run", "arguments": {"command": "subfinder smartia.domain.com"}}
```
"""
    calls = AgentEngine._extract_tool_calls_from_text(sample)
    assert len(calls) == 1
    assert calls[0]["function"]["name"] == "execute"
    assert calls[0]["function"]["arguments"]["command"] == "subfinder -d smartia.domain.com"


def test_eval_extract_tool_call_known_binary():
    sample = """
```json
{"name": "subfinder", "arguments": {"domain": "target.local"}}
```
"""
    calls = AgentEngine._extract_tool_calls_from_text(sample)
    assert len(calls) == 1
    assert calls[0]["function"]["name"] == "execute"
    assert calls[0]["function"]["arguments"]["command"] == "subfinder -d target.local"


def test_eval_extract_tool_call_inline_command():
    sample = 'Vou verificar as portas: {"command": "nmap -sV -p 80,443 192.168.1.1"}'
    calls = AgentEngine._extract_tool_calls_from_text(sample)
    assert len(calls) == 1
    assert calls[0]["function"]["name"] == "execute"
    assert "192.168.1.1" in calls[0]["function"]["arguments"]["command"]


def test_eval_extract_native_tool_call():
    sample = 'Consultando memoria: {"name": "read_memory", "arguments": {"section": "target_map"}}'
    calls = AgentEngine._extract_tool_calls_from_text(sample)
    assert len(calls) == 1
    assert calls[0]["function"]["name"] == "read_memory"
    assert calls[0]["function"]["arguments"]["section"] == "target_map"


# ===========================================================================
# 3. EVALUATION: Pedagogical Explanation Generator
# ===========================================================================

def test_eval_pedagogical_explanations():
    engine = AgentEngine(llm=MagicMock(), tool_executor=MagicMock(), session={"target": "test.target.com"})

    # Check nmap explanation
    exp_nmap = engine._explain_shell_command("nmap -sV -p 80,443 test.target.com", "test.target.com")
    assert "what" in exp_nmap and "Nmap" in exp_nmap["what"]
    assert "why" in exp_nmap and "test.target.com" in exp_nmap["why"]
    assert "params" in exp_nmap and "-sV" in exp_nmap["params"]

    # Check subfinder explanation
    exp_sub = engine._explain_shell_command("subfinder -d test.target.com", "test.target.com")
    assert "Subfinder" in exp_sub["what"]
    assert "test.target.com" in exp_sub["why"]
    assert "-d" in exp_sub["params"]

    # Check native read_memory explanation
    exp_mem = engine._explain_tool_action("read_memory", {"section": "target_map"})
    assert "target_map" in exp_mem["what"]
    assert "why" in exp_mem
    assert "params" in exp_mem


# ===========================================================================
# 4. EVALUATION: Living Memory Auto-Update & Persistence
# ===========================================================================

def test_eval_living_memory_initialization(tmp_path):
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=tmp_path, db=None)

    nmap_scan_output = """
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-01 17:17 UTC
Nmap scan report for test-target.com (72.61.34.133)
Host is up (0.010s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Golang net/http server
443/tcp open  ssl/http Golang net/http server

Nmap done: 1 IP address scanned.
"""
    # Trigger auto-update
    executor._auto_update_target_map(nmap_scan_output)

    target_map_file = tmp_path / "wiki" / "TARGET_MAP.md"
    assert target_map_file.exists(), "TARGET_MAP.md should be automatically created!"

    content = target_map_file.read_text(encoding="utf-8")
    assert "# Target Map" in content
    assert "80/tcp" in content
    assert "443/tcp" in content
    assert "Golang net/http server" in content

    # Test deduplication: parsing the same output again should not duplicate rows
    initial_len = len(content.splitlines())
    executor._auto_update_target_map(nmap_scan_output)
    second_len = len(target_map_file.read_text(encoding="utf-8").splitlines())
    assert initial_len == second_len, "Duplicate ports should not be added multiple times"


# ===========================================================================
# 5. EVALUATION: Docker Sandbox Security & Capability Settings
# ===========================================================================

@pytest.mark.asyncio
async def test_eval_docker_container_config(tmp_path, monkeypatch):
    """The sandbox MUST be hardened: non-root, no capabilities, no privilege
    escalation. A TCP connect scan (nmap -sT -sV) works fine under this profile
    (validated in-container), so running as root with NET_RAW/NET_ADMIN is
    both unnecessary and a container-escape risk."""
    sandbox = SandboxManager()

    captured_cmd = []

    async def mock_subprocess_exec(*args, **kwargs):
        captured_cmd.extend(args)
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"container-id-12345\n", b"")
        return mock_proc

    monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess_exec)

    cid = await sandbox.create_container(tmp_path)
    assert cid == "container-id-12345"

    cmd_str = " ".join(captured_cmd)
    # Hardening requirements
    assert "--user nobody" in cmd_str, "Sandbox must NOT run as root"
    assert "no-new-privileges" in cmd_str, "Must set no-new-privileges"
    assert "--cap-drop=ALL" in cmd_str, "Must drop all Linux capabilities"
    assert "--pids-limit" in cmd_str, "Must cap process count"
    # Explicitly reject the previously-regressed insecure flags
    assert "--user root" not in cmd_str, "Regression: sandbox running as root"
    assert "NET_ADMIN" not in cmd_str, "Regression: gratuitous NET_ADMIN capability"


@pytest.mark.asyncio
async def test_eval_nmap_syn_downgraded_to_connect():
    """Unprivileged sandbox can't open raw sockets, so -sS must be rewritten to
    -sT so scans don't fail with 'Operation not permitted'."""
    repaired = _auto_repair_command("nmap -sS -sV -p 80,443 example.com")
    assert "-sS" not in repaired and "-sT" in repaired
    assert "-Pn" in repaired and "80,443" in repaired


@pytest.mark.integration
@pytest.mark.asyncio
async def test_integration_nmap_connect_scan_as_nobody(tmp_path):
    """REAL end-to-end proof: a connect+version scan runs inside the hardened
    (non-root, cap-drop ALL) sandbox and detects a service. Skips cleanly if
    Docker or the sandbox image is unavailable (e.g. CI without the image)."""
    import shutil
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    sandbox = SandboxManager()
    if not await sandbox.ensure_image():
        pytest.skip("arcanum-sandbox image not built")
    cid = await sandbox.create_container(tmp_path)
    try:
        # Loopback target only — no external traffic. 127.0.0.1 is inside the
        # container's own netns, so nothing leaves the host.
        res = await sandbox.execute(cid, "nmap -sT -p 22,80 -Pn 127.0.0.1", timeout=60)
        assert res.exit_code == 0, f"nmap failed under hardened profile: {res.stderr}"
        assert "Operation not permitted" not in res.stderr
        assert "PORT" in res.stdout and "127.0.0.1" in res.stdout
    finally:
        await sandbox.cleanup()
