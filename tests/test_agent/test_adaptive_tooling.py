import pytest
from unittest.mock import MagicMock
from arcanum.agent.engine import AgentEngine
from arcanum.agent.tools import _auto_repair_command, _bare_host, ToolExecutor


def test_bare_host_strips_scheme_port_path_keeps_cidr():
    assert _bare_host("host.docker.internal:8080") == "host.docker.internal"
    assert _bare_host("http://host.docker.internal:8080/x") == "host.docker.internal"
    assert _bare_host("10.0.0.5:22") == "10.0.0.5"
    # CIDR must survive (keep_path) — it has no :port to strip.
    assert _bare_host("10.0.0.0/24", keep_path=True) == "10.0.0.0/24"
    assert _bare_host("example.com") == "example.com"


def test_auto_repair_nmap_strips_hostport_target():
    # The real gap: nmap got 'host.docker.internal:8080' and failed to resolve it.
    repaired = _auto_repair_command("nmap -sT -Pn -sV -p 80,443,8080 host.docker.internal:8080")
    assert "host.docker.internal:8080" not in repaired
    assert "host.docker.internal" in repaired
    assert "-p 80,443,8080" in repaired          # the port LIST (flag value) is untouched


def test_auto_repair_nmap_keeps_cidr_and_portlist():
    repaired = _auto_repair_command("nmap -p 22,80 10.0.0.0/24")
    assert "10.0.0.0/24" in repaired and "-p 22,80" in repaired


def test_auto_repair_subfinder_strips_scheme_and_port():
    repaired = _auto_repair_command("subfinder http://host.docker.internal:8080 -silent")
    assert repaired.startswith("subfinder -d host.docker.internal ")
    assert ":8080" not in repaired and "http://" not in repaired


def test_auto_repair_katana_extension_filter_and_limits():
    cmd = "katana http://news.example.com"
    repaired = _auto_repair_command(cmd)
    assert repaired.startswith("katana -u http://news.example.com")
    assert "-d 2" in repaired
    assert "-ct 60s" in repaired
    assert "-fsu" in repaired
    assert "-mdp 50" in repaired
    assert "-ef" in repaired
    assert "png" in repaired


def test_auto_repair_wpscan():
    # Without --url flag and missing scheme
    cmd1 = "wpscan target.com"
    repaired1 = _auto_repair_command(cmd1)
    assert repaired1.startswith("wpscan --url https://target.com")
    assert "--no-banner" in repaired1
    assert "--random-user-agent" in repaired1

    # With --url already specified
    cmd2 = "wpscan --url https://target.com --enumerate vp"
    repaired2 = _auto_repair_command(cmd2)
    assert "--enumerate vp" in repaired2
    assert "--no-banner" in repaired2
    assert "--random-user-agent" in repaired2


@pytest.mark.asyncio
async def test_handle_execute_caps_katana_timeout():
    te = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    # Even if caller passes timeout=600, Katana must be capped to at most 90s
    res = await te._handle_execute("katana -u http://example.com", timeout=600)
    # Since sandbox is None, it returns sandbox indisponivel, but timeout was capped internally
    assert "Sandbox indisponível" in res["stderr"]


def test_recovery_hint_katana_timeout():
    H = AgentEngine._recovery_hint
    # Katana timeout error
    err_res = {"output": {"exit_code": -1, "stderr": "Command timed out after 300s"}}
    hint = H("katana -u http://leouve.com.br", err_res)
    assert hint is not None
    assert "NÃO repita o crawler" in hint
    assert "NÃO aumente o timeout" in hint
    assert "wpscan" in hint or "httpx-toolkit" in hint


def test_pedagogical_explanation_wpscan():
    eng = AgentEngine(llm=None, tool_executor=None,
                      session={"name": "test", "target": "site.com", "mode": "autopilot"})
    exp = eng._explain_tool_action("execute", {"command": "wpscan --url https://site.com --enumerate vp,u"})
    assert "what" in exp and "WPScan" in exp["what"]
    assert "why" in exp and "plugins" in exp["why"]
    assert "params" in exp and "--enumerate vp" in exp["params"]


def test_tactical_guidance_wordpress():
    eng = AgentEngine(llm=None, tool_executor=None,
                      session={"name": "test", "target": "leouve.com.br", "mode": "autopilot"})
    eng.current_phase = "analysis"
    # Simulate user or memory mentioning plugins / wordpress
    eng.messages = [{"role": "user", "content": "encontre plugins que deixam portas abertas"}]
    
    guidance = eng._get_tactical_technology_guidance()
    assert guidance is not None
    assert guidance["signature"] == "wordpress_analysis"
    assert "wpscan" in guidance["directive"]
    assert "/wp-json/wp/v2/users" in guidance["directive"]
    assert "NUNCA execute crawlers abertos" in guidance["directive"]


def test_tactical_guidance_cloudflare():
    eng = AgentEngine(llm=None, tool_executor=None,
                      session={"name": "test", "target": "leouve.com.br", "mode": "autopilot"})
    eng.current_phase = "recon"
    # Simulate Cloudflare in recent messages
    eng.messages = [{"role": "tool", "content": "80/tcp open http Cloudflare http proxy"}]
    
    guidance = eng._get_tactical_technology_guidance()
    assert guidance is not None
    assert guidance["signature"] == "cloudflare_recon"
    assert "Cloudflare" in guidance["summary"]
    assert "subdomínios" in guidance["directive"]


def test_tactical_guidance_web_probe_in_analysis():
    eng = AgentEngine(llm=None, tool_executor=None,
                      session={"name": "test", "target": "app.example.com", "mode": "autopilot"})
    eng.current_phase = "analysis"
    eng.messages = [{"role": "user", "content": "analise o alvo"}]
    
    guidance = eng._get_tactical_technology_guidance()
    assert guidance is not None
    assert guidance["signature"] == "web_probe_analysis"
    assert "httpx-toolkit" in guidance["directive"]
