import pytest
from arcanum.agent.engine import AgentEngine


def test_extract_target_hosts_ignores_dns_resolvers():
    engine = AgentEngine(llm=None, tool_executor=None, session={"name": "test", "target": "leouve.com.br"})
    
    # dig query specifying Google Public DNS @8.8.8.8
    cmd = "dig @8.8.8.8 leouve.com.br A +short"
    hosts = engine._extract_target_hosts(cmd)
    
    # 8.8.8.8 should NOT be extracted as a target host
    assert "8.8.8.8" not in hosts
    assert "leouve.com.br" in hosts


def test_auto_repair_target_arguments():
    engine = AgentEngine(llm=None, tool_executor=None, session={"name": "test", "target": "leouve.com.br"})
    
    # Model accidentally copied example from documentation schema
    raw_args = {
        "url": "https://corp.com.br/admin",
        "domain": "corp.com.br",
        "custom_paths": ["https://corp.com.br/api", "https://example.com/v1"]
    }
    repaired = engine._auto_repair_target_arguments("audit_waf_bypass_heuristics", raw_args)
    
    assert repaired["url"] == "https://leouve.com.br/admin"
    assert repaired["domain"] == "leouve.com.br"
    assert repaired["custom_paths"] == ["https://leouve.com.br/api", "https://leouve.com.br/v1"]


def test_scope_violation_with_repaired_args():
    engine = AgentEngine(llm=None, tool_executor=None, session={"name": "test", "target": "leouve.com.br"})
    
    # Raw args with placeholder
    raw_args = {"url": "https://corp.com.br/login"}
    repaired = engine._auto_repair_target_arguments("audit_security_headers", raw_args)
    
    # After auto-repair, it should not violate scope
    violation = engine._scope_violation("audit_security_headers", repaired)
    assert violation is None


def test_auto_repair_infrastructure_ips_and_aliases():
    engine = AgentEngine(llm=None, tool_executor=None, session={"name": "test", "target": "leouve.com.br"})
    
    # Model hallucinated 8.8.8.8 for reputation check
    dnsbl_args = {"target": "8.8.8.8"}
    repaired_dnsbl = engine._auto_repair_target_arguments("audit_dnsbl_reputation", dnsbl_args)
    assert repaired_dnsbl["target"] == "leouve.com.br"
    
    # Model passed hostname with URL prefix to audit_tls_ssl
    tls_args = {"hostname": "https://leouve.com.br/path"}
    repaired_tls = engine._auto_repair_target_arguments("audit_tls_ssl", tls_args)
    assert repaired_tls["host"] == "leouve.com.br"
    assert "hostname" not in repaired_tls
    
    # Model passed bare target to audit_security_headers
    headers_args = {"target": "leouve.com.br"}
    repaired_headers = engine._auto_repair_target_arguments("audit_security_headers", headers_args)
    assert repaired_headers["url"] == "https://leouve.com.br"
    assert "target" not in repaired_headers


def test_detect_explicit_requested_tools_and_summary():
    prompt = "Arcanum, verifique os cabeçalhos de segurança HTTP e o certificado SSL de https://leouve.com.br e me mostre o resumo em português."
    explicit = AgentEngine._detect_explicit_requested_tools(prompt)
    assert "audit_security_headers" in explicit
    assert "audit_tls_ssl" in explicit
    assert AgentEngine._user_requested_summary(prompt) is True

