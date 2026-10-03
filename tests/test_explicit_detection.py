import pytest
from arcanum.agent.engine import AgentEngine

def test_detect_explicit_tools_with_ddns_domain():
    p1 = "Arcanum, execute o Passo 1 da Campanha Blue Team: chame a ferramenta audit_tls_ssl(host='analysislaudo.ddns.net') para auditar o certificado SSL/TLS, cadeia de confiança e suporte a TLS 1.3, verificando cifras fracas e gerando o parecer técnico."
    t1 = AgentEngine._detect_explicit_requested_tools(p1)
    assert t1 == ["audit_tls_ssl"], f"Expected ['audit_tls_ssl'], got {t1}"

    p2 = "Arcanum, execute o Passo 2 da Campanha Blue Team: chame a ferramenta audit_security_headers(url='https://analysislaudo.ddns.net')"
    t2 = AgentEngine._detect_explicit_requested_tools(p2)
    assert t2 == ["audit_security_headers"], f"Expected ['audit_security_headers'], got {t2}"

    p3 = "Arcanum, execute o Passo 3 da Campanha Blue Team: chame a ferramenta audit_dns_email_security(domain='analysislaudo.ddns.net')"
    t3 = AgentEngine._detect_explicit_requested_tools(p3)
    assert t3 == ["audit_dns_email_security"], f"Expected ['audit_dns_email_security'], got {t3}"

    p4 = "Arcanum, execute o Passo 4 da Campanha Blue Team: chame a ferramenta detect_waf_firewall(url='https://analysislaudo.ddns.net')"
    t4 = AgentEngine._detect_explicit_requested_tools(p4)
    assert t4 == ["detect_waf_firewall"], f"Expected ['detect_waf_firewall'], got {t4}"

def test_detect_explicit_dns_when_explicitly_requested():
    p = "verifique os registros dns e spf do servidor"
    t = AgentEngine._detect_explicit_requested_tools(p)
    assert "audit_dns_email_security" in t
