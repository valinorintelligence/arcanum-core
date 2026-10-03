import pytest
import json
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock
from arcanum.agent.engine import AgentEngine
from arcanum.agent.tools import ToolExecutor, get_tools_for_phase, REPORT_TOOLS, EXPLOIT_TOOLS


@pytest.mark.asyncio
async def test_auto_ingest_native_findings():
    db_mock = MagicMock()
    db_mock.execute = AsyncMock()
    te = ToolExecutor(sandbox=MagicMock(), browser=MagicMock(), workspace_dir=Path("tmp"), db=db_mock, session_id="test-session")
    llm_mock = MagicMock()
    session = {"id": "test-session", "target": "38.3.132.211", "name": "test"}

    engine = AgentEngine(llm=llm_mock, tool_executor=te, session=session)

    # 1. Ingest security headers
    headers_result = {
        "status_code": 200,
        "score": 0,
        "grade": "F",
        "missing_headers": [
            {"header": "Content-Security-Policy", "severity": "high", "description": "CSP missing", "remediation": "Add CSP"},
            {"header": "Strict-Transport-Security", "severity": "medium", "description": "HSTS missing", "remediation": "Add HSTS"},
            {"header": "X-Frame-Options", "severity": "medium", "description": "XFO missing", "remediation": "Add XFO"},
            {"header": "X-Content-Type-Options", "severity": "low", "description": "XCTO missing", "remediation": "Add XCTO"},
        ]
    }
    ingested = await engine._auto_ingest_native_findings("audit_security_headers", {"url": "https://38.3.132.211"}, headers_result)
    # Should ingest high and medium (3 items), skip low (1 item)
    assert len(ingested) == 3
    assert engine.findings_count == 3

    # 2. Ingest DNS email security
    dns_result = {
        "domain": "38.3.132.211",
        "score": 25,
        "grade": "F",
        "findings": [
            {"record": "DMARC", "severity": "high", "issue": "DMARC record missing", "impact": "Spoofing", "recommendation": "Add DMARC"},
            {"record": "SPF", "severity": "high", "issue": "SPF record missing", "impact": "Spoofing", "recommendation": "Add SPF"},
        ]
    }
    ingested_dns = await engine._auto_ingest_native_findings("audit_dns_email_security", {"domain": "38.3.132.211"}, dns_result)
    assert len(ingested_dns) == 2
    assert engine.findings_count == 5


def test_phase_tools_scoping():
    recon_tools = get_tools_for_phase("recon")
    analysis_tools = get_tools_for_phase("analysis")
    exploit_tools = get_tools_for_phase("exploit")
    report_tools = get_tools_for_phase("report")

    recon_names = {t["function"]["name"] for t in recon_tools}
    report_names = {t["function"]["name"] for t in report_tools}

    assert "audit_sbom_dependencies" in {t["function"]["name"] for t in analysis_tools}
    assert "audit_sbom_dependencies" not in report_names
    assert "audit_security_headers" not in report_names
    assert "create_finding" in report_names
    assert "calculate_breach_risk_cost" in report_names
    assert len(report_tools) == len(REPORT_TOOLS)
    assert len(exploit_tools) == len(EXPLOIT_TOOLS)
