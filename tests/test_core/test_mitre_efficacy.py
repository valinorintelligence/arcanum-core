"""Unit tests for MITRE ATT&CK Matrix & Defensive Efficacy Engine (Picus-Style BAS)."""
import pytest
from arcanum.mitre.database import DEFAULT_MITRE_TECHNIQUES
from arcanum.mitre.engine import MitreEfficacyEngine
from arcanum.mitre.models import DefenseStatus, TacticEnum, TechniqueEvaluation
from arcanum.agent.tools import ToolExecutor


def test_default_mitre_techniques_database():
    """Verify that default MITRE techniques cover the matrix and contain Sigma rules."""
    assert len(DEFAULT_MITRE_TECHNIQUES) >= 15
    tactics = {t.tactic for t in DEFAULT_MITRE_TECHNIQUES}
    assert len(tactics) >= 10

    # Ensure all techniques have valid IDs, descriptions, and remediation guidance
    for tech in DEFAULT_MITRE_TECHNIQUES:
        assert tech.technique_id.startswith("T")
        assert len(tech.name) > 0
        assert len(tech.description) > 0
        assert len(tech.remediation_guidance) > 0
        if tech.sigma_rule_yaml:
            assert "title:" in tech.sigma_rule_yaml
            assert "detection:" in tech.sigma_rule_yaml


def test_mitre_engine_matrix_and_initial_state():
    """Test initial state of the matrix before any simulation."""
    engine = MitreEfficacyEngine()
    matrix_data = engine.get_matrix()

    assert "matrix" in matrix_data
    assert "tactics_summary" in matrix_data
    assert matrix_data["total_techniques"] >= 15
    assert matrix_data["tested_techniques"] == 0
    assert matrix_data["prevention_rate"] == 0.0
    assert matrix_data["overall_efficacy_score"] == 0.0


def test_mitre_engine_evaluate_single_technique():
    """Test evaluating a single technique manually."""
    engine = MitreEfficacyEngine()
    updated = engine.evaluate_technique(
        technique_id="T1190",
        status=DefenseStatus.BLOCKED,
        prevention_control="Cloudflare WAF Custom Rule",
        execution_log="Blocked with HTTP 403 Forbidden.",
    )
    assert updated is not None
    assert updated.status == DefenseStatus.BLOCKED
    assert updated.prevention_control == "Cloudflare WAF Custom Rule"
    assert "403" in updated.execution_log
    assert updated.simulated_at is not None

    # Check efficacy calculation
    report = engine.calculate_efficacy()
    assert report.tested_techniques == 1
    assert report.blocked_count == 1
    assert report.prevention_rate == 100.0
    assert report.overall_efficacy_score == 60.0  # 100 * 0.6 + 0 * 0.4 = 60.0


def test_mitre_engine_simulate_campaign_full_adversary():
    """Test executing a full adversary simulation campaign."""
    engine = MitreEfficacyEngine()
    report = engine.simulate_campaign(
        target_name="Fintech Banking Network",
        scenario="full_adversary",
    )

    assert report.campaign_id.startswith("bas-")
    assert report.target_environment == "Fintech Banking Network"
    assert report.tested_techniques >= 15
    assert report.blocked_count > 0
    assert report.detected_count > 0
    assert report.missed_count > 0

    # Validate Picus formula: score = (prevention * 0.6) + (detection * 0.4)
    expected_score = round((report.prevention_rate * 0.6) + (report.detection_rate * 0.4), 1)
    assert abs(report.overall_efficacy_score - expected_score) < 0.2

    # Validate critical gaps sorting
    assert len(report.critical_gaps) > 0
    for gap in report.critical_gaps:
        assert gap.status == DefenseStatus.MISSED

    # Validate tactics breakdown
    assert len(report.tactics_breakdown) == len(TacticEnum)
    recon = next(t for t in report.tactics_breakdown if t.tactic == TacticEnum.RECONNAISSANCE)
    assert recon.total_techniques > 0


def test_mitre_engine_map_findings_to_mitre():
    """Test automatic mapping of Arcanum vulnerability findings to MITRE ATT&CK techniques."""
    engine = MitreEfficacyEngine()
    findings = [
        {"title": "SQL Injection in /api/v1/checkout", "category": "web", "status": "CONFIRMED"},
        {"title": "Kerberoasting Vulnerability in SPN MSSQL", "category": "identity", "status": "VERIFYING"},
        {"title": "LSASS Memory Dump Unprotected", "category": "endpoint", "status": "CONFIRMED"},
    ]

    mapped = engine.map_findings_to_mitre(findings)
    assert len(mapped) == 3

    # T1190 mapped from SQLi
    t1190 = engine.get_technique("T1190")
    assert t1190.status == DefenseStatus.MISSED

    # T1558.003 mapped from Kerberoast
    t1558 = engine.get_technique("T1558.003")
    assert t1558.status == DefenseStatus.DETECTED


def test_mitre_engine_get_remediation():
    """Test retrieving Sigma detection rules and Blue Team playbooks."""
    engine = MitreEfficacyEngine()
    rem = engine.get_remediation("T1059.001")

    assert rem is not None
    assert rem["technique_id"] == "T1059.001"
    assert rem["name"] == "Command and Scripting Interpreter: PowerShell"
    assert "Script Block Logging" in rem["remediation_guidance"]
    assert "title: Obfuscated PowerShell EncodedCommand Execution" in rem["sigma_rule_yaml"]


@pytest.mark.asyncio
async def test_agent_tool_executor_evaluate_defensive_efficacy():
    """Test integration of evaluate_defensive_efficacy with ReAct ToolExecutor."""
    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    assert "evaluate_defensive_efficacy" in executor._handlers

    result = await executor.execute_tool(
        "evaluate_defensive_efficacy",
        {
            "target_environment": "Cloud Production VPC",
            "scenario": "full_adversary",
        },
    )

    assert result.get("success") is True
    output = result.get("output", {})
    assert "campaign_id" in output
    assert output["overall_efficacy_score"] > 0
    assert output["prevention_rate"] > 0
    assert len(output["critical_gaps"]) > 0
    assert "Campanha BAS concluída com Score Picus" in output["summary"]
