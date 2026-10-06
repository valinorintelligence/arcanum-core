"""Unit tests for the Active Directory & Identity Graph Analyzer (BloodHound / Pentera Engine)."""

import pytest
from arcanum.identity.analyzer import ADIdentityAnalyzer


@pytest.fixture
def identity_analyzer(tmp_path):
    db_file = tmp_path / "test_identity.db"
    return ADIdentityAnalyzer(db_path=str(db_file))


@pytest.fixture
def populated_analyzer(identity_analyzer):
    # Setup a realistic corporate AD environment
    objects = [
        {"sid": "S-1-5-21-500", "name": "Administrator", "object_type": "user", "is_tier_zero": True, "is_admin": True},
        {"sid": "S-1-5-21-512", "name": "Domain Admins", "object_type": "group", "is_tier_zero": True, "is_admin": True},
        {"sid": "S-1-5-21-1001", "name": "carlos.estagiario", "object_type": "user", "is_tier_zero": False},
        {"sid": "S-1-5-21-1002", "name": "Grupo Suporte TI", "object_type": "group", "is_tier_zero": False},
        {"sid": "S-1-5-21-1003", "name": "SRV-PRINT-01", "object_type": "computer", "is_tier_zero": False},
        {"sid": "S-1-5-21-1004", "name": "svc-sql-prod", "object_type": "user", "has_spn": True, "metadata": {"spn": "MSSQLSvc/db01.corp:1433"}},
        {"sid": "S-1-5-21-1005", "name": "legado.vpn", "object_type": "user", "dont_req_preauth": True},
        {"sid": "S-1-5-21-1006", "name": "backup.operator", "object_type": "user", "is_tier_zero": False},
    ]

    edges = [
        # Chain 1: carlos -> Suporte TI -> SRV-PRINT -> Domain Admins
        {"source": "S-1-5-21-1001", "target": "S-1-5-21-1002", "rel": "ForceChangePassword"},
        {"source": "S-1-5-21-1002", "target": "S-1-5-21-1003", "rel": "AdminTo"},
        {"source": "S-1-5-21-1003", "target": "S-1-5-21-512", "rel": "GenericAll"},

        # Chain 2: backup.operator -> Suporte TI (shares choke point!)
        {"source": "S-1-5-21-1006", "target": "S-1-5-21-1002", "rel": "MemberOf"},

        # DCSync edge directly to domain root / Tier zero
        {"source": "S-1-5-21-500", "target": "S-1-5-21-512", "rel": "MemberOf"},
        {"source": "S-1-5-21-512", "target": "S-1-5-21-500", "rel": "DCSync"},
    ]

    identity_analyzer.ingest_domain(
        domain_name="corp.local",
        objects_data=objects,
        edges_data=edges,
    )
    return identity_analyzer


def test_ingest_domain_and_tier_zero_detection(populated_analyzer):
    analyzer = populated_analyzer
    domain_id = "dom-corp-local"

    assert domain_id in analyzer.domains
    domain_info = analyzer.domains[domain_id]
    assert domain_info["name"] == "corp.local"

    # Verify auto-detection of Tier Zero
    da_obj = analyzer.objects["S-1-5-21-512"]
    assert da_obj.is_tier_zero is True
    assert da_obj.name == "Domain Admins"

    admin_obj = analyzer.objects["S-1-5-21-500"]
    assert admin_obj.is_tier_zero is True


def test_find_attack_paths_to_tier_zero(populated_analyzer):
    analyzer = populated_analyzer
    domain_id = "dom-corp-local"

    paths = analyzer.find_attack_paths_to_tier_zero(domain_id=domain_id, start_sid="S-1-5-21-1001")
    assert len(paths) >= 1

    path = paths[0]
    assert path.start_sid == "S-1-5-21-1001"
    assert path.start_name == "carlos.estagiario"
    assert path.target_name in ("Domain Admins", "Administrator")
    assert path.length == 3  # carlos -> Suporte TI -> SRV-PRINT -> Domain Admins

    # Check hops
    assert path.hops[0]["relationship"] == "ForceChangePassword"
    assert path.hops[1]["relationship"] == "AdminTo"
    assert path.hops[2]["relationship"] == "GenericAll"

    # Check Brazilian Portuguese narrative
    assert "Cadeia de Invasão iniciada a partir de 'carlos.estagiario'" in path.narrative_ptbr
    assert "Passo 1" in path.narrative_ptbr
    assert "Passo 2" in path.narrative_ptbr
    assert "Comprometimento completo" in path.narrative_ptbr


def test_calculate_identity_choke_points(populated_analyzer):
    analyzer = populated_analyzer
    domain_id = "dom-corp-local"

    choke_points = analyzer.calculate_choke_points(domain_id=domain_id)
    assert len(choke_points) > 0

    top_choke = choke_points[0]
    # 'Grupo Suporte TI' or 'SRV-PRINT-01' should be the highest-impact choke points
    assert top_choke.name in ("Grupo Suporte TI", "SRV-PRINT-01")
    assert top_choke.cut_paths_count >= 1
    assert top_choke.cut_percentage > 0.0
    assert "Revogar permissões" in top_choke.recommendation


def test_kerberoasting_and_asrep_roasting_detection(populated_analyzer):
    analyzer = populated_analyzer
    domain_id = "dom-corp-local"

    # Kerberoasting
    kerb_users = analyzer.find_kerberoastable_accounts(domain_id=domain_id)
    assert len(kerb_users) == 1
    assert kerb_users[0].name == "svc-sql-prod"
    assert kerb_users[0].spn == "MSSQLSvc/db01.corp:1433"
    assert "$krb5tgs$23$" in kerb_users[0].hash_sample

    # AS-REP Roasting
    asrep_users = analyzer.find_asrep_roastable_accounts(domain_id=domain_id)
    assert len(asrep_users) == 1
    assert asrep_users[0].name == "legado.vpn"
    assert "$krb5asrep$23$" in asrep_users[0].hash_sample


def test_dcsync_and_simulation(populated_analyzer):
    analyzer = populated_analyzer
    domain_id = "dom-corp-local"

    # DCSync principals
    dcsync_list = analyzer.find_dcsync_principals(domain_id=domain_id)
    assert len(dcsync_list) >= 1
    assert any(d["relationship"] == "DCSync" for d in dcsync_list)

    # Attack simulation from carlos
    sim_res = analyzer.simulate_attack(start_identity="carlos.estagiario", domain_id=domain_id)
    assert sim_res["success"] is True
    assert sim_res["target_reached"] is True
    assert sim_res["hops_count"] == 3
    assert sim_res["primary_choke_point"] is not None


@pytest.mark.asyncio
async def test_agent_tool_analyze_active_directory():
    """Verify analyze_active_directory tool runs via ToolExecutor and returns actionable intelligence."""
    from arcanum.agent.tools import ToolExecutor, NATIVE_TOOLS

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    assert "analyze_active_directory" in tool_names

    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    assert "analyze_active_directory" in executor._handlers

    # 1. Summary action
    res_summary = await executor.execute_tool(
        "analyze_active_directory",
        {"domain_name": "corp.local", "action": "summary"},
    )
    assert res_summary["success"] is True
    out = res_summary["output"]
    assert out["domain"] == "corp.local"
    assert out["total_attack_paths"] >= 1
    assert out["kerberoastable_count"] >= 1

    # 2. Simulate Attack action
    res_sim = await executor.execute_tool(
        "analyze_active_directory",
        {"domain_name": "corp.local", "start_identity": "carlos.estagiario", "action": "simulate_attack"},
    )
    assert res_sim["success"] is True
    assert res_sim["output"]["target_reached"] is True
    assert res_sim["output"]["hops_count"] == 3

