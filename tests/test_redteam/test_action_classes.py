"""F0 — deterministic action classification + HITL tiers."""

from arcanum.redteam.action_classes import (
    ActionClass, classify, hitl_tier, class_order, TOOL_ACTION_CLASS,
)


def test_passive_native_audit_tools():
    assert classify("audit_security_headers", {"url": "https://example.com"}) == ActionClass.PASSIVE
    assert classify("query_whois_rdap", {"domain": "example.com"}) == ActionClass.PASSIVE
    assert classify("search_cert_transparency", {"domain": "example.com"}) == ActionClass.PASSIVE
    assert classify("detect_waf_firewall", {"url": "https://example.com"}) == ActionClass.PASSIVE
    assert classify("generate_detection_rules", {}) == ActionClass.PASSIVE


def test_internal_bookkeeping_is_passive():
    for t in ("read_memory", "update_memory", "query_playbook", "save_playbook",
              "query_graph", "create_finding", "search_cve"):
        assert classify(t, {}) == ActionClass.PASSIVE
        assert TOOL_ACTION_CLASS[t] == ActionClass.PASSIVE


def test_execute_defaults_to_active():
    assert classify("execute", {"command": "nmap -sV example.com"}) == ActionClass.ACTIVE
    assert classify("execute", {"command": "httpx -u https://example.com"}) == ActionClass.ACTIVE
    # shell aliases normalize to execute
    assert classify("bash", {"command": "subfinder -d example.com"}) == ActionClass.ACTIVE


def test_execute_exploit_markers():
    for cmd in [
        "msfconsole -q -x 'use exploit/...'",
        "hydra -l admin -P rockyou.txt ssh://10.0.0.1",
        "crackmapexec smb 10.0.0.0/24",
        "netexec smb 10.0.0.1 -u u -p p",
        "impacket-secretsdump domain/user@host",
        "evil-winrm -i 10.0.0.1 -u u -p p",
        "hashcat -m 1000 hashes.txt rockyou.txt",
        "sqlmap -u 'http://x/?id=1' --dump",
    ]:
        assert classify("execute", {"command": cmd}) == ActionClass.EXPLOIT, cmd


def test_sqlmap_without_weaponized_flags_is_active():
    # Plain detection run (no --dump/--os-shell) stays ACTIVE, not EXPLOIT.
    assert classify("execute", {"command": "sqlmap -u 'http://x/?id=1' --batch"}) == ActionClass.ACTIVE


def test_execute_destructive_markers():
    for cmd in [
        "rm -rf /var/www",
        "mkfs.ext4 /dev/sdb",
        "dd if=/dev/zero of=/dev/sda",
        "shutdown -h now",
        "DROP TABLE users;",
    ]:
        assert classify("execute", {"command": cmd}) == ActionClass.DESTRUCTIVE, cmd


def test_unknown_tool_defaults_active():
    # Unmapped, non-passive-prefixed tool escalates to ACTIVE (never silently passive).
    assert classify("totally_new_tool", {}) == ActionClass.ACTIVE


def test_side_effecting_tools_are_not_passive():
    # Regression (2nd-opinion review #1): these LOOK passive by name/prefix but
    # have real side effects, so they must NOT be auto-executed as PASSIVE.
    # headless_web_audit actively drives a browser against the target;
    # dispatch_* tools push to Jira/SIEM or trigger a remote probe (external effect).
    assert classify("headless_web_audit", {"url": "https://example.com"}) == ActionClass.ACTIVE
    assert classify("dispatch_enterprise_integration", {"finding_id": "x"}) == ActionClass.ACTIVE
    assert classify("dispatch_to_satellite_probe", {"probe_id": "p"}) == ActionClass.ACTIVE
    # overrides must beat the passive prefix rule
    assert TOOL_ACTION_CLASS["headless_web_audit"] == ActionClass.ACTIVE
    assert hitl_tier(classify("dispatch_enterprise_integration", {})) == "approve"


def test_hitl_tiers():
    assert hitl_tier(ActionClass.PASSIVE) == "auto"
    assert hitl_tier(ActionClass.ACTIVE) == "approve"
    assert hitl_tier(ActionClass.EXPLOIT) == "double"
    assert hitl_tier(ActionClass.POST_EXPLOIT) == "double"
    assert hitl_tier(ActionClass.DESTRUCTIVE) == "double"


def test_class_order_is_monotonic():
    order = [class_order(c) for c in (
        ActionClass.PASSIVE, ActionClass.ACTIVE, ActionClass.EXPLOIT,
        ActionClass.POST_EXPLOIT, ActionClass.DESTRUCTIVE)]
    assert order == sorted(order)
    assert order == [0, 1, 2, 3, 4]
