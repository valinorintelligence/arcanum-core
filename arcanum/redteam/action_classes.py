"""Graded action classes and deterministic classification (F0).

Every tool call is classified into one of five graded classes. The class drives
two independent safety mechanisms in the engine:

1. **ROE enforcement** — if an engagement is active, a class the engagement does
   not permit is blocked *deterministically* (never model-trusted).
2. **HITL tier** — the class maps to a human-in-the-loop tier:
   ``auto`` (passive) · ``approve`` (active) · ``double`` (exploit/post-exploit/destructive).

The classification is intentionally conservative: when in doubt it escalates to
the *higher* class. It contains no attack logic — only name/keyword heuristics
used to decide *how much authorization* an action needs.
"""
from __future__ import annotations

from enum import Enum


class ActionClass(str, Enum):
    """Graded classes of action, from least to most dangerous."""

    PASSIVE = "passive"            # read-only recon / audit / internal bookkeeping
    ACTIVE = "active"              # active probing/scanning that touches the target
    EXPLOIT = "exploit"           # weaponization / gaining access / cracking
    POST_EXPLOIT = "post_exploit"  # actions performed through an established foothold
    DESTRUCTIVE = "destructive"   # irreversible / data-affecting impact


# Monotonic ordering so callers can compare severity (higher == more dangerous).
_ORDER: dict[ActionClass, int] = {
    ActionClass.PASSIVE: 0,
    ActionClass.ACTIVE: 1,
    ActionClass.EXPLOIT: 2,
    ActionClass.POST_EXPLOIT: 3,
    ActionClass.DESTRUCTIVE: 4,
}


def class_order(cls: ActionClass) -> int:
    """Return the monotonic severity rank of a class (PASSIVE=0 … DESTRUCTIVE=4)."""
    return _ORDER.get(cls, 1)


# ---------------------------------------------------------------------------
# Explicit per-tool overrides.
#
# The vast majority of native tools are passive audits (handled by prefix rules
# below). This dict is the hook F1/F4/F5 will extend when structured offensive
# tools land — e.g. {"exploit_webapp": ActionClass.EXPLOIT, "dump_credentials":
# ActionClass.POST_EXPLOIT}. It is empty of offensive entries today because no
# offensive tool exists yet (F0 is governance only).
# ---------------------------------------------------------------------------
TOOL_ACTION_CLASS: dict[str, ActionClass] = {
    # Internal bookkeeping / knowledge tools — never touch a target.
    "read_memory": ActionClass.PASSIVE,
    "update_memory": ActionClass.PASSIVE,
    "query_playbook": ActionClass.PASSIVE,
    "save_playbook": ActionClass.PASSIVE,
    "query_graph": ActionClass.PASSIVE,
    "read_file": ActionClass.PASSIVE,
    "create_file": ActionClass.PASSIVE,
    "create_finding": ActionClass.PASSIVE,
    "stash_artifact": ActionClass.PASSIVE,
    "search_cve": ActionClass.PASSIVE,
    "web_search": ActionClass.PASSIVE,
    # Overrides that beat the passive prefixes below. These LOOK passive by name
    # but have real side effects, so they must NOT be auto-executed as PASSIVE:
    #   - headless_web_audit actively drives a browser AGAINST the target.
    #   - dispatch_* tools cause EXTERNAL effects (push to Jira/SIEM, trigger a
    #     remote probe), so they require at least operator approval.
    "headless_web_audit": ActionClass.ACTIVE,
    "dispatch_enterprise_integration": ActionClass.ACTIVE,
    "dispatch_to_satellite_probe": ActionClass.ACTIVE,
    # Blue Team (F2): deploying rules / applying hardening / IR containment are
    # real defensive CHANGES (external effect), so they are ACTIVE (operator
    # approval + audit + rollback). Verifying a deployment is read-only ⇒ PASSIVE.
    "deploy_detection_rule": ActionClass.ACTIVE,
    "apply_hardening": ActionClass.ACTIVE,
    "ir_contain": ActionClass.ACTIVE,
    "verify_detection_active": ActionClass.PASSIVE,
    # Purple Team (F3): BAS runs real attack techniques (adversary emulation) ⇒
    # EXPLOIT (ROE + dual approval). Measurement/reporting is read-only ⇒ PASSIVE.
    "run_bas_test": ActionClass.EXPLOIT,
    "run_purple_campaign": ActionClass.EXPLOIT,
    "verify_detection": ActionClass.PASSIVE,
    "measure_coverage": ActionClass.PASSIVE,
    # Offensive F1 (initial access):
    #   - map_service_to_exploits actively scans the target (nmap -sV) then correlates
    #     to CVEs — active probing, no attack ⇒ ACTIVE (operator approval).
    #   - exploit_webapp delegates real exploitation to an established tool to gain
    #     access ⇒ EXPLOIT (ROE + dual approval).
    #   - capture_proof only formats/records evidence already obtained ⇒ PASSIVE.
    "map_service_to_exploits": ActionClass.ACTIVE,
    "exploit_webapp": ActionClass.EXPLOIT,
    "capture_proof": ActionClass.PASSIVE,
    # Offensive F4 (post-exploitation & lateral) — all operate through a foothold and
    # delegate to established tools. POST_EXPLOIT/EXPLOIT ⇒ the engine requires dual
    # approval (and ROE) before they run; crack_hashes is offline/local ⇒ ACTIVE.
    "run_on_target": ActionClass.POST_EXPLOIT,
    "enumerate_privesc": ActionClass.POST_EXPLOIT,
    "attempt_privesc": ActionClass.POST_EXPLOIT,
    "dump_credentials": ActionClass.POST_EXPLOIT,
    "discover_on_host": ActionClass.POST_EXPLOIT,
    "establish_c2": ActionClass.POST_EXPLOIT,
    "lateral_move": ActionClass.EXPLOIT,          # per-hop approval
    "setup_pivot": ActionClass.EXPLOIT,
    "crack_hashes": ActionClass.ACTIVE,
    # Offensive F5 (collection / exfil / impact) — maximum gate.
    "collect_sample": ActionClass.POST_EXPLOIT,
    "demo_exfiltration": ActionClass.DESTRUCTIVE,
    "impact_poc": ActionClass.DESTRUCTIVE,
}


# Passive prefixes: audit/query/search/… native tools are read-only assessments.
_PASSIVE_PREFIXES = (
    "audit_", "query_", "search_", "detect_", "enrich_", "calculate_",
    "map_", "simulate_", "generate_", "scan_", "analyze_", "check_",
    "evaluate_", "dispatch_", "headless_",
)

# ---------------------------------------------------------------------------
# `execute` command heuristics. The sandbox `execute` tool is ACTIVE by default;
# these keyword families *upgrade* it. Matching is substring, case-insensitive.
# None of these are attack recipes — they are the names of established tools and
# obviously-destructive shell verbs, used only to decide the authorization tier.
# ---------------------------------------------------------------------------
_DESTRUCTIVE_MARKERS = (
    "rm -rf", "rm -fr", "rm -r ", "mkfs", "dd if=", "of=/dev/", "> /dev/sd",
    "shred", "wipefs", ":(){", "fork()", "fdisk", "parted", "format c:",
    "del /f", "rmdir /s", "cryptsetup", "ransomware", "/dev/sda",
    "drop table", "drop database", "truncate table", "shutdown", "reboot",
    "halt", "poweroff",
)

_EXPLOIT_MARKERS = (
    # cracking / brute force
    "hydra", "medusa", "ncrack", "patator", "hashcat", "john ", "john\t",
    # frameworks / weaponization
    "metasploit", "msfconsole", "msfvenom", "msf ", "sliver", "empire",
    "cobaltstrike", "cobalt strike",
    # credential dumping / AD
    "mimikatz", "secretsdump", "lsassy", "impacket", "crackmapexec",
    "netexec", "nxc ", "evil-winrm", "wmiexec", "psexec", "smbexec",
    "ntlmrelayx", "responder", "kerbrute", "rubeus", "certipy",
    # tunnels / C2 handlers
    "pwncat", "chisel", "ligolo",
    # generic exploitation intent
    "exploit/", " exploit ", "--exploit",
)

# sqlmap is active for discovery, but weaponized flags turn it into exploitation.
_SQLMAP_EXPLOIT_FLAGS = ("--dump", "--os-shell", "--os-cmd", "--os-pwn", "--sql-shell", "--file-read", "--file-write")


def _classify_command(command: str) -> ActionClass:
    cmd = (command or "").lower()
    if any(m in cmd for m in _DESTRUCTIVE_MARKERS):
        return ActionClass.DESTRUCTIVE
    if "sqlmap" in cmd and any(f in cmd for f in _SQLMAP_EXPLOIT_FLAGS):
        return ActionClass.EXPLOIT
    if any(m in cmd for m in _EXPLOIT_MARKERS):
        return ActionClass.EXPLOIT
    return ActionClass.ACTIVE


def classify(tool: str, arguments: dict | None = None) -> ActionClass:
    """Classify a tool call into an :class:`ActionClass` (deterministic).

    Rules (conservative — escalate when uncertain):
    - ``execute`` → ACTIVE, upgraded by command heuristics (EXPLOIT/DESTRUCTIVE).
    - explicit overrides in :data:`TOOL_ACTION_CLASS` win for known tools.
    - passive-prefixed native tools (audit_/query_/search_/…) → PASSIVE.
    - anything else defaults to ACTIVE (safer than assuming passive).
    """
    name = (tool or "").strip()
    args = arguments if isinstance(arguments, dict) else {}

    # Normalize common shell aliases to "execute" (mirrors ToolExecutor).
    if name in ("run_command", "bash", "sh", "terminal"):
        name = "execute"

    if name == "execute":
        return _classify_command(args.get("command", ""))

    override = TOOL_ACTION_CLASS.get(name)
    if override is not None:
        return override

    if any(name.startswith(p) for p in _PASSIVE_PREFIXES):
        return ActionClass.PASSIVE

    # Unknown / unmapped tool: treat as ACTIVE so it requires at least operator
    # approval rather than slipping through as passive.
    return ActionClass.ACTIVE


# ---------------------------------------------------------------------------
# HITL tiers
# ---------------------------------------------------------------------------
_TIER_BY_CLASS: dict[ActionClass, str] = {
    ActionClass.PASSIVE: "auto",       # no approval required (mode may still gate)
    ActionClass.ACTIVE: "approve",     # single operator approval
    ActionClass.EXPLOIT: "double",     # dual approval
    ActionClass.POST_EXPLOIT: "double",
    ActionClass.DESTRUCTIVE: "double",
}


def hitl_tier(cls: ActionClass) -> str:
    """Map an action class to its human-in-the-loop tier.

    ``auto`` · ``approve`` (1 approval) · ``double`` (2 independent approvals).
    """
    return _TIER_BY_CLASS.get(cls, "approve")
