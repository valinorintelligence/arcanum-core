"""Blue Team: real defensive action (F2).

Turns Arcanum's *generated* defenses into *deployed, verified, reversible* ones:

- ``registry``             — ``DeploymentRegistry``: the rollback registry (every
                             real/mock change is recorded so it can be reversed).
- ``deployers/``           — SIEM / WAF / EDR adapters: ``deploy`` → ``verify`` →
                             ``rollback``, with **honest mock** when no credentials
                             are configured (never fakes a real deploy).
- ``hardening``            — apply a hardening baseline: dry-run → diff → apply →
                             verify, with rollback.
- ``response``             — incident-response containment (isolate host, disable
                             account, block IP), reversible.

All of these are consumed by F0-governed agent tools (``deploy_detection_rule``,
``verify_detection_active``, ``apply_hardening``, ``ir_contain``) so every action
is classified, gated (HITL), and written to the immutable audit trail.
"""

from .registry import DeploymentRegistry
from .deployers.siem import SIEMDeployer
from .deployers.waf import WAFDeployer
from .deployers.edr import EDRDeployer
from .hardening import HardeningApplier
from .response import IncidentResponder

__all__ = [
    "DeploymentRegistry",
    "SIEMDeployer",
    "WAFDeployer",
    "EDRDeployer",
    "HardeningApplier",
    "IncidentResponder",
]
