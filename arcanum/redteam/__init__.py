"""Red Team governance foundation (F0).

This package is the *keystone* that gates every real Red/Blue/Purple action
behind an authorized engagement (ROE). It intentionally contains **no exploits,
payloads or attack techniques** — only the safety rails described in
``docs/RED_TEAM_ROADMAP.md`` §10 (F0):

- ``action_classes``  — graded action classes (PASSIVE→DESTRUCTIVE) + ``classify``.
- ``engagement``      — ``EngagementManager`` (ROE: scope, window, allowed classes).
- ``audit``           — ``ActionAuditLog`` (append-only, hash-chained action trail).
- ``sessions``        — ``SessionRegistry`` (footholds/implants + guaranteed cleanup).

These are consumed by ``arcanum/agent/engine.py`` (deterministic gating + HITL
tiers + audit) and exposed over the API (``arcanum/api/routes/redteam.py``).
"""

from .action_classes import (
    ActionClass,
    classify,
    hitl_tier,
    class_order,
    TOOL_ACTION_CLASS,
)
from .engagement import EngagementManager
from .audit import ActionAuditLog, mask_arguments, summarize_result
from .sessions import SessionRegistry

__all__ = [
    "ActionClass",
    "classify",
    "hitl_tier",
    "class_order",
    "TOOL_ACTION_CLASS",
    "EngagementManager",
    "ActionAuditLog",
    "mask_arguments",
    "summarize_result",
    "SessionRegistry",
]
