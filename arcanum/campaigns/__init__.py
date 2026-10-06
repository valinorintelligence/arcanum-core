"""Adaptive campaign engine (Phase 2).

A campaign is an ordered list of steps that ADAPTS to what earlier steps found:
recon fingerprints the stack, and later steps unlock conditionally (WordPress ->
wpscan, a GraphQL endpoint -> graphqlmap, a live web port -> nuclei/feroxbuster).

Design invariants (same spirit as the rest of the platform):

* **No exploit/payload here.** This module only decides WHICH established Kali tool
  to run NEXT and PARSES its output. The actual execution is delegated through the
  SAME governed path as the manual console (``classify`` + ROE + immutable audit),
  in the sandbox, never on the host.
* **Governed per step.** Every step is classified and ROE-checked before it runs; a
  step outside scope/class pauses the campaign honestly (never silently skipped).
* **HITL preserved.** Intrusive steps require operator approval on a normal
  engagement; only a lab ``auto_approve`` engagement runs them straight through.
* **Honest findings.** Findings are created only from real, structured tool output
  (nuclei JSONL) — never fabricated.

The engine itself is pure/dependency-injected (``exec_fn``/``govern_fn``/``approve_fn``/
``emit``/``finding_fn``) so the adaptive brain is unit-testable without a sandbox,
DB or WebSocket. The WS route wires the real implementations.
"""
from .engine import CampaignRunner
from .definitions import CAMPAIGNS, get_campaign

__all__ = ["CampaignRunner", "CAMPAIGNS", "get_campaign"]
