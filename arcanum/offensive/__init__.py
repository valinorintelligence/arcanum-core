"""Governed offensive framework (F1+).

This package is the **orchestration and governance layer** for real offensive
actions — NOT an exploit library. It contains no exploits, payloads, attack
techniques or evasion code. Every offensive capability is a *governed wrapper*
that:

1. is classified by F0 (``redteam/action_classes``) so the engine enforces ROE,
   the authorization window and the HITL tier (EXPLOIT ⇒ dual approval);
2. **delegates** the actual technique to an established tool already in the Kali
   sandbox image (Metasploit, nuclei, impacket, netexec, hashcat, …), invoked
   through the governed ``execute`` path — the "how to exploit" is the tool's;
3. captures **minimal, masked proof** (never secrets in clear text);
4. updates the **compromise state** (graph ``owned``/``foothold_id``) and registers
   a **foothold with a teardown recipe** so cleanup is real and nothing is left
   behind;
5. is recorded in the immutable **audit trail** with a deconfliction tag.

Nothing here runs without an authorized sandbox; initial access additionally needs
an active engagement (ROE). F1 = initial access (``access``); F4/F5 extend the same
contract for post-exploitation/impact (gated, not built yet).
"""
