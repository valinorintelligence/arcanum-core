"""Purple Team: closed-loop BAS with MEASURED efficacy (F3).

Closes the loop between Red (attack emulation) and Blue (detection): run an
ATT&CK technique → measure whether it was detected → if MISS, generate + deploy a
detection rule (via F2) → re-run → re-measure → report coverage. Efficacy is
**measured**, not a static seed.

- ``store``     — ``PurpleResultStore``: measured BAS results (``purple_results``).
- ``bas``       — ``BASRunner``: executes a technique (Atomic Red Team via sandbox
                  when available; honest simulation otherwise), stamped with a
                  deconfliction tag.
- ``verify``    — ``DetectionVerifier``: was the technique detected? (measured from
                  deployed detection rules + optional real SIEM query).
- ``efficacy``  — feeds measured results into ``MitreEfficacyEngine``.
- ``loop``      — ``PurpleLoop``: detect→tune→re-measure for one technique.
- ``campaign``  — ``PurpleCampaign``: chain techniques, measure coverage, gap report.

All of this is driven by F0-governed agent tools (``run_bas_test``,
``verify_detection``, ``measure_coverage``, ``run_purple_campaign``) so every
emulation is classified, gated and audited.
"""

from .store import PurpleResultStore
from .bas import BASRunner
from .verify import DetectionVerifier
from .efficacy import apply_measured_results, measured_efficacy_report
from .loop import PurpleLoop
from .campaign import PurpleCampaign

__all__ = [
    "PurpleResultStore",
    "BASRunner",
    "DetectionVerifier",
    "apply_measured_results",
    "measured_efficacy_report",
    "PurpleLoop",
    "PurpleCampaign",
]
