"""Purple Team API (F3): read measured BAS results, coverage and efficacy.

Read-only by design: executing techniques (adversary emulation, classified
EXPLOIT) happens ONLY through the F0-governed agent tools (``run_bas_test`` /
``run_purple_campaign``), so emulation is always classified, ROE-gated and
audited — never launched by an unguarded HTTP call.
"""
from __future__ import annotations

from fastapi import APIRouter, Request

from ...purple.store import PurpleResultStore
from ...purple.efficacy import measured_efficacy_report

router = APIRouter(prefix="/api/purple", tags=["purple"])


@router.get("/results")
async def list_results(request: Request, campaign_id: str | None = None):
    store = PurpleResultStore(request.app.state.db)
    return {"results": await store.list(campaign_id=campaign_id)}


@router.get("/coverage/{campaign_id}")
async def coverage(request: Request, campaign_id: str):
    store = PurpleResultStore(request.app.state.db)
    cov = await store.coverage(campaign_id)
    cov["measured_efficacy"] = measured_efficacy_report(cov.get("techniques", []))
    return cov
