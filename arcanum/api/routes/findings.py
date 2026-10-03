"""Findings endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

router = APIRouter()


from typing import Any

class CreateFindingRequest(BaseModel):
    session_id: str
    title: str
    type: str | None = None
    severity: str = "medium"
    status: str = "confirmed"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected: Any = None
    evidence: Any = None
    poc: Any = None
    cve_id: str | None = None
    cwe_ids: list[str] | None = None
    remediation: str | None = None
    verified: bool = False
    retest_tool: str | None = None
    retest_arguments: dict | None = None


class RetestFindingRequest(BaseModel):
    tool: str | None = None
    arguments: dict | None = None


def _format_finding_row(row: dict) -> dict:
    import json
    row = dict(row)
    for col in ("affected", "evidence", "poc", "cwe_ids", "retest_arguments", "retest_proof"):
        val = row.get(col)
        if isinstance(val, str) and val.strip():
            try:
                row[col] = json.loads(val)
            except Exception:
                pass
    return row


@router.get("/")
async def list_findings(request: Request, session_id: str = None):
    if session_id:
        rows = await request.app.state.db.fetch_all(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at DESC", (session_id,)
        )
    else:
        rows = await request.app.state.db.fetch_all("SELECT * FROM findings ORDER BY created_at DESC")
    return {"findings": [_format_finding_row(r) for r in rows]}


@router.post("/")
async def create_finding(request: Request, body: CreateFindingRequest):
    import uuid, json
    finding_id = f"finding-{uuid.uuid4().hex[:8]}"
    await request.app.state.db.execute(
        """INSERT INTO findings (id, session_id, title, type, severity, status, cvss_score, cvss_vector,
           affected, evidence, poc, cve_id, cwe_ids, remediation, verified, retest_tool, retest_arguments)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (finding_id, body.session_id, body.title, body.type, body.severity, body.status,
         body.cvss_score, body.cvss_vector,
         json.dumps(body.affected) if body.affected else None,
         json.dumps(body.evidence) if body.evidence else None,
         json.dumps(body.poc) if body.poc else None,
         body.cve_id, json.dumps(body.cwe_ids) if body.cwe_ids else None,
         body.remediation, body.verified,
         body.retest_tool,
         json.dumps(body.retest_arguments) if body.retest_arguments else None),
    )
    # Update session findings count
    await request.app.state.db.execute(
        "UPDATE sessions SET findings_count = findings_count + 1 WHERE id = ?", (body.session_id,)
    )
    # Alert engine scan
    if hasattr(request.app.state, "alert_engine") and request.app.state.alert_engine:
        await request.app.state.alert_engine.scan_finding(body.model_dump())
    return {"finding": {"id": finding_id, **body.model_dump()}}


@router.get("/{finding_id}")
async def get_finding(request: Request, finding_id: str):
    row = await request.app.state.db.fetch_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
    if not row:
        raise HTTPException(404, "Finding not found")
    return {"finding": _format_finding_row(row)}


@router.post("/{finding_id}/retest")
async def retest_finding(request: Request, finding_id: str, body: RetestFindingRequest = None):
    from arcanum.core.retest import RetestEngine
    tool_exec = getattr(request.app.state, "tool_executor", None)
    retest_engine = RetestEngine(db=request.app.state.db, tool_executor=tool_exec)
    custom_tool = body.tool if body else None
    custom_args = body.arguments if body else None

    result = await retest_engine.retest_finding(
        finding_id=finding_id,
        custom_tool=custom_tool,
        custom_args=custom_args,
    )
    if not result.get("success"):
        raise HTTPException(404, result.get("error", "Retest failed"))
    return {"retest": result}
