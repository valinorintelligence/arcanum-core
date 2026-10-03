"""Report generation endpoints."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ...core.config import get_config
from ...core.reports import ReportConfig

router = APIRouter()


class GenerateReportRequest(BaseModel):
    session_name: str
    formats: list[str] = ["html", "json", "md"]
    title: str | None = None
    classification: str = "CONFIDENTIAL"


@router.get("/")
async def list_reports():
    """List all available generated reports across operations."""
    config = get_config()
    items = []
    if config.ops_dir.exists():
        for op_dir in sorted(config.ops_dir.iterdir()):
            if op_dir.is_dir():
                rep_dir = op_dir / "reports"
                if rep_dir.is_dir():
                    for f in sorted(rep_dir.glob("*.*")):
                        ext = f.suffix.lstrip(".").lower()
                        if ext in ("pdf", "html", "md", "json"):
                            items.append({
                                "session": op_dir.name,
                                "name": f.name,
                                "format": ext,
                                "size": f.stat().st_size,
                            })
    return {"reports": items}


@router.post("/generate")
async def generate_report(request: Request, body: GenerateReportRequest):
    session = await request.app.state.session_mgr.get_session(body.session_name)
    if not session:
        raise HTTPException(404, "Session not found")

    findings = await request.app.state.db.fetch_all(
        "SELECT * FROM findings WHERE session_id = ?", (session["id"],)
    )
    parsed_findings = []
    for f in findings:
        fd = dict(f)
        for field in ("affected", "evidence", "poc", "cwe_ids"):
            if fd.get(field) and isinstance(fd[field], str):
                try:
                    fd[field] = json.loads(fd[field])
                except json.JSONDecodeError:
                    pass
        parsed_findings.append(fd)

    config = ReportConfig(
        title=body.title or f"Security Assessment - {session.get('target', 'Unknown')}",
        classification=body.classification,
    )

    output_dir = get_config().ops_dir / body.session_name / "reports"
    results = await request.app.state.report_engine.export(
        session=session,
        findings=parsed_findings,
        output_dir=output_dir,
        formats=body.formats,
        config=config,
    )

    return {"reports": {fmt: str(path) for fmt, path in results.items()}}


@router.get("/download/{session_name}/{format}")
async def download_report(session_name: str, format: str):
    from ...agent.session import validate_session_name
    # Validate inputs: session_name becomes a path component and format feeds a
    # glob — reject traversal / wildcards instead of trusting the URL.
    try:
        session_name = validate_session_name(session_name)
    except ValueError:
        raise HTTPException(400, "Invalid session name")
    if format not in ("pdf", "html", "md", "json"):
        raise HTTPException(400, "Invalid format")

    config = get_config()
    report_dir = (config.ops_dir / session_name / "reports").resolve()
    if config.ops_dir.resolve() not in report_dir.parents or not report_dir.exists():
        raise HTTPException(404, "No reports found")

    files = sorted(report_dir.glob(f"*.{format}"))
    if not files:
        if format == "pdf":
            html_files = sorted(report_dir.glob("*.html"))
            if html_files:
                return FileResponse(html_files[-1], filename=html_files[-1].name, media_type="text/html")
        raise HTTPException(404, f"No {format} report found")

    return FileResponse(files[-1], filename=files[-1].name)
