"""FastAPI application for Arcanum Core Web UI."""
import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from ..core.config import get_config
from ..core.database import Database
from ..core.cve_kb import CVEKnowledgeBase
from ..core.stash import StashManager
from ..core.alerts import AlertEngine
from ..core.reports import ReportEngine
from ..core.demo_data import seed_all_demo_data
from ..agent.llm import OllamaClient
from ..agent.session import SessionManager

from .routes import sessions, tools, findings, stash, cve, reports
from .websocket import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources."""
    config = get_config()

    # Initialize database
    db = Database(config.data_dir / "arcanum.db")
    await db.connect()
    await db.init_db()
    app.state.db = db

    # Initialize CVE KB
    cve_kb = CVEKnowledgeBase(config.cve_db)
    await cve_kb.connect()
    app.state.cve_kb = cve_kb

    # Initialize managers
    app.state.session_mgr = SessionManager(db)
    app.state.stash_mgr = StashManager(db)
    app.state.alert_engine = AlertEngine()
    app.state.report_engine = ReportEngine()

    # Initialize Playbook KB (pre-seed proven techniques so the agent isn't
    # cold-starting). ensure_defaults is idempotent and additive: it tops up any
    # missing built-ins without touching learned entries.
    from ..core.playbooks import PlaybookManager
    pm = PlaybookManager(db)
    try:
        added = await pm.ensure_defaults()
        if added:
            import logging
            logging.getLogger("arcanum").info(f"Playbooks: {added} técnica(s) padrão adicionada(s).")
    except Exception:
        pass
    app.state.playbook_mgr = pm

    # Initialize Docker Sandbox
    try:
        from ..sandbox.docker import SandboxManager
        sandbox = SandboxManager(
            image=config.sandbox_image,
            timeout=config.sandbox_timeout,
        )
        if await sandbox.ensure_image():
            app.state.sandbox = sandbox
        else:
            app.state.sandbox = None
    except Exception:
        app.state.sandbox = None

    # Initialize Fast LLM client (tactical: recon, scans, tool calls)
    app.state.llm = OllamaClient(
        base_url=config.ollama_url,
        model=config.ollama_fast_model,
        timeout=config.ollama_timeout,
        num_ctx=config.ollama_num_ctx,
        temperature=config.ollama_temperature,
        num_predict=config.ollama_fast_predict,
        repeat_penalty=config.ollama_repeat_penalty,
        enable_thinking=config.ollama_enable_thinking,
    )

    # Initialize Deep LLM client (strategic: exploit planning, reports, reflection)
    app.state.deep_llm = OllamaClient(
        base_url=config.ollama_url,
        model=config.ollama_deep_model,
        timeout=config.ollama_timeout,
        num_ctx=config.ollama_num_ctx,
        temperature=config.ollama_temperature,
        num_predict=config.ollama_deep_predict,
        repeat_penalty=config.ollama_repeat_penalty,
        enable_thinking=config.ollama_enable_thinking,
    )

    # Active sessions/engines
    app.state.active_engines = {}

    # API access token: use configured value or generate one per process.
    import logging
    import secrets
    _log = logging.getLogger("arcanum")
    app.state.api_token = config.api_token or secrets.token_urlsafe(32)
    if not config.api_token:
        _log.warning(
            "ARCANUM_API_TOKEN not set — generated an ephemeral token for this "
            "run. The bundled UI receives it automatically; external clients "
            "use: Authorization: Bearer %s", app.state.api_token,
        )

    # Seed demo data only when explicitly requested (never silently in prod).
    if config.seed_demo:
        try:
            result = await seed_all_demo_data(db, cve_kb)
            if any(v > 0 for v in result.values()):
                _log.info(f"Demo data seeded: {result}")
        except Exception:
            pass  # Non-fatal — demo data is optional

    yield

    # Cleanup
    await db.close()
    await cve_kb.close()
    await app.state.llm.close()
    if hasattr(app.state, "deep_llm") and app.state.deep_llm:
        await app.state.deep_llm.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Arcanum Core",
        description="Autonomous AI-Powered Security Reconnaissance Platform",
        version="3.0.0",
        lifespan=lifespan,
    )

    # CORS: the bundled UI is same-origin, so default to loopback origins only.
    # A wildcard with credentials is invalid per the CORS spec anyway. Override
    # via ARCANUM_CORS_ORIGINS (comma-separated) for a proxied deployment.
    import os
    cors_env = os.environ.get("ARCANUM_CORS_ORIGINS", "")
    allow_origins = [o.strip() for o in cors_env.split(",") if o.strip()] or [
        "http://localhost:8000", "http://127.0.0.1:8000",
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from .auth import require_token
    auth = [Depends(require_token)]

    # API routes (all require a valid token)
    app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"], dependencies=auth)
    app.include_router(tools.router, prefix="/api/tools", tags=["tools"], dependencies=auth)
    app.include_router(findings.router, prefix="/api/findings", tags=["findings"], dependencies=auth)
    app.include_router(stash.router, prefix="/api/stash", tags=["stash"], dependencies=auth)
    app.include_router(cve.router, prefix="/api/cve", tags=["cve"], dependencies=auth)
    app.include_router(reports.router, prefix="/api/reports", tags=["reports"], dependencies=auth)
    app.include_router(ws_router)

    # Health check
    @app.get("/api/health")
    async def health():
        try:
            llm_ok = await app.state.llm.check_health()
        except Exception:
            llm_ok = False
        return {
            "status": "ok",
            "version": "3.0.0",
            "llm_connected": llm_ok,
            "fast_model": getattr(app.state.llm, "model", None),
            "deep_model": getattr(getattr(app.state, "deep_llm", None), "model", None),
        }

    # Dashboard stats
    @app.get("/api/stats", dependencies=auth)
    async def stats():
        sessions = await app.state.db.fetch_all("SELECT status FROM sessions")
        findings = await app.state.db.fetch_all("SELECT severity FROM findings")
        stash_count = await app.state.db.fetch_one("SELECT COUNT(*) as cnt FROM stash")
        cve_count = await app.state.cve_kb.count()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "sessions": {
                "total": len(sessions),
                "running": sum(1 for s in sessions if s["status"] == "running"),
                "complete": sum(1 for s in sessions if s["status"] == "complete"),
            },
            "findings": {
                "total": len(findings),
                **severity_counts,
            },
            "stash": stash_count["cnt"] if stash_count else 0,
            "cves": cve_count,
        }

    # Playbooks endpoints
    @app.get("/api/playbooks", dependencies=auth)
    async def get_playbooks(q: str = ""):
        from ..core.playbooks import PlaybookManager
        pm = PlaybookManager(app.state.db)
        results = await pm.search(q, limit=50)
        return {"playbooks": results}

    @app.post("/api/playbooks", dependencies=auth)
    async def create_playbook(body: dict):
        from ..core.playbooks import PlaybookManager
        pm = PlaybookManager(app.state.db)
        tools = body.get("tools", [])
        if isinstance(tools, str):
            tools = [t.strip() for t in tools.split(",") if t.strip()]
        res = await pm.save_playbook(
            title=body.get("title", "Untitled Playbook"),
            category=body.get("category", "general"),
            trigger=body.get("trigger", ""),
            steps=body.get("steps", ""),
            tools=tools,
            notes=body.get("notes", ""),
            author=body.get("author", "operator"),
        )
        return {"playbook": res}


    # Demo seed endpoint
    @app.post("/api/demo/seed", dependencies=auth)
    async def demo_seed():
        from ..core.demo_data import seed_all_demo_data
        result = await seed_all_demo_data(app.state.db, app.state.cve_kb)
        return {"seeded": result}

    # Serve frontend — check multiple locations (dev vs Docker)
    frontend_candidates = [
        Path(__file__).parent.parent.parent / "frontend",  # dev: repo root
        Path("/app/frontend"),                              # Docker workdir
    ]
    frontend_dir = next((d for d in frontend_candidates if (d / "index.html").exists()), None)
    if frontend_dir:
        assets_dir = frontend_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

        @app.get("/")
        async def serve_frontend():
            # Inject the per-process API token so the same-origin UI can
            # authenticate without the operator copying it by hand. Served over
            # loopback by default; for remote exposure protect "/" at the proxy.
            from fastapi.responses import HTMLResponse
            html = (frontend_dir / "index.html").read_text(encoding="utf-8")
            token = getattr(app.state, "api_token", "") or ""
            inject = f'<script>window.ARCANUM_TOKEN={json.dumps(token)};</script>'
            if "</head>" in html:
                html = html.replace("</head>", inject + "</head>", 1)
            else:
                html = inject + html
            return HTMLResponse(html)

        @app.get("/favicon.ico", include_in_schema=False)
        async def favicon():
            from fastapi.responses import Response
            return Response(status_code=204)

    return app


app = create_app()
