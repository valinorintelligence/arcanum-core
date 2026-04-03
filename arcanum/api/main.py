"""FastAPI application for Arcanum Core Web UI."""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from ..core.config import get_config
from ..core.database import Database
from ..core.cve_kb import CVEKnowledgeBase
from ..core.stash import StashManager
from ..core.alerts import AlertEngine
from ..core.reports import ReportEngine
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

    # Initialize LLM client
    app.state.llm = OllamaClient(config.ollama_url, config.ollama_model)

    # Active sessions/engines
    app.state.active_engines = {}

    yield

    # Cleanup
    await db.close()
    await cve_kb.close()
    await app.state.llm.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Arcanum Core",
        description="Autonomous AI-Powered Security Reconnaissance Platform",
        version="3.0.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API routes
    app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
    app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
    app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
    app.include_router(stash.router, prefix="/api/stash", tags=["stash"])
    app.include_router(cve.router, prefix="/api/cve", tags=["cve"])
    app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
    app.include_router(ws_router)

    # Health check
    @app.get("/api/health")
    async def health():
        llm_ok = await app.state.llm.check_health()
        return {
            "status": "ok",
            "version": "3.0.0",
            "llm_connected": llm_ok,
        }

    # Serve frontend
    frontend_dir = Path(__file__).parent.parent.parent / "frontend"
    if frontend_dir.exists():
        app.mount("/assets", StaticFiles(directory=frontend_dir / "assets"), name="assets")

        @app.get("/")
        async def serve_frontend():
            return FileResponse(frontend_dir / "index.html")

    return app


app = create_app()
