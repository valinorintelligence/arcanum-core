"""Tests for report listing/download routes and operator abort control."""

import pytest
from unittest.mock import MagicMock, AsyncMock
from pathlib import Path
from fastapi.testclient import TestClient

from arcanum.api.main import create_app
from arcanum.agent.engine import AgentEngine
from arcanum.core.config import get_config


def test_reports_list_and_download(tmp_path, monkeypatch):
    """Test that reports listing lists available reports and download route works."""
    monkeypatch.setenv("ARCANUM_DATA_DIR", str(tmp_path))
    get_config.cache_clear()
    ops_dir = get_config().ops_dir
    rep_dir = ops_dir / "test-op" / "reports"
    rep_dir.mkdir(parents=True, exist_ok=True)
    (rep_dir / "report.html").write_text("<h1>Report</h1>", encoding="utf-8")
    (rep_dir / "report.json").write_text("{}", encoding="utf-8")

    app = create_app()
    app.state.api_token = "test-token"

    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    # List reports
    resp = client.get("/api/reports/", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "reports" in data
    assert len(data["reports"]) == 2
    formats = {r["format"] for r in data["reports"]}
    assert formats == {"html", "json"}

    # Download report via token in query param
    dl_resp = client.get("/api/reports/download/test-op/html?token=test-token")
    assert dl_resp.status_code == 200
    assert "<h1>Report</h1>" in dl_resp.text


@pytest.mark.asyncio
async def test_agent_engine_abort():
    """Test that calling engine.abort() stops the execution loop immediately."""
    llm = MagicMock()
    # Mock LLM to return repeated thoughts
    llm.chat_stream = AsyncMock(return_value=_fake_generator())
    tool_executor = MagicMock()

    engine = AgentEngine(llm=llm, tool_executor=tool_executor, session={"name": "test", "target": "127.0.0.1"})

    # Signal abort before or during run
    engine.abort()
    assert engine._abort_requested is True

    events = []
    async for event in engine.run("test scan"):
        events.append(event)

    # Should exit immediately with stop info
    assert any(e.get("type") == "info" and "interrompida" in e.get("content", "") for e in events)


async def _fake_generator():
    yield {"message": {"content": "thinking..."}}
