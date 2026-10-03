"""Integration tests for Graph, Choke Points and Blast Radius API endpoints."""

import pytest
import pytest_asyncio
import httpx

from arcanum.api.main import create_app
from arcanum.core.config import get_config
from arcanum.core.graph import GraphManager, HOST, PORT, SERVICE


@pytest_asyncio.fixture
async def async_client(tmp_path, monkeypatch):
    """Provides an AsyncClient with an isolated database and test token."""
    monkeypatch.setenv("ARCANUM_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ARCANUM_API_TOKEN", "test-secret-token")
    get_config.cache_clear()

    app = create_app()

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            client.app = app
            yield client


@pytest.mark.asyncio
async def test_session_graph_api_endpoints(async_client):
    """Test graph, choke-points, and blast-radius HTTP endpoints end-to-end."""
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}

    # 1. Create a session
    sess_resp = await client.post(
        "/api/sessions/",
        headers=headers,
        json={"name": "graph-pentest", "target": "10.10.10.50"},
    )
    assert sess_resp.status_code == 200
    session_id = sess_resp.json()["session"]["id"]

    # Ingest graph nodes into this session's graph using database
    db = client.app.state.db
    gm = GraphManager(db)

    h1 = await gm.add_node(session_id, HOST, "10.10.10.50", label="10.10.10.50")
    p80 = await gm.add_node(session_id, PORT, "10.10.10.50:80", label="80/tcp")
    s_web = await gm.add_node(session_id, SERVICE, "10.10.10.50:80:http", label="Apache")
    p6379 = await gm.add_node(session_id, PORT, "10.10.10.50:6379", label="6379/tcp")
    s_redis = await gm.add_node(session_id, SERVICE, "10.10.10.50:6379:redis", label="Redis")

    await gm.add_edge(session_id, h1, "exposes", p80)
    await gm.add_edge(session_id, p80, "runs", s_web)
    await gm.add_edge(session_id, h1, "exposes", p6379)
    await gm.add_edge(session_id, p6379, "runs", s_redis)

    # 2. Test GET /api/sessions/{name}/graph
    graph_resp = await client.get("/api/sessions/graph-pentest/graph", headers=headers)
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()["graph"]
    assert graph_data["total_nodes"] == 5
    assert graph_data["total_edges"] == 4
    assert any(n["label"] == "Redis" for n in graph_data["nodes"])

    # 3. Test GET /api/sessions/{name}/graph/choke-points
    choke_resp = await client.get("/api/sessions/graph-pentest/graph/choke-points", headers=headers)
    assert choke_resp.status_code == 200
    chokes = choke_resp.json()["choke_points"]
    assert isinstance(chokes, list)

    # 4. Test GET /api/sessions/{name}/graph/blast-radius
    blast_resp = await client.get(
        f"/api/sessions/graph-pentest/graph/blast-radius?node_id={h1}",
        headers=headers,
    )
    assert blast_resp.status_code == 200
    blast = blast_resp.json()["blast_radius"]
    assert blast["origin"]["id"] == h1
    assert blast["total_reachable_nodes"] >= 4
    assert "Redis" in blast["affected_services"]
    assert "Contenção Prioritária" in blast["containment_strategy"]
