"""Unit tests for Visual Graph, Choke Points and Blast Radius simulation."""

import pytest
import pytest_asyncio
from arcanum.core.database import Database
from arcanum.core.graph import GraphManager, HOST, PORT, SERVICE, TECH, ENDPOINT, FINDING, CRED


@pytest_asyncio.fixture
async def graph():
    db = Database(":memory:")
    await db.connect()
    await db.init_db()
    yield GraphManager(db), db
    await db.close()


@pytest.mark.asyncio
async def test_get_visual_graph_structure(graph):
    """Test get_visual_graph formats nodes and edges for visual rendering."""
    gm, _ = graph
    session_id = "sess-vis"

    # Add host, port, service
    h_id = await gm.add_node(session_id, HOST, "10.0.0.5", label="10.0.0.5")
    p_id = await gm.add_node(session_id, PORT, "10.0.0.5:6379", label="6379/tcp")
    s_id = await gm.add_node(session_id, SERVICE, "10.0.0.5:6379:redis", label="Redis Server")
    await gm.add_edge(session_id, h_id, "exposes", p_id)
    await gm.add_edge(session_id, p_id, "runs", s_id)

    vis = await gm.get_visual_graph(session_id)
    assert vis["session_id"] == session_id
    assert vis["total_nodes"] == 3
    assert vis["total_edges"] == 2

    # Port 6379 is a sensitive port
    port_node = next(n for n in vis["nodes"] if n["type"] == PORT)
    assert port_node["is_sensitive"] is True
    assert port_node["severity"] == "high"

    # Check edge format
    edge = vis["edges"][0]
    assert "source" in edge
    assert "target" in edge
    assert "rel" in edge


@pytest.mark.asyncio
async def test_calculate_choke_points(graph):
    """Test calculate_choke_points identifies bottleneck nodes in attack chains."""
    gm, _ = graph
    session_id = "sess-choke"

    # Topology:
    # Public Gateway (Host 1) -> Exposes Port 80 (NGINX Proxy)
    # Port 80 -> Reverse Proxy Service
    # Reverse Proxy -> Internal Host 2 (App Server)
    # Internal Host 2 -> Exposes Port 5432 (PostgreSQL - Crown Jewel)
    gw_id = await gm.add_node(session_id, HOST, "gateway.corp", label="gateway.corp")
    p80_id = await gm.add_node(session_id, PORT, "gateway.corp:80", label="80/tcp")
    proxy_id = await gm.add_node(session_id, SERVICE, "gateway.corp:80:nginx", label="nginx")
    app_id = await gm.add_node(session_id, HOST, "app.internal", label="app.internal")
    p5432_id = await gm.add_node(session_id, PORT, "app.internal:5432", label="5432/tcp")
    db_id = await gm.add_node(session_id, SERVICE, "app.internal:5432:postgresql", label="PostgreSQL")

    await gm.add_edge(session_id, gw_id, "exposes", p80_id)
    await gm.add_edge(session_id, p80_id, "runs", proxy_id)
    await gm.add_edge(session_id, proxy_id, "routes_to", app_id)
    await gm.add_edge(session_id, app_id, "exposes", p5432_id)
    await gm.add_edge(session_id, p5432_id, "runs", db_id)

    chokes = await gm.calculate_choke_points(session_id)
    assert len(chokes) > 0

    # Intermediate nodes along the path (e.g. p80, proxy, app_id) should be flagged as choke points
    labels = [c["label"] for c in chokes]
    assert any(label in ("80/tcp", "nginx", "app.internal") for label in labels)
    for c in chokes:
        assert c["impact_percentage"] > 0
        assert "recommendation" in c
        assert c["paths_severed"] >= 1


@pytest.mark.asyncio
async def test_simulate_blast_radius(graph):
    """Test simulate_blast_radius calculates lateral movement, reachability, and score."""
    gm, _ = graph
    session_id = "sess-blast"

    # Topology:
    # Victim Host (compromised)
    # Connected to:
    #   - Port 22 (SSH)
    #   - Endpoint /admin
    #   - Credential admin:hash
    #   - Pivot to Database Server (10.0.0.99) with Port 3306 (MySQL)
    h_victim = await gm.add_node(session_id, HOST, "victim-srv", label="victim-srv")
    p22 = await gm.add_node(session_id, PORT, "victim-srv:22", label="22/tcp")
    ep_admin = await gm.add_node(session_id, ENDPOINT, "http://victim-srv/admin", label="/admin")
    cred = await gm.add_node(session_id, CRED, "admin:***", label="admin:***")
    
    h_db = await gm.add_node(session_id, HOST, "db-srv", label="db-srv")
    p3306 = await gm.add_node(session_id, PORT, "db-srv:3306", label="3306/tcp")

    await gm.add_edge(session_id, h_victim, "exposes", p22)
    await gm.add_edge(session_id, h_victim, "has_endpoint", ep_admin)
    await gm.add_edge(session_id, cred, "for", h_victim)
    await gm.add_edge(session_id, h_victim, "connects_to", h_db)
    await gm.add_edge(session_id, h_db, "exposes", p3306)

    # Simulate blast radius from initial foothold at h_victim
    blast = await gm.simulate_blast_radius(session_id, h_victim, max_depth=3)

    assert blast["origin"]["id"] == h_victim
    assert blast["origin"]["label"] == "victim-srv"
    assert blast["total_reachable_nodes"] >= 5
    assert blast["blast_score"] >= 50
    assert blast["risk_level"] in ("HIGH", "CRITICAL")
    assert "db-srv" in blast["affected_hosts"]
    assert any("3306" in cj or "MySQL" in cj for cj in blast["crown_jewels_at_risk"])
    assert len(blast["hops"]) >= 4
    assert "Contenção Prioritária" in blast["containment_strategy"]
