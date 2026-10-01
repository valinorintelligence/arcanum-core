"""Tests for the engagement knowledge graph (ingestion, summary, synthesis)."""
import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.core.graph import GraphManager, HOST, PORT, SERVICE, TECH, ENDPOINT


NMAP = (
    "Nmap scan report for host.example.com (1.2.3.4)\n"
    "80/tcp  open http nginx\n"
    "443/tcp open ssl/http nginx\n"
    "3306/tcp open mysql MySQL 8.0.35\n"
)
HTTPX = "https://host.example.com [200] [Express,Node.js]"
KATANA = "https://host.example.com/login\nhttps://host.example.com/admin\n"


@pytest_asyncio.fixture
async def graph():
    db = Database(":memory:")
    await db.connect()
    await db.init_db()
    yield GraphManager(db), db
    await db.close()


@pytest.mark.asyncio
async def test_ingest_builds_nodes_and_is_idempotent(graph):
    g, _ = graph
    await g.ingest_text("s1", NMAP)
    await g.ingest_text("s1", HTTPX)
    await g.ingest_text("s1", KATANA)
    c = await g.counts("s1")
    assert c.get(HOST) == 1
    assert c.get(PORT) == 3
    assert c.get(SERVICE) == 3
    assert c.get(TECH) == 2
    assert c.get(ENDPOINT, 0) >= 2
    # re-ingesting the same output must not duplicate
    await g.ingest_text("s1", NMAP)
    assert (await g.counts("s1")).get(PORT) == 3


@pytest.mark.asyncio
async def test_sessions_are_isolated(graph):
    g, _ = graph
    await g.ingest_text("s1", NMAP)
    assert (await g.counts("s2")) == {}


@pytest.mark.asyncio
async def test_summary_and_candidate_findings(graph):
    g, _ = graph
    await g.ingest_text("s1", NMAP)
    summary = await g.summary("s1")
    assert "host.example.com" in summary and "3306/tcp" in summary
    cands = await g.candidate_findings("s1")
    # exposed MySQL (3306) must be surfaced as a high-severity candidate
    mysql = [c for c in cands if "3306" in c["title"]]
    assert mysql and mysql[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_add_finding_links_to_host(graph):
    g, _ = graph
    await g.ingest_text("s1", NMAP)
    await g.add_finding("s1", "finding-1", "SQLi", "critical", "http://host.example.com/api")
    assert (await g.counts("s1")).get("finding") == 1
