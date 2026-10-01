"""Unit tests for PlaybookManager continuous learning knowledge base."""
import pytest
import pytest_asyncio
import tempfile
from pathlib import Path
from arcanum.core.database import Database
from arcanum.core.playbooks import PlaybookManager


@pytest_asyncio.fixture
async def memory_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_playbooks.db"
        db = Database(db_file)
        await db.connect()
        await db.init_db()
        yield db
        await db.close()


@pytest.mark.asyncio
async def test_seed_defaults_and_search(memory_db):
    pm = PlaybookManager(memory_db)
    seeded = await pm.seed_defaults_if_empty()
    assert seeded >= 5

    # Test FTS5 search
    results = await pm.search("403", limit=5)
    assert len(results) > 0
    assert any("403" in r.get("title", "") or "403" in r.get("technique", "") for r in results)

    # Test technology search
    results = await pm.search("wordpress", limit=5)
    assert len(results) > 0
    assert results[0].get("category") == "wordpress"


@pytest.mark.asyncio
async def test_save_and_update_playbook(memory_db):
    pm = PlaybookManager(memory_db)
    res = await pm.save_playbook(
        title="Custom SQLi Auth Bypass",
        category="web",
        trigger="Admin login endpoint vulnerable to blind SQL injection",
        steps="sqlmap -u 'http://target/login' --data='user=admin&pass=1' --batch",
        tools=["sqlmap"],
        notes="High risk production test",
    )
    assert res["title"] == "Custom SQLi Auth Bypass"
    assert res["times_used"] == 1

    # Search for it
    search_res = await pm.search("SQLi Auth Bypass")
    assert len(search_res) > 0
    assert search_res[0]["title"] == "Custom SQLi Auth Bypass"
