"""Offline tests for the vector store (no embedding model / network needed)."""
import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.core.vectordb import VectorStore, cosine, playbook_embed_text


@pytest_asyncio.fixture
async def db():
    d = Database(":memory:")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


def test_cosine_basic():
    assert cosine([1, 0, 0], [1, 0, 0]) == pytest.approx(1.0)
    assert cosine([1, 0], [0, 1]) == pytest.approx(0.0)
    assert cosine([1, 1], [2, 2]) == pytest.approx(1.0)
    assert cosine([], [1]) == 0.0


@pytest.mark.asyncio
async def test_vector_store_roundtrip_and_search(db):
    vs = VectorStore(db)
    await vs.upsert("c", "a", "alpha", [1.0, 0.0, 0.0])
    await vs.upsert("c", "b", "beta", [0.0, 1.0, 0.0])
    await vs.upsert("c", "c", "gamma", [0.9, 0.1, 0.0])
    assert await vs.count("c") == 3
    assert await vs.has("c", "a") is True
    assert await vs.has("c", "zzz") is False
    # query close to 'a'/'c' direction
    res = await vs.search("c", [1.0, 0.0, 0.0], top_k=2)
    assert [r["ref_id"] for r in res] == ["a", "c"]
    assert res[0]["score"] >= res[1]["score"]


@pytest.mark.asyncio
async def test_vector_upsert_overwrites(db):
    vs = VectorStore(db)
    await vs.upsert("c", "a", "v1", [1.0, 0.0])
    await vs.upsert("c", "a", "v2", [0.0, 1.0])
    assert await vs.count("c") == 1
    res = await vs.search("c", [0.0, 1.0], top_k=1)
    assert res and res[0]["text"] == "v2"


def test_playbook_embed_text_readable():
    t = playbook_embed_text({"technology": "nginx", "technique": "403_bypass",
                             "commands": "curl ..;/admin", "notes": "path normalization"})
    assert "403 bypass" in t and "nginx" in t and "curl" in t
