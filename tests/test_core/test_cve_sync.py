"""Tests for incremental CVE sync primitives (metadata marker + item parser)."""
import pytest
import pytest_asyncio

from arcanum.core.database import Database  # noqa: F401 (ensures package import)
from arcanum.core.cve_kb import CVEKnowledgeBase
from arcanum.__main__ import _parse_cve_item


@pytest_asyncio.fixture
async def kb(tmp_path):
    k = CVEKnowledgeBase(tmp_path / "cve.db")
    await k.connect()
    yield k
    await k.close()


@pytest.mark.asyncio
async def test_sync_marker_roundtrip(kb):
    assert await kb.get_meta("last_sync") is None
    await kb.set_meta("last_sync", "2026-10-02T00:00:00.000")
    assert await kb.get_meta("last_sync") == "2026-10-02T00:00:00.000"
    # upsert overwrites, doesn't duplicate
    await kb.set_meta("last_sync", "2026-10-02T12:00:00.000")
    assert await kb.get_meta("last_sync") == "2026-10-02T12:00:00.000"


def test_parse_cve_item_extracts_core_fields():
    item = {
        "cve": {
            "id": "CVE-2026-9999",
            "published": "2026-05-01T10:00:00.000",
            "descriptions": [
                {"lang": "es", "value": "ignore"},
                {"lang": "en", "value": "Example RCE in widget parser."},
            ],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}}]},
            "weaknesses": [{"description": [{"value": "CWE-78"}]}],
        }
    }
    e = _parse_cve_item(item)
    assert e.id == "CVE-2026-9999"
    assert e.cvss_score == 9.8
    assert e.cwe_ids == ["CWE-78"]
    assert "RCE" in e.description
    assert e.published_at == "2026-05-01"


def test_parse_cve_item_without_id_is_skipped():
    assert _parse_cve_item({"cve": {}}) is None
