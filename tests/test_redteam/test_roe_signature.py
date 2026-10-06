"""F0 #6 — ROE signed with HMAC (unforgeable), not just a content hash.

A content hash is tamper-EVIDENT (anyone can recompute it); the HMAC signature is
tamper-PROOF — a ROE row cannot be forged or widened and still verify without the
server secret. The engine refuses an engagement whose signature is invalid.
"""

import json

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.redteam.engagement import EngagementManager
from arcanum.redteam.action_classes import ActionClass


@pytest.fixture(autouse=True)
def fixed_secret(monkeypatch):
    # Deterministic secret so create() and verify() agree within the test.
    monkeypatch.setattr("arcanum.redteam.engagement._resolve_roe_secret", lambda: "unit-test-secret")


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(db_path=tmp_path / "sig.db")
    await d.connect()
    await d.init_db()
    yield d
    await d.close()


def test_signature_is_hmac_not_content_hash_and_needs_the_secret():
    args = ("op", ["h"], [ActionClass.ACTIVE], "", "", False)
    content_hash = EngagementManager.compute_roe_hash(*args)
    sig_a = EngagementManager.compute_roe_sig(*args, secret="A")
    assert sig_a != content_hash                                   # HMAC != sha256
    # Without the right secret you cannot reproduce the signature.
    assert sig_a != EngagementManager.compute_roe_sig(*args, secret="B")


@pytest.mark.asyncio
async def test_created_engagement_is_signed_and_valid(db):
    eng = await EngagementManager(db).create(
        name="op", scope=["h"], allowed_classes=[ActionClass.ACTIVE])
    assert eng["roe_sig"]
    assert EngagementManager.verify_signature(eng) == "valid"


@pytest.mark.asyncio
async def test_tampering_a_field_invalidates_signature(db):
    mgr = EngagementManager(db)
    eng = await mgr.create(name="op", scope=["h"], allowed_classes=[ActionClass.ACTIVE])
    # Privilege-escalation attempt: widen the allowed classes directly in the DB.
    await db.execute("UPDATE engagements SET allowed_classes=? WHERE id=?",
                     (json.dumps(["passive", "active", "exploit", "post_exploit", "destructive"]), eng["id"]))
    assert mgr.verify_signature(await mgr.get(eng["id"])) == "invalid"


@pytest.mark.asyncio
async def test_forged_signature_is_invalid(db):
    mgr = EngagementManager(db)
    eng = await mgr.create(name="op", scope=["h"], allowed_classes=[ActionClass.ACTIVE])
    await db.execute("UPDATE engagements SET roe_sig=? WHERE id=?", ("deadbeef", eng["id"]))
    assert mgr.verify_signature(await mgr.get(eng["id"])) == "invalid"


@pytest.mark.asyncio
async def test_legacy_unsigned_reports_unsigned(db):
    mgr = EngagementManager(db)
    eng = await mgr.create(name="op", scope=["h"], allowed_classes=[ActionClass.ACTIVE])
    await db.execute("UPDATE engagements SET roe_sig=NULL WHERE id=?", (eng["id"],))
    assert mgr.verify_signature(await mgr.get(eng["id"])) == "unsigned"


@pytest.mark.asyncio
async def test_active_for_rejects_tampered_engagement(db):
    mgr = EngagementManager(db)
    eng = await mgr.create(name="op", session_id="s1", scope=["h"],
                           allowed_classes=[ActionClass.ACTIVE])
    await db.execute("UPDATE engagements SET allowed_classes=? WHERE id=?",
                     (json.dumps(["destructive"]), eng["id"]))
    # A tampered engagement must never become the active one.
    assert await mgr.active_for("s1") is None


@pytest.mark.asyncio
async def test_active_for_honors_unsigned_unless_required(db, monkeypatch):
    mgr = EngagementManager(db)
    eng = await mgr.create(name="op", session_id="s1", scope=["h"],
                           allowed_classes=[ActionClass.ACTIVE])
    await db.execute("UPDATE engagements SET roe_sig=NULL WHERE id=?", (eng["id"],))
    # Default: legacy unsigned engagements are still honored (backward-compat).
    assert (await mgr.active_for("s1"))["id"] == eng["id"]

    # With require_signed_roe on, an unsigned engagement is rejected.
    class _Cfg:
        require_signed_roe = True
    monkeypatch.setattr("arcanum.core.config.get_config", lambda: _Cfg())
    assert await mgr.active_for("s1") is None
