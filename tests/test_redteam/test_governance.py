"""F0 — EngagementManager (ROE), ActionAuditLog (hash chain), SessionRegistry."""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio

from arcanum.core.database import Database
from arcanum.redteam.engagement import EngagementManager
from arcanum.redteam.audit import ActionAuditLog, mask_arguments, summarize_result
from arcanum.redteam.sessions import SessionRegistry
from arcanum.redteam.action_classes import ActionClass


@pytest_asyncio.fixture
async def db():
    with tempfile.TemporaryDirectory() as tmp:
        d = Database(db_path=Path(tmp) / "rt.db")
        await d.connect()
        await d.init_db()
        yield d
        await d.close()


# ---------------------------------------------------------------------------
# Schema / migration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_f0_tables_and_graph_columns_exist(db):
    for tbl in ("engagements", "actions_log", "redteam_sessions"):
        row = await db.fetch_one(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (tbl,))
        assert row is not None, f"missing table {tbl}"
    cur = await db.execute("PRAGMA table_info(graph_nodes)")
    cols = {r["name"] for r in await cur.fetchall()}
    assert {"owned", "creds_held", "foothold_id"} <= cols


# ---------------------------------------------------------------------------
# EngagementManager
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_engagement_has_roe_hash_and_classes(db):
    mgr = EngagementManager(db)
    eng = await mgr.create(
        name="Test Op", scope=["example.com"],
        allowed_classes=[ActionClass.PASSIVE, ActionClass.ACTIVE])
    assert eng["roe_hash"]
    assert eng["status"] == "active"
    assert set(eng["allowed_classes"]) == {"passive", "active"}
    assert eng["deconfliction_tag"].startswith("ARC-")


@pytest.mark.asyncio
async def test_is_allowed_blocks_class_outside_roe(db):
    mgr = EngagementManager(db)
    eng = await mgr.create(name="Op", allowed_classes=[ActionClass.PASSIVE, ActionClass.ACTIVE])
    ok, _ = mgr.is_allowed(eng, ActionClass.ACTIVE, "example.com")
    assert ok is True
    ok, reason = mgr.is_allowed(eng, ActionClass.EXPLOIT, "example.com")
    assert ok is False and "class" in reason.lower()


@pytest.mark.asyncio
async def test_is_allowed_no_engagement_is_legacy_allow(db):
    mgr = EngagementManager(db)
    ok, _ = mgr.is_allowed(None, ActionClass.DESTRUCTIVE, "anything")
    assert ok is True


@pytest.mark.asyncio
async def test_is_allowed_scope_enforced(db):
    mgr = EngagementManager(db)
    eng = await mgr.create(name="Op", scope=["example.com"],
                           allowed_classes=[ActionClass.ACTIVE])
    ok, _ = mgr.is_allowed(eng, ActionClass.ACTIVE, "api.example.com")  # subdomain in scope
    assert ok is True
    ok, reason = mgr.is_allowed(eng, ActionClass.ACTIVE, "evil.org")
    assert ok is False and "scope" in reason.lower()


@pytest.mark.asyncio
async def test_is_allowed_window_expired(db):
    mgr = EngagementManager(db)
    past = datetime.now(timezone.utc) - timedelta(days=2)
    yday = datetime.now(timezone.utc) - timedelta(days=1)
    eng = await mgr.create(name="Op", allowed_classes=[ActionClass.ACTIVE],
                           window={"start": past.isoformat(), "end": yday.isoformat()})
    ok, reason = mgr.is_allowed(eng, ActionClass.ACTIVE, "example.com")
    assert ok is False and ("window" in reason.lower() or "expired" in reason.lower())


@pytest.mark.asyncio
async def test_active_for_prefers_session_then_global(db):
    mgr = EngagementManager(db)
    g = await mgr.create(name="Global", allowed_classes=[ActionClass.PASSIVE])
    s = await mgr.create(name="Session", session_id="op-1", allowed_classes=[ActionClass.ACTIVE])
    assert (await mgr.active_for("op-1"))["id"] == s["id"]
    assert (await mgr.active_for("op-other"))["id"] == g["id"]
    await mgr.close(s["id"])
    assert (await mgr.active_for("op-1"))["id"] == g["id"]


# ---------------------------------------------------------------------------
# ActionAuditLog — hash chain
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_chain_links_and_verifies(db):
    log = ActionAuditLog(db)
    r1 = await log.record(tool="audit_tls_ssl", action_class="passive", decision="executed",
                          target="example.com")
    r2 = await log.record(tool="execute", action_class="active", decision="executed",
                          target="example.com", arguments={"command": "nmap example.com"})
    assert r1["prev_hash"] == ""          # genesis
    assert r2["prev_hash"] == r1["entry_hash"]
    v = await log.verify_chain()
    assert v["valid"] is True and v["length"] == 2 and v["broken_at"] is None


@pytest.mark.asyncio
async def test_audit_tamper_breaks_chain(db):
    log = ActionAuditLog(db)
    await log.record(tool="a", action_class="passive", decision="executed")
    await log.record(tool="b", action_class="active", decision="executed")
    # Tamper with the first row's payload directly.
    await db.execute("UPDATE actions_log SET payload = ? WHERE id = (SELECT MIN(id) FROM actions_log)",
                     ('{"tampered":true}',))
    v = await log.verify_chain()
    assert v["valid"] is False and v["broken_at"] is not None


@pytest.mark.asyncio
async def test_audit_masks_secrets(db):
    log = ActionAuditLog(db)
    await log.record(tool="execute", action_class="active", decision="executed",
                     arguments={"password": "hunter2", "url": "https://example.com", "token": "abc"})
    rows = await log.list(limit=10)
    args = rows[0]["arguments"]
    assert args["password"] == "***REDACTED***"
    assert args["token"] == "***REDACTED***"
    assert args["url"] == "https://example.com"


def test_mask_arguments_and_summarize_pure():
    masked = mask_arguments({"api_key": "x", "nested": {"secret": "y", "host": "h"}, "big": "z" * 1000})
    assert masked["api_key"] == "***REDACTED***"
    assert masked["nested"]["secret"] == "***REDACTED***"
    assert masked["nested"]["host"] == "h"
    assert masked["big"].endswith("…<truncated>")
    assert summarize_result({"success": True, "output": {"score": 1}}).startswith("ok")
    assert summarize_result({"success": False, "error": "boom"}).startswith("fail")


def test_mask_arguments_scrubs_inline_credentials_in_values():
    # Regression (2nd-opinion review #2): key-based masking misses secrets passed
    # INLINE in a value (notably the `execute` command, or a URL). Those must be
    # scrubbed too.
    # sshpass inline password in a command string:
    m = mask_arguments({"command": "sshpass -p S3nhaSecreta ssh root@10.0.0.1"})
    assert "S3nhaSecreta" not in m["command"] and "***REDACTED***" in m["command"]
    # long-form flag:
    m = mask_arguments({"command": "mytool --password=Hunter2 --host example.com"})
    assert "Hunter2" not in m["command"]
    # URL userinfo scheme://user:pass@host:
    m = mask_arguments({"url": "https://admin:P4ssw0rd@internal.example.com/x"})
    assert "P4ssw0rd" not in m["url"] and "admin" in m["url"]
    # credential CLI short flag (mysql -pSECRET):
    m = mask_arguments({"command": "mysql -u root -pTopSecret -h db.example.com"})
    assert "TopSecret" not in m["command"]
    # Bearer token:
    m = mask_arguments({"command": "curl -H 'Authorization: Bearer abcdef0123456789' https://x"})
    assert "abcdef0123456789" not in m["command"]


def test_mask_arguments_preserves_benign_port_flags():
    # Must NOT over-redact: nmap -p is a port list, not a password.
    m = mask_arguments({"command": "nmap -sV -p 80,443,8080 example.com"})
    assert "80,443,8080" in m["command"]
    assert "***REDACTED***" not in m["command"]


# ---------------------------------------------------------------------------
# SessionRegistry — footholds + cleanup
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_foothold_registry_and_cleanup(db):
    reg = SessionRegistry(db)
    f1 = await reg.create_foothold(engagement_id="eng-1", host="10.0.0.1", access_level="user")
    f2 = await reg.create_foothold(engagement_id="eng-1", host="10.0.0.2", access_level="admin")
    assert f1["status"] == "open"
    openlist = await reg.list(engagement_id="eng-1", status="open")
    assert len(openlist) == 2

    res = await reg.cleanup("eng-1")
    assert res["cleaned"] == 2
    assert set(res["ids"]) == {f1["id"], f2["id"]}
    assert await reg.list(engagement_id="eng-1", status="open") == []
    cleaned = await reg.list(engagement_id="eng-1", status="cleaned")
    assert len(cleaned) == 2
