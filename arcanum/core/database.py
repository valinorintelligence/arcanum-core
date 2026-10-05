"""Async SQLite database layer for Arcanum."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import aiosqlite

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    target TEXT,
    mode TEXT DEFAULT 'manual',
    status TEXT DEFAULT 'created',
    scope TEXT,          -- JSON
    progress TEXT,       -- JSON
    assets TEXT,         -- JSON
    findings_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    type TEXT,
    severity TEXT,
    status TEXT DEFAULT 'confirmed',
    cvss_score REAL,
    cvss_vector TEXT,
    affected TEXT,       -- JSON
    evidence TEXT,       -- JSON
    poc TEXT,            -- JSON
    cve_id TEXT,
    cwe_ids TEXT,        -- JSON
    remediation TEXT,
    verified BOOLEAN DEFAULT FALSE,
    retest_tool TEXT,
    retest_arguments TEXT, -- JSON
    retested_at DATETIME,
    retest_proof TEXT,   -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS stash (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    note TEXT,
    session_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    technology TEXT NOT NULL,
    technique TEXT NOT NULL,
    commands TEXT NOT NULL,
    notes TEXT,
    success_count INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Engagement knowledge graph (assets + relationships)
CREATE TABLE IF NOT EXISTS graph_nodes (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    type TEXT NOT NULL,
    key TEXT NOT NULL,
    label TEXT,
    attrs TEXT,          -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id, type, key)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    src TEXT NOT NULL,
    rel TEXT NOT NULL,
    dst TEXT NOT NULL,
    attrs TEXT,          -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id, src, rel, dst)
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_session ON graph_nodes(session_id, type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_session ON graph_edges(session_id);

-- Semantic retrieval (RAG): embeddings stored as float32 BLOBs per collection
CREATE TABLE IF NOT EXISTS vectors (
    id TEXT PRIMARY KEY,          -- "<collection>:<ref_id>"
    collection TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    text TEXT,
    dim INTEGER,
    vec BLOB,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(collection, ref_id)
);
CREATE INDEX IF NOT EXISTS idx_vectors_collection ON vectors(collection);

CREATE VIRTUAL TABLE IF NOT EXISTS playbooks_fts USING fts5(
    technology, technique, commands, notes, content='playbooks', content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS playbooks_ai AFTER INSERT ON playbooks BEGIN
  INSERT INTO playbooks_fts(rowid, technology, technique, commands, notes) VALUES (new.rowid, new.technology, new.technique, new.commands, new.notes);
END;

CREATE TRIGGER IF NOT EXISTS playbooks_ad AFTER DELETE ON playbooks BEGIN
  INSERT INTO playbooks_fts(playbooks_fts, rowid, technology, technique, commands, notes) VALUES('delete', old.rowid, old.technology, old.technique, old.commands, old.notes);
END;

CREATE TRIGGER IF NOT EXISTS playbooks_au AFTER UPDATE ON playbooks BEGIN
  INSERT INTO playbooks_fts(playbooks_fts, rowid, technology, technique, commands, notes) VALUES('delete', old.rowid, old.technology, old.technique, old.commands, old.notes);
  INSERT INTO playbooks_fts(rowid, technology, technique, commands, notes) VALUES (new.rowid, new.technology, new.technique, new.commands, new.notes);
END;

-- Distributed Satellite Probes & Remote Dispatch
CREATE TABLE IF NOT EXISTS satellite_probes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT,
    ip_address TEXT,
    status TEXT DEFAULT 'online',
    tags TEXT,
    capabilities TEXT,
    version TEXT DEFAULT '3.0.0',
    last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
    registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS probe_tasks (
    id TEXT PRIMARY KEY,
    probe_id TEXT NOT NULL,
    session_id TEXT,
    tool_name TEXT NOT NULL,
    arguments TEXT,
    status TEXT DEFAULT 'pending',
    result TEXT,
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    assigned_at DATETIME,
    completed_at DATETIME,
    FOREIGN KEY (probe_id) REFERENCES satellite_probes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_probe_tasks_probe ON probe_tasks(probe_id, status);

-- Active Directory & Identity Graph (BloodHound / Pentera Engine)
CREATE TABLE IF NOT EXISTS ad_domains (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    forest_name TEXT,
    domain_sid TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ad_objects (
    id TEXT PRIMARY KEY,
    domain_id TEXT NOT NULL,
    object_sid TEXT NOT NULL,
    object_type TEXT NOT NULL,
    name TEXT NOT NULL,
    display_name TEXT,
    is_tier_zero INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0,
    has_spn INTEGER DEFAULT 0,
    dont_req_preauth INTEGER DEFAULT 0,
    metadata_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES ad_domains(id) ON DELETE CASCADE,
    UNIQUE(domain_id, object_sid)
);

CREATE TABLE IF NOT EXISTS ad_edges (
    id TEXT PRIMARY KEY,
    domain_id TEXT NOT NULL,
    source_sid TEXT NOT NULL,
    target_sid TEXT NOT NULL,
    relationship TEXT NOT NULL,
    is_inherited INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES ad_domains(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ad_objects_domain ON ad_objects(domain_id, object_type);
CREATE INDEX IF NOT EXISTS idx_ad_edges_source ON ad_edges(domain_id, source_sid);
CREATE INDEX IF NOT EXISTS idx_ad_edges_target ON ad_edges(domain_id, target_sid);

-- Red Team governance (F0): engagements (ROE), immutable action log, foothold registry.
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    session_id TEXT,              -- optional: scope the engagement to one session
    scope TEXT,                   -- JSON list of authorized hosts/CIDRs
    allowed_classes TEXT,         -- JSON list of ActionClass values
    window_start DATETIME,
    window_end DATETIME,
    roe_hash TEXT NOT NULL,       -- tamper-evidence hash of the contract
    status TEXT DEFAULT 'active', -- active | closed
    operator TEXT,
    auto_approve INTEGER DEFAULT 0, -- 1 = full-scope LAB ROE: the signed engagement pre-authorizes
                                    -- its allowed classes, waiving the per-action HITL pause (audit/
                                    -- scope/cleanup/deconfliction STILL apply; DESTRUCTIVE also needs
                                    -- allow_destructive_testing). Only for an operator's own lab.
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    closed_at DATETIME
);

CREATE TABLE IF NOT EXISTS actions_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT,
    session_id TEXT,
    tool TEXT,
    action_class TEXT,
    target TEXT,
    decision TEXT,                -- executed | blocked_by_roe | kill_switch | ...
    risk TEXT,
    arguments TEXT,               -- JSON (masked)
    result_summary TEXT,
    operator TEXT,
    deconfliction_tag TEXT,
    prev_hash TEXT,               -- chain linkage
    entry_hash TEXT NOT NULL,     -- sha256(prev_hash + payload)
    payload TEXT,                 -- exact JSON that was hashed (for verification)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_actions_log_engagement ON actions_log(engagement_id);

-- Tamper anchor for the actions_log hash chain (F0 follow-up #4). The hash chain
-- alone detects edits to existing rows but NOT truncation of the tail (deleting
-- the last N entries). This single-row anchor records the expected entry count and
-- last hash, updated under the same append lock as actions_log, so verify_chain
-- can catch tail truncation (count/last-hash mismatch). It does not defend against
-- an attacker who rewrites both the log AND the anchor (same threat model as a full
-- chain rewrite) — for that, anchor the last hash in external storage.
CREATE TABLE IF NOT EXISTS audit_anchor (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- single row
    entry_count INTEGER NOT NULL DEFAULT 0,
    last_hash TEXT NOT NULL DEFAULT '',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS redteam_sessions (
    id TEXT PRIMARY KEY,
    engagement_id TEXT,
    session_id TEXT,
    host TEXT,
    access_level TEXT DEFAULT 'user',  -- none | user | admin | system
    implant_type TEXT DEFAULT 'shell',
    parent_id TEXT,              -- pivot parent foothold
    status TEXT DEFAULT 'open',  -- open | cleaned | closed | cleanup_pending | cleanup_failed
    metadata TEXT,               -- JSON (incl. optional teardown_recipe for real cleanup)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    closed_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_redteam_sessions_engagement ON redteam_sessions(engagement_id, status);

-- Blue Team (F2): rollback registry for real defensive actions (detection-rule
-- deploys, hardening applies, IR containment). Every change is recorded so it
-- can be verified and reversed.
CREATE TABLE IF NOT EXISTS blue_deployments (
    id TEXT PRIMARY KEY,
    kind TEXT,                   -- detection_rule | hardening | ir_action
    target_system TEXT,          -- siem | waf | edr | firewall | host | account
    rule_type TEXT,              -- sigma | modsecurity | suricata | elastic | host-hardening | ...
    name TEXT,
    status TEXT DEFAULT 'active',-- active | rolled_back | failed | dry_run | planned
    mock INTEGER DEFAULT 0,      -- 1 = honest mock (no real external deploy)
    reversible INTEGER DEFAULT 1,
    payload TEXT,                -- JSON (rule/diff/action detail)
    external_id TEXT,            -- id returned by a real external system
    session_id TEXT,
    engagement_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    verified_at DATETIME,
    rolled_back_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_blue_deployments_kind ON blue_deployments(kind, status);

-- Purple Team (F3): MEASURED BAS results (closed loop). Each run of a technique
-- plus its detection verdict is stored so efficacy is computed from measurement,
-- not a static seed, and so the detect→tune→re-measure loop is auditable.
CREATE TABLE IF NOT EXISTS purple_results (
    id TEXT PRIMARY KEY,
    campaign_id TEXT,
    technique_id TEXT,
    tactic TEXT,
    deconfliction_tag TEXT,
    executed INTEGER DEFAULT 0,
    execution_status TEXT,       -- executed | simulated | blocked
    detected INTEGER,            -- NULL = unknown, 0 = miss, 1 = hit
    detection_source TEXT,       -- deployed_rule | deployed_rule_simulated | siem | none
    detection_simulated INTEGER DEFAULT 0, -- 1 = detection only via a MOCK deploy (no real control)
    prevented INTEGER,           -- NULL = unknown, 0 = not prevented, 1 = BLOCKED by a control
    prevention_source TEXT,      -- bas_blocked | deployed_control | deployed_control_simulated | none
    prevention_simulated INTEGER DEFAULT 0, -- 1 = prevention only via a MOCK preventive deploy
    tuned INTEGER DEFAULT 0,     -- a detection rule was deployed to close the gap
    deployment_id TEXT,          -- the rule deployed to close the gap (if any)
    session_id TEXT,
    engagement_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_purple_results_campaign ON purple_results(campaign_id);
"""


class Database:
    """Thin async wrapper around an aiosqlite connection."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------
    # Standalone connect / close
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the database connection (standalone, outside context manager)."""
        if self._conn is None:
            self._conn = await aiosqlite.connect(self.db_path)
            self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA journal_mode=WAL")
            await self._conn.execute("PRAGMA foreign_keys=ON")

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "Database":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    async def init_db(self) -> None:
        """Create tables if they don't already exist and apply migrations."""
        assert self._conn is not None, "Database not connected"
        await self._conn.executescript(_SCHEMA_SQL)
        await self._conn.commit()

        # Migrate existing findings table if columns are missing
        try:
            cursor = await self._conn.execute("PRAGMA table_info(findings)")
            cols = {row["name"] for row in await cursor.fetchall()}
            if "status" not in cols:
                await self._conn.execute("ALTER TABLE findings ADD COLUMN status TEXT DEFAULT 'confirmed'")
            if "retest_tool" not in cols:
                await self._conn.execute("ALTER TABLE findings ADD COLUMN retest_tool TEXT")
            if "retest_arguments" not in cols:
                await self._conn.execute("ALTER TABLE findings ADD COLUMN retest_arguments TEXT")
            if "retested_at" not in cols:
                await self._conn.execute("ALTER TABLE findings ADD COLUMN retested_at DATETIME")
            if "retest_proof" not in cols:
                await self._conn.execute("ALTER TABLE findings ADD COLUMN retest_proof TEXT")
            await self._conn.commit()
        except Exception:
            pass

        # Compromise-state columns on graph nodes (F0): track owned access level,
        # held credentials and the foothold that owns the node. Idempotent — only
        # adds columns that are missing (fresh DBs created without them above).
        try:
            cursor = await self._conn.execute("PRAGMA table_info(graph_nodes)")
            gcols = {row["name"] for row in await cursor.fetchall()}
            if "owned" not in gcols:
                await self._conn.execute(
                    "ALTER TABLE graph_nodes ADD COLUMN owned TEXT DEFAULT 'none'")  # none/user/admin/system
            if "creds_held" not in gcols:
                await self._conn.execute("ALTER TABLE graph_nodes ADD COLUMN creds_held TEXT")  # JSON (masked)
            if "foothold_id" not in gcols:
                await self._conn.execute("ALTER TABLE graph_nodes ADD COLUMN foothold_id TEXT")
            await self._conn.commit()
        except Exception:
            pass

        # Purple honesty column (F3 review): detection via a MOCK deploy is
        # SIMULATED coverage, not a real control — tracked separately so it never
        # inflates the real detection rate. Idempotent for already-created DBs.
        try:
            cursor = await self._conn.execute("PRAGMA table_info(purple_results)")
            pcols = {row["name"] for row in await cursor.fetchall()}
            if pcols and "detection_simulated" not in pcols:
                await self._conn.execute(
                    "ALTER TABLE purple_results ADD COLUMN detection_simulated INTEGER DEFAULT 0")
            # F3 (d): PREVENTION (BLOCKED by a control) is distinct from DETECTION
            # (alerted/logged). Tracked separately, with the same real-vs-simulated
            # honesty split. Idempotent for already-created DBs.
            if pcols and "prevented" not in pcols:
                await self._conn.execute(
                    "ALTER TABLE purple_results ADD COLUMN prevented INTEGER")
            if pcols and "prevention_source" not in pcols:
                await self._conn.execute(
                    "ALTER TABLE purple_results ADD COLUMN prevention_source TEXT")
            if pcols and "prevention_simulated" not in pcols:
                await self._conn.execute(
                    "ALTER TABLE purple_results ADD COLUMN prevention_simulated INTEGER DEFAULT 0")
            await self._conn.commit()
        except Exception:
            pass

        # Full-scope lab ROE (auto_approve): pre-authorizes allowed classes for an
        # operator's own lab, waiving the per-action HITL pause (rails stay). Idempotent.
        try:
            cursor = await self._conn.execute("PRAGMA table_info(engagements)")
            ecols = {row["name"] for row in await cursor.fetchall()}
            if ecols and "auto_approve" not in ecols:
                await self._conn.execute(
                    "ALTER TABLE engagements ADD COLUMN auto_approve INTEGER DEFAULT 0")
            await self._conn.commit()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    async def execute(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> aiosqlite.Cursor:
        """Execute a single SQL statement and commit."""
        assert self._conn is not None, "Database not connected"
        cursor = await self._conn.execute(sql, params)
        await self._conn.commit()
        return cursor

    async def fetch_one(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> dict[str, Any] | None:
        """Return a single row as a dict, or None."""
        assert self._conn is not None, "Database not connected"
        cursor = await self._conn.execute(sql, params)
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    async def fetch_all(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> list[dict[str, Any]]:
        """Return all matching rows as a list of dicts."""
        assert self._conn is not None, "Database not connected"
        cursor = await self._conn.execute(sql, params)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
