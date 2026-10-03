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
