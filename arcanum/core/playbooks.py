"""Continuous learning playbook knowledge base backed by SQLite and FTS5."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


DEFAULT_PLAYBOOKS = [
    {
        "technology": "nginx",
        "technique": "403_forbidden_path_normalization_bypass",
        "commands": "curl -k -s -I 'https://TARGET/..;/admin'\ncurl -k -s -I 'https://TARGET/%2e/admin'\ncurl -k -s -I 'https://TARGET/admin/.'",
        "notes": "Bypasses reverse proxy restrictions via URI normalization discrepancies (Nginx / Tomcat / Spring).",
    },
    {
        "technology": "http_waf",
        "technique": "header_origin_ip_spoofing",
        "commands": "curl -k -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1' -H 'X-Custom-IP-Authorization: 127.0.0.1' 'https://TARGET/'",
        "notes": "Tests if internal access control or rate-limiting is fooled by client-controlled IP headers.",
    },
    {
        "technology": "springboot",
        "technique": "actuator_endpoint_enumeration",
        "commands": "curl -k -s 'https://TARGET/actuator'\ncurl -k -s 'https://TARGET/actuator/env'\ncurl -k -s 'https://TARGET/actuator/heapdump' -o heapdump.hprof",
        "notes": "Spring Boot 2.x/3.x exposed actuators can reveal sensitive credentials, tokens, and heap dumps.",
    },
    {
        "technology": "wordpress",
        "technique": "xmlrpc_methods_and_user_enumeration",
        "commands": "curl -k -s -X POST -d '<methodCall><methodName>system.listMethods</methodName></methodCall>' 'https://TARGET/xmlrpc.php'\ncurl -k -s 'https://TARGET/wp-json/wp/v2/users'",
        "notes": "Checks for XML-RPC pingback DDoS/bruteforce capability and REST API user disclosure.",
    },
    {
        "technology": "nmap",
        "technique": "stealth_fast_service_discovery",
        "commands": "nmap -sS -T4 --top-ports 1000 --open -sV -sC -Pn -oA /workspace/output/nmap_fast TARGET",
        "notes": "Optimized balance of speed and detection accuracy for initial host reconnaissance.",
    },
]


class PlaybookManager:
    """Manages cross-operation playbooks with FTS5 search."""

    def __init__(self, db: Any):
        self.db = db

    def _format_row(self, row: dict | Any) -> dict:
        d = dict(row)
        tech = d.get("technology", "")
        technique = d.get("technique", "")
        formatted_title = technique.replace("_", " ").title() if "_" in technique else technique
        d["title"] = formatted_title or technique or tech
        d["category"] = tech
        d["steps"] = d.get("commands", "")
        d["trigger"] = f"Trigger: {tech.upper()} detection or {formatted_title}"
        if "[Trigger:" in d.get("notes", ""):
            import re
            m = re.search(r'\[Trigger:\s*(.*?)\]', d["notes"])
            if m:
                d["trigger"] = m.group(1).strip()
        d["tools"] = [tech] if tech else []
        d["times_used"] = d.get("success_count", 1)
        d["author"] = "builtin"
        return d

    async def search(self, query: str, limit: int = 5) -> list[dict]:
        """Search playbooks using full-text search with fallback to LIKE."""
        if not query or not query.strip():
            rows = await self.db.fetch_all("SELECT * FROM playbooks ORDER BY success_count DESC LIMIT ?", (limit,))
            return [self._format_row(r) for r in rows]

        clean_query = query.strip().replace("'", "").replace('"', "")
        try:
            # Try FTS5 MATCH
            fts_query = f"{clean_query}*"
            sql = """
                SELECT p.*
                FROM playbooks_fts fts
                JOIN playbooks p ON p.rowid = fts.rowid
                WHERE playbooks_fts MATCH ?
                ORDER BY rank, p.success_count DESC
                LIMIT ?
            """
            rows = await self.db.fetch_all(sql, (fts_query, limit))
            if rows:
                return [self._format_row(r) for r in rows]
        except Exception:
            pass

        # Fallback to standard LIKE
        like_pattern = f"%{clean_query}%"
        sql = """
            SELECT * FROM playbooks
            WHERE technology LIKE ? OR technique LIKE ? OR commands LIKE ? OR notes LIKE ?
            ORDER BY success_count DESC
            LIMIT ?
        """
        rows = await self.db.fetch_all(sql, (like_pattern, like_pattern, like_pattern, like_pattern, limit))
        return [self._format_row(r) for r in rows]

    async def save(
        self,
        technology: str,
        technique: str,
        commands: str,
        notes: str = "",
    ) -> dict:
        """Save or increment success count of a proven playbook technique."""
        now = datetime.now(timezone.utc).isoformat()

        # Check if technique already exists for this technology
        existing = await self.db.fetch_one(
            "SELECT * FROM playbooks WHERE LOWER(technology) = LOWER(?) AND LOWER(technique) = LOWER(?)",
            (technology.strip(), technique.strip()),
        )
        if existing:
            playbook_id = existing["id"]
            new_count = (existing["success_count"] or 1) + 1
            await self.db.execute(
                """UPDATE playbooks
                   SET commands = ?, notes = ?, success_count = ?, updated_at = ?
                   WHERE id = ?""",
                (commands.strip(), notes.strip(), new_count, now, playbook_id),
            )
            return self._format_row({
                "id": playbook_id,
                "technology": technology,
                "technique": technique,
                "commands": commands,
                "notes": notes,
                "success_count": new_count,
                "action": "updated",
            })

        playbook_id = f"pb-{uuid.uuid4().hex[:8]}"
        await self.db.execute(
            """INSERT INTO playbooks (id, technology, technique, commands, notes, success_count, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
            (playbook_id, technology.strip().lower(), technique.strip(), commands.strip(), notes.strip(), now, now),
        )
        return self._format_row({
            "id": playbook_id,
            "technology": technology,
            "technique": technique,
            "commands": commands,
            "notes": notes,
            "success_count": 1,
            "action": "created",
        })

    async def save_playbook(
        self,
        title: str,
        category: str = "general",
        trigger: str = "",
        steps: str = "",
        tools: list[str] | str | None = None,
        notes: str = "",
        author: str = "operator",
    ) -> dict:
        """Save playbook using higher-level tactical attributes."""
        technique = title.strip()
        technology = category.strip().lower()
        commands = steps.strip()
        full_notes = notes.strip()
        if trigger:
            full_notes = f"[Trigger: {trigger.strip()}] {full_notes}".strip()
        res = await self.save(
            technology=technology,
            technique=technique,
            commands=commands,
            notes=full_notes,
        )
        res["author"] = author
        if tools:
            res["tools"] = tools if isinstance(tools, list) else [tools]
        return res

    async def seed_defaults_if_empty(self) -> int:
        """Seed default pentesting playbooks if the database table is empty."""
        count_row = await self.db.fetch_one("SELECT COUNT(*) as cnt FROM playbooks")
        if count_row and count_row["cnt"] > 0:
            return 0

        seeded = 0
        for item in DEFAULT_PLAYBOOKS:
            await self.save(
                technology=item["technology"],
                technique=item["technique"],
                commands=item["commands"],
                notes=item["notes"],
            )
            seeded += 1
        return seeded
