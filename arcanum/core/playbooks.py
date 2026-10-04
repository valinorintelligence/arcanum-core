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
        "technique": "fast_service_discovery",
        "commands": "nmap -sT -Pn -T4 --top-ports 1000 --open -sV -oA /workspace/output/nmap_fast TARGET",
        "notes": "Connect scan (-sT) for the non-root sandbox: -sS/SYN needs raw sockets and fails. -Pn skips ICMP (cloud targets drop ping).",
    },
    {
        "technology": "httpx",
        "technique": "http_probe_tech_detect",
        "commands": "httpx-toolkit -u TARGET -tech-detect -status-code -title",
        "notes": "Use 'httpx-toolkit' (ProjectDiscovery). On the sandbox '/usr/bin/httpx' is the Python HTTP client and has no -u flag.",
    },
    {
        "technology": "nuclei",
        "technique": "safe_vuln_scan",
        "commands": "nuclei -u TARGET -severity critical,high -rl 50",
        "notes": "Rate-limit (-rl) so fragile cloud/proxy targets don't go unresponsive mid-scan under thousands of connections.",
    },
    # --- Recon ------------------------------------------------------------
    {
        "technology": "subfinder",
        "technique": "passive_subdomain_enum",
        "commands": "subfinder -d TARGET -all -silent -o /workspace/output/subdomains.txt",
        "notes": "Passive OSINT subdomain enumeration (no direct traffic to the target).",
    },
    {
        "technology": "dnsx",
        "technique": "resolve_and_records",
        "commands": "dnsx -l /workspace/output/subdomains.txt -a -resp -silent -o /workspace/output/dns.txt",
        "notes": "Resolve discovered subdomains to live IPs and pull A/CNAME records.",
    },
    {
        "technology": "katana",
        "technique": "endpoint_crawl",
        "commands": "katana -u https://TARGET -jc -silent -o /workspace/output/endpoints.txt",
        "notes": "Crawl pages + JavaScript (-jc) to map endpoints, forms and hidden API routes.",
    },
    # --- Web discovery ----------------------------------------------------
    {
        "technology": "ffuf",
        "technique": "directory_bruteforce",
        "commands": "ffuf -u https://TARGET/FUZZ -w /opt/seclists/Discovery/Web-Content/common.txt -mc 200,204,301,302,307,401,403 -t 40 -o /workspace/output/ffuf.json",
        "notes": "Content discovery with SecLists common wordlist; -mc filters interesting status codes.",
    },
    {
        "technology": "feroxbuster",
        "technique": "recursive_content_discovery",
        "commands": "feroxbuster -u https://TARGET -w /opt/seclists/Discovery/Web-Content/raft-medium-directories.txt -d 2 -s 200,301,302,401,403 --silent",
        "notes": "Recursive directory discovery (depth 2) — good for finding nested admin/api paths.",
    },
    {
        "technology": "exposure",
        "technique": "sensitive_files_probe",
        "commands": "curl -k -s -o /dev/null -w '%{http_code} .git/HEAD\\n' https://TARGET/.git/HEAD\ncurl -k -s -o /dev/null -w '%{http_code} .env\\n' https://TARGET/.env\ncurl -k -s -o /dev/null -w '%{http_code} .DS_Store\\n' https://TARGET/.DS_Store",
        "notes": "Checks for exposed source control, environment files and metadata (common misconfig leaks).",
    },
    {
        "technology": "api",
        "technique": "openapi_swagger_discovery",
        "commands": "for p in /swagger.json /openapi.json /api-docs /v2/api-docs /swagger-ui.html; do curl -k -s -o /dev/null -w \"%{http_code} $p\\n\" \"https://TARGET$p\"; done",
        "notes": "Locate API documentation that reveals endpoints, parameters and auth schemes.",
    },
    {
        "technology": "http_headers",
        "technique": "security_header_review",
        "commands": "curl -k -s -I https://TARGET",
        "notes": "Review for missing CSP / X-Frame-Options / HSTS / X-Content-Type-Options and Server banner disclosure.",
    },
    {
        "technology": "cors",
        "technique": "cors_misconfig_probe",
        "commands": "curl -k -s -I -H 'Origin: https://evil.example' https://TARGET | grep -i 'access-control-allow'",
        "notes": "If the origin is reflected with Allow-Credentials:true, CORS is misconfigured.",
    },
    # --- Technology-specific ---------------------------------------------
    {
        "technology": "graphql",
        "technique": "introspection_query",
        "commands": "curl -k -s -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}' https://TARGET/graphql",
        "notes": "If introspection is enabled it dumps the full schema (types, queries, mutations).",
    },
    {
        "technology": "jwt",
        "technique": "none_algorithm_and_weak_secret",
        "commands": "jwt_tool <TOKEN> -X a\njwt_tool <TOKEN> -C -d /opt/seclists/Passwords/jwt.secrets.list",
        "notes": "Test the 'none' algorithm bypass and brute-force weak HS256 signing secrets.",
    },
    {
        "technology": "wordpress",
        "technique": "wpscan_enumeration",
        "commands": "wpscan --url https://TARGET --enumerate vp,u --random-user-agent --no-banner",
        "notes": "Enumerate vulnerable plugins (vp) and users (u). Add --api-token for CVE data.",
    },
    # --- Safe vulnerability confirmation ---------------------------------
    {
        "technology": "sqlmap",
        "technique": "sqli_detection_batch",
        "commands": "sqlmap -u 'https://TARGET/path?id=1' --batch --level 2 --risk 1 --random-agent",
        "notes": "Non-destructive SQLi detection (level 2/risk 1). Escalate only with authorization.",
    },
    {
        "technology": "dalfox",
        "technique": "xss_detection",
        "commands": "dalfox url https://TARGET --silence --skip-bav",
        "notes": "Reflected/stored XSS detection on parameters discovered during crawl.",
    },
    {
        "technology": "default_creds",
        "technique": "exposed_panels_and_default_logins",
        "commands": "nuclei -u TARGET -tags exposure,default-login,panel -rl 50",
        "notes": "Detect exposed admin panels and services still using default credentials.",
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

    async def ensure_defaults(self) -> int:
        """Idempotently insert any missing default playbooks without disturbing
        existing rows. Unlike seed_defaults_if_empty this runs even when the KB
        already has entries (e.g. learned ones), so expanding the built-in
        library reaches existing installs on the next boot — and it does NOT
        bump success_count (no inflation) nor overwrite what the agent learned."""
        now = datetime.now(timezone.utc).isoformat()
        added = 0
        for item in DEFAULT_PLAYBOOKS:
            existing = await self.db.fetch_one(
                "SELECT id FROM playbooks WHERE LOWER(technology)=LOWER(?) AND LOWER(technique)=LOWER(?)",
                (item["technology"].strip(), item["technique"].strip()),
            )
            if existing:
                continue
            playbook_id = f"pb-{uuid.uuid4().hex[:8]}"
            await self.db.execute(
                """INSERT INTO playbooks (id, technology, technique, commands, notes, success_count, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
                (playbook_id, item["technology"].strip().lower(), item["technique"].strip(),
                 item["commands"].strip(), item["notes"].strip(), now, now),
            )
            added += 1
        return added

    async def ensure_skill_playbooks(self) -> int:
        """Seed the built-in Skill library (arcanum/agent/skills.py) into the
        playbook KB so its 57 curated methodologies are reachable via semantic
        recall (RAG/FTS) — WITHOUT bloating the system prompt. Idempotent: skips
        skills already present (matched by technology=category + technique=name).

        This is how the Skill library is 'wired' into the agent: instead of the
        unused SkillRouter injecting steps into the prompt, the skills become
        recall entries that the engine surfaces only when the context matches.
        """
        try:
            from ..agent.skills import BUILTIN_SKILLS
        except Exception:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        added = 0
        for sk in BUILTIN_SKILLS:
            technology = (getattr(sk, "category", "") or "general").strip().lower()
            technique = (getattr(sk, "name", "") or "").strip()
            if not technique:
                continue
            existing = await self.db.fetch_one(
                "SELECT id FROM playbooks WHERE LOWER(technology)=LOWER(?) AND LOWER(technique)=LOWER(?)",
                (technology, technique),
            )
            if existing:
                continue
            steps = getattr(sk, "steps", []) or []
            commands = "\n".join(s for s in steps if s).strip()
            kws = ", ".join(getattr(sk, "keywords", []) or [])
            tools = ", ".join(getattr(sk, "tools", []) or [])
            desc = (getattr(sk, "description", "") or "").strip()
            risk = getattr(sk, "risk_level", "medium")
            notes = f"{desc}".strip()
            if kws:
                notes = f"[Trigger: {kws}] {notes}".strip()
            if tools:
                notes = f"{notes} [Tools: {tools}]".strip()
            notes = f"{notes} [Risk: {risk}] [Fonte: skill library]".strip()
            playbook_id = f"pb-{uuid.uuid4().hex[:8]}"
            await self.db.execute(
                """INSERT INTO playbooks (id, technology, technique, commands, notes, success_count, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
                (playbook_id, technology, technique, commands, notes, now, now),
            )
            added += 1
        return added
