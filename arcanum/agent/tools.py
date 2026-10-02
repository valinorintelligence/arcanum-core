"""Native tool definitions and executor for the Arcanum agent."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Tool definitions (OpenAI-style tool-calling format)
# ---------------------------------------------------------------------------

NATIVE_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "execute",
            "description": (
                "Run a shell command inside the non-root Docker sandbox. Use the EXACT syntax for this sandbox: "
                "subdomains 'subfinder -d <target>'; HTTP probe 'httpx-toolkit -u <target> -tech-detect -status-code' "
                "(NOT 'httpx', which here is the Python client); ports 'nmap -sT -Pn -sV -p 80,443 <target>' "
                "(use -sT connect scan; SYN/-sS needs root and will fail); crawl 'katana -u http://<target>'; "
                "vuln scan 'nuclei -u <target> -severity critical,high -rl 50'. One action at a time."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute."},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default 300)."},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_action",
            "description": "Perform headless browser action.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["navigate", "click", "type", "screenshot", "get_text", "get_source"]},
                    "url": {"type": "string", "description": "URL to navigate to."},
                    "selector": {"type": "string", "description": "Target CSS selector."},
                    "text": {"type": "string", "description": "Text to type."},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for CVEs, exploits, or security advisories.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query."},
                    "num_results": {"type": "integer", "description": "Max results (default 5)."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_file",
            "description": "Write a file to the operation workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path in workspace."},
                    "content": {"type": "string", "description": "File content."},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from the operation workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path in workspace."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_finding",
            "description": "Record a confirmed vulnerability with CVSS and proof of concept.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short vulnerability title."},
                    "type": {"type": "string", "description": "Type: sqli, xss, rce, ssrf, idor, lfi, xxe, csrf, misconfiguration."},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "cvss_score": {"type": "number", "description": "CVSS base score (0.0-10.0)."},
                    "affected": {"type": "object", "description": "Target: {url, parameter, method}."},
                    "evidence": {"type": "object", "description": "Evidence: {request, response}."},
                    "poc": {"type": "object", "description": "Proof of concept: {command, script}."},
                    "remediation": {"type": "string", "description": "Remediation guidance."},
                },
                "required": ["title", "type", "severity", "cvss_score", "affected", "evidence", "poc", "remediation"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_cve",
            "description": "Search local CVE database by keyword, product, or CVE ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Keyword or product name."},
                    "limit": {"type": "integer", "description": "Max results (default 10)."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stash_artifact",
            "description": "Store or retrieve cross-operation artifacts (credentials, tokens, hosts).",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["add", "list", "pull"]},
                    "type": {"type": "string", "description": "Artifact type (credential, host, token, payload)."},
                    "value": {"type": "string", "description": "Artifact value."},
                    "note": {"type": "string", "description": "Optional note."},
                    "id": {"type": "string", "description": "Artifact ID (for pull)."},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_memory",
            "description": "Read operation memory (target_map, attack_surface, or log).",
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {"type": "string", "enum": ["target_map", "attack_surface", "log"]},
                },
                "required": ["section"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_memory",
            "description": "Record newly discovered hosts, ports, or milestones to operation memory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {"type": "string", "enum": ["target_map", "attack_surface", "log"]},
                    "content": {"type": "string", "description": "Markdown entry or table row."},
                    "mode": {"type": "string", "enum": ["append", "replace"]},
                },
                "required": ["section", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_playbook",
            "description": "Search playbook KB for tested techniques and bypasses (e.g. 'nginx 403', 'wordpress', 'sqli').",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Technology or attack keyword."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_playbook",
            "description": "Save an effective attack technique or command to the continuous learning KB.",
            "parameters": {
                "type": "object",
                "properties": {
                    "technology": {"type": "string", "description": "Target technology (e.g. nginx, wordpress)."},
                    "technique": {"type": "string", "description": "Identifier (e.g. 403_bypass, sqli_tamper)."},
                    "commands": {"type": "string", "description": "Exact commands or payload."},
                    "notes": {"type": "string", "description": "Context and why it worked."},
                },
                "required": ["technology", "technique", "commands"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_graph",
            "description": "Query the engagement knowledge graph (hosts, ports, services, technologies, endpoints, findings and their relationships). view='summary' returns the target topology; view='candidates' returns graph-derived candidate findings (exposed sensitive services).",
            "parameters": {
                "type": "object",
                "properties": {
                    "view": {"type": "string", "enum": ["summary", "candidates"]},
                },
                "required": [],
            },
        },
    },
]

RECON_TOOLS = {"execute", "read_memory", "update_memory", "query_playbook", "save_playbook", "read_file", "web_search", "query_graph"}
ANALYSIS_TOOLS = {"execute", "search_cve", "create_finding", "read_memory", "update_memory", "query_playbook", "read_file", "web_search", "query_graph"}


def get_tools_for_phase(phase: str = "recon") -> list[dict]:
    """Return an optimized, phase-scoped subset of tools to minimize prompt prefill tokens."""
    if phase == "recon":
        return [t for t in NATIVE_TOOLS if t["function"]["name"] in RECON_TOOLS]
    elif phase == "analysis":
        return [t for t in NATIVE_TOOLS if t["function"]["name"] in ANALYSIS_TOOLS]
    return NATIVE_TOOLS


# ---------------------------------------------------------------------------
# Vulnerability deduplication (Jaccard similarity)
# ---------------------------------------------------------------------------

def _jaccard_similarity(a: str, b: str) -> float:
    """Compute Jaccard similarity between two strings (token-level)."""
    set_a = set(a.lower().split())
    set_b = set(b.lower().split())
    if not set_a or not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union)


def _auto_repair_command(cmd: str) -> str:
    """Auto-repair common command-line syntax mistakes made by LLMs."""
    if not cmd or not isinstance(cmd, str):
        return cmd
    cmd = cmd.strip()
    parts = cmd.split()
    if not parts:
        return cmd

    binary = parts[0].lower()

    if binary == "subfinder":
        has_input_flag = any(p in ("-d", "-dl", "-list", "-f") for p in [p.lower() for p in parts[1:]])
        if not has_input_flag:
            target_arg = None
            other_args = []
            for p in parts[1:]:
                if not p.startswith("-") and target_arg is None:
                    target_arg = p
                else:
                    other_args.append(p)
            if target_arg:
                cmd = f"subfinder -d {target_arg} {' '.join(other_args)}".strip()

    elif binary in ("httpx", "httpx-toolkit"):
        # On the Kali sandbox, /usr/bin/httpx is the *Python* HTTP client (CLI
        # "httpx [OPTIONS] URL", no -u -> "Error: No such option: -u"), while
        # ProjectDiscovery's httpx is installed as 'httpx-toolkit'. Always target
        # the PD binary so the agent's -u/-tech-detect/-status-code flags work.
        rest = parts[1:]
        has_input_flag = any(p.lower() in ("-u", "-target", "-l", "-list") for p in rest)
        if not has_input_flag:
            target_arg = None
            other_args = []
            for p in rest:
                if not p.startswith("-") and target_arg is None:
                    target_arg = p
                else:
                    other_args.append(p)
            if target_arg:
                cmd = f"httpx-toolkit -u {target_arg} {' '.join(other_args)}".strip()
            else:
                cmd = f"httpx-toolkit {' '.join(rest)}".strip()
        else:
            cmd = f"httpx-toolkit {' '.join(rest)}".strip()

    elif binary == "nuclei":
        has_input_flag = any(p in ("-u", "-target", "-l", "-list") for p in [p.lower() for p in parts[1:]])
        if not has_input_flag:
            target_arg = None
            other_args = []
            for p in parts[1:]:
                if not p.startswith("-") and target_arg is None:
                    target_arg = p
                else:
                    other_args.append(p)
            if target_arg:
                cmd = f"nuclei -u {target_arg} {' '.join(other_args)}".strip()
        # Rate-limit by default: without it nuclei opened thousands of
        # connections and fragile targets (cloud/proxy) went unresponsive
        # mid-scan. Add a modest -rl unless the model already set one.
        low = cmd.lower()
        if "-rl" not in low and "-rate-limit" not in low:
            cmd = f"{cmd} -rl 50".strip()

    elif binary == "katana":
        has_input_flag = any(p in ("-u", "-list") for p in [p.lower() for p in parts[1:]])
        if not has_input_flag:
            target_arg = None
            other_args = []
            for p in parts[1:]:
                if not p.startswith("-") and target_arg is None:
                    target_arg = p
                else:
                    other_args.append(p)
            if target_arg:
                cmd = f"katana -u {target_arg} {' '.join(other_args)}".strip()

    elif binary == "nmap":
        # The sandbox runs as non-root with no raw-socket capability. Any scan
        # that needs raw packets fails with "Couldn't open a raw socket.
        # Operation not permitted". Two cases must be handled:
        #   1. explicit SYN scan (-sS)  -> rewrite to TCP connect (-sT)
        #   2. NO scan type given       -> nmap defaults to SYN (raw) even as
        #      an unprivileged user in this image, so force -sT explicitly.
        # -sT needs no privilege and still gives open ports + -sV service/version.
        rest = [("-sT" if p.lower() == "-ss" else p) for p in parts[1:]]
        lowers = [p.lower() for p in rest]
        # Scan-type flags that select the port-scan technique.
        scan_types = {"-st", "-su", "-sa", "-sw", "-sm", "-sf",
                      "-sx", "-sy", "-sz", "-so", "-sn"}
        if not any(p in scan_types for p in lowers):
            rest = ["-sT"] + rest  # force unprivileged TCP connect scan
            lowers = [p.lower() for p in rest]
        # Ensure -Pn so firewalls dropping ICMP ping don't cause false
        # 'Host seems down' aborts (common on cloud/VPS targets).
        has_pn = any(p in ("-pn", "-p0") for p in lowers)
        prefix = "nmap" if has_pn else "nmap -Pn"
        cmd = f"{prefix} {' '.join(rest)}".strip()

    elif binary in ("ffuf", "feroxbuster", "gobuster"):
        # Wordlists live under /opt/seclists in the sandbox. Models often emit a
        # non-existent path (e.g. /workspace/wordlists/common.txt), which makes
        # ffuf print its help and exit 1. Rewrite known-bad paths to SecLists,
        # and inject a default wordlist when none is provided.
        default_wl = "/opt/seclists/Discovery/Web-Content/common.txt"
        toks = parts[:]
        has_w = False
        for i, p in enumerate(toks):
            if p in ("-w", "--wordlist") and i + 1 < len(toks):
                has_w = True
                wl = toks[i + 1]
                if "/workspace/wordlists" in wl or wl.endswith("/common.txt") and "seclists" not in wl.lower():
                    toks[i + 1] = default_wl
        if not has_w:
            toks += ["-w", default_wl]
        cmd = " ".join(toks)

    return cmd


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

class ToolExecutor:
    """Dispatches tool calls to the appropriate handler."""

    VULN_SIMILARITY_THRESHOLD = 0.7

    def __init__(
        self,
        sandbox: Any,
        browser: Any,
        workspace_dir: str | Path,
        db: Any,
        cve_kb: Any = None,
        stash_mgr: Any = None,
        alert_engine: Any = None,
        session_id: str = None,
    ):
        self.sandbox = sandbox
        self.browser = browser
        self.workspace_dir = Path(workspace_dir) if workspace_dir else Path.cwd()
        self.db = db
        self.cve_kb = cve_kb
        self.stash_mgr = stash_mgr
        self.alert_engine = alert_engine
        self.session_id = session_id
        try:
            from ..core.config import get_config
            self.VULN_SIMILARITY_THRESHOLD = get_config().vuln_similarity_threshold
        except Exception:
            pass  # keep class default
        self._findings: list[dict] = []
        self.playbook_mgr = None
        self.graph_mgr = None
        if self.db:
            try:
                from ..core.playbooks import PlaybookManager
                self.playbook_mgr = PlaybookManager(self.db)
            except Exception:
                pass
            try:
                from ..core.graph import GraphManager
                self.graph_mgr = GraphManager(self.db)
            except Exception:
                pass

        self._handlers: dict[str, Any] = {
            "execute": self._handle_execute,
            "browser_action": self._handle_browser_action,
            "web_search": self._handle_web_search,
            "create_file": self._handle_create_file,
            "read_file": self._handle_read_file,
            "create_finding": self._handle_create_finding,
            "search_cve": self._handle_search_cve,
            "stash_artifact": self._handle_stash_artifact,
            "read_memory": self._handle_read_memory,
            "update_memory": self._handle_update_memory,
            "query_playbook": self._handle_query_playbook,
            "save_playbook": self._handle_save_playbook,
            "query_graph": self._handle_query_graph,
        }

    async def execute_tool(self, tool_name: str, arguments: dict) -> dict:
        if tool_name in ("run_command", "bash", "sh", "terminal"):
            tool_name = "execute"
        handler = self._handlers.get(tool_name)
        if handler is None:
            return {"success": False, "output": None, "error": f"Unknown tool: {tool_name}"}
        try:
            result = await handler(**arguments)
            # Run alert engine on results
            if self.alert_engine and isinstance(result, dict):
                text = json.dumps(result, default=str)
                await self.alert_engine.scan_output(text, source=tool_name)
            return {"success": True, "output": result, "error": None}
        except Exception as exc:
            return {"success": False, "output": None, "error": str(exc)}

    # -- execute: run command in Docker sandbox --------------------------------

    async def _handle_execute(self, command: str, timeout: int = 300) -> dict:
        command = _auto_repair_command(command)
        try:
            from ..core.config import get_config
            cap = get_config().command_timeout
        except Exception:
            cap = 900
        timeout = min(timeout, cap)  # respect ARCANUM_COMMAND_TIMEOUT
        if self.sandbox is None:
            # SECURITY: never fall back to running attacker/LLM-influenced
            # commands directly on the host. Refuse instead. The previous
            # create_subprocess_shell fallback was a host RCE path whenever the
            # sandbox image was unavailable (e.g. no Docker socket in the
            # compose deployment). Build the image with `arcanum sandbox build`.
            return {
                "stdout": "",
                "stderr": (
                    "Sandbox indisponível — execução recusada por segurança. "
                    "Construa a imagem com 'arcanum sandbox build' e verifique o acesso ao Docker."
                ),
                "exit_code": -1,
                "duration": 0.0,
            }

        # Use sandbox container
        container_id = self.sandbox._active_container
        if not container_id:
            self.workspace_dir.mkdir(parents=True, exist_ok=True)
            container_id = await self.sandbox.create_container(self.workspace_dir)

        result = await self.sandbox.execute(container_id, command, timeout=timeout)
        self._auto_update_target_map(result.stdout)
        # Feed the knowledge graph from this tool's output (hosts/ports/services/
        # tech/endpoints) so the agent can reason over relationships, not just logs.
        if self.graph_mgr and result.stdout:
            try:
                await self.graph_mgr.ingest_text(self.session_id, result.stdout)
            except Exception:
                pass
        return {
            "stdout": result.stdout[:50000],
            "stderr": result.stderr[:10000],
            "exit_code": result.exit_code,
            "duration": round(result.duration, 2),
        }

    # -- browser_action: headless Chromium automation ---------------------------

    async def _handle_browser_action(
        self, action: str, url: str = None, selector: str = None, text: str = None,
    ) -> dict:
        if self.browser is None:
            return {"error": "Browser not available. Install playwright: pip install playwright && playwright install chromium"}

        if action == "navigate":
            if not url:
                return {"error": "URL required for navigate action"}
            result = await self.browser.navigate(url)
            return {"status": "navigated", "url": url, **result}
        elif action == "click":
            if not selector:
                return {"error": "Selector required for click action"}
            result = await self.browser.click(selector)
            return {"status": "clicked", "selector": selector, **result}
        elif action == "type":
            if not selector or not text:
                return {"error": "Selector and text required for type action"}
            result = await self.browser.type_text(selector, text)
            return {"status": "typed", "selector": selector, **result}
        elif action == "screenshot":
            path = self.workspace_dir / "evidence" / f"screenshot-{uuid.uuid4().hex[:8]}.png"
            path.parent.mkdir(parents=True, exist_ok=True)
            result = await self.browser.screenshot(str(path))
            return {"status": "screenshot_taken", "path": str(path), **result}
        elif action == "get_text":
            if not selector:
                return {"error": "Selector required for get_text action"}
            content = await self.browser.get_text(selector)
            return {"status": "ok", "text": content}
        elif action == "get_source":
            source = await self.browser.get_page_source()
            return {"status": "ok", "source": source[:50000]}
        else:
            return {"error": f"Unknown browser action: {action}"}

    # -- web_search: search the web for CVEs, bypasses -------------------------

    async def _handle_web_search(self, query: str, num_results: int = 5) -> dict:
        # Use httpx to search via DuckDuckGo HTML (no API key needed)
        import httpx
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                resp = await client.get(
                    "https://html.duckduckgo.com/html/",
                    params={"q": query},
                    headers={"User-Agent": "Mozilla/5.0 (compatible; ArcanumBot/3.0)"},
                )
                # Parse basic results from HTML
                results = []
                text = resp.text
                import re
                links = re.findall(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.+?)</a>', text)
                for href, title in links[:num_results]:
                    title_clean = re.sub(r'<[^>]+>', '', title).strip()
                    results.append({"url": href, "title": title_clean})
                return {"query": query, "results": results, "count": len(results)}
        except Exception as e:
            return {"query": query, "results": [], "error": str(e)}

    # -- create_file / read_file: workspace file operations --------------------

    def _safe_path(self, rel: str) -> Path:
        """Resolve ``rel`` strictly inside the workspace. Rejects absolute paths
        and ``..`` traversal (both validated as arbitrary read/write before)."""
        base = self.workspace_dir.resolve()
        candidate = (base / rel).resolve()
        if candidate != base and base not in candidate.parents:
            raise ValueError(f"Path escapes workspace: {rel!r}")
        return candidate

    async def _handle_create_file(self, path: str, content: str) -> dict:
        full_path = self._safe_path(path)
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)
        return {"path": path, "bytes_written": len(content), "full_path": str(full_path)}

    async def _handle_read_file(self, path: str) -> dict:
        full_path = self._safe_path(path)
        if not full_path.is_file():
            # Also check workspace/output
            alt_path = self._safe_path(str(Path("output") / path))
            if alt_path.is_file():
                full_path = alt_path
            else:
                raise FileNotFoundError(f"File not found: {path}")
        content = full_path.read_text(errors="replace")
        return {"path": path, "content": content[:100000], "size": len(content)}

    # -- create_finding: record a verified vulnerability -----------------------

    async def _handle_create_finding(
        self, title: str, type: str, severity: str, cvss_score: float,
        affected: dict, evidence: dict, poc: dict, remediation: str,
    ) -> dict:
        # Deduplicate via Jaccard similarity
        for existing in self._findings:
            sig_new = f"{title} {type} {json.dumps(affected)}"
            sig_old = f"{existing['title']} {existing['type']} {json.dumps(existing.get('affected', {}))}"
            if _jaccard_similarity(sig_new, sig_old) > self.VULN_SIMILARITY_THRESHOLD:
                return {
                    "id": existing["id"],
                    "status": "duplicate",
                    "message": f"Similar finding already exists: {existing['title']}",
                }

        finding_id = f"finding-{uuid.uuid4().hex[:8]}"
        finding = {
            "id": finding_id,
            "session_id": self.session_id,
            "title": title,
            "type": type,
            "severity": severity,
            "cvss_score": cvss_score,
            "affected": affected,
            "evidence": evidence,
            "poc": poc,
            "remediation": remediation,
            "verified": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._findings.append(finding)

        # Persist to database
        if self.db:
            try:
                await self.db.execute(
                    """INSERT INTO findings (id, session_id, title, type, severity, cvss_score,
                       affected, evidence, poc, remediation, verified)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (finding_id, self.session_id, title, type, severity, cvss_score,
                     json.dumps(affected), json.dumps(evidence), json.dumps(poc),
                     remediation, True),
                )
                if self.session_id:
                    await self.db.execute(
                        "UPDATE sessions SET findings_count = findings_count + 1 WHERE id = ?",
                        (self.session_id,),
                    )
            except Exception:
                pass  # Don't fail tool execution on DB error

        # Write finding to workspace
        findings_dir = self.workspace_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        (findings_dir / f"{finding_id}.json").write_text(json.dumps(finding, indent=2))

        # Trigger alerts
        if self.alert_engine:
            await self.alert_engine.scan_finding(finding)

        # Link the finding into the knowledge graph (finding -> affects -> host).
        if self.graph_mgr:
            try:
                await self.graph_mgr.add_finding(
                    self.session_id, finding_id, title, severity,
                    (affected or {}).get("url") if isinstance(affected, dict) else None,
                )
            except Exception:
                pass

        return {"id": finding_id, "finding": finding, "status": "created"}

    # -- search_cve: query local CVE knowledge base ----------------------------

    async def _handle_search_cve(self, query: str, limit: int = 10) -> dict:
        if self.cve_kb:
            try:
                results = await self.cve_kb.search(query, limit=limit)
                return {
                    "query": query,
                    "results": [
                        {
                            "id": r.id,
                            "description": r.description[:300] if r.description else "",
                            "cvss_score": r.cvss_score,
                            "exploit_available": r.exploit_available,
                        }
                        for r in results
                    ],
                    "count": len(results),
                }
            except Exception as e:
                return {"query": query, "results": [], "error": str(e)}

        # Fallback: search web for CVEs
        return await self._handle_web_search(f"CVE {query} site:nvd.nist.gov", num_results=limit)

    # -- stash_artifact: cross-operation artifact sharing ----------------------

    async def _handle_stash_artifact(
        self, action: str, type: str = None, value: str = None,
        note: str = None, id: str = None,
    ) -> dict:
        if self.stash_mgr:
            if action == "add":
                if not type or not value:
                    return {"error": "type and value required for add"}
                from ..core.models import StashType
                try:
                    item = await self.stash_mgr.add(StashType(type), value, note, self.session_id)
                    return {"id": item.id, "status": "added", "type": type}
                except ValueError:
                    return {"error": f"Invalid stash type: {type}. Use: credential, hash, host, range, payload, script, token"}
            elif action == "list":
                items = await self.stash_mgr.list()
                return {
                    "items": [
                        {"id": i.id, "type": i.type if isinstance(i.type, str) else i.type.value,
                         "value": i.value[:50], "note": i.note}
                        for i in items[:20]
                    ],
                    "count": len(items),
                }
            elif action == "pull":
                if not id:
                    return {"error": "id required for pull"}
                item = await self.stash_mgr.get(id)
                if item:
                    return {"id": item.id, "type": item.type if isinstance(item.type, str) else item.type.value,
                            "value": item.value, "note": item.note}
                return {"error": f"Artifact not found: {id}"}

        # Fallback: in-memory stash
        if not hasattr(self, '_mem_stash'):
            self._mem_stash = []
        if action == "add":
            art_id = f"stash-{uuid.uuid4().hex[:8]}"
            self._mem_stash.append({"id": art_id, "type": type, "value": value, "note": note})
            return {"id": art_id, "status": "added"}
        elif action == "list":
            return {"items": self._mem_stash, "count": len(self._mem_stash)}
        elif action == "pull":
            for art in self._mem_stash:
                if art["id"] == id:
                    return art
            return {"error": f"Artifact not found: {id}"}
        return {"error": f"Unknown stash action: {action}"}

    # -- Memory / Wiki Handlers -----------------------------------------------

    def _get_wiki_path(self, section: str) -> Path:
        wiki_dir = self.workspace_dir / "wiki"
        wiki_dir.mkdir(parents=True, exist_ok=True)
        filename_map = {
            "target_map": "TARGET_MAP.md",
            "targets": "TARGET_MAP.md",
            "attack_surface": "ATTACK_SURFACE.md",
            "log": "OPERATION_LOG.md",
            "operation_log": "OPERATION_LOG.md",
        }
        filename = filename_map.get(section.lower().strip(), "OPERATION_LOG.md")
        return wiki_dir / filename

    def _auto_update_target_map(self, text: str) -> None:
        """Automatically parse port scans and host discovery into TARGET_MAP.md."""
        if not text or ("open" not in text and "Nmap scan report" not in text):
            return
        try:
            import re
            lines = text.splitlines()
            open_ports = []
            current_host = "auto-detected"
            for line in lines:
                if "Nmap scan report for" in line:
                    parts = line.split("for")
                    if len(parts) > 1:
                        current_host = parts[1].strip()
                match = re.search(r'(\d+/(?:tcp|udp))\s+open\s+(\S+)(?:\s+(.*))?', line)
                if match:
                    port, service, version = match.group(1), match.group(2), match.group(3) or "-"
                    open_ports.append((current_host, port, service, version.strip()))

            if open_ports:
                target_file = self._get_wiki_path("target_map")
                if not target_file.exists():
                    header = (
                        "# Target Map (Living Memory)\n\n"
                        "| Host / IP | Port | Service | Product / Version | Notes |\n"
                        "| :--- | :--- | :--- | :--- | :--- |\n"
                    )
                    target_file.write_text(header, encoding="utf-8")

                current = target_file.read_text(encoding="utf-8")
                new_rows = []
                for host, port, service, version in open_ports:
                    row = f"| {host} | {port} | {service} | {version} | Auto-discovered by scan |"
                    if port not in current:
                        new_rows.append(row)
                if new_rows:
                    target_file.write_text(current.rstrip() + "\n" + "\n".join(new_rows) + "\n", encoding="utf-8")
        except Exception:
            pass

    async def _handle_read_memory(self, section: str) -> dict:
        target_file = self._get_wiki_path(section)
        if not target_file.exists():
            return {"section": section, "content": "Memory file is currently empty.", "exists": False}
        try:
            content = target_file.read_text(encoding="utf-8")
            return {"section": section, "content": content[:10000], "exists": True}
        except Exception as e:
            return {"section": section, "error": str(e)}

    async def _handle_update_memory(self, section: str, content: str, mode: str = "append") -> dict:
        target_file = self._get_wiki_path(section)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        try:
            if mode == "replace" or not target_file.exists():
                target_file.write_text(content.strip() + "\n", encoding="utf-8")
            else:
                existing = target_file.read_text(encoding="utf-8")
                if not content.startswith("\n"):
                    content = "\n" + content
                target_file.write_text(existing.rstrip() + f"\n{content.strip()}\n", encoding="utf-8")
            return {"section": section, "status": "updated", "mode": mode, "timestamp": now}
        except Exception as e:
            return {"section": section, "error": str(e)}

    # -- Playbook Handlers ----------------------------------------------------

    async def _handle_query_playbook(self, query: str) -> dict:
        if self.playbook_mgr:
            try:
                results = await self.playbook_mgr.search(query, limit=5)
                return {"query": query, "playbooks": results, "count": len(results)}
            except Exception as e:
                return {"query": query, "error": str(e), "playbooks": []}
        return {"query": query, "error": "Playbook manager not initialized", "playbooks": []}

    async def _handle_save_playbook(
        self, technology: str, technique: str, commands: str, notes: str = "",
    ) -> dict:
        if self.playbook_mgr:
            try:
                res = await self.playbook_mgr.save(technology, technique, commands, notes)
                return {"status": "saved", "playbook": res}
            except Exception as e:
                return {"status": "error", "error": str(e)}
        return {"status": "error", "error": "Playbook manager not initialized"}

    # -- Knowledge graph ------------------------------------------------------

    async def _handle_query_graph(self, view: str = "summary") -> dict:
        """Expose the engagement knowledge graph (assets + relationships) to the
        agent. 'summary' = topology view; 'candidates' = graph-derived candidate
        findings (exposed sensitive services)."""
        if not self.graph_mgr:
            return {"error": "Graph manager not initialized", "summary": ""}
        try:
            if view == "candidates":
                cands = await self.graph_mgr.candidate_findings(self.session_id)
                return {"view": "candidates", "candidates": cands, "count": len(cands)}
            summary = await self.graph_mgr.summary(self.session_id)
            counts = await self.graph_mgr.counts(self.session_id)
            return {"view": "summary", "summary": summary, "counts": counts}
        except Exception as e:
            return {"error": str(e), "summary": ""}
