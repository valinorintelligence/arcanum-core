"""Native tool definitions and executor for the Arcanum agent."""

from __future__ import annotations

import json
import uuid
from typing import Any

# ---------------------------------------------------------------------------
# Tool definitions (OpenAI-style tool-calling format)
# ---------------------------------------------------------------------------

NATIVE_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "execute",
            "description": "Run a shell command inside the Docker sandbox environment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Maximum execution time in seconds.",
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_action",
            "description": "Perform a headless browser automation action.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["navigate", "click", "type", "screenshot", "get_text"],
                        "description": "The browser action to perform.",
                    },
                    "url": {
                        "type": "string",
                        "description": "URL to navigate to (for navigate action).",
                    },
                    "selector": {
                        "type": "string",
                        "description": "CSS selector for the target element.",
                    },
                    "text": {
                        "type": "string",
                        "description": "Text to type (for type action).",
                    },
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for information.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query.",
                    },
                    "num_results": {
                        "type": "integer",
                        "description": "Number of results to return.",
                        "default": 5,
                    },
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
                    "path": {
                        "type": "string",
                        "description": "Relative path within the workspace.",
                    },
                    "content": {
                        "type": "string",
                        "description": "File content to write.",
                    },
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
                    "path": {
                        "type": "string",
                        "description": "Relative path within the workspace.",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_finding",
            "description": "Create a new vulnerability finding for the current operation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short title of the vulnerability.",
                    },
                    "type": {
                        "type": "string",
                        "description": "Vulnerability type (e.g. sqli, xss, rce, ssrf, idor).",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Severity level.",
                    },
                    "cvss_score": {
                        "type": "number",
                        "description": "CVSS v3.1 base score (0.0 - 10.0).",
                    },
                    "affected": {
                        "type": "object",
                        "description": "Affected asset info: url, parameter, component, version.",
                    },
                    "evidence": {
                        "type": "object",
                        "description": "Evidence: request, response, screenshots, logs.",
                    },
                    "poc": {
                        "type": "object",
                        "description": "Proof of concept: steps, payload, script.",
                    },
                    "remediation": {
                        "type": "string",
                        "description": "Recommended remediation steps.",
                    },
                },
                "required": [
                    "title",
                    "type",
                    "severity",
                    "cvss_score",
                    "affected",
                    "evidence",
                    "poc",
                    "remediation",
                ],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_cve",
            "description": "Search the CVE database for known vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (CVE ID, product name, keyword).",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return.",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stash_artifact",
            "description": "Store, list, or retrieve artifacts for the current operation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["add", "list", "pull"],
                        "description": "Whether to add, list, or pull artifacts.",
                    },
                    "type": {
                        "type": "string",
                        "description": "Artifact type (e.g. subdomain, endpoint, credential, token).",
                    },
                    "value": {
                        "type": "string",
                        "description": "Artifact value (for add).",
                    },
                    "note": {
                        "type": "string",
                        "description": "Optional note for the artifact.",
                    },
                    "id": {
                        "type": "string",
                        "description": "Artifact ID (for pull).",
                    },
                },
                "required": ["action"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------


class ToolExecutor:
    """Dispatches tool calls to the appropriate handler."""

    def __init__(
        self,
        sandbox: Any,
        browser: Any,
        workspace_dir: str,
        db: Any,
    ):
        self.sandbox = sandbox
        self.browser = browser
        self.workspace_dir = workspace_dir
        self.db = db
        self._artifacts: list[dict] = []

        self._handlers: dict[str, Any] = {
            "execute": self._handle_execute,
            "browser_action": self._handle_browser_action,
            "web_search": self._handle_web_search,
            "create_file": self._handle_create_file,
            "read_file": self._handle_read_file,
            "create_finding": self._handle_create_finding,
            "search_cve": self._handle_search_cve,
            "stash_artifact": self._handle_stash_artifact,
        }

    async def execute_tool(self, tool_name: str, arguments: dict) -> dict:
        """Execute a tool by name with the given arguments.

        Returns a dict with keys: success (bool), output (Any), error (str|None).
        """
        handler = self._handlers.get(tool_name)
        if handler is None:
            return {
                "success": False,
                "output": None,
                "error": f"Unknown tool: {tool_name}",
            }

        try:
            result = await handler(**arguments)
            return {"success": True, "output": result, "error": None}
        except Exception as exc:
            return {"success": False, "output": None, "error": str(exc)}

    # -- Individual handlers ------------------------------------------------

    async def _handle_execute(self, command: str, timeout: int = 300) -> dict:
        """Run a shell command inside the sandbox."""
        result = await self.sandbox.exec(command, timeout=timeout)
        return {
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "exit_code": result.get("exit_code", -1),
        }

    async def _handle_browser_action(
        self,
        action: str,
        url: str | None = None,
        selector: str | None = None,
        text: str | None = None,
    ) -> dict:
        """Perform a headless browser action."""
        if action == "navigate":
            await self.browser.navigate(url)
            return {"status": "navigated", "url": url}
        elif action == "click":
            await self.browser.click(selector)
            return {"status": "clicked", "selector": selector}
        elif action == "type":
            await self.browser.type(selector, text)
            return {"status": "typed", "selector": selector}
        elif action == "screenshot":
            data = await self.browser.screenshot()
            return {"status": "screenshot_taken", "data_length": len(data)}
        elif action == "get_text":
            content = await self.browser.get_text(selector)
            return {"status": "ok", "text": content}
        else:
            raise ValueError(f"Unknown browser action: {action}")

    async def _handle_web_search(self, query: str, num_results: int = 5) -> dict:
        """Search the web and return results."""
        # Delegates to an external search provider configured on the sandbox
        results = await self.sandbox.web_search(query, limit=num_results)
        return {"query": query, "results": results}

    async def _handle_create_file(self, path: str, content: str) -> dict:
        """Write a file into the workspace directory."""
        import os

        full_path = os.path.join(self.workspace_dir, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as fh:
            fh.write(content)
        return {"path": path, "bytes_written": len(content)}

    async def _handle_read_file(self, path: str) -> dict:
        """Read a file from the workspace directory."""
        import os

        full_path = os.path.join(self.workspace_dir, path)
        if not os.path.isfile(full_path):
            raise FileNotFoundError(f"File not found: {path}")
        with open(full_path) as fh:
            content = fh.read()
        return {"path": path, "content": content}

    async def _handle_create_finding(
        self,
        title: str,
        type: str,
        severity: str,
        cvss_score: float,
        affected: dict,
        evidence: dict,
        poc: dict,
        remediation: str,
    ) -> dict:
        """Record a new vulnerability finding."""
        finding_id = f"finding-{uuid.uuid4().hex[:8]}"
        finding = {
            "id": finding_id,
            "title": title,
            "type": type,
            "severity": severity,
            "cvss_score": cvss_score,
            "affected": affected,
            "evidence": evidence,
            "poc": poc,
            "remediation": remediation,
        }
        return {"id": finding_id, "finding": finding}

    async def _handle_search_cve(self, query: str, limit: int = 10) -> dict:
        """Search the CVE database."""
        results = await self.sandbox.exec(
            f"search-cve --query '{query}' --limit {limit} --json",
            timeout=30,
        )
        try:
            cves = json.loads(results.get("stdout", "[]"))
        except json.JSONDecodeError:
            cves = []
        return {"query": query, "results": cves}

    async def _handle_stash_artifact(
        self,
        action: str,
        type: str | None = None,
        value: str | None = None,
        note: str | None = None,
        id: str | None = None,
    ) -> dict:
        """Store, list, or retrieve artifacts."""
        if action == "add":
            artifact_id = f"art-{uuid.uuid4().hex[:8]}"
            artifact = {
                "id": artifact_id,
                "type": type,
                "value": value,
                "note": note,
            }
            self._artifacts.append(artifact)
            return {"id": artifact_id, "status": "added"}
        elif action == "list":
            filtered = self._artifacts
            if type:
                filtered = [a for a in filtered if a["type"] == type]
            return {"artifacts": filtered, "count": len(filtered)}
        elif action == "pull":
            for artifact in self._artifacts:
                if artifact["id"] == id:
                    return {"artifact": artifact}
            raise ValueError(f"Artifact not found: {id}")
        else:
            raise ValueError(f"Unknown stash action: {action}")
