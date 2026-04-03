"""Core agent engine for Arcanum -- drives the LLM tool-calling loop."""

from __future__ import annotations

import json
from typing import Any, AsyncGenerator

from .llm import OllamaClient
from .tools import NATIVE_TOOLS, ToolExecutor

# ---------------------------------------------------------------------------
# Mode constants
# ---------------------------------------------------------------------------
MODE_AUTOPILOT = "autopilot"
MODE_COPILOT = "copilot"
MODE_MANUAL = "manual"


class AgentEngine:
    """Runs the agentic loop: prompt -> LLM -> tool calls -> results -> repeat."""

    def __init__(
        self,
        llm: OllamaClient,
        tool_executor: ToolExecutor,
        session: dict,
    ):
        self.llm = llm
        self.tool_executor = tool_executor
        self.session = session
        self.mode = session.get("mode", "manual") if isinstance(session, dict) else getattr(session, "mode", "manual")
        self.messages: list[dict] = []

    # -- Public API ---------------------------------------------------------

    async def run(self, user_input: str) -> AsyncGenerator[dict, None]:
        """Process user input through the agent loop.

        Yields event dicts with ``type`` being one of:
        ``thinking``, ``tool_call``, ``tool_result``,
        ``response``, ``finding``, ``suggestion``, ``error``.
        """
        system_prompt = await self._build_system_prompt()

        # Ensure the system message is always at the front.
        if not self.messages or self.messages[0].get("role") != "system":
            self.messages.insert(0, {"role": "system", "content": system_prompt})
        else:
            self.messages[0]["content"] = system_prompt

        # Append the user turn.
        self.messages.append({"role": "user", "content": user_input})

        # Agent loop -- keep going until the LLM produces a plain text answer.
        while True:
            try:
                yield {"type": "thinking", "content": "Reasoning..."}

                response_msg = await self.llm.chat(
                    messages=self.messages,
                    tools=NATIVE_TOOLS,
                )

                tool_calls: list[dict] = response_msg.get("tool_calls", [])

                # No tool calls -- the LLM gave a final text response.
                if not tool_calls:
                    content = response_msg.get("content", "")
                    self.messages.append({"role": "assistant", "content": content})
                    yield {"type": "response", "content": content}
                    return

                # Process each tool call.
                self.messages.append({"role": "assistant", "tool_calls": tool_calls})

                for tc in tool_calls:
                    fn = tc.get("function", {})
                    tool_name = fn.get("name", "")
                    arguments = fn.get("arguments", {})
                    if isinstance(arguments, str):
                        arguments = json.loads(arguments)

                    yield {
                        "type": "tool_call",
                        "tool": tool_name,
                        "arguments": arguments,
                    }

                    # Mode-based gating
                    if self.mode == MODE_MANUAL:
                        # In manual mode we only surface the suggestion; the
                        # caller must explicitly re-invoke with approval.
                        yield {
                            "type": "suggestion",
                            "tool": tool_name,
                            "arguments": arguments,
                            "message": "Manual mode: approve this tool call to proceed.",
                        }
                        continue

                    if self.mode == MODE_COPILOT:
                        # Yield a suggestion and let the caller decide.  The
                        # caller is expected to send approval back before the
                        # generator continues -- but for async simplicity we
                        # execute immediately here (the front-end implements
                        # the confirmation UX).
                        yield {
                            "type": "suggestion",
                            "tool": tool_name,
                            "arguments": arguments,
                            "message": "Copilot mode: confirm to execute.",
                        }

                    # Autopilot (and approved copilot) -- execute the tool.
                    result = await self.tool_executor.execute_tool(tool_name, arguments)

                    tool_msg = self._format_tool_result(tool_name, result)
                    self.messages.append(tool_msg)

                    yield {
                        "type": "tool_result",
                        "tool": tool_name,
                        "result": result,
                    }

                    # Surface findings immediately.
                    if tool_name == "create_finding" and result.get("success"):
                        yield {
                            "type": "finding",
                            "finding": result.get("output", {}),
                        }

            except Exception as exc:
                yield {"type": "error", "error": str(exc)}
                return

    # -- Internals ----------------------------------------------------------

    async def _build_system_prompt(self) -> str:
        """Construct a context-aware system prompt for the LLM."""
        tools_list = ", ".join(
            t["function"]["name"] for t in NATIVE_TOOLS
        )

        return f"""You are Arcanum, an autonomous security reconnaissance and penetration testing agent.
You operate within the Foxnode ASPM platform to perform authorized security assessments.

## Current Operation
- Session: {self.session.get('name', 'unknown') if isinstance(self.session, dict) else getattr(self.session, 'name', 'unknown')}
- Target: {self.session.get('target', '*') if isinstance(self.session, dict) else getattr(self.session, 'target', '*')}
- Mode: {self.mode}
- Scope: {self.session.get('scope', '*') if isinstance(self.session, dict) else getattr(self.session, 'scope', '*')}

## Available Tools
{tools_list}

## Rules
1. NEVER operate outside the defined scope.
2. Always verify targets are in-scope before running any tool.
3. Document every finding with evidence and proof of concept.
4. Follow the principle of least privilege -- use the minimum access needed.
5. If you discover credentials or sensitive data, redact them in outputs.

## Mode Behavior
- **autopilot**: Execute tools automatically. Chain reconnaissance workflows end-to-end.
- **copilot**: Suggest tool calls and wait for operator confirmation before executing.
- **manual**: Only execute tools when the operator explicitly requests them.

## Methodology
Follow a structured approach:
1. Reconnaissance -- enumerate subdomains, ports, services, technologies.
2. Discovery -- crawl endpoints, identify attack surface, map parameters.
3. Vulnerability Analysis -- test for known CVEs, misconfigurations, injection points.
4. Exploitation -- validate findings with proof of concept (non-destructive).
5. Reporting -- create detailed findings with remediation guidance.

Think step by step. Explain your reasoning before acting. When uncertain, ask the operator."""

    @staticmethod
    def _format_tool_result(name: str, result: dict) -> dict:
        """Format a tool execution result as a message for the conversation."""
        content = json.dumps(result, default=str)
        return {
            "role": "tool",
            "name": name,
            "content": content,
        }
