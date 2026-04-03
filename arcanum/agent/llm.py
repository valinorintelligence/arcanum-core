"""Ollama LLM client for Arcanum agent engine."""

from __future__ import annotations

from typing import AsyncGenerator

import httpx


class OllamaClient:
    """Client for communicating with the Ollama API."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.1"):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=120.0)

    async def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> dict:
        """Send a chat completion request to Ollama.

        Returns the response message dict from the API.
        """
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools

        resp = await self._client.post("/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {})

    async def chat_stream(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> AsyncGenerator[dict, None]:
        """Stream a chat completion from Ollama, yielding chunks."""
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "stream": True,
        }
        if tools:
            payload["tools"] = tools

        async with self._client.stream("POST", "/api/chat", json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line:
                    continue
                import json as _json

                chunk = _json.loads(line)
                yield chunk

    async def list_models(self) -> list[str]:
        """List available models from the Ollama instance."""
        resp = await self._client.get("/api/tags")
        resp.raise_for_status()
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]

    async def check_health(self) -> bool:
        """Check whether the Ollama server is reachable."""
        try:
            resp = await self._client.get("/api/tags")
            return resp.status_code == 200
        except (httpx.HTTPError, ConnectionError):
            return False

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
