"""Local semantic retrieval (RAG) for Arcanum.

Gives the small local model far more effective knowledge than fits in its
weights: instead of keyword (FTS) matching, we embed the knowledge (playbooks,
findings, optionally CVEs) once and retrieve the most *semantically* relevant
entries for the current context — e.g. detecting "Express/Node" recalls
"prototype pollution", "JWT in Node apps" without an exact keyword hit.

Everything runs locally: embeddings via Ollama (`nomic-embed-text` by default),
vectors stored as float32 BLOBs in SQLite, cosine similarity in pure Python
(NumPy used automatically if present). Fully optional and non-fatal: if the
embedding model is unavailable, callers fall back to keyword search.
"""
from __future__ import annotations

import array
import math
from typing import Any

import httpx

DEFAULT_EMBED_MODEL = "nomic-embed-text"


def playbook_embed_text(row: dict) -> str:
    """Readable one-liner for a playbook row — used both as the embedded text
    and as the hint injected into the agent context on recall."""
    tech = row.get("technology") or row.get("category") or ""
    technique = (row.get("technique") or row.get("title") or "").replace("_", " ")
    commands = (row.get("commands") or row.get("steps") or "").replace("\n", " ; ")
    notes = row.get("notes") or ""
    return f"{technique} [{tech}]: {commands[:220]}" + (f" — {notes[:160]}" if notes else "")


class EmbeddingClient:
    """Thin async client over Ollama's embeddings endpoint."""

    def __init__(self, base_url: str = "http://localhost:11434",
                 model: str = DEFAULT_EMBED_MODEL, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._available: bool | None = None

    async def embed(self, texts: list[str]) -> list[list[float]] | None:
        """Embed a batch of texts. Returns one vector per text, or None on error
        (so callers degrade to keyword search instead of crashing)."""
        if not texts:
            return []
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout) as c:
                resp = await c.post("/api/embed", json={"model": self.model, "input": texts})
                resp.raise_for_status()
                data = resp.json()
            embs = data.get("embeddings")
            if embs and isinstance(embs[0], list):
                self._available = True
                return embs
            # /api/embed with a single input may return {"embedding": [...]}
            one = data.get("embedding")
            if one:
                self._available = True
                return [one]
            return None
        except Exception:
            self._available = False
            return None

    async def embed_one(self, text: str) -> list[float] | None:
        res = await self.embed([text])
        return res[0] if res else None

    async def available(self) -> bool:
        if self._available is None:
            await self.embed_one("ping")
        return bool(self._available)


# -- cosine similarity (NumPy if available, else pure Python) ----------------

try:  # optional acceleration
    import numpy as _np
except Exception:  # pragma: no cover
    _np = None


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    if _np is not None:
        va, vb = _np.asarray(a, dtype="float32"), _np.asarray(b, dtype="float32")
        na, nb = float(_np.linalg.norm(va)), float(_np.linalg.norm(vb))
        return float(va.dot(vb) / (na * nb)) if na and nb else 0.0
    dot = na = nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    return dot / (math.sqrt(na) * math.sqrt(nb)) if na and nb else 0.0


def _pack(vec: list[float]) -> bytes:
    return array.array("f", vec).tobytes()


def _unpack(blob: bytes) -> list[float]:
    a = array.array("f")
    a.frombytes(blob)
    return a.tolist()


class VectorStore:
    """Vector persistence + brute-force cosine search over a collection.

    Brute force is fine for the sizes we index (playbooks/findings: dozens to
    hundreds). Large corpora (CVEs) are opt-in and still tractable in RAM."""

    def __init__(self, db: Any):
        self.db = db

    async def upsert(self, collection: str, ref_id: str, text: str, vector: list[float]) -> None:
        vid = f"{collection}:{ref_id}"
        await self.db.execute(
            "INSERT INTO vectors (id, collection, ref_id, text, dim, vec) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET text=excluded.text, dim=excluded.dim, vec=excluded.vec",
            (vid, collection, str(ref_id), text, len(vector), _pack(vector)),
        )

    async def has(self, collection: str, ref_id: str) -> bool:
        row = await self.db.fetch_one(
            "SELECT 1 AS x FROM vectors WHERE collection=? AND ref_id=?", (collection, str(ref_id)))
        return bool(row)

    async def count(self, collection: str) -> int:
        row = await self.db.fetch_one(
            "SELECT COUNT(*) AS n FROM vectors WHERE collection=?", (collection,))
        return row["n"] if row else 0

    async def search(self, collection: str, query_vec: list[float], top_k: int = 5,
                     min_score: float = 0.3) -> list[dict]:
        rows = await self.db.fetch_all(
            "SELECT ref_id, text, vec FROM vectors WHERE collection=?", (collection,))
        scored = []
        for r in rows:
            score = cosine(query_vec, _unpack(r["vec"]))
            if score >= min_score:
                scored.append({"ref_id": r["ref_id"], "text": r["text"], "score": round(score, 4)})
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]


class SemanticIndex:
    """High-level: embed+store items, then semantic-search a collection."""

    def __init__(self, db: Any, embedder: EmbeddingClient | None = None):
        self.db = db
        self.store = VectorStore(db)
        self.embedder = embedder or EmbeddingClient()

    async def index_items(self, collection: str, items: list[tuple], skip_existing: bool = True) -> int:
        """Embed and store (ref_id, text) pairs. Returns #newly indexed."""
        pending = []
        for ref_id, text in items:
            if not text:
                continue
            if skip_existing and await self.store.has(collection, ref_id):
                continue
            pending.append((str(ref_id), text))
        if not pending:
            return 0
        vectors = await self.embedder.embed([t for _, t in pending])
        if not vectors:
            return 0  # embedding unavailable -> caller keeps keyword fallback
        n = 0
        for (ref_id, text), vec in zip(pending, vectors):
            await self.store.upsert(collection, ref_id, text, vec)
            n += 1
        return n

    async def search(self, collection: str, query_text: str, top_k: int = 5) -> list[dict] | None:
        """Semantic search. Returns None if embeddings are unavailable (so the
        caller falls back to keyword search)."""
        qv = await self.embedder.embed_one(query_text)
        if not qv:
            return None
        return await self.store.search(collection, qv, top_k=top_k)
