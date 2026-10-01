"""Engagement knowledge graph.

Models the target as a graph of assets and relationships — hosts, ports,
services, technologies, endpoints, findings, credentials (nodes) connected by
relations (exposes / runs / uses / has_endpoint / affects ...) — instead of flat
markdown. This is what lets the agent reason about attack chains ("this service
runs on that host, which exposes this port") rather than firing tools blindly.

Backed by two SQLite tables (graph_nodes, graph_edges), scoped per session.
Node ids are deterministic (session+type+key) so ingestion is idempotent and
edges can reference nodes without a lookup.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any


# Node types
HOST, PORT, SERVICE, TECH, ENDPOINT, FINDING, CRED = (
    "host", "port", "service", "tech", "endpoint", "finding", "cred"
)

# Ports that are noteworthy when exposed (fuel for auto-synthesis).
_SENSITIVE_PORTS = {
    "3306": "MySQL", "5432": "PostgreSQL", "27017": "MongoDB", "6379": "Redis",
    "9200": "Elasticsearch", "445": "SMB", "3389": "RDP", "23": "Telnet",
    "21": "FTP", "11211": "Memcached", "5984": "CouchDB", "1433": "MSSQL",
    "2375": "Docker API", "9000": "Portainer/PHP-FPM",
}


def _nid(session_id: str, ntype: str, key: str) -> str:
    return "n" + hashlib.sha1(f"{session_id}|{ntype}|{key}".encode()).hexdigest()[:15]


def _eid(session_id: str, src: str, rel: str, dst: str) -> str:
    return "e" + hashlib.sha1(f"{session_id}|{src}|{rel}|{dst}".encode()).hexdigest()[:15]


class GraphManager:
    """CRUD + ingestion over the engagement knowledge graph."""

    def __init__(self, db: Any):
        self.db = db

    # -- primitives ---------------------------------------------------------

    async def add_node(self, session_id: str, ntype: str, key: str,
                       label: str | None = None, attrs: dict | None = None) -> str:
        nid = _nid(session_id or "", ntype, str(key))
        await self.db.execute(
            "INSERT OR IGNORE INTO graph_nodes (id, session_id, type, key, label, attrs) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (nid, session_id, ntype, str(key), label or str(key), json.dumps(attrs or {})),
        )
        if label or attrs:
            await self.db.execute(
                "UPDATE graph_nodes SET label = COALESCE(?, label), attrs = ? WHERE id = ?",
                (label, json.dumps(attrs or {}), nid),
            )
        return nid

    async def add_edge(self, session_id: str, src: str, rel: str, dst: str,
                       attrs: dict | None = None) -> str:
        eid = _eid(session_id or "", src, rel, dst)
        await self.db.execute(
            "INSERT OR IGNORE INTO graph_edges (id, session_id, src, rel, dst, attrs) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (eid, session_id, src, rel, dst, json.dumps(attrs or {})),
        )
        return eid

    async def nodes(self, session_id: str, ntype: str | None = None) -> list[dict]:
        if ntype:
            rows = await self.db.fetch_all(
                "SELECT * FROM graph_nodes WHERE session_id = ? AND type = ? ORDER BY created_at",
                (session_id, ntype))
        else:
            rows = await self.db.fetch_all(
                "SELECT * FROM graph_nodes WHERE session_id = ? ORDER BY type, created_at",
                (session_id,))
        return rows

    async def counts(self, session_id: str) -> dict:
        rows = await self.db.fetch_all(
            "SELECT type, COUNT(*) AS n FROM graph_nodes WHERE session_id = ? GROUP BY type",
            (session_id,))
        return {r["type"]: r["n"] for r in rows}

    # -- ingestion from tool output ----------------------------------------

    async def ingest_text(self, session_id: str, text: str) -> int:
        """Parse common scanner output (nmap / httpx / katana) into the graph.
        Returns the number of nodes touched. Best-effort and non-fatal."""
        if not text:
            return 0
        text = re.sub(r"\x1b\[[0-9;]*m", "", text)  # strip ANSI
        touched = 0
        current_host: str | None = None
        try:
            for line in text.splitlines():
                s = line.strip()
                if not s:
                    continue

                # nmap: host line
                m = re.search(r"Nmap scan report for\s+([^\s(]+)", s)
                if m:
                    current_host = m.group(1).strip()
                    await self.add_node(session_id, HOST, current_host)
                    touched += 1
                    continue

                # nmap: open port line  "80/tcp open http Golang net/http server"
                m = re.match(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)(?:\s+(.*))?", s)
                if m and current_host:
                    port, proto, state, service, version = (
                        m.group(1), m.group(2), m.group(3), m.group(4), (m.group(5) or "").strip())
                    host_id = await self.add_node(session_id, HOST, current_host)
                    port_id = await self.add_node(
                        session_id, PORT, f"{current_host}:{port}",
                        label=f"{port}/{proto}", attrs={"state": state, "proto": proto})
                    await self.add_edge(session_id, host_id, "exposes", port_id)
                    if service and service not in ("-",):
                        svc_id = await self.add_node(
                            session_id, SERVICE, f"{current_host}:{port}:{service}",
                            label=service, attrs={"version": version})
                        await self.add_edge(session_id, port_id, "runs", svc_id)
                    touched += 1
                    continue

                # httpx: "https://host [200] [Express,Node.js]"
                m = re.match(r"(https?://\S+)\s+\[(\d{3})\](?:\s+\[([^\]]+)\])?", s)
                if m:
                    url, status, techs = m.group(1), m.group(2), (m.group(3) or "")
                    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
                    host_id = await self.add_node(session_id, HOST, host)
                    ep_id = await self.add_node(session_id, ENDPOINT, url,
                                                attrs={"status": status})
                    await self.add_edge(session_id, host_id, "has_endpoint", ep_id)
                    for t in [x.strip() for x in techs.split(",") if x.strip()]:
                        tid = await self.add_node(session_id, TECH, f"{host}:{t}", label=t)
                        await self.add_edge(session_id, host_id, "uses", tid)
                    touched += 1
                    continue

                # katana / plain URL lines
                m = re.match(r"(https?://\S+)$", s)
                if m:
                    url = m.group(1)
                    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
                    host_id = await self.add_node(session_id, HOST, host)
                    ep_id = await self.add_node(session_id, ENDPOINT, url)
                    await self.add_edge(session_id, host_id, "has_endpoint", ep_id)
                    touched += 1
        except Exception:
            pass
        return touched

    async def add_finding(self, session_id: str, finding_id: str, title: str,
                          severity: str, affected_url: str | None = None) -> None:
        """Link a confirmed finding into the graph (finding -> affects -> host)."""
        try:
            fid = await self.add_node(session_id, FINDING, finding_id,
                                      label=title, attrs={"severity": severity})
            if affected_url:
                host = re.sub(r"^https?://", "", affected_url).split("/")[0].split(":")[0]
                host_id = await self.add_node(session_id, HOST, host)
                await self.add_edge(session_id, fid, "affects", host_id)
        except Exception:
            pass

    # -- recall / planning --------------------------------------------------

    async def summary(self, session_id: str, max_items: int = 12) -> str:
        """Compact text view of the graph for injection into the agent context."""
        counts = await self.counts(session_id)
        if not counts:
            return ""
        lines = [f"## Grafo do Alvo ({', '.join(f'{v} {k}' for k, v in counts.items())})"]
        # Hosts with their open ports/services
        hosts = await self.nodes(session_id, HOST)
        ports = await self.nodes(session_id, PORT)
        svcs = {s["key"]: s for s in await self.nodes(session_id, SERVICE)}
        for h in hosts[:max_items]:
            hp = [p for p in ports if p["key"].startswith(h["key"] + ":")]
            parts = []
            for p in hp:
                port_num = p["key"].split(":")[-1]
                svc = next((s for k, s in svcs.items() if k.startswith(h["key"] + f":{port_num}:")), None)
                parts.append(f"{p['label']}" + (f"({svc['label']})" if svc else ""))
            lines.append(f"- {h['key']}: " + (", ".join(parts) if parts else "sem portas mapeadas"))
        techs = await self.nodes(session_id, TECH)
        if techs:
            lines.append("Tecnologias: " + ", ".join(sorted({t["label"] for t in techs}))[:200])
        return "\n".join(lines)

    async def candidate_findings(self, session_id: str) -> list[dict]:
        """Derive candidate findings from the graph (exposed sensitive services).
        Deterministic, conservative — for operator review, not auto-confirmed."""
        out: list[dict] = []
        for p in await self.nodes(session_id, PORT):
            if (p.get("attrs") and '"state": "open"' not in p["attrs"]):
                pass
            port_num = p["key"].split(":")[-1]
            host = p["key"].rsplit(":", 1)[0]
            if port_num in _SENSITIVE_PORTS:
                out.append({
                    "title": f"{_SENSITIVE_PORTS[port_num]} exposto na porta {port_num} em {host}",
                    "type": "misconfiguration",
                    "severity": "high" if port_num in ("3306", "5432", "27017", "6379", "9200", "2375", "1433", "11211") else "medium",
                    "affected": {"url": f"{host}:{port_num}", "method": "TCP"},
                    "remediation": f"Restringir o acesso à porta {port_num} ({_SENSITIVE_PORTS[port_num]}) a redes confiáveis / firewall.",
                    "source": "graph-synthesis",
                })
        return out
