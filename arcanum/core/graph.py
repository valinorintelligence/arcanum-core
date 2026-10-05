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

    async def edges(self, session_id: str) -> list[dict]:
        return await self.db.fetch_all(
            "SELECT id, src, rel, dst, attrs FROM graph_edges WHERE session_id = ?", (session_id,))

    async def attack_paths(self, session_id: str, limit: int = 8) -> list[dict]:
        """Multi-hop traversal that chains assets into prioritized attack paths
        (cred → host → exposed sensitive service / confirmed finding), instead of
        a flat list. Ranked by severity so the agent pursues the real leads."""
        nodes = {n["id"]: n for n in await self.nodes(session_id)}
        out_adj, in_adj = {}, {}
        for e in await self.edges(session_id):
            out_adj.setdefault(e["src"], []).append((e["rel"], e["dst"]))
            in_adj.setdefault(e["dst"], []).append((e["rel"], e["src"]))

        def attrs(n):
            try:
                return json.loads(n.get("attrs") or "{}")
            except Exception:
                return {}

        paths = []
        for nid, n in nodes.items():
            if n["type"] != HOST:
                continue
            host = n["key"]
            ports = [nodes[d] for (r, d) in out_adj.get(nid, []) if r == "exposes" and d in nodes]
            svc_by_port = {}
            for p in ports:
                for (r, d) in out_adj.get(p["id"], []):
                    if r == "runs" and d in nodes:
                        svc_by_port[p["key"]] = nodes[d]
            techs = sorted({nodes[d]["label"] for (r, d) in out_adj.get(nid, []) if r == "uses" and d in nodes})
            findings = [nodes[s] for (r, s) in in_adj.get(nid, [])
                        if r == "affects" and s in nodes and nodes[s]["type"] == FINDING]
            creds = [nodes[s] for (r, s) in in_adj.get(nid, [])
                     if r in ("for", "authenticates") and s in nodes and nodes[s]["type"] == CRED]
            sensitive = [p for p in ports if p["key"].split(":")[-1] in _SENSITIVE_PORTS]

            sev, score = "info", 0
            if findings:
                sevs = [attrs(f).get("severity", "") for f in findings]
                if "critical" in sevs:
                    sev, score = "critical", 100
                elif "high" in sevs:
                    sev, score = "high", 80
                else:
                    sev, score = "medium", 60
            elif sensitive:
                sev, score = "high", 50
            elif ports or techs:
                sev, score = "medium", 20
            if creds:
                score += 15
            if score == 0:
                continue

            segs = [f"host {host}"]
            if ports:
                segs.append("expõe " + ", ".join(
                    p["label"] + (f"({svc_by_port[p['key']]['label']})" if p["key"] in svc_by_port else "")
                    for p in ports[:6]))
            if techs:
                segs.append("tecnologias: " + ", ".join(techs[:5]))
            if sensitive:
                segs.append("SERVIÇO SENSÍVEL EXPOSTO: " + ", ".join(
                    f"{_SENSITIVE_PORTS[p['key'].split(':')[-1]]}" for p in sensitive))
            if creds:
                segs.append("credencial disponível: " + ", ".join(c["label"] for c in creds[:3]))
            if findings:
                segs.append("findings: " + ", ".join(f["label"] for f in findings[:3]))
            paths.append({"host": host, "severity": sev, "score": score, "chain": " → ".join(segs)})

        paths.sort(key=lambda x: x["score"], reverse=True)
        return paths[:limit]

    async def add_cred(self, session_id: str, masked_label: str, for_host: str | None = None) -> None:
        """Add a credential node (masked, never the secret) and optionally link it
        to the host it is for — enabling cred→host attack-path hops."""
        try:
            cid = await self.add_node(session_id, CRED, masked_label, label=masked_label)
            if for_host:
                h = re.sub(r"^https?://", "", for_host).split("/")[0].split(":")[0]
                host_id = await self.add_node(session_id, HOST, h)
                await self.add_edge(session_id, cid, "for", host_id)
        except Exception:
            pass

    async def mark_compromised(self, session_id: str, host: str, owned: str = "user",
                               creds_held=None, foothold_id: str | None = None) -> str:
        """Record compromise state on a host node (F1+): access level (``owned``),
        a registered foothold id, and/or held credentials (masked). Upserts the host
        node and sets the F0 state columns. Returns the node id."""
        h = re.sub(r"^https?://", "", str(host)).split("/")[0].split(":")[0]
        nid = await self.add_node(session_id, HOST, h)
        sets, params = ["owned = ?"], [owned]
        if foothold_id is not None:
            sets.append("foothold_id = ?")
            params.append(foothold_id)
        if creds_held is not None:
            sets.append("creds_held = ?")
            params.append(creds_held if isinstance(creds_held, str) else json.dumps(creds_held))
        params.append(nid)
        await self.db.execute(
            f"UPDATE graph_nodes SET {', '.join(sets)} WHERE id = ?", tuple(params))
        return nid

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

    async def get_visual_graph(self, session_id: str) -> dict:
        """Returns node and edge definitions formatted for D3.js force graphs and UI visualization."""
        raw_nodes = await self.nodes(session_id)
        raw_edges = await self.edges(session_id)

        formatted_nodes = []
        for n in raw_nodes:
            raw_attrs = n.get("attrs")
            attrs = json.loads(raw_attrs) if isinstance(raw_attrs, str) and raw_attrs.strip() else (raw_attrs or {})
            ntype = n["type"]
            label = n.get("label") or n.get("key") or n["id"]
            is_sensitive = False
            severity = attrs.get("severity")

            if ntype == PORT and n["key"].split(":")[-1] in _SENSITIVE_PORTS:
                is_sensitive = True
                if not severity:
                    severity = "high"
            elif ntype == FINDING:
                if attrs.get("severity") in ("critical", "high"):
                    is_sensitive = True
            elif ntype == CRED:
                is_sensitive = True

            formatted_nodes.append({
                "id": n["id"],
                "key": n["key"],
                "type": ntype,
                "label": label,
                "attrs": attrs,
                "severity": severity or "info",
                "is_sensitive": is_sensitive,
            })

        formatted_edges = []
        for e in raw_edges:
            eid = e.get("id") or _eid(session_id, e["src"], e["rel"], e["dst"])
            raw_attrs = e.get("attrs")
            attrs = json.loads(raw_attrs) if isinstance(raw_attrs, str) and raw_attrs.strip() else (raw_attrs or {})
            formatted_edges.append({
                "id": eid,
                "source": e["src"],
                "target": e["dst"],
                "rel": e["rel"],
                "attrs": attrs,
            })

        return {
            "session_id": session_id,
            "nodes": formatted_nodes,
            "edges": formatted_edges,
            "total_nodes": len(formatted_nodes),
            "total_edges": len(formatted_edges),
        }

    async def calculate_choke_points(self, session_id: str) -> list[dict]:
        """Calculates critical choke points (bottlenecks) in attack paths.
        A choke point is an asset or service whose mitigation severs the maximum number
        of attack chains directed at high-value targets (databases, credentials, crown jewels).
        """
        raw_nodes = await self.nodes(session_id)
        if not raw_nodes:
            return []

        nodes_by_id = {n["id"]: n for n in raw_nodes}
        raw_edges = await self.edges(session_id)

        # Adjacency
        out_adj: dict[str, list[tuple[str, str]]] = {}
        in_adj: dict[str, list[tuple[str, str]]] = {}
        for e in raw_edges:
            out_adj.setdefault(e["src"], []).append((e["rel"], e["dst"]))
            in_adj.setdefault(e["dst"], []).append((e["rel"], e["src"]))

        # Identify Crown Jewels (high-value targets)
        crown_jewels = set()
        for nid, n in nodes_by_id.items():
            ntype = n["type"]
            raw_attrs = n.get("attrs")
            attrs = json.loads(raw_attrs) if isinstance(raw_attrs, str) and raw_attrs.strip() else (raw_attrs or {})
            if ntype == PORT and n["key"].split(":")[-1] in _SENSITIVE_PORTS:
                crown_jewels.add(nid)
            elif ntype == SERVICE and any(n["key"].split(":")[-2] in _SENSITIVE_PORTS for _ in [1] if len(n["key"].split(":")) >= 3):
                crown_jewels.add(nid)
            elif ntype == FINDING and attrs.get("severity") in ("critical", "high"):
                crown_jewels.add(nid)
            elif ntype == CRED:
                crown_jewels.add(nid)

        if not crown_jewels:
            for nid, n in nodes_by_id.items():
                if n["type"] in (SERVICE, FINDING):
                    crown_jewels.add(nid)

        # Identify Entry Points (external hosts, endpoints, initial footholds)
        entry_points = set()
        for nid, n in nodes_by_id.items():
            if n["type"] in (HOST, ENDPOINT):
                entry_points.add(nid)

        if not entry_points:
            entry_points = set(nodes_by_id.keys()) - crown_jewels

        # Trace simple paths from entry points to crown jewels (depth <= 6)
        all_paths: list[list[str]] = []
        for entry in entry_points:
            queue = [[entry]]
            while queue and len(all_paths) < 100:
                path = queue.pop(0)
                curr = path[-1]
                if len(path) > 6:
                    continue
                if curr in crown_jewels and len(path) > 1:
                    all_paths.append(path)
                    continue

                for rel, nxt in out_adj.get(curr, []):
                    if nxt not in path and nxt in nodes_by_id:
                        queue.append(path + [nxt])

        if not all_paths:
            degree_map = {}
            for nid in nodes_by_id:
                deg = len(out_adj.get(nid, [])) + len(in_adj.get(nid, []))
                if deg > 1:
                    degree_map[nid] = deg
            choke_candidates = sorted(degree_map.items(), key=lambda x: x[1], reverse=True)[:5]
            results = []
            for nid, deg in choke_candidates:
                n = nodes_by_id[nid]
                results.append({
                    "node_id": nid,
                    "label": n.get("label") or n.get("key"),
                    "type": n["type"],
                    "paths_severed": deg,
                    "impact_percentage": 100.0,
                    "severity": "high",
                    "recommendation": f"Ponto de convergência no ativo '{n.get('label')}'. Aplicar isolamento perimetral.",
                })
            return results

        # Count intermediary nodes across all paths
        node_sever_counts: dict[str, int] = {}
        for path in all_paths:
            sub_nodes = set(path[1:-1]) if len(path) > 2 else set(path)
            for nid in sub_nodes:
                node_sever_counts[nid] = node_sever_counts.get(nid, 0) + 1

        total_paths = len(all_paths)
        sorted_chokes = sorted(node_sever_counts.items(), key=lambda x: x[1], reverse=True)

        choke_points = []
        for nid, count in sorted_chokes[:6]:
            n = nodes_by_id[nid]
            pct = round((count / total_paths) * 100, 1)
            ntype = n["type"]
            label = n.get("label") or n.get("key")
            
            if pct >= 70:
                sev = "critical"
            elif pct >= 40:
                sev = "high"
            else:
                sev = "medium"

            rec = f"Mitigar ou isolar '{label}' ({ntype}) corta {pct}% dos caminhos de invasão identificados ({count}/{total_paths})."
            if ntype == PORT:
                rec += " Recomenda-se fechar a porta no firewall perimetral ou exigir VPN corporativa."
            elif ntype == HOST:
                rec += " Recomenda-se aplicar microsegmentação de rede (Zero Trust)."
            elif ntype == CRED:
                rec += " Recomenda-se revogar a credencial imediatamente e ativar MFA."

            choke_points.append({
                "node_id": nid,
                "label": label,
                "type": ntype,
                "paths_severed": count,
                "impact_percentage": pct,
                "severity": sev,
                "recommendation": rec,
            })

        return choke_points

    async def simulate_blast_radius(self, session_id: str, origin_node_id: str, max_depth: int = 4) -> dict:
        """Simulates lateral movement and compromise propagation from origin_node_id.
        Explores reachable assets, credentials, databases and flags crown jewels at risk.
        """
        raw_nodes = await self.nodes(session_id)
        nodes_by_id = {n["id"]: n for n in raw_nodes}
        if origin_node_id not in nodes_by_id:
            return {"error": f"Nó de origem '{origin_node_id}' não encontrado no grafo da sessão."}

        raw_edges = await self.edges(session_id)
        # Bidirectional graph for lateral movement analysis
        adj: dict[str, list[tuple[str, str, str]]] = {}
        for e in raw_edges:
            src, dst, rel = e["src"], e["dst"], e["rel"]
            adj.setdefault(src, []).append((dst, rel, "forward"))
            adj.setdefault(dst, []).append((src, rel, "reverse"))

        visited = {origin_node_id: 0}
        queue = [(origin_node_id, 0)]
        hops_detail = []
        affected_nodes = [origin_node_id]

        while queue:
            curr_id, depth = queue.pop(0)
            if depth >= max_depth:
                continue

            for neighbor_id, rel, direction in adj.get(curr_id, []):
                if neighbor_id not in visited and neighbor_id in nodes_by_id:
                    visited[neighbor_id] = depth + 1
                    queue.append((neighbor_id, depth + 1))
                    affected_nodes.append(neighbor_id)
                    nb_node = nodes_by_id[neighbor_id]
                    hops_detail.append({
                        "hop": depth + 1,
                        "node_id": neighbor_id,
                        "label": nb_node.get("label") or nb_node.get("key"),
                        "type": nb_node["type"],
                        "direction": direction,
                        "relation": rel,
                    })

        # Categorize affected assets
        affected_hosts = []
        affected_services = []
        affected_creds = []
        crown_jewels_at_risk = []

        for nid in affected_nodes:
            n = nodes_by_id[nid]
            ntype = n["type"]
            label = n.get("label") or n.get("key")
            raw_attrs = n.get("attrs")
            attrs = json.loads(raw_attrs) if isinstance(raw_attrs, str) and raw_attrs.strip() else (raw_attrs or {})

            if ntype == HOST:
                affected_hosts.append(label)
            elif ntype == SERVICE:
                affected_services.append(label)
            elif ntype == CRED:
                affected_creds.append(label)

            # Crown jewels
            if ntype == PORT and n["key"].split(":")[-1] in _SENSITIVE_PORTS:
                crown_jewels_at_risk.append(f"{label} ({_SENSITIVE_PORTS[n['key'].split(':')[-1]]})")
            elif ntype == FINDING and attrs.get("severity") in ("critical", "high"):
                crown_jewels_at_risk.append(f"Vulnerabilidade: {label} [{attrs.get('severity')}]")
            elif ntype == CRED:
                crown_jewels_at_risk.append(f"Credencial: {label}")

        base_score = (len(affected_hosts) * 20) + (len(affected_creds) * 25) + (len(crown_jewels_at_risk) * 35) + (len(affected_services) * 8)
        blast_score = min(100, max(15, base_score))

        if blast_score >= 80 or len(crown_jewels_at_risk) > 0:
            risk_level = "CRITICAL"
        elif blast_score >= 50:
            risk_level = "HIGH"
        elif blast_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        origin_node = nodes_by_id[origin_node_id]
        origin_label = origin_node.get("label") or origin_node.get("key")

        containment = (
            f"Contenção Prioritária para '{origin_label}': Isolar o host afetado da VLAN interna, "
            f"revogar credenciais associadas e bloquear comunicações com os seguintes ativos de alto risco: "
            f"{', '.join(crown_jewels_at_risk[:3]) if crown_jewels_at_risk else 'serviços adjacentes'}."
        )

        return {
            "origin": {
                "id": origin_node_id,
                "label": origin_label,
                "type": origin_node["type"],
            },
            "blast_score": blast_score,
            "risk_level": risk_level,
            "total_reachable_nodes": len(affected_nodes),
            "hops_depth_simulated": max(visited.values()) if visited else 0,
            "affected_hosts": list(set(affected_hosts)),
            "affected_services": list(set(affected_services)),
            "affected_credentials": list(set(affected_creds)),
            "crown_jewels_at_risk": list(set(crown_jewels_at_risk)),
            "hops": hops_detail,
            "containment_strategy": containment,
        }

