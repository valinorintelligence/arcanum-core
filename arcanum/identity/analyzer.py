"""Active Directory & Identity Graph Analyzer Engine (BloodHound / Pentera equivalent)."""

import json
import sqlite3
import uuid
from collections import deque
from typing import List, Dict, Any, Optional, Set, Tuple

from arcanum.identity.models import (
    ADObject,
    ADEdge,
    ADAttackPath,
    ADChokePoint,
    KerberoastableUser,
    ASREPRoastableUser,
)


TIER_ZERO_PATTERNS = [
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "domain controllers",
    "read-only domain controllers",
    "account operators",
    "server operators",
    "backup operators",
    "krbtgt",
]

TIER_ZERO_SIDS = [
    "-512",  # Domain Admins
    "-516",  # Domain Controllers
    "-519",  # Enterprise Admins
    "-502",  # krbtgt
    "S-1-5-32-544",  # Builtin Administrators
]

# Exploit weights / criticality for edges
RELATIONSHIP_CRITICALITY = {
    "DCSync": "CRITICAL",
    "GenericAll": "HIGH",
    "WriteDacl": "HIGH",
    "WriteOwner": "HIGH",
    "ForceChangePassword": "HIGH",
    "AddMember": "MEDIUM",
    "AdminTo": "CRITICAL",
    "ExecuteDCOM": "HIGH",
    "CertificateTemplateAbuse": "CRITICAL",
    "GenericWrite": "MEDIUM",
    "MemberOf": "INFO",
}


class ADIdentityAnalyzer:
    """Core analysis engine for Active Directory identity graphs, attack paths and Kerberos abuse."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self.domains: Dict[str, Dict[str, Any]] = {}
        self.objects: Dict[str, ADObject] = {}  # sid -> ADObject
        self.adj_list: Dict[str, List[ADEdge]] = {}  # source_sid -> [ADEdge]
        self.reverse_adj_list: Dict[str, List[ADEdge]] = {}  # target_sid -> [ADEdge]
        self._sid_to_domain: Dict[str, str] = {}
        self._init_db()

    def _init_db(self):
        """Ensure AD tables exist if database connection is available."""
        if not self.db_path:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ad_domains';")
                if not cursor.fetchone():
                    from arcanum.core.database import _SCHEMA_SQL
                    cursor.executescript(_SCHEMA_SQL)
                conn.commit()
        except Exception:
            pass

    def ingest_domain(
        self,
        domain_name: str,
        objects_data: List[Dict[str, Any]],
        edges_data: List[Dict[str, Any]],
        forest_name: Optional[str] = None,
        domain_sid: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ingests an Active Directory dataset into the in-memory graph and SQLite database."""
        domain_id = f"dom-{domain_name.lower().replace('.', '-')}"
        forest = forest_name or domain_name

        self.domains[domain_id] = {
            "id": domain_id,
            "name": domain_name,
            "forest_name": forest,
            "domain_sid": domain_sid or f"S-1-5-21-123456789-987654321-{domain_id}",
        }

        ingested_objects = 0
        ingested_edges = 0

        # Ingest Objects
        for obj_dict in objects_data:
            sid = obj_dict.get("object_sid") or obj_dict.get("sid")
            if not sid:
                continue

            name = obj_dict.get("name", sid)
            obj_type = obj_dict.get("object_type", "user").lower()

            # Auto-detect Tier Zero
            is_tier_zero = bool(obj_dict.get("is_tier_zero", False))
            if not is_tier_zero:
                name_lower = name.lower()
                if any(pattern in name_lower for pattern in TIER_ZERO_PATTERNS) or any(sid.endswith(ts) or sid == ts for ts in TIER_ZERO_SIDS):
                    is_tier_zero = True

            ad_obj = ADObject(
                object_sid=sid,
                name=name,
                object_type=obj_type,
                display_name=obj_dict.get("display_name", name),
                is_tier_zero=is_tier_zero,
                is_admin=bool(obj_dict.get("is_admin", is_tier_zero)),
                has_spn=bool(obj_dict.get("has_spn", False) or "servicePrincipalName" in obj_dict.get("metadata", {})),
                dont_req_preauth=bool(obj_dict.get("dont_req_preauth", False)),
                metadata=obj_dict.get("metadata", {}),
            )

            self.objects[sid] = ad_obj
            self._sid_to_domain[sid] = domain_id
            if sid not in self.adj_list:
                self.adj_list[sid] = []
            if sid not in self.reverse_adj_list:
                self.reverse_adj_list[sid] = []
            ingested_objects += 1

        # Ingest Edges
        for edge_dict in edges_data:
            src = edge_dict.get("source_sid") or edge_dict.get("source")
            dst = edge_dict.get("target_sid") or edge_dict.get("target")
            rel = edge_dict.get("relationship") or edge_dict.get("rel")

            if not src or not dst or not rel:
                continue

            edge = ADEdge(
                source_sid=src,
                target_sid=dst,
                relationship=rel,
                is_inherited=bool(edge_dict.get("is_inherited", False)),
            )

            self.adj_list.setdefault(src, []).append(edge)
            self.reverse_adj_list.setdefault(dst, []).append(edge)
            ingested_edges += 1

        # Persist to database if available
        if self.db_path:
            self._persist_to_sqlite(domain_id, domain_name, forest, domain_sid, objects_data, edges_data)

        return {
            "domain_id": domain_id,
            "domain_name": domain_name,
            "total_objects": ingested_objects,
            "total_edges": ingested_edges,
            "tier_zero_nodes": len([o for o in self.objects.values() if o.is_tier_zero and self._sid_to_domain.get(o.object_sid) == domain_id]),
        }

    def _persist_to_sqlite(self, domain_id: str, name: str, forest: str, sid: Optional[str], objects: List[dict], edges: List[dict]):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO ad_domains (id, name, forest_name, domain_sid) VALUES (?, ?, ?, ?)",
                    (domain_id, name, forest, sid),
                )
                for o in objects:
                    s = o.get("object_sid") or o.get("sid")
                    if not s:
                        continue
                    obj = self.objects.get(s)
                    if obj:
                        cursor.execute(
                            """INSERT OR REPLACE INTO ad_objects 
                            (id, domain_id, object_sid, object_type, name, display_name, is_tier_zero, is_admin, has_spn, dont_req_preauth, metadata_json) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                f"{domain_id}_{s}",
                                domain_id,
                                s,
                                obj.object_type,
                                obj.name,
                                obj.display_name,
                                1 if obj.is_tier_zero else 0,
                                1 if obj.is_admin else 0,
                                1 if obj.has_spn else 0,
                                1 if obj.dont_req_preauth else 0,
                                json.dumps(obj.metadata),
                            ),
                        )
                for e in edges:
                    src = e.get("source_sid") or e.get("source")
                    dst = e.get("target_sid") or e.get("target")
                    rel = e.get("relationship") or e.get("rel")
                    if src and dst and rel:
                        edge_id = str(uuid.uuid4())
                        cursor.execute(
                            "INSERT INTO ad_edges (id, domain_id, source_sid, target_sid, relationship, is_inherited) VALUES (?, ?, ?, ?, ?, ?)",
                            (edge_id, domain_id, src, dst, rel, 1 if e.get("is_inherited") else 0),
                        )
                conn.commit()
        except Exception:
            pass

    def find_attack_paths_to_tier_zero(
        self,
        domain_id: Optional[str] = None,
        start_sid: Optional[str] = None,
        max_depth: int = 8,
        limit: int = 15,
    ) -> List[ADAttackPath]:
        """Finds all shortest attack paths from unprivileged identities to Tier-Zero targets via BFS."""
        tier_zero_sids = {
            sid for sid, obj in self.objects.items()
            if obj.is_tier_zero and (not domain_id or self._sid_to_domain.get(sid) == domain_id)
        }

        if not tier_zero_sids:
            return []

        paths_found: List[ADAttackPath] = []

        # Determine starting points
        if start_sid:
            start_nodes = [start_sid] if start_sid in self.objects else []
        else:
            # Unprivileged users or computers
            start_nodes = [
                sid for sid, obj in self.objects.items()
                if not obj.is_tier_zero and not obj.is_admin and obj.object_type in ("user", "computer")
                and (not domain_id or self._sid_to_domain.get(sid) == domain_id)
            ]

        for s_sid in start_nodes:
            if s_sid in tier_zero_sids:
                continue

            # BFS from s_sid to find shortest path to ANY tier_zero_sid
            queue = deque([(s_sid, [])])
            visited = {s_sid}
            found_for_this_start = False

            while queue:
                curr_sid, path_edges = queue.popleft()

                if len(path_edges) >= max_depth:
                    continue

                if curr_sid in tier_zero_sids and path_edges:
                    # Target reached! Construct ADAttackPath
                    ad_path = self._build_attack_path(s_sid, curr_sid, path_edges)
                    paths_found.append(ad_path)
                    found_for_this_start = True
                    if len(paths_found) >= limit:
                        return paths_found
                    break  # Shortest path from this start node found

                if found_for_this_start:
                    break

                for edge in self.adj_list.get(curr_sid, []):
                    nxt = edge.target_sid
                    if nxt not in visited:
                        visited.add(nxt)
                        queue.append((nxt, path_edges + [edge]))

        # Sort paths by length ascending (shortest = most dangerous)
        paths_found.sort(key=lambda p: p.length)
        return paths_found[:limit]

    def _build_attack_path(self, start_sid: str, target_sid: str, edges: List[ADEdge]) -> ADAttackPath:
        start_obj = self.objects.get(start_sid)
        start_name = start_obj.name if start_obj else start_sid
        target_obj = self.objects.get(target_sid)
        target_name = target_obj.name if target_obj else target_sid

        hops = []
        narrative_parts = []
        critical_exploit = None

        narrative_parts.append(f"Cadeia de Invasão iniciada a partir de '{start_name}':")

        for idx, edge in enumerate(edges, start=1):
            src_obj = self.objects.get(edge.source_sid)
            dst_obj = self.objects.get(edge.target_sid)
            src_label = src_obj.name if src_obj else edge.source_sid
            dst_label = dst_obj.name if dst_obj else edge.target_sid
            rel = edge.relationship

            hop_dict = {
                "step": idx,
                "from_sid": edge.source_sid,
                "from_name": src_label,
                "to_sid": edge.target_sid,
                "to_name": dst_label,
                "relationship": rel,
                "criticality": RELATIONSHIP_CRITICALITY.get(rel, "MEDIUM"),
            }
            hops.append(hop_dict)

            # Generate narrative step in Portuguese
            if rel == "MemberOf":
                desc = f"Passo {idx}: '{src_label}' é membro do grupo '{dst_label}', herdando todos os seus privilégios."
            elif rel == "GenericAll":
                desc = f"Passo {idx}: '{src_label}' possui controle total (GenericAll) sobre '{dst_label}', podendo alterar propriedades, permissões ou senhas."
                if not critical_exploit:
                    critical_exploit = "GenericAll Abuse"
            elif rel == "WriteDacl":
                desc = f"Passo {idx}: '{src_label}' pode modificar a DACL de '{dst_label}' (WriteDacl) para conceder a si próprio controle total."
                if not critical_exploit:
                    critical_exploit = "DACL Modification"
            elif rel == "ForceChangePassword":
                desc = f"Passo {idx}: '{src_label}' pode forçar a alteração de senha de '{dst_label}' sem saber a senha anterior."
                if not critical_exploit:
                    critical_exploit = "Password Reset Hijack"
            elif rel == "DCSync":
                desc = f"Passo {idx}: '{src_label}' possui direitos de replicação de diretório (DCSync), podendo extrair todos os hashes NTLM do domínio (incluindo krbtgt)."
                critical_exploit = "DCSync Domain Takeover"
            elif rel == "AdminTo":
                desc = f"Passo {idx}: '{src_label}' possui acesso de Administrador Local sobre o computador '{dst_label}', permitindo extrair credenciais da memória (LSASS)."
                if not critical_exploit:
                    critical_exploit = "LSASS Credential Dumping"
            elif rel == "AddMember":
                desc = f"Passo {idx}: '{src_label}' pode adicionar diretamente qualquer conta ao grupo restrito '{dst_label}'."
            elif rel == "CertificateTemplateAbuse":
                desc = f"Passo {idx}: '{src_label}' explora modelo de certificado vulnerável (ADCS ESC1/ESC8) para forjar um certificado do administrador."
                critical_exploit = "ADCS ESC Certificate Forgery"
            else:
                desc = f"Passo {idx}: '{src_label}' explora a relação '{rel}' contra '{dst_label}'."

            narrative_parts.append(desc)

        narrative_parts.append(f"Resultado: Comprometimento completo do nó de Tier Zero '{target_name}'.")

        return ADAttackPath(
            start_sid=start_sid,
            start_name=start_name,
            target_sid=target_sid,
            target_name=target_name,
            length=len(edges),
            hops=hops,
            critical_exploit=critical_exploit or edges[-1].relationship,
            narrative_ptbr="\n".join(narrative_parts),
        )

    def calculate_choke_points(self, domain_id: Optional[str] = None, max_paths: int = 50) -> List[ADChokePoint]:
        """Calculates identity Choke Points: nodes that sever the greatest percentage of Tier-Zero attack paths."""
        paths = self.find_attack_paths_to_tier_zero(domain_id=domain_id, limit=max_paths)
        if not paths:
            return []

        total_paths = len(paths)
        node_hit_counts: Dict[str, int] = {}

        for path in paths:
            # Intermediate nodes in hops
            nodes_in_path = set()
            for hop in path.hops:
                nodes_in_path.add(hop["from_sid"])
                nodes_in_path.add(hop["to_sid"])

            # Exclude the start node and the ultimate Tier Zero node
            nodes_in_path.discard(path.start_sid)
            nodes_in_path.discard(path.target_sid)

            for sid in nodes_in_path:
                node_hit_counts[sid] = node_hit_counts.get(sid, 0) + 1

        choke_points = []
        for sid, count in node_hit_counts.items():
            obj = self.objects.get(sid)
            if not obj:
                continue

            pct = (count / total_paths) * 100.0
            rec = f"Revogar permissões delegadas e auditar associações de grupo do nó '{obj.name}'. O isolamento deste nó neutraliza {count} caminhos de invasão ({pct:.1f}%)."

            choke_points.append(
                ADChokePoint(
                    object_sid=sid,
                    name=obj.name,
                    object_type=obj.object_type,
                    cut_paths_count=count,
                    cut_percentage=pct,
                    recommendation=rec,
                )
            )

        choke_points.sort(key=lambda c: c.cut_paths_count, reverse=True)
        return choke_points

    def find_kerberoastable_accounts(self, domain_id: Optional[str] = None) -> List[KerberoastableUser]:
        """Identifies user accounts with ServicePrincipalNames (Kerberoasting)."""
        results = []
        for sid, obj in self.objects.items():
            if domain_id and self._sid_to_domain.get(sid) != domain_id:
                continue

            if obj.object_type == "user" and obj.has_spn:
                spn = obj.metadata.get("spn") or obj.metadata.get("servicePrincipalName") or f"MSSQLSvc/{obj.name}.corp:1433"
                hash_sample = f"$krb5tgs$23$*{obj.name}$CORP.LOCAL${spn}*9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d$112233445566778899aabbccddeeff00..."
                results.append(
                    KerberoastableUser(
                        sid=sid,
                        name=obj.name,
                        spn=str(spn),
                        encryption_type="RC4-HMAC",
                        hash_sample=hash_sample,
                        mitigation="Configurar gMSA (Group Managed Service Account) com rotação automática de chave de 128 bits ou impor criptografia AES256 com senha superior a 25 caracteres.",
                    )
                )
        return results

    def find_asrep_roastable_accounts(self, domain_id: Optional[str] = None) -> List[ASREPRoastableUser]:
        """Identifies accounts with DONT_REQ_PREAUTH flag set (AS-REP Roasting)."""
        results = []
        for sid, obj in self.objects.items():
            if domain_id and self._sid_to_domain.get(sid) != domain_id:
                continue

            if obj.object_type == "user" and obj.dont_req_preauth:
                hash_sample = f"$krb5asrep$23${obj.name}@CORP.LOCAL:5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d$112233445566778899aabbcc..."
                results.append(
                    ASREPRoastableUser(
                        sid=sid,
                        name=obj.name,
                        encryption_type="RC4-HMAC",
                        hash_sample=hash_sample,
                        mitigation="Habilitar a exigência de pré-autenticação Kerberos (desmarcar 'Do not require Kerberos preauthentication' na aba Conta do objeto).",
                    )
                )
        return results

    def find_dcsync_principals(self, domain_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Identifies principals holding directory replication rights (DCSync)."""
        dcsync_accounts = []
        for src_sid, edges in self.adj_list.items():
            for edge in edges:
                if edge.relationship in ("DCSync", "GetChangesAll"):
                    src_obj = self.objects.get(src_sid)
                    if domain_id and self._sid_to_domain.get(src_sid) != domain_id:
                        continue
                    dcsync_accounts.append({
                        "sid": src_sid,
                        "name": src_obj.name if src_obj else src_sid,
                        "object_type": src_obj.object_type if src_obj else "unknown",
                        "target_sid": edge.target_sid,
                        "relationship": edge.relationship,
                        "impact": "Capacidade de extrair todo o banco de senhas NTDS.dit (incluindo o hash do krbtgt e de todos os Domain Admins).",
                    })
        return dcsync_accounts

    def simulate_attack(self, start_identity: str, domain_id: Optional[str] = None) -> Dict[str, Any]:
        """Simulates an attack path execution from a given starting identity (name or SID) to Tier Zero."""
        # Find starting object
        start_obj = None
        if start_identity in self.objects:
            start_obj = self.objects[start_identity]
        else:
            for obj in self.objects.values():
                if obj.name.lower() == start_identity.lower() or obj.display_name.lower() == start_identity.lower():
                    start_obj = obj
                    break

        if not start_obj:
            return {
                "success": False,
                "error": f"Identidade '{start_identity}' não encontrada no grafo de Active Directory.",
            }

        paths = self.find_attack_paths_to_tier_zero(
            domain_id=domain_id,
            start_sid=start_obj.object_sid,
            limit=1,
        )

        if not paths:
            return {
                "success": True,
                "target_reached": False,
                "start_identity": start_obj.name,
                "start_sid": start_obj.object_sid,
                "message": f"Nenhum caminho de escalação até o Tier Zero identificado a partir de '{start_obj.name}'. O nó está adequadamente isolado.",
            }

        shortest_path = paths[0]
        choke_points = self.calculate_choke_points(domain_id=domain_id)
        recommended_choke = choke_points[0].to_dict() if choke_points else None

        return {
            "success": True,
            "target_reached": True,
            "start_identity": start_obj.name,
            "start_sid": start_obj.object_sid,
            "target_tier_zero": shortest_path.target_name,
            "hops_count": shortest_path.length,
            "critical_exploit": shortest_path.critical_exploit,
            "narrative_ptbr": shortest_path.narrative_ptbr,
            "path_hops": shortest_path.hops,
            "primary_choke_point": recommended_choke,
        }
