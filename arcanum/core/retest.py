"""Closed-Loop Retesting & Remediation Verification Engine (1-Click Retest).

Provides surgical re-verification of individual security findings, transitioning
vulnerabilities through their formal lifecycle (confirmed -> verifying -> remediated/regressed).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from arcanum.core.models import FindingStatus


class RetestEngine:
    """Orchestrates closed-loop verification of security findings."""

    def __init__(self, db: Any, tool_executor: Any = None):
        self.db = db
        self.executor = tool_executor

    async def retest_finding(
        self,
        finding_id: str,
        custom_tool: Optional[str] = None,
        custom_args: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Surgically re-test a single finding and update its lifecycle state."""
        # 1. Fetch finding record
        row = await self.db.fetch_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if not row:
            return {
                "success": False,
                "finding_id": finding_id,
                "error": f"Finding '{finding_id}' not found",
            }

        finding = dict(row)
        for col in ("affected", "evidence", "poc", "cwe_ids", "retest_arguments", "retest_proof"):
            val = finding.get(col)
            if isinstance(val, str) and val.strip():
                try:
                    finding[col] = json.loads(val)
                except Exception:
                    pass

        # 2. Mark state as verifying
        await self.db.execute(
            "UPDATE findings SET status = ? WHERE id = ?",
            (FindingStatus.verifying.value, finding_id),
        )

        # 3. Determine tool and parameters
        tool_name = custom_tool or finding.get("retest_tool")
        tool_args = custom_args or finding.get("retest_arguments") or {}

        if not tool_name:
            tool_name, tool_args = self._infer_retest_probe(finding)

        # 4. Execute surgical probe
        probe_result = None
        probe_error = None
        if self.executor:
            try:
                exec_res = await self.executor.execute_tool(tool_name, tool_args)
                if exec_res.get("success"):
                    probe_result = exec_res.get("output")
                else:
                    probe_error = exec_res.get("error")
            except Exception as exc:
                probe_error = str(exc)
        else:
            # Standalone/mock verification without active tool executor
            probe_result = {"status": "mock_simulated", "findings": []}

        # 5. Determine remediation outcome
        now_iso = datetime.now(timezone.utc).isoformat()
        is_remediated, reason = self._evaluate_probe_outcome(finding, probe_result, probe_error)

        prev_status = finding.get("status") or FindingStatus.confirmed.value

        if is_remediated:
            new_status = FindingStatus.remediated.value
            verdict = "REMEDIATED"
        else:
            if prev_status == FindingStatus.remediated.value:
                new_status = FindingStatus.regressed.value
                verdict = "REGRESSED"
            else:
                new_status = FindingStatus.confirmed.value
                verdict = "CONFIRMED"

        retest_proof = {
            "verdict": verdict,
            "remediated": is_remediated,
            "retested_at": now_iso,
            "tool": tool_name,
            "arguments": tool_args,
            "reason": reason,
            "probe_output": probe_result,
            "probe_error": probe_error,
        }

        # 6. Update database record
        await self.db.execute(
            """UPDATE findings
               SET status = ?, retest_tool = ?, retest_arguments = ?,
                   retested_at = ?, retest_proof = ?
               WHERE id = ?""",
            (
                new_status,
                tool_name,
                json.dumps(tool_args),
                now_iso,
                json.dumps(retest_proof),
                finding_id,
            ),
        )

        return {
            "success": True,
            "finding_id": finding_id,
            "previous_status": prev_status,
            "new_status": new_status,
            "verdict": verdict,
            "is_remediated": is_remediated,
            "proof": retest_proof,
        }

    def _infer_retest_probe(self, finding: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Infer the appropriate tool and arguments from finding metadata."""
        ftype = (finding.get("type") or "").lower()
        title = (finding.get("title") or "").lower()
        affected = finding.get("affected") or {}
        if isinstance(affected, list) and affected:
            affected = {"target": affected[0]}
        target = affected.get("url") or affected.get("host") or affected.get("target") or "target.local"

        if "clickjack" in title or "clickjack" in ftype:
            return "audit_clickjacking_and_ui_redressing", {"url": target}
        if "sri" in title or "subresource" in ftype:
            return "audit_subresource_integrity_sri", {"url": target}
        if "vector" in title or "chroma" in title or "qdrant" in title:
            return "audit_vector_database_exposure", {"host": target}
        if "llm" in title or "prompt injection" in title or "jailbreak" in title:
            return "audit_llm_prompt_injection_and_jailbreaks", {"url": target}
        if "webhook" in title or "ssrf" in title:
            return "audit_webhook_ssrf_and_dns_rebinding", {"url": target}
        if "dependency confusion" in title:
            return "audit_dependency_confusion_and_namespaces", {"manifest_content": "{}"}
        if "dacl" in title or "active directory" in title:
            return "audit_ad_dacl_abuse_paths", {"domain": target}
        if "token" in title or "impersonate" in title:
            return "audit_windows_token_privileges", {"privileges_data": []}
        if "mtls" in title or "mesh" in title:
            return "audit_mtls_and_mesh_security", {"url": target}
        if "ebpf" in title or "rootkit" in title:
            return "audit_ebpf_integrity_and_rootkits", {"ebpf_programs": []}
        if "header" in title:
            return "audit_security_headers", {"url": target}
        if "tls" in title or "ssl" in title:
            return "audit_tls_ssl", {"target": target}

        # Fallback probe
        return "audit_security_headers", {"url": target if target.startswith("http") else f"https://{target}"}

    def _evaluate_probe_outcome(
        self,
        finding: dict[str, Any],
        probe_result: Any,
        probe_error: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Evaluate if the finding was remediated.

        Conservative by design: a security tool must NEVER report a finding as
        'remediated' unless the probe can POSITIVELY confirm the vulnerable
        condition is gone. Any error, mock, unrecognized result, or uncertainty
        keeps the finding open — a false 'fixed' is far more dangerous than a
        false 'still open'.
        """
        if probe_error:
            return False, f"Re-teste falhou ao executar a sonda: {probe_error}"

        if not isinstance(probe_result, dict):
            return False, "Re-teste não produziu um resultado analisável; condição não pôde ser certificada como corrigida."

        # Retest ran without a real tool executor (mock fallback) — nothing was
        # actually tested, so remediation cannot be confirmed.
        if probe_result.get("status") == "mock_simulated":
            return False, "Re-teste indisponível (executor não configurado); não é possível confirmar a remediação."

        findings_list = probe_result.get("findings") or []
        missing_headers = probe_result.get("missing_headers") or []
        vulns_detected = (
            probe_result.get("vulnerabilities_detected")
            or probe_result.get("escalation_vectors_found")
            or probe_result.get("dangerous_privileges")
            or probe_result.get("exposed_databases")
            or probe_result.get("scripts_missing_sri")
            or probe_result.get("unscoped_internal_candidates")
            or probe_result.get("ssrf_vectors_accepted")
            or probe_result.get("injected_headers_accepted")
            or probe_result.get("suspicious_programs")
            or probe_result.get("abusable_paths")
            or probe_result.get("exposed_secrets")
            or probe_result.get("exposed_files")
        )
        critical_issues = [
            f for f in findings_list
            if isinstance(f, dict) and f.get("severity") in ("critical", "high", "medium")
        ]

        # --- Still-vulnerable signals (any of these => NOT remediated) ---
        if vulns_detected and len(vulns_detected) > 0:
            return False, f"Vulnerabilidade ainda ativa: {len(vulns_detected)} vetor(es) detectado(s) no re-teste."
        if missing_headers:
            return False, f"Condição ainda presente: {len(missing_headers)} controle(s)/cabeçalho(s) ausente(s) no re-teste."
        if critical_issues:
            return False, f"Re-teste ainda encontrou {len(critical_issues)} problema(s) de severidade relevante."

        # --- Positive remediation: require an explicit 'clean' indicator ---
        score = probe_result.get("score")
        grade = str(probe_result.get("grade", "")).upper()
        if (score is not None and score >= 90) or grade in ("A", "A+"):
            return True, (f"Correção confirmada: score {score if score is not None else 'alto'}/100 "
                          f"(Grade {grade or 'A'}) sem vetores remanescentes.")
        if probe_result.get("remediated") is True or probe_result.get("secure") is True:
            return True, "Correção confirmada: a sonda reportou o alvo como seguro."

        # --- Uncertain -> conservative: keep the finding open ---
        return False, ("Re-teste não conseguiu certificar a eliminação da condição vulnerável "
                       "(resultado inconclusivo); finding mantido em aberto.")
