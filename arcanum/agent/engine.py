"""Core agent engine for Arcanum — drives the LLM tool-calling loop with
extended thinking, phase checkpoints, context compression, and self-evaluation."""

from __future__ import annotations

import json
import re
from typing import Any, AsyncGenerator

from .llm import OllamaClient
from .tools import NATIVE_TOOLS, ToolExecutor, get_tools_for_phase, _auto_repair_command
from ..redteam.action_classes import (
    classify as _rt_classify, hitl_tier as _rt_hitl_tier,
    class_order as _rt_class_order, ActionClass,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MODE_AUTOPILOT = "autopilot"
MODE_COPILOT = "copilot"
MODE_MANUAL = "manual"

PHASES = ["recon", "analysis", "exploit", "report"]

CHECKPOINT_EVAL_INTERVAL = 5     # Phase evaluation every N iterations
SELF_EVAL_INTERVAL = 10          # Self-evaluation every N iterations
CONTEXT_COMPRESS_INTERVAL = 15   # Context compression every N iterations
MAX_ITERATIONS = 50              # Safety limit per run
MAX_RUN_SECONDS = 1800           # Wall-clock watchdog per continuous loop (30 min)


class AgentEngine:
    """Runs the agentic loop with extended thinking, phase tracking, and
    context compression (inspired by airecon's checkpoint system)."""

    def __init__(
        self,
        llm: OllamaClient,
        tool_executor: ToolExecutor,
        session: dict,
        deep_llm: OllamaClient | None = None,
    ):
        self.llm = llm
        self.deep_llm = deep_llm or llm
        self.tool_executor = tool_executor
        self.session = session
        self.mode = session.get("mode", "manual") if isinstance(session, dict) else getattr(session, "mode", "manual")
        self.messages: list[dict] = []
        self.iteration = 0
        self.current_phase = "recon"
        self.completed_phases: list[str] = []
        self.findings_count = 0
        self.enable_thinking = getattr(llm, "enable_thinking", False)
        self.pending_action: dict | None = None
        # Stagnation guard / feedback memory: per-command outcome history so we
        # can tell "already succeeded, move on" apart from "failing in a loop".
        self._cmd_history: dict[str, dict] = {}   # sig -> {runs, ok, fail, summary}
        self._repeat_after_success = 0
        self._stagnation_aborted = False
        # Continuous-learning loop: phases already enriched with KB playbooks,
        # and whether anything new was learned this run.
        self._consulted_phases: set[str] = set()
        self._synthesized_phases: set[str] = set()
        self._report_generated = False
        self._learned_count = 0
        self._abort_requested = False
        self._native_tool_history: dict[str, int] = {}
        self._native_tool_runs: dict[str, int] = {}
        self._last_executed_tool: str | None = None
        self._current_user_request: str = ""
        # F0 governance (ROE/audit/sessions): lazily built from the tool
        # executor's DB. "unset" sentinel distinguishes "not yet built" from
        # "built but unavailable" (None).
        self._gov_cache: Any = "unset"
        self._active_engagement: dict | None = None
        self._engagement_loaded = False

    # Internal/bookkeeping tools never touch a target — skip them in the audit
    # trail so the log stays a meaningful record of real actions.
    _AUDIT_SKIP = frozenset({
        "read_memory", "update_memory", "query_graph", "query_playbook",
        "save_playbook", "read_file", "create_file", "web_search",
    })

    def abort(self) -> None:
        """Signal the agent execution loop to stop immediately."""
        self._abort_requested = True
        self.pending_action = None

    # -- F0 governance (ROE / audit / kill-switch) --------------------------

    def _governance(self) -> dict | None:
        """Lazily build the F0 governance helpers from the tool executor's DB.

        Returns None when there is no usable DB (e.g. mock/legacy constructions),
        so every governance hook degrades to a no-op instead of failing."""
        cache = getattr(self, "_gov_cache", "unset")
        if cache != "unset":
            return cache
        gov = None
        try:
            db = getattr(self.tool_executor, "db", None)
            if db is not None and all(hasattr(db, m) for m in ("fetch_all", "fetch_one", "execute")):
                from ..redteam.engagement import EngagementManager
                from ..redteam.audit import ActionAuditLog
                from ..redteam.sessions import SessionRegistry
                gov = {
                    "engagements": EngagementManager(db),
                    "audit": ActionAuditLog(db),
                    "sessions": SessionRegistry(db),
                }
        except Exception:
            gov = None
        self._gov_cache = gov
        return gov

    def _session_id(self):
        s = self.session
        if isinstance(s, dict):
            return s.get("id") or s.get("name")
        return getattr(s, "id", None) or getattr(s, "name", None)

    def _session_target(self):
        s = self.session
        if isinstance(s, dict):
            return s.get("target")
        return getattr(s, "target", None)

    def _primary_target(self, arguments: dict | None):
        """Best-effort primary target of a tool call (for the audit trail/ROE)."""
        if not isinstance(arguments, dict):
            return self._session_target()
        if "command" in arguments:
            return self._session_target()
        for k in ("url", "domain", "hostname", "target", "host", "target_url",
                  "authorization_url", "metadata_url", "bucket_name", "ioc", "entry_point"):
            if arguments.get(k):
                return arguments.get(k)
        return self._session_target()

    async def _get_active_engagement(self) -> dict | None:
        """Return (cached per run) the active engagement for this session, or None."""
        if getattr(self, "_engagement_loaded", False):
            return self._active_engagement
        self._engagement_loaded = True
        self._active_engagement = None
        gov = self._governance()
        if not gov:
            return None
        try:
            self._active_engagement = await gov["engagements"].active_for(self._session_id())
        except Exception:
            self._active_engagement = None
        return self._active_engagement

    async def _roe_authorize(self, tool_name: str, arguments: dict) -> str | None:
        """Deterministic ROE gate. Returns a block reason (str) if the active
        engagement forbids this action's class/target, else None. A blocked
        attempt is recorded in the immutable audit log. No active engagement =>
        None (legacy behavior preserved)."""
        gov = self._governance()
        if not gov:
            return None
        try:
            eng = await self._get_active_engagement()
        except Exception:
            eng = None
        if not eng:
            return None
        try:
            cls = _rt_classify(tool_name, arguments)
            target = self._primary_target(arguments)
            allowed, reason = gov["engagements"].is_allowed(eng, cls, target)
        except Exception:
            return None
        if allowed:
            return None
        await self._audit_record(tool=tool_name, arguments=arguments, action_cls=cls,
                                 decision="blocked_by_roe", risk=None, result=None, target=target)
        return reason

    async def _audit_record(self, *, tool: str, arguments: dict, action_cls,
                            decision: str, risk: str | None = None,
                            result: dict | None = None, target=None,
                            operator: str | None = None, strict: bool = False) -> bool:
        """Append an action to the immutable audit trail (masked). Returns True when
        a record was written (or there is no governance to write to).

        ``strict=True`` is **fail-closed** (follow-up #3): if governance IS present
        but the write fails, the exception propagates so the caller can ABORT the
        action (used for EXPLOIT/POST_EXPLOIT/DESTRUCTIVE before they run). With no
        governance at all, behavior is unchanged (no-op, backward-compat).

        ``operator`` records WHO authorized/ran the action; it falls back to the
        engine mode when no operator identity is available (follow-up #2)."""
        gov = self._governance()
        if not gov or tool in self._AUDIT_SKIP:
            return True
        op = operator if operator else (self.mode if isinstance(self.mode, str) else None)
        try:
            from ..redteam.audit import summarize_result
            try:
                eng = await self._get_active_engagement()
            except Exception:
                eng = None
            cls_val = getattr(action_cls, "value", str(action_cls))
            await gov["audit"].record(
                tool=tool,
                action_class=cls_val,
                decision=decision,
                target=target if target is not None else self._primary_target(arguments),
                risk=risk,
                arguments=arguments,
                result_summary=summarize_result(result),
                engagement_id=(eng or {}).get("id"),
                session_id=self._session_id(),
                operator=op,
                deconfliction_tag=(eng or {}).get("deconfliction_tag"),
            )
            return True
        except Exception:
            if strict:
                # Fail-closed: the caller must not proceed with a high-risk action
                # that could not be written to the immutable trail.
                raise
            return False

    async def _preaudit_high_risk(self, *, tool: str, arguments: dict, action_cls,
                                  risk: str | None = None, operator: str | None = None) -> str | None:
        """Fail-closed pre-execution audit (follow-up #3) for EXPLOIT/POST_EXPLOIT/
        DESTRUCTIVE actions. Writes a strict ``authorized`` entry BEFORE the action
        runs; returns None when it is safe to proceed, or an error string to abort.
        Lower classes need no pre-audit and return None."""
        try:
            if _rt_class_order(action_cls) < _rt_class_order(ActionClass.EXPLOIT):
                return None
        except Exception:
            return None
        try:
            await self._audit_record(tool=tool, arguments=arguments, action_cls=action_cls,
                                     decision="authorized", risk=risk, operator=operator,
                                     strict=True)
            return None
        except Exception as exc:
            cls_val = getattr(action_cls, "value", action_cls)
            return (f"Ação de alto risco ({cls_val}) abortada: falha ao registrar na trilha "
                    f"de auditoria imutável ({exc}). Nenhuma ação ofensiva executa sem "
                    f"auditoria (fail-closed).")

    async def _preauthorized(self, action_cls) -> bool:
        """True when a full-scope LAB ROE (an active engagement with ``auto_approve``)
        pre-authorizes this action's class, so the per-action HITL pause is waived.

        This is the legitimate "full power without per-action friction" for an operator's
        OWN lab: the signed engagement is the authorization. The rails stay — the action
        is still ROE-scoped (``_roe_authorize`` already ran), audited, deconflicted and
        reversible. DESTRUCTIVE additionally requires ``allow_destructive_testing`` so the
        hardest class never auto-runs on a flag alone."""
        gov = self._governance()
        if not gov:
            return False
        try:
            eng = await self._get_active_engagement()
        except Exception:
            eng = None
        if not eng or not eng.get("auto_approve"):
            return False
        cls_val = getattr(action_cls, "value", str(action_cls))
        allowed = {str(c).lower() for c in (eng.get("allowed_classes") or [])}
        if allowed and cls_val not in allowed:
            return False  # not pre-authorized for a class the ROE doesn't grant
        if action_cls == ActionClass.DESTRUCTIVE:
            try:
                from ..core.config import get_config
                if not get_config().allow_destructive_testing:
                    return False
            except Exception:
                return False
        return True

    async def kill_switch(self) -> dict:
        """Global kill-switch for THIS engine: abort the run and clean up every
        open foothold/implant of the active engagement (cleanup obligation).

        Passes the sandbox executor so cleanup performs a REAL teardown of any
        foothold that carries a teardown recipe (follow-up #5), not just a flag."""
        self.abort()
        summary = {"aborted": True, "cleaned_sessions": 0}
        gov = self._governance()
        if not gov:
            return summary
        try:
            eng = await self._get_active_engagement()
            res = await gov["sessions"].cleanup(
                (eng or {}).get("id") if eng else None,
                executor=getattr(self, "tool_executor", None))
            summary["cleaned_sessions"] = res.get("cleaned", 0)
            summary["cleanup_pending"] = res.get("pending", [])
            summary["cleanup_failed"] = res.get("failed", [])
            await self._audit_record(tool="kill_switch", arguments={}, action_cls=ActionClass.PASSIVE,
                                     decision="kill_switch", result=res)
        except Exception:
            pass
        return summary

    # -- Public API ---------------------------------------------------------

    async def run(self, user_input: str) -> AsyncGenerator[dict, None]:
        """Process user input through the agent loop.

        Yields event dicts with ``type``:
        thinking, tool_call, tool_result, response, finding, suggestion,
        phase_change, checkpoint, error.
        """
        if not self.messages or self.messages[0].get("role") != "system":
            system_prompt = await self._build_system_prompt()
            self.messages.insert(0, {"role": "system", "content": system_prompt})

        # Append compact dynamic phase context if available
        mem_summary = self._get_living_memory_summary()
        graph_ctx = await self._graph_summary_text()
        prompt_with_context = f"{user_input}\n\n[Context: Phase={self.current_phase}]"
        if graph_ctx:
            prompt_with_context += f"\n{graph_ctx}"
        if mem_summary:
            prompt_with_context += f"\n{mem_summary}"

        self._current_user_request = user_input or ""
        self._native_repeat_count = 0
        # Reset the per-run iteration budget. The engine instance is cached in
        # app.state.active_engines and reused for every user message in a session,
        # so without this the iteration counter accumulates across turns and the
        # session permanently fails with "Limite máximo de iterações" after ~50
        # cumulative iterations. Phase/messages are kept for continuity.
        self.iteration = 0
        self._repeat_after_success = 0
        self._stagnation_aborted = False
        # Re-resolve the active engagement at the start of each run (an operator
        # may have created/closed one between turns).
        self._engagement_loaded = False
        self.messages.append({"role": "user", "content": prompt_with_context})

        # Deep recon autostart: bare domain triggers full pipeline
        from ..core.config import get_config
        if (self.mode == MODE_AUTOPILOT and get_config().deep_recon_autostart
                and self._is_bare_domain(user_input)):
            expanded = self._expand_to_full_recon(user_input)
            self.messages[-1]["content"] = expanded

        async for event in self._run_loop():
            yield event

    async def _run_loop(self) -> AsyncGenerator[dict, None]:
        """Internal execution loop driven by LLM tool-calling."""
        import time as _time
        loop_started = _time.monotonic()
        while self.iteration < MAX_ITERATIONS:
            if getattr(self, "_abort_requested", False):
                self._abort_requested = False
                yield {"type": "info", "content": "Operação interrompida a pedido do operador."}
                return

            # Wall-clock watchdog: a few very slow local-model inferences could
            # otherwise keep a run alive indefinitely. Stop gracefully.
            if _time.monotonic() - loop_started > MAX_RUN_SECONDS:
                yield {"type": "error", "subtype": "run_timeout", "iteration": self.iteration,
                       "error": (f"Tempo máximo de execução ({MAX_RUN_SECONDS // 60} min) atingido. "
                                 "Operação pausada — reveja os resultados ou continue com uma nova instrução.")}
                return
            self.iteration += 1

            # --- Checkpoint system ---
            if self.iteration % CHECKPOINT_EVAL_INTERVAL == 0:
                phase_event = await self._evaluate_phase()
                if phase_event:
                    yield phase_event

            if self.iteration % SELF_EVAL_INTERVAL == 0 and self.iteration > 0:
                eval_result = await self._self_evaluate()
                yield {"type": "checkpoint", "subtype": "self_eval", "iteration": self.iteration,
                       "phase": self.current_phase, "findings": self.findings_count,
                       "evaluation": eval_result}

            if self.iteration % CONTEXT_COMPRESS_INTERVAL == 0:
                compressed = self._compress_context()
                if compressed:
                    yield {"type": "checkpoint", "subtype": "context_compressed",
                           "iteration": self.iteration, "messages_before": compressed[0],
                           "messages_after": compressed[1]}

            try:
                phase_names_pt = {
                    "recon": "Reconhecimento",
                    "analysis": "Análise de Vulnerabilidades",
                    "exploit": "Exploração Controlada",
                    "report": "Relatório Final",
                }
                pt_phase = phase_names_pt.get(self.current_phase, self.current_phase)
                yield {"type": "thinking", "content": f"Iteração {self.iteration} — Fase: {pt_phase} ({self.current_phase})"}

                # Continuous learning (recall): enrich the new phase with proven
                # techniques from the KB for whatever tech was detected.
                consulted = await self._consult_playbooks()
                if consulted:
                    yield {"type": "checkpoint", "subtype": "playbook_recall",
                           "phase": self.current_phase, "keywords": consulted["keywords"],
                           "count": consulted["count"],
                           "content": f"Memória de longo prazo consultada ({consulted['count']} técnica(s) para: {consulted['keywords']})"}

                # Graph-driven synthesis: when moving into analysis/report, turn
                # the asset graph into candidate findings so the agent concludes.
                if self.current_phase in ("analysis", "report"):
                    synth = await self._synthesize_from_graph()
                    if synth:
                        yield {"type": "checkpoint", "subtype": "graph_synthesis",
                               "phase": self.current_phase, "count": synth["count"],
                               "content": f"Grafo gerou {synth['count']} achado(s) candidato(s) para confirmação"}

                # Auto-report: on reaching the report phase, generate the report
                # artifact deterministically (before the slow deep-model turn), so
                # an operation always ends with a report even if interrupted.
                if self.current_phase == "report" and not self._report_generated:
                    rep = await self._generate_report()
                    if rep and not rep.get("error"):
                        yield {"type": "report", "phase": "report",
                               "findings": rep["findings"], "reports": rep["reports"],
                               "content": (f"Relatório gerado automaticamente com {rep['findings']} "
                                           f"finding(s): " + ", ".join(rep["reports"].values()))}

                # Adaptive Technology Guidance: dynamic tactical steering based on detected tech
                tech_guidance = self._get_tactical_technology_guidance()
                if tech_guidance:
                    sig = tech_guidance.get("signature", "")
                    active_sigs = getattr(self, "_active_tech_signatures", None)
                    if active_sigs is None:
                        active_sigs = set()
                        self._active_tech_signatures = active_sigs
                    if sig and sig not in active_sigs:
                        active_sigs.add(sig)
                        directive = tech_guidance.get("directive", "")
                        if directive:
                            self.messages.append({"role": "system", "content": directive})
                        yield {
                            "type": "thinking",
                            "content": f"Roteamento adaptativo ativo: {tech_guidance.get('summary', 'Estratégia ajustada para a tecnologia do alvo.')}"
                        }

                explicit_tools = self._detect_explicit_requested_tools(getattr(self, "_current_user_request", ""))
                target_str = (self.session.get("target") if isinstance(self.session, dict) else getattr(self.session, "target", "")) or ""
                clean_target = re.sub(r'^https?://', '', target_str.lower()).split('/')[0].split(':')[0]
                is_ip_target = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_target))

                # If target is an IP, filter out tools that only make sense for FQDN domains
                if is_ip_target and explicit_tools:
                    domain_only = {"audit_dns_email_security", "search_cert_transparency", "audit_subdomain_takeover", "audit_mta_sts_dane", "audit_dkim_bimi"}
                    filtered_explicit = [t for t in explicit_tools if t not in domain_only]
                    if filtered_explicit:
                        explicit_tools = filtered_explicit
                    elif "enrich_ip_intel" not in explicit_tools:
                        explicit_tools = ["enrich_ip_intel"]

                # Calculate executed tools and remaining pending tools for this campaign
                executed_names = {m.get("name") for m in self.messages if m.get("role") == "tool"}
                pending_tools = [t for t in explicit_tools if t not in executed_names and t != "execute"] if explicit_tools else []
                all_explicit_done = len(pending_tools) == 0 if explicit_tools else False

                # Guide the 7B model at EVERY iteration with the exact next tool to execute
                if explicit_tools and not all_explicit_done and pending_tools:
                    next_tool = pending_tools[0]
                    self.messages.append({
                        "role": "system",
                        "content": (
                            f"[DIRETIVA DA ETAPA {self.iteration}]\n"
                            f"Alvo autorizado: '{target_str}'.\n"
                            f"Ferramentas concluídas até agora: {', '.join(executed_names & set(explicit_tools)) or 'nenhuma'}.\n"
                            f"👉 PRÓXIMA AÇÃO OBRIGATÓRIA: Chame imediatamente a ferramenta '{next_tool}' para o alvo '{target_str}'.\n"
                            f"Ferramentas restantes na fila: {', '.join(pending_tools)}.\n"
                            f"NÃO repita ferramentas anteriores. Execute '{next_tool}' agora."
                        )
                    })

                # If all requested native tools have executed, synthesize the final response in Portuguese and conclude the turn!
                if explicit_tools and all_explicit_done:
                    self.messages.append({
                        "role": "system",
                        "content": (
                            "[SISTEMA] Todas as ferramentas solicitadas pelo operador foram executadas com sucesso. "
                            "Apresente agora ao operador uma resposta executiva completa, pedagógica e estruturada em Português do Brasil (pt-BR), "
                            "detalhando os achados, notas de segurança (Score/Grade), pontos fortes e recomendações de mitigação. "
                            "Não faça novas chamadas de ferramentas; conclua com o resumo."
                        )
                    })
                    response_msg = await self.deep_llm.chat(
                        messages=self.messages,
                        tools=None,
                        fmt=None,
                        num_predict=600,
                    )
                    content = response_msg.get("content", "")
                    raw_thinking = response_msg.get("thinking", "")
                    extracted_thinking, clean_content = self._extract_thinking(content)
                    thinking = (raw_thinking.strip() if raw_thinking else "") or extracted_thinking
                    if thinking:
                        yield {"type": "thinking", "content": thinking}
                    final_text = clean_content or content or "Análise concluída com sucesso."
                    self.messages.append({"role": "assistant", "content": final_text})
                    yield {"type": "response", "content": final_text}
                    return

                # If in report phase and report has been generated, conclude with executive summary
                if self.current_phase == "report" and self._report_generated:
                    self.messages.append({
                        "role": "system",
                        "content": (
                            "[SISTEMA - RELATÓRIO FINAL] O relatório formal da operação foi gerado e salvo no workspace. "
                            f"Total de vulnerabilidades confirmadas: {self.findings_count}. "
                            "Apresente ao operador o Resumo Executivo Final em Português do Brasil (pt-BR) consolidando todos os achados "
                            "confirmados, severidades, superfícies afetadas e roteiro prioritário de remediação. "
                            "Não execute ferramentas adicionais; conclua com o resumo executivo."
                        )
                    })
                    response_msg = await self.deep_llm.chat(
                        messages=self.messages,
                        tools=None,
                        fmt=None,
                        num_predict=600,
                    )
                    content = response_msg.get("content", "")
                    raw_thinking = response_msg.get("thinking", "")
                    extracted_thinking, clean_content = self._extract_thinking(content)
                    thinking = (raw_thinking.strip() if raw_thinking else "") or extracted_thinking
                    if thinking:
                        yield {"type": "thinking", "content": thinking}
                    final_text = clean_content or content or "Relatório executivo final gerado com sucesso."
                    self.messages.append({"role": "assistant", "content": final_text})
                    yield {"type": "response", "content": final_text}
                    return

                # Hybrid routing: fast tactical tier for recon/scan tools, deep tier for exploit/report
                active_llm = self.deep_llm if self.current_phase in ("exploit", "report") else self.llm
                if explicit_tools and not all_explicit_done:
                    # Provide ONLY the remaining pending tools to the LLM (plus minimal internal utilities)
                    # This prevents the LLM from ever re-calling an already executed tool!
                    focused_set = set(pending_tools) | {"execute", "read_memory", "update_memory", "query_graph"}
                    active_tools = [t for t in NATIVE_TOOLS if t["function"]["name"] in focused_set]
                else:
                    all_phase_tools = get_tools_for_phase(self.current_phase)
                    if is_ip_target:
                        domain_only = {"audit_dns_email_security", "search_cert_transparency", "audit_subdomain_takeover", "audit_mta_sts_dane", "audit_dkim_bimi"}
                        all_phase_tools = [t for t in all_phase_tools if t["function"]["name"] not in domain_only]

                    # For Qwen 7B & local LLMs: exclude already executed tools (prevent loops and token bloat)
                    unexecuted = [
                        t for t in all_phase_tools
                        if t["function"]["name"] not in executed_names
                        or t["function"]["name"] in ("execute", "create_finding", "read_memory", "update_memory", "query_graph")
                    ]

                    # If still too large (>16 tools), prioritize core discovery/assessment tools to keep prompt small
                    if len(unexecuted) > 16:
                        if self.current_phase == "recon":
                            priority_order = [
                                "audit_tls_ssl", "audit_security_headers", "detect_waf_firewall",
                                "query_whois_rdap", "enrich_ip_intel", "search_cert_transparency",
                                "audit_dns_email_security", "audit_dnsbl_reputation", "audit_git_and_env_leakage",
                                "scan_exposed_secrets", "execute", "read_memory", "update_memory", "query_graph"
                            ]
                        elif self.current_phase == "analysis":
                            priority_order = [
                                "audit_cors_advanced", "audit_http_methods", "audit_api_spec",
                                "audit_rate_limiting", "audit_cloud_storage", "audit_ssrf_cloud_metadata",
                                "audit_compliance_matrix", "generate_detection_rules", "create_finding",
                                "search_cve", "execute", "read_memory", "query_graph"
                            ]
                        else:
                            priority_order = []

                        priority_tools = [t for t in unexecuted if t["function"]["name"] in priority_order]
                        other_tools = [t for t in unexecuted if t["function"]["name"] not in priority_order]
                        active_tools = (priority_tools + other_tools)[:16]
                    else:
                        active_tools = unexecuted

                # Constrain the fast tool-calling phases to JSON output: weak
                # local models otherwise emit a long tutorial instead of a tool
                # call (measured 37s+/turn -> ~6-8s with format=json). The deep
                # exploit/report phases stay free-text so they can write prose.
                fmt = "json" if self.current_phase in ("recon", "analysis") else None
                response_msg = await active_llm.chat(
                    messages=self.messages,
                    tools=active_tools,
                    fmt=fmt,
                )

                # --- Extended thinking extraction ---
                content = response_msg.get("content", "")
                raw_thinking = response_msg.get("thinking", "")
                extracted_thinking, clean_content = self._extract_thinking(content)
                thinking = (raw_thinking.strip() if raw_thinking else "") or extracted_thinking
                if thinking:
                    yield {"type": "thinking", "content": thinking}

                tool_calls: list[dict] = response_msg.get("tool_calls", [])

                # Fallback: extract tool call from content if model emitted JSON or bare tool calls in text
                if not tool_calls and content:
                    extracted_calls = self._extract_tool_calls_from_text(content, default_target=target_str)
                    if extracted_calls:
                        tool_calls = extracted_calls

                # No tool calls — final text response
                if not tool_calls:
                    final_text = clean_content or content or thinking or "Análise concluída."
                    # With format=json the model may return a JSON object that
                    # isn't a tool call (e.g. a final summary). Surface a
                    # human-readable field instead of dumping raw JSON.
                    final_text = self._humanize_final_text(final_text)
                    if final_text.strip().lower() in ("generate_report", "generate_report()", "generatereport", "report"):
                        rep = await self._generate_report()
                        rep_msg = "Relatório executivo gerado com sucesso! Você pode visualizá-lo e baixá-lo (PDF, HTML, MD, JSON) na aba 'Relatórios' no menu superior do Arcanum."
                        if rep and rep.get("reports"):
                            rep_msg += f"\nArquivos salvos: " + ", ".join(rep["reports"].values())
                        final_text = rep_msg
                    self.messages.append({"role": "assistant", "content": final_text})
                    yield {"type": "response", "content": final_text}
                    return

                self.messages.append({"role": "assistant", "content": content or "", "tool_calls": tool_calls})

                # If the assistant provided explanatory text along with tool calls, yield it
                text_explanation = self._clean_explanatory_text(clean_content)
                if text_explanation:
                    yield {"type": "response", "content": text_explanation}

                for tc in tool_calls:
                    fn = tc.get("function", {})
                    tool_name = fn.get("name", "")
                    arguments = fn.get("arguments", {})

                    # Robust normalization of tool names and parameters
                    normalized = self._normalize_tool_call_dict({"name": tool_name, "arguments": arguments}, default_target=target_str)
                    if normalized:
                        tool_name = normalized["function"]["name"]
                        arguments = normalized["function"]["arguments"]

                    if tool_name == "execute" and isinstance(arguments, dict) and "command" in arguments:
                        arguments["command"] = _auto_repair_command(arguments["command"])

                        # Stagnation / feedback guard. A weak local model can
                        # re-propose a command it already ran. Distinguish:
                        #  - already SUCCEEDED -> it just didn't register the
                        #    result; feed a concise reminder and skip the re-run
                        #    (don't kill the operation as "no progress").
                        #  - FAILED >=2x identically -> real failure loop, abort.
                        sig = arguments["command"].strip()
                        h = self._cmd_history.get(sig)
                        if h and h.get("ok", 0) > 0:
                            self._repeat_after_success += 1
                            self.messages.append({
                                "role": "tool", "name": "execute",
                                "content": (
                                    f"[JÁ EXECUTADO] '{sig}' já rodou com sucesso. Resultado: "
                                    f"{h.get('summary', 'concluído')}. NÃO repita; avance para uma "
                                    "ação DIFERENTE (outra ferramenta/porta/endpoint) ou finalize com resumo."
                                ),
                            })
                            yield {"type": "info",
                                   "content": f"Comando já concluído com sucesso; pulando repetição: {sig}"}
                            if self._repeat_after_success >= 3:
                                yield {"type": "error",
                                       "error": "Agente preso repetindo ações já concluídas. Finalize ou redirecione a operação.",
                                       "iteration": self.iteration}
                                self._stagnation_aborted = True
                                return
                            continue  # skip; re-query the model next iteration
                        if h and h.get("fail", 0) >= 2:
                            self.messages.append({
                                "role": "user",
                                "content": (
                                    f"[SISTEMA] O comando '{sig}' falhou repetidamente. Pare de repetir. "
                                    "Analise o erro e escolha uma AÇÃO DIFERENTE ou finalize com um resumo."
                                ),
                            })
                            yield {"type": "error",
                                   "error": f"Execução interrompida: '{sig}' falhou {h['fail']}x sem progresso. Redirecione a operação.",
                                   "iteration": self.iteration}
                            self._stagnation_aborted = True
                            return

                    # Auto-repair placeholder domains (e.g. corp.com.br from docs) to session target
                    arguments = self._auto_repair_target_arguments(tool_name, arguments)

                    # Scope enforcement (deterministic, NOT model-trusted): never
                    # touch a host outside the authorized scope, in any mode.
                    offending = self._scope_violation(tool_name, arguments)
                    if offending:
                        self.messages.append({
                            "role": "tool", "name": tool_name,
                            "content": (f"[FORA DE ESCOPO] O host '{offending}' nao esta no escopo "
                                        f"autorizado ({self._scope_label()}). Acao BLOQUEADA — nada foi "
                                        "executado. Teste apenas alvos dentro do escopo."),
                        })
                        yield {"type": "error", "subtype": "scope_blocked", "tool": tool_name,
                               "iteration": self.iteration,
                               "error": (f"Ação bloqueada por escopo: '{offending}' está fora do escopo "
                                         f"autorizado ({self._scope_label()}). Nada foi executado.")}
                        continue

                    # --- F0: Engagement (ROE) class-based authorization ---
                    # If an engagement is active, an action whose class the ROE
                    # does not permit (or whose window/scope is out of contract)
                    # is blocked deterministically and recorded. With no active
                    # engagement this is a no-op (legacy operator-driven behavior).
                    roe_reason = await self._roe_authorize(tool_name, arguments)
                    if roe_reason:
                        self.messages.append({
                            "role": "tool", "name": tool_name,
                            "content": (f"[BLOQUEADO POR ROE] {roe_reason}. Ação NÃO executada. "
                                        "Escolha uma ação dentro das classes autorizadas pelo engajamento "
                                        "ou solicite ao operador a ampliação do contrato (ROE)."),
                        })
                        yield {"type": "error", "subtype": "blocked_by_roe", "tool": tool_name,
                               "iteration": self.iteration,
                               "error": f"Ação bloqueada pelo contrato de engajamento (ROE): {roe_reason}"}
                        continue

                    # Native tool deduplication / stagnation guard:
                    if tool_name != "execute":
                        # 1. Immediate consecutive stagnation guard (calling the same tool 2x in a row)
                        if getattr(self, "_last_executed_tool", None) == tool_name and (
                            tool_name.startswith(("audit_", "query_", "search_", "detect_", "scan_", "calculate_", "generate_", "simulate_"))
                            or tool_name in ("update_memory", "read_memory", "read_file", "query_graph", "query_playbook", "save_playbook")
                        ):
                            self._native_repeat_count = getattr(self, "_native_repeat_count", 0) + 1
                            self.messages.append({
                                "role": "tool", "name": tool_name,
                                "content": (
                                    f"[STAGNATION] A ferramenta '{tool_name}' já foi executada e teve seus resultados registrados. "
                                    "NÃO repita esta ferramenta. Prossiga para a conclusão com o resumo dos achados ou avance para outra etapa."
                                ),
                            })
                            yield {"type": "info", "content": f"Ferramenta '{tool_name}' chamada consecutivamente; pulando repetição."}
                            if self._native_repeat_count >= 2:
                                # Break out of repetitive loops: synthesize executive findings and conclude gracefully
                                self.messages.append({
                                    "role": "system",
                                    "content": (
                                        "[SISTEMA] Etapas solicitadas foram concluídas. "
                                        "Apresente agora ao operador uma resposta executiva completa, pedagógica e estruturada em Português do Brasil (pt-BR), "
                                        "detalhando os achados, notas de segurança (Score/Grade) e recomendações de mitigação. Não chame ferramentas."
                                    )
                                })
                                response_msg = await self.deep_llm.chat(
                                    messages=self.messages,
                                    tools=None,
                                    fmt=None,
                                    num_predict=600,
                                )
                                content = response_msg.get("content", "")
                                extracted_thinking, clean_content = self._extract_thinking(content)
                                final_text = clean_content or content or "Análise concluída com sucesso."
                                self.messages.append({"role": "assistant", "content": final_text})
                                yield {"type": "response", "content": final_text}
                                return
                            continue

                        # 2. Reject tools with missing/empty required content
                        if tool_name == "audit_sbom_dependencies":
                            manifest = arguments.get("manifest_content")
                            pkgs = arguments.get("packages")
                            if (not manifest or str(manifest).strip() in ("", "...")) and (not pkgs or not len(pkgs)):
                                self.messages.append({
                                    "role": "tool", "name": tool_name,
                                    "content": (
                                        "[ARGUMENTO INVÁLIDO] Nenhum manifesto de dependências ou lista de pacotes foi fornecido. "
                                        "Pule 'audit_sbom_dependencies' e avance para a próxima etapa ou conclusão."
                                    ),
                                })
                                yield {"type": "info", "content": "Parâmetro vazio para audit_sbom_dependencies; pulando."}
                                continue

                        # 3. Global single-run tools
                        SINGLE_RUN_TOOLS = {
                            "audit_sbom_dependencies", "audit_compliance_matrix", "audit_binary_protections",
                            "analyze_forensic_artifacts", "calculate_breach_risk_cost", "calculate_cvss_vector",
                            "generate_hardening_baseline", "generate_ir_playbook", "generate_detection_rules",
                            "generate_yara_rule", "map_mitre_attack", "generate_atomic_test",
                            "evaluate_defensive_efficacy", "simulate_cloud_iam_privesc", "simulate_attack_path",
                            "audit_iac_misconfigurations", "audit_dockerfile_security", "audit_kubernetes_rbac",
                            "audit_cicd_pipeline_security", "audit_cicd_workflow_poisoning", "audit_ebpf_integrity_and_rootkits",
                        }
                        if tool_name in SINGLE_RUN_TOOLS and getattr(self, "_native_tool_runs", {}).get(tool_name, 0) >= 1:
                            self.messages.append({
                                "role": "tool", "name": tool_name,
                                "content": (
                                    f"[JÁ EXECUTADO] A ferramenta '{tool_name}' já foi executada nesta sessão. "
                                    "NÃO repita a mesma ferramenta; avance para uma etapa diferente ou finalize com o resumo."
                                ),
                            })
                            yield {"type": "info", "content": f"Ferramenta '{tool_name}' já executada nesta sessão; pulando repetição."}
                            continue

                        # 4. Per-target single-run tools
                        tool_sig = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
                        tool_count = self._native_tool_history.get(tool_sig, 0)

                        host_raw = arguments.get("host") or arguments.get("domain") or arguments.get("target") or arguments.get("url")
                        host_key = re.sub(r'^https?://', '', str(host_raw).lower()).split('/')[0].split(':')[0] if host_raw else None
                        host_sig = f"{tool_name}@{host_key}" if host_key else None
                        host_count = self._native_tool_history.get(host_sig, 0) if host_sig else 0

                        SINGLE_RUN_PER_TARGET = {
                            "audit_smtp_open_relay_and_spoofing", "audit_security_headers", "audit_dns_email_security",
                            "audit_tls_ssl", "search_cert_transparency", "audit_subdomain_takeover", "query_whois_rdap",
                            "detect_waf_firewall", "audit_dnsbl_reputation", "query_threat_feeds", "enrich_ip_intel",
                            "audit_git_and_env_leakage", "audit_well_known_security", "audit_compliance_matrix",
                            "audit_cors_advanced", "audit_http_methods", "scan_exposed_secrets", "audit_dkim_bimi",
                        }

                        if tool_count >= 1 or (host_count >= 1 and (tool_name in SINGLE_RUN_PER_TARGET or tool_name.startswith("audit_"))):
                            self.messages.append({
                                "role": "tool", "name": tool_name,
                                "content": (
                                    f"[JÁ EXECUTADO] A ferramenta '{tool_name}' já foi executada para o alvo '{host_key or arguments}' nesta sessão. "
                                    "O resultado já foi registrado. NÃO repita a mesma ferramenta de auditoria; "
                                    "avance para uma etapa diferente ou compile a tabela/resumo solicitado pelo operador."
                                ),
                            })
                            yield {"type": "info", "content": f"Ferramenta '{tool_name}' já executada nesta sessão para {host_key or 'este alvo'}; pulando repetição."}
                            continue

                    explanation = self._explain_tool_action(tool_name, arguments)

                    yield {
                        "type": "tool_call",
                        "tool": tool_name,
                        "arguments": arguments,
                        "iteration": self.iteration,
                        "explanation": explanation,
                        "content": f"{explanation['what']} | Objetivo: {explanation['why']}",
                    }

                    # Mode-based gating
                    risk = self._assess_risk(tool_name, arguments)
                    # F0: the action CLASS drives the HITL tier. EXPLOIT /
                    # POST_EXPLOIT / DESTRUCTIVE require dual approval regardless
                    # of mode; PASSIVE/ACTIVE keep the existing mode behavior.
                    action_cls = _rt_classify(tool_name, arguments)
                    tier = _rt_hitl_tier(action_cls)
                    approvals_required = 2 if tier == "double" else 1
                    requires_approval = False
                    # Internal bookkeeping tools never touch the target and carry
                    # no risk — don't gate them (avoids approval spam on every
                    # memory note / KB lookup observed in manual mode).
                    INTERNAL_TOOLS = ("read_memory", "update_memory", "query_playbook",
                                      "save_playbook", "search_cve")
                    if self.mode == MODE_MANUAL:
                        requires_approval = tool_name not in INTERNAL_TOOLS
                    elif self.mode == MODE_COPILOT:
                        requires_approval = risk in ("MEDIUM", "HIGH")
                    elif self.mode == MODE_AUTOPILOT:
                        # Even in autopilot, destructive/high-risk tooling
                        # (metasploit, hydra, sqlmap, --risk 3...) requires
                        # explicit opt-in via ARCANUM_ALLOW_DESTRUCTIVE_TESTING;
                        # otherwise pause for operator approval.
                        from ..core.config import get_config
                        if risk == "HIGH" and not get_config().allow_destructive_testing:
                            requires_approval = True
                    # Dual-approval classes always require human sign-off.
                    if tier == "double":
                        requires_approval = True

                    # Full-scope LAB ROE (auto_approve): the signed engagement is the
                    # authorization, so waive the per-action human pause for its allowed
                    # classes. Everything is still audited, scope-enforced, deconflicted
                    # and reversible; DESTRUCTIVE still requires allow_destructive_testing.
                    preauthorized = False
                    if requires_approval and await self._preauthorized(action_cls):
                        requires_approval = False
                        preauthorized = True

                    if requires_approval:
                        self.pending_action = {
                            "tool": tool_name, "arguments": arguments,
                            "action_class": action_cls.value,
                            "approvals_required": approvals_required,
                            "approvals_given": 0,
                            "approvers": [],
                        }
                        risk_pt = {"LOW": "BAIXO", "MEDIUM": "MÉDIO", "HIGH": "ALTO"}.get(risk, risk)
                        # Honest wording: without operator identity (no auth yet) these
                        # are two CONFIRMATIONS; the two-person rule (distinct approvers)
                        # is enforced only when an operator identity is supplied.
                        dual_note = ("\n\n⚠️ DUPLA APROVAÇÃO: esta ação exige duas confirmações "
                                     "do operador antes de executar (aprovadores independentes "
                                     "quando houver identidade de operador).") if approvals_required > 1 else ""
                        yield {
                            "type": "suggestion",
                            "tool": tool_name,
                            "arguments": arguments,
                            "risk": risk,
                            "action_class": action_cls.value,
                            "approvals_required": approvals_required,
                            "approvals_given": 0,
                            "explanation": explanation,
                            "message": (
                                f"Modo {self.mode.capitalize()}: aprovação do operador necessária (Risco: {risk_pt}).\n\n"
                                f"📌 O QUE FAZ:\n{explanation['what']}\n\n"
                                f"🎯 POR QUE EXECUTAR:\n{explanation['why']}\n\n"
                                f"⚙️ PARÂMETROS / EXEMPLO:\n{explanation['params']}" + dual_note
                            ),
                        }
                        return  # Pause loop until operator approves or cancels

                    # Fail-closed pre-audit for high-risk classes (follow-up #3).
                    # (These are normally gated to approval above; this is defense in
                    # depth so an EXPLOIT+ action can never run unaudited.)
                    preaudit_err = await self._preaudit_high_risk(
                        tool=tool_name, arguments=arguments, action_cls=action_cls, risk=risk)
                    if preaudit_err:
                        yield {"type": "error", "error": preaudit_err, "iteration": self.iteration}
                        return

                    # Execute the tool
                    result = await self.tool_executor.execute_tool(tool_name, arguments)
                    self._last_executed_tool = tool_name
                    self._native_repeat_count = 0
                    # F0: immutable audit trail of the executed action (masked args).
                    await self._audit_record(tool=tool_name, arguments=arguments,
                                             action_cls=action_cls,
                                             decision="executed_preauthorized" if preauthorized else "executed",
                                             risk=risk, result=result)
                    if tool_name == "execute":
                        self._record_cmd_result(arguments.get("command", ""), result)
                        await self._auto_learn(arguments.get("command", ""), result, self.current_phase)
                    else:
                        self._native_tool_runs[tool_name] = self._native_tool_runs.get(tool_name, 0) + 1
                        tool_sig = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
                        self._native_tool_history[tool_sig] = self._native_tool_history.get(tool_sig, 0) + 1
                        host_raw = arguments.get("host") or arguments.get("domain") or arguments.get("target") or arguments.get("url")
                        if host_raw:
                            host_key = re.sub(r'^https?://', '', str(host_raw).lower()).split('/')[0].split(':')[0]
                            host_sig = f"{tool_name}@{host_key}"
                            self._native_tool_history[host_sig] = self._native_tool_history.get(host_sig, 0) + 1

                    tool_msg = self._format_tool_result(tool_name, result)
                    self.messages.append(tool_msg)
                    if tool_name == "execute":
                        _hint = self._recovery_hint(arguments.get("command", ""), result)
                        if _hint:
                            self.messages.append({"role": "system", "content": f"[DICA DE CORREÇÃO] {_hint}"})

                    tool_out = result.get("output") or result.get("stdout") or result.get("error") or "Sucesso"
                    yield {
                        "type": "tool_result",
                        "tool": tool_name,
                        "result": result,
                        "output": tool_out,
                        "content": json.dumps(tool_out, default=str) if isinstance(tool_out, (dict, list)) else str(tool_out),
                        "iteration": self.iteration,
                    }

                    # Surface findings from explicit create_finding
                    if tool_name == "create_finding" and result.get("success"):
                        self.findings_count += 1
                        output = result.get("output", {})
                        if output.get("status") != "duplicate":
                            yield {"type": "finding", "finding": output}

                    # Auto-ingest findings from native audit tools
                    auto_findings = await self._auto_ingest_native_findings(tool_name, arguments, result)
                    for af in auto_findings:
                        yield {"type": "finding", "finding": af}

            except Exception as exc:
                yield {"type": "error", "error": str(exc), "iteration": self.iteration}
                return

        yield {"type": "error", "error": f"Limite máximo de iterações ({MAX_ITERATIONS}) atingido", "iteration": self.iteration}

    async def execute_approved(self, operator: str | None = None) -> AsyncGenerator[dict, None]:
        """Execute a tool action previously held for operator approval.

        Dual-approval classes (EXPLOIT/POST_EXPLOIT/DESTRUCTIVE) require two
        approvals: the first re-arms the pending action and requests the second;
        only the final approval executes.

        ``operator`` identifies WHO is approving (follow-up #1/#2). When identities
        are supplied, the **two-person rule** is enforced: the same operator cannot
        provide both approvals. Without an identity (no auth yet) it falls back to a
        plain count of confirmations, and the wording says so honestly."""
        if not self.pending_action:
            yield {"type": "info", "content": "Nenhuma ação pendente de aprovação."}
            return

        action = self.pending_action
        tool_name = action["tool"]
        arguments = action["arguments"]
        action_cls = _rt_classify(tool_name, arguments)

        # --- F0 dual approval gate (identity-aware) ---
        need = int(action.get("approvals_required", 1) or 1)
        approvers = list(action.get("approvers") or [])
        # Two-person rule: a known operator cannot approve the same action twice.
        if operator is not None and operator in approvers:
            self.pending_action = action  # unchanged — still waiting
            yield {
                "type": "suggestion",
                "tool": tool_name,
                "arguments": arguments,
                "risk": self._assess_risk(tool_name, arguments),
                "action_class": action_cls.value,
                "approvals_required": need,
                "approvals_given": len(approvers),
                "message": (
                    f"Aprovação recusada: o operador '{operator}' já aprovou esta ação. "
                    f"A regra de dois exige a aprovação de um operador DIFERENTE antes de "
                    f"executar '{tool_name}'."
                ),
            }
            return
        given = int(action.get("approvals_given", 0) or 0) + 1
        if operator is not None:
            approvers.append(operator)
        if given < need:
            # Keep pending; wait for the next approval.
            self.pending_action = {**action, "approvals_given": given, "approvers": approvers}
            explanation = self._explain_tool_action(tool_name, arguments)
            # Honest wording: "independent approvers" only when identities are tracked.
            independence = ("de um operador DIFERENTE (regra de dois)" if operator is not None
                            else "do operador (identidade de operador exige autenticação)")
            yield {
                "type": "suggestion",
                "tool": tool_name,
                "arguments": arguments,
                "risk": self._assess_risk(tool_name, arguments),
                "action_class": action_cls.value,
                "approvals_required": need,
                "approvals_given": given,
                "approvers": approvers,
                "explanation": explanation,
                "message": (
                    f"Aprovação {given}/{need} registrada. DUPLA APROVAÇÃO exigida: "
                    f"é necessária mais {need - given} aprovação {independence} "
                    f"antes de executar '{tool_name}'."
                ),
            }
            return

        self.pending_action = None
        # Who is accountable for this action in the audit trail (follow-up #2).
        operator_label = ", ".join(approvers) if approvers else operator

        # Fail-closed pre-audit for high-risk classes (follow-up #3): abort if the
        # action cannot be written to the immutable trail BEFORE it runs.
        preaudit_err = await self._preaudit_high_risk(
            tool=tool_name, arguments=arguments, action_cls=action_cls,
            risk=self._assess_risk(tool_name, arguments), operator=operator_label)
        if preaudit_err:
            yield {"type": "error", "error": preaudit_err, "iteration": self.iteration}
            return

        yield {"type": "thinking", "content": f"Executando ação aprovada pelo operador: {tool_name}"}
        try:
            result = await self.tool_executor.execute_tool(tool_name, arguments)
        except Exception as exc:
            await self._audit_record(tool=tool_name, arguments=arguments, action_cls=action_cls,
                                     decision="executed_error", operator=operator_label,
                                     result={"success": False, "error": str(exc)})
            yield {"type": "error", "error": f"Falha na execução da ferramenta {tool_name}: {exc}", "iteration": self.iteration}
            return
        self._last_executed_tool = tool_name
        self._native_repeat_count = 0
        # F0: immutable audit trail of the operator-approved action.
        await self._audit_record(tool=tool_name, arguments=arguments, action_cls=action_cls,
                                 decision="executed_approved", operator=operator_label,
                                 risk=self._assess_risk(tool_name, arguments), result=result)
        if tool_name == "execute":
            self._record_cmd_result(arguments.get("command", ""), result)
            await self._auto_learn(arguments.get("command", ""), result, self.current_phase)
        else:
            self._native_tool_runs[tool_name] = self._native_tool_runs.get(tool_name, 0) + 1
            tool_sig = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
            self._native_tool_history[tool_sig] = self._native_tool_history.get(tool_sig, 0) + 1
            host_raw = arguments.get("host") or arguments.get("domain") or arguments.get("target") or arguments.get("url")
            if host_raw:
                host_key = re.sub(r'^https?://', '', str(host_raw).lower()).split('/')[0].split(':')[0]
                host_sig = f"{tool_name}@{host_key}"
                self._native_tool_history[host_sig] = self._native_tool_history.get(host_sig, 0) + 1

        tool_msg = self._format_tool_result(tool_name, result)
        self.messages.append(tool_msg)
        if tool_name == "execute":
            _hint = self._recovery_hint(arguments.get("command", ""), result)
            if _hint:
                self.messages.append({"role": "system", "content": f"[DICA DE CORREÇÃO] {_hint}"})

        tool_out = result.get("output") or result.get("stdout") or result.get("error") or "Sucesso"
        yield {
            "type": "tool_result",
            "tool": tool_name,
            "result": result,
            "output": tool_out,
            "content": json.dumps(tool_out, default=str) if isinstance(tool_out, (dict, list)) else str(tool_out),
            "iteration": self.iteration,
        }

        if tool_name == "create_finding" and result.get("success"):
            self.findings_count += 1
            output = result.get("output", {})
            if output.get("status") != "duplicate":
                yield {"type": "finding", "finding": output}

        # Auto-ingest findings from native audit tools
        auto_findings = await self._auto_ingest_native_findings(tool_name, arguments, result)
        for af in auto_findings:
            yield {"type": "finding", "finding": af}

        # Continue the agentic loop to process tool output
        async for event in self._run_loop():
            yield event

    def cancel_pending(self) -> str | None:
        """Cancel any pending tool action and inform the conversation history."""
        if not self.pending_action:
            return None
        cancelled_tool = self.pending_action["tool"]
        self.pending_action = None
        self.messages.append({
            "role": "user",
            "content": f"[RECUSA DO OPERADOR] O operador cancelou a execução sugerida da ferramenta: {cancelled_tool}."
        })
        return cancelled_tool

    def _record_cmd_result(self, command: str, result: dict) -> None:
        """Record the outcome of an executed shell command for the stagnation /
        feedback guard: success is exit_code == 0; keep a short result summary."""
        sig = (command or "").strip()
        if not sig:
            return
        out = result.get("output") if isinstance(result, dict) else None
        exit_code = None
        stdout = stderr = ""
        if isinstance(out, dict):
            exit_code = out.get("exit_code")
            stdout = out.get("stdout") or ""
            stderr = out.get("stderr") or ""
        ok = (exit_code == 0) and bool(result.get("success", True))
        # Concise summary: prefer a meaningful stdout line, else the error.
        summary = ""
        clean = self._clean_scan_text(stdout) if stdout else ""
        if clean:
            lines = [l for l in clean.splitlines() if l.strip() and not l.startswith("...[")]
            summary = (lines[-1] if lines else "")[:200]
        if not summary:
            summary = (self._clean_scan_text(stderr)[:200] if stderr else "") or (f"exit_code={exit_code}")
        h = self._cmd_history.setdefault(sig, {"runs": 0, "ok": 0, "fail": 0, "summary": ""})
        h["runs"] += 1
        h["ok" if ok else "fail"] += 1
        h["summary"] = summary

    @staticmethod
    def _recovery_hint(command: str, result: dict) -> str | None:
        """Map a failed command's error to a concrete corrective hint, so the
        (small) model self-corrects instead of blindly repeating."""
        out = result.get("output") if isinstance(result, dict) else None
        err = ""
        if isinstance(out, dict):
            if out.get("exit_code", 0) == 0:
                return None
            err = ((out.get("stderr") or "") + " " + (out.get("stdout") or "")).lower()
        elif isinstance(result, dict) and result.get("error"):
            err = str(result.get("error")).lower()
        if not err:
            return None
        binary = (command or "").split()[0] if command else "a ferramenta"
        if binary == "katana" or "katana" in (command or "").lower():
            if any(n in err for n in ("timed out", "timeout", "i/o timeout", "killed", "terminated")):
                return (
                    "O crawler (Katana) esgotou o tempo limite navegando no alvo. "
                    "NÃO repita o crawler e NÃO aumente o timeout em sites de conteúdo ou portais de notícias. "
                    "Mude a abordagem para auditoria direcionada: detecte a stack com 'httpx-toolkit -u https://<alvo> -tech-detect', "
                    "ou use 'wpscan --url https://<alvo> --enumerate vp,u' ou 'ffuf' focado no core do CMS."
                )
            return (
                "Katana encontrou dificuldades no alvo. Em vez de varredura recursiva aberta, "
                "priorize ferramentas cirúrgicas para a tecnologia identificada (httpx-toolkit, ffuf, wpscan ou nuclei)."
            )
        rules = [
            (("command not found", "not found", "executable file not found"),
             f"'{binary}' não está instalado no sandbox. Use uma ferramenta equivalente ou pule este passo."),
            (("no such option", "unknown flag", "unknown shorthand", "usage:"),
             f"Sintaxe inválida para '{binary}'. Revise as flags (httpx-toolkit usa -u; nmap usa -sT; nuclei usa -u)."),
            (("operation not permitted", "raw socket", "dnet:"),
             "Sem privilégio no sandbox: use nmap -sT (TCP connect), não -sS/SYN."),
            (("no such file or directory",),
             "Caminho inexistente. Wordlists ficam em /opt/seclists; grave saídas em /workspace/output."),
            (("timed out", "timeout", "i/o timeout"),
             "O alvo respondeu devagar/limitou. Reduza o escopo (menos portas/templates) ou use -rl."),
            (("could not resolve", "name or service not known", "no such host"),
             "Falha de DNS no alvo. Confirme o host ou tente pelo IP."),
        ]
        for needles, hint in rules:
            if any(n in err for n in needles):
                return hint
        return None

    # -- Continuous-learning loop (deterministic playbook KB) ----------------

    _TECH_TOKENS = (
        "nginx", "apache", "iis", "express", "node", "nodejs", "php", "wordpress",
        "joomla", "drupal", "tomcat", "spring", "springboot", "django", "flask",
        "laravel", "react", "angular", "vue", "graphql", "jenkins", "gitlab",
        "grafana", "kibana", "elastic", "mysql", "postgres", "mongodb", "redis",
        "docker", "kubernetes", "jira", "confluence", "cloudflare", "iis",
    )

    def _detect_tech_keywords(self) -> str:
        """Pull technology keywords from the living memory so we can look up
        proven techniques for what was actually detected on the target."""
        te = getattr(self, "tool_executor", None)
        found: list[str] = []
        try:
            if te and hasattr(te, "_get_wiki_path"):
                for section in ("attack_surface", "target_map"):
                    f = te._get_wiki_path(section)
                    if f.exists():
                        text = f.read_text(encoding="utf-8", errors="replace").lower()
                        for tok in self._TECH_TOKENS:
                            if tok in text and tok not in found:
                                found.append(tok)
        except Exception:
            pass

        # Also inspect recent conversation messages (tool outputs, user intents).
        # Skip the system message: it contains the methodology (which mentions
        # "wordpress"/"plugins") and, early in a run, sits within the last 6
        # messages — scanning it produced a false WordPress match on EVERY session.
        try:
            for msg in getattr(self, "messages", [])[-6:]:
                if msg.get("role") == "system":
                    continue
                content = str(msg.get("content") or "").lower()
                for tok in self._TECH_TOKENS:
                    if tok in content and tok not in found:
                        found.append(tok)
                # Infer WordPress from CMS indicators or an explicit operator
                # request about plugins. The false positives came from scanning
                # the system message above (now skipped), not from these terms.
                if any(ind in content for ind in ("wp-content", "wp-includes", "wp-json", "/wp-admin", "plugins", "wordpress")):
                    if "wordpress" not in found:
                        found.append("wordpress")
        except Exception:
            pass

        return " ".join(found[:5])

    def _get_tactical_technology_guidance(self) -> dict | None:
        """Derive targeted, technology-aware directives to steer the LLM away from
        unconstrained spiders/scanners and toward the right tools for the stack."""
        s = getattr(self, "session", {}) or {}
        raw_target = s.get("target", "") if isinstance(s, dict) else getattr(s, "target", "")
        raw_target = (raw_target or "o alvo").strip()
        domain = re.sub(r'^https?://', '', raw_target).split('/')[0].split(':')[0]
        url = f"https://{domain}" if not domain.startswith("http") else domain

        kw = self._detect_tech_keywords()
        kw_set = set(kw.split())

        # 1. WordPress / CMS plugins requested or detected
        if "wordpress" in kw_set:
            return {
                "signature": f"wordpress_{self.current_phase}",
                "summary": "CMS WordPress detectado — priorizando wpscan e endpoints da REST API.",
                "directive": (
                    f"[DIRETIVA TÁTICA ATIVA — CMS WORDPRESS DETECTADO]\n"
                    f"O alvo ({domain}) opera sobre WordPress (ou o operador solicitou busca por plugins/credenciais):\n"
                    f"1. REGRA MANDATÓRIA: NUNCA execute crawlers abertos (katana) em páginas de artigos/notícias. "
                    f"Portais de conteúdo possuem milhares de links que esgotam tempo e recursos sem ganho técnico.\n"
                    f"2. Enumere plugins, temas e usuários vulneráveis: "
                    f"execute com 'wpscan --url {url} --enumerate vp,u --no-banner'\n"
                    f"3. Inspecione a API REST oficial para listar usuários reais: "
                    f"execute com 'curl -s {url}/wp-json/wp/v2/users'\n"
                    f"4. Fuzzing de endpoints específicos do WordPress com SecLists: "
                    f"execute com 'ffuf -u {url}/FUZZ -w /opt/seclists/Discovery/Web-Content/CMS/wordpress.txt -mc 200,301,302,401,403'\n"
                    f"5. Teste se rotas de autenticação ou RPC estão expostas: /wp-login.php e /xmlrpc.php."
                ),
            }

        # 2. Joomla
        if "joomla" in kw_set:
            return {
                "signature": f"joomla_{self.current_phase}",
                "summary": "CMS Joomla detectado — priorizando componentes e rotas administrativas.",
                "directive": (
                    f"[DIRETIVA TÁTICA ATIVA — CMS JOOMLA DETECTADO]\n"
                    f"1. NÃO use crawlers genéricos em portais com grande volume de páginas.\n"
                    f"2. Fuzzing focado em componentes Joomla: "
                    f"execute com 'ffuf -u {url}/FUZZ -w /opt/seclists/Discovery/Web-Content/CMS/joomla.txt -mc 200,301,302,401,403'\n"
                    f"3. Inspecione rotas administrativas: /administrator e /api/index.php/v1."
                ),
            }

        # 3. Drupal
        if "drupal" in kw_set:
            return {
                "signature": f"drupal_{self.current_phase}",
                "summary": "CMS Drupal detectado — priorizando verificação de módulos e CHANGELOG.",
                "directive": (
                    f"[DIRETIVA TÁTICA ATIVA — CMS DRUPAL DETECTADO]\n"
                    f"1. Inspecione versões e arquivos expostos: {url}/core/CHANGELOG.txt ou /user/login\n"
                    f"2. Varredura com templates dedicados: execute com 'nuclei -u {url} -tags drupal -rl 50'"
                ),
            }

        # 4. Cloudflare / CDN
        if "cloudflare" in kw_set and self.current_phase in ("recon", "analysis"):
            return {
                "signature": f"cloudflare_{self.current_phase}",
                "summary": "Proxy Cloudflare detectado — priorizando subdomínios mapeados.",
                "directive": (
                    f"[DIRETIVA TÁTICA ATIVA — PROXY CLOUDFLARE DETECTADO]\n"
                    f"O domínio principal ({domain}) está sob proxy/WAF Cloudflare.\n"
                    f"1. Portas abertas na CDN refletem os nós de borda, não necessariamente o servidor de origem.\n"
                    f"2. Priorize analisar subdomínios descobertos no reconhecimento passivo (ex: painel, staging, dev, mail, api) "
                    f"que possam expor painéis desprotegidos ou o IP de origem.\n"
                    f"3. Utilize taxa moderada de requisições (-rl 50) para evitar mitigação automática."
                ),
            }

        # 5. Analysis phase with unclassified web app
        if self.current_phase == "analysis":
            return {
                "signature": f"web_probe_{self.current_phase}",
                "summary": "Aplicação web não catalogada — priorizando sonda com httpx-toolkit e audit_security_headers.",
                "directive": (
                    f"[DIRETIVA TÁTICA ATIVA — DETECÇÃO DE STACK WEB OBRIGATÓRIA]\n"
                    f"Antes de executar scanners pesados ou crawlers no alvo ({domain}):\n"
                    f"1. Identifique a tecnologia e servidor exatos: "
                    f"execute com 'httpx-toolkit -u {url} -tech-detect -status-code -title'\n"
                    f"2. Audite a postura defensiva e cabeçalhos de proteção: chame audit_security_headers(url='{url}')\n"
                    f"3. Inspecione os cabeçalhos de resposta: execute com 'curl -sI {url}'\n"
                    f"4. Se o site for um portal de conteúdo/notícias, NÃO execute katana sem filtro; "
                    f"utilize ffuf com wordlist específica ou sonde a API REST."
                ),
            }

        return None

    async def _auto_ingest_native_findings(self, tool_name: str, arguments: dict, result: dict) -> list[dict]:
        """Automatically create verified findings in DB and memory when native tools discover vulnerabilities.

        This prevents 0-finding false negatives and hallucinated clean summaries caused by small local models
        not knowing to call create_finding manually.
        """
        if not isinstance(result, dict) or not hasattr(self, "tool_executor"):
            return []

        # ToolExecutor.execute_tool wraps every handler result as
        # {"success", "output", "error"}; the tool's actual data
        # (findings/missing_headers/exposed_secrets/...) lives under "output".
        # Without this unwrap, every .get() below reads the wrapper and finds
        # nothing — so NO findings were ever auto-created from native tools.
        if isinstance(result.get("output"), dict):
            result = result["output"]

        # Never ingest simulated/mock results as real findings. The headless
        # browser agent falls back to a simulated audit when Playwright is absent
        # and fabricates findings flagged simulated — those must not be persisted
        # as verified vulnerabilities.
        if result.get("simulated") is True or result.get("mode") == "simulated":
            return []

        host_key = (
            arguments.get("url") or arguments.get("host") or arguments.get("domain") or
            arguments.get("target") or (self.session.get("target") if isinstance(self.session, dict) else getattr(self.session, "target", ""))
        )
        target_str = str(host_key or "unknown")

        candidates = []

        # 1. Standard "findings" list in native tools
        raw_findings = result.get("findings")
        if isinstance(raw_findings, list):
            for f in raw_findings:
                if isinstance(f, dict):
                    # Skip findings explicitly flagged as simulated/mock.
                    if f.get("simulated") is True or (isinstance(f.get("evidence"), dict) and f["evidence"].get("simulated") is True):
                        continue
                    sev = str(f.get("severity", "medium")).lower()
                    if sev in ("critical", "high", "medium"):
                        title = f.get("issue") or f.get("title") or f.get("record") or f"{tool_name} finding"
                        candidates.append({
                            "title": f"[{tool_name}] {title}",
                            "type": tool_name,
                            "severity": sev,
                            "remediation": f.get("recommendation") or f.get("remediation") or "Aplicar configuração defensiva recomendada.",
                            "evidence": {"raw": f, "target": target_str},
                            "impact": f.get("impact", ""),
                        })

        # 2. "missing_headers" in audit_security_headers
        missing = result.get("missing_headers")
        if isinstance(missing, list):
            for h in missing:
                if isinstance(h, dict):
                    sev = str(h.get("severity", "medium")).lower()
                    if sev in ("critical", "high", "medium"):
                        header_name = h.get("header", "Header")
                        candidates.append({
                            "title": f"Cabeçalho de Segurança Ausente: {header_name}",
                            "type": "missing_security_header",
                            "severity": sev,
                            "remediation": h.get("remediation") or f"Configure o cabeçalho {header_name} nas respostas do servidor web.",
                            "evidence": {"header": header_name, "description": h.get("description", ""), "target": target_str},
                            "impact": h.get("description", ""),
                        })

        # 3. "exposed_secrets" in scan_exposed_secrets
        secrets = result.get("exposed_secrets")
        if isinstance(secrets, list):
            for s in secrets:
                if isinstance(s, dict):
                    candidates.append({
                        "title": f"Chave/Segredo Exposto no Código: {s.get('type', 'Credencial')}",
                        "type": "exposed_secret",
                        "severity": str(s.get("severity", "critical")).lower(),
                        "remediation": s.get("remediation") or "Revogue imediatamente a credencial e configure variáveis de ambiente seguras.",
                        "evidence": {"secret_type": s.get("type"), "evidence": s.get("evidence", ""), "target": target_str},
                        "impact": "Exposição pública de credenciais administrativas ou de API.",
                    })

        # 4. "exposed_files" in audit_git_and_env_leakage
        files = result.get("exposed_files")
        if isinstance(files, list):
            for ef in files:
                if isinstance(ef, dict):
                    path = ef.get("path") or ef.get("url") or "Arquivo Sensível"
                    candidates.append({
                        "title": f"Exposição de Arquivo Sensível: {path}",
                        "type": "information_disclosure",
                        "severity": str(ef.get("severity", "high")).lower(),
                        "remediation": "Bloqueie o acesso público a diretórios .git, .env e arquivos de backup no servidor web.",
                        "evidence": {"file": path, "target": target_str},
                        "impact": "Acesso não autorizado a código-fonte, configurações internas ou credenciais.",
                    })

        # 5. "vulnerabilities" in other tools
        vulns = result.get("vulnerabilities")
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    candidates.append({
                        "title": v.get("title") or v.get("name") or f"Vulnerabilidade identificada via {tool_name}",
                        "type": v.get("type", tool_name),
                        "severity": str(v.get("severity", "high")).lower(),
                        "remediation": v.get("remediation", "Atualizar componentes e aplicar patches de segurança."),
                        "evidence": {"vuln_details": v, "target": target_str},
                        "impact": v.get("impact", ""),
                    })

        severity_scores = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}
        created_findings = []

        for cand in candidates:
            sev = cand["severity"]
            score = severity_scores.get(sev, 5.0)
            try:
                res = await self.tool_executor._handle_create_finding(
                    title=cand["title"],
                    type=cand["type"],
                    severity=sev,
                    cvss_score=score,
                    affected={"target": target_str, "tool": tool_name},
                    evidence=cand["evidence"],
                    poc={"description": f"Detectado deterministicamente pela ferramenta de auditoria '{tool_name}'."},
                    remediation=cand["remediation"],
                )
                if res and res.get("status") != "duplicate":
                    created_findings.append(res)
                    self.findings_count += 1
            except Exception:
                pass

        return created_findings

    async def _consult_playbooks(self) -> dict | None:
        """Before acting in a new phase, inject proven techniques from the KB for
        the detected tech. This is the 'recall' half of continuous learning: it
        does not rely on the (weak) model remembering to call query_playbook."""
        if self.current_phase in self._consulted_phases:
            return None
        self._consulted_phases.add(self.current_phase)
        pm = getattr(self.tool_executor, "playbook_mgr", None)
        if not pm:
            return None
        kw = self._detect_tech_keywords()
        if not kw:
            return None

        lines, mode = [], "keyword"
        # 1) Semantic recall (RAG) — retrieves by meaning, not exact keyword.
        si = getattr(self.tool_executor, "semantic_index", None)
        if si:
            try:
                hits = await si.search("playbooks", kw, top_k=3)
            except Exception:
                hits = None
            if hits:
                mode = "semantic"
                lines = [f"- {h['text']}" for h in hits]

        # 2) Keyword (FTS) fallback — per term, merged (multi-word MATCH ANDs).
        if not lines:
            results, seen = [], set()
            for term in kw.split():
                try:
                    found = await pm.search(term, limit=2)
                except Exception:
                    continue
                for r in found:
                    rid = r.get("id") or r.get("title")
                    if rid not in seen:
                        seen.add(rid)
                        results.append(r)
                if len(results) >= 3:
                    break
            for r in results[:3]:
                steps = (r.get("steps") or r.get("commands") or "").replace("\n", " ")[:160]
                lines.append(f"- {r.get('title', '')} ({r.get('category', '')}): {steps}")

        if not lines:
            return None
        hint = ("[MEMÓRIA DE LONGO PRAZO — técnicas já comprovadas para a tecnologia "
                f"detectada ({kw}); reutilize se aplicável]\n" + "\n".join(lines))
        self.messages.append({"role": "system", "content": hint})
        return {"keywords": kw, "count": len(lines), "hint": hint, "mode": mode}

    _LEARNABLE = {
        "nmap", "subfinder", "dnsx", "httpx-toolkit", "httpx", "katana", "nuclei",
        "ffuf", "feroxbuster", "gobuster", "sqlmap", "dalfox", "wpscan", "arjun", "whatweb",
    }

    async def _auto_learn(self, command: str, result: dict, phase: str) -> None:
        """The 'store' half of continuous learning: when a command succeeds,
        persist a generalized version to the KB so future operations reuse it.
        Driven by the harness, not by the model calling save_playbook."""
        pm = getattr(self.tool_executor, "playbook_mgr", None)
        if not pm or not command:
            return
        out = result.get("output") if isinstance(result, dict) else None
        if not isinstance(out, dict) or out.get("exit_code") != 0:
            return  # learn only from successes
        parts = command.split()
        if not parts:
            return
        binary = parts[0].lower()
        if binary not in self._LEARNABLE:
            return
        target = self.session.get("target") if isinstance(self.session, dict) else getattr(self.session, "target", None)
        generalized = command.replace(target, "TARGET") if target else command
        tech = binary.replace("-toolkit", "")
        try:
            saved = await pm.save(
                technology=tech,
                technique=f"{tech}_{phase}_proven",
                commands=generalized,
                notes=f"Auto-aprendido pelo harness: comando bem-sucedido na fase '{phase}'.",
            )
            self._learned_count += 1
            # Also index it semantically so it's recallable by meaning at once.
            si = getattr(self.tool_executor, "semantic_index", None)
            if si and isinstance(saved, dict) and saved.get("id"):
                try:
                    from ..core.vectordb import playbook_embed_text
                    await si.index_items("playbooks", [(saved["id"], playbook_embed_text(saved))])
                except Exception:
                    pass
        except Exception:
            pass

    # -- Knowledge graph (recall + synthesis) --------------------------------

    async def _graph_summary_text(self) -> str:
        gm = getattr(self.tool_executor, "graph_mgr", None)
        if not gm or not self.session_id_for_graph:
            return ""
        try:
            return await gm.summary(self.session_id_for_graph)
        except Exception:
            return ""

    @property
    def session_id_for_graph(self):
        te = getattr(self, "tool_executor", None)
        return getattr(te, "session_id", None) if te else None

    async def _synthesize_from_graph(self) -> dict | None:
        """When entering analysis/report, surface graph-derived candidate
        findings (exposed sensitive services) so the agent consolidates results
        into findings instead of only scanning. Runs once per phase."""
        if self.current_phase in self._synthesized_phases:
            return None
        self._synthesized_phases.add(self.current_phase)
        gm = getattr(self.tool_executor, "graph_mgr", None)
        if not gm or not self.session_id_for_graph:
            return None
        try:
            cands = await gm.candidate_findings(self.session_id_for_graph)
            paths = await gm.attack_paths(self.session_id_for_graph)
        except Exception:
            return None
        if not cands and not paths:
            return None
        blocks = []
        if paths:
            blocks.append("[CAMINHOS DE ATAQUE — priorizados pelo grafo; persiga os de maior severidade]\n"
                          + "\n".join(f"- [{p['severity'].upper()}] {p['chain']}" for p in paths[:6]))
        if cands:
            blocks.append("[ACHADOS CANDIDATOS — para cada um CONFIRMADO, registre com create_finding "
                          "(evidência/PoC); descarte os não aplicáveis]\n"
                          + "\n".join(f"- [{c['severity'].upper()}] {c['title']}" for c in cands))
        self.messages.append({"role": "system", "content": "\n\n".join(blocks)})
        return {"count": len(cands), "candidates": cands, "paths": len(paths)}

    async def _generate_report(self) -> dict | None:
        """Auto-generate the assessment report (HTML/MD/JSON) from the session's
        findings when the operation concludes — so an operation always ends with
        a report artifact, without relying on the model to trigger it. Runs once."""
        if self._report_generated:
            return None
        self._report_generated = True
        te = getattr(self, "tool_executor", None)
        db = getattr(te, "db", None)
        if not db:
            return None
        s = self.session
        sid = s.get("id") if isinstance(s, dict) else getattr(s, "id", None)
        name = (s.get("name") if isinstance(s, dict) else getattr(s, "name", None)) or "operation"
        target = (s.get("target") if isinstance(s, dict) else getattr(s, "target", None)) or "unknown"
        try:
            rows = await db.fetch_all(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at DESC", (sid,))
        except Exception:
            return None
        parsed = []
        for r in rows:
            fd = dict(r)
            for col in ("affected", "evidence", "poc", "cwe_ids"):
                if isinstance(fd.get(col), str) and fd[col].strip():
                    try:
                        fd[col] = json.loads(fd[col])
                    except Exception:
                        pass
            parsed.append(fd)
        try:
            from ..core.reports import ReportEngine, ReportConfig
            from ..core.config import get_config
            out_dir = get_config().ops_dir / name / "reports"
            cfg = ReportConfig(title=f"Security Assessment - {target}")
            results = await ReportEngine().export(
                session=s if isinstance(s, dict) else {"name": name, "target": target, "mode": self.mode},
                findings=parsed, output_dir=out_dir, formats=["html", "md", "json"], config=cfg)
            return {"findings": len(parsed), "reports": {k: str(v) for k, v in results.items()}}
        except Exception as e:
            return {"error": str(e)}

    # -- Extended Thinking ---------------------------------------------------

    def _extract_thinking(self, content: str) -> tuple[str | None, str]:
        """Extract <think>...</think> blocks from LLM output."""
        match = re.search(r'<think>(.*?)</think>', content, re.DOTALL)
        if match:
            thinking = match.group(1).strip()
            clean = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
            return thinking, clean
        return None, content

    @staticmethod
    def _normalize_tool_call_dict(data: dict, default_target: str = "") -> dict | None:
        """Normalize various LLM tool call schemas (e.g. OpenAI, Anthropic, Qwen, Ollama, plain JSON)."""
        if not isinstance(data, dict):
            return None

        name = data.get("name") or data.get("function", {}).get("name") or data.get("tool") or data.get("action") or data.get("tool_name") or data.get("call")
        args = (
            data.get("arguments")
            or data.get("function", {}).get("arguments")
            or data.get("params")
            or data.get("parameters")
            or data.get("action_input")
            or data.get("tool_input")
            or data.get("tool_arguments")
            or data.get("args")
            or {}
        )

        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {"command": args}

        if not isinstance(args, dict):
            args = {"command": str(args)}

        if "command" not in args:
            for k in ("cmd", "exec", "script", "line"):
                if k in args:
                    args["command"] = args.pop(k)
                    break

        exec_aliases = {
            "execute", "run", "run_command", "bash", "sh", "terminal", "cmd", "shell",
            "exec", "command", "run_shell", "execute_command", "system", "terminal_command"
        }

        known_binaries = {
            "nmap", "subfinder", "dnsx", "httpx", "nuclei", "ffuf", "feroxbuster",
            "gobuster", "katana", "sqlmap", "curl", "wget", "whois", "dig", "host",
            "dalfox", "arjun", "wpscan", "nikto", "hydra"
        }

        TOOL_ALIASES = {
            "audit_waf_normalization_bypasses": "audit_waf_bypass_heuristics",
            "audit_waf_normalization": "audit_waf_bypass_heuristics",
            "audit_waf_bypass": "audit_waf_bypass_heuristics",
            "audit_waf": "detect_waf_firewall",
            "waf_detection": "detect_waf_firewall",
            "audit_s3_bucket": "audit_s3_bucket_permissions_deep",
            "audit_s3_permissions": "audit_s3_bucket_permissions_deep",
            "audit_s3": "audit_s3_bucket_permissions_deep",
            "audit_cloud_buckets": "audit_cloud_storage",
            "audit_ssrf": "audit_ssrf_cloud_metadata",
            "audit_imds": "audit_ssrf_cloud_metadata",
            "audit_k8s_rbac": "audit_kubernetes_rbac",
            "audit_k8s": "audit_kubernetes_rbac",
            "audit_docker": "audit_dockerfile_security",
            "audit_cicd": "audit_cicd_pipeline_security",
            "audit_llm": "audit_llm_prompt_injection_and_jailbreaks",
            "audit_jailbreak": "audit_llm_prompt_injection_and_jailbreaks",
            "audit_vector_db": "audit_vector_database_exposure",
            "audit_yara": "generate_yara_rule",
            "audit_sigma": "generate_detection_rules",
            "audit_ir_playbook": "generate_ir_playbook",
            "audit_atomic_test": "generate_atomic_test",
        }

        TOOL_DEFAULT_PARAM = {
            "url": ["audit_waf_bypass_heuristics", "detect_waf_firewall", "audit_security_headers", "audit_cors_advanced",
                    "audit_rate_limiting", "audit_git_and_env_leakage", "audit_ssrf_cloud_metadata", "audit_well_known_security",
                    "audit_http_methods"],
            "host": ["audit_tls_ssl", "analyze_forensic_artifacts", "audit_binary_protections"],
            "domain": ["audit_dns_email_security", "search_cert_transparency", "audit_subdomain_takeover", "query_whois_rdap",
                       "audit_mta_sts_dane", "audit_dkim_bimi", "audit_ad_dacl_abuse_paths", "audit_kerberoasting_surface"],
            "target": ["query_threat_feeds", "audit_dnsbl_reputation", "enrich_ip_intel", "scan_exposed_secrets",
                       "audit_cloud_storage", "audit_compliance_matrix", "generate_atomic_test", "evaluate_defensive_efficacy",
                       "map_mitre_attack"],
            "bucket_name": ["audit_s3_bucket_permissions_deep"],
            "repo_or_url": ["audit_cicd_pipeline_security"],
            "package_name": ["audit_dependency_confusion_and_namespaces"],
            "manifest_content": ["audit_sbom_dependencies"],
            "endpoint_url": ["audit_llm_prompt_injection_and_jailbreaks"],
            "target_url": ["audit_vector_database_exposure", "audit_api_spec"],
            "base_url": ["audit_api_idor_matrix", "audit_reverse_proxy_path_traversal"],
            "dockerfile_content": ["audit_dockerfile_security"],
            "manifest_yaml": ["audit_kubernetes_rbac"],
            "target_host": ["audit_container_breakout_vectors"],
            "domain_or_tenant": ["audit_identity_access_hygiene"],
            "file_or_process_path": ["audit_binary_protections"],
        }

        if name:
            name_str = str(name).strip().lower()
            if name_str in TOOL_ALIASES:
                name_str = TOOL_ALIASES[name_str]

            if name_str in exec_aliases:
                if "command" in args and isinstance(args["command"], str):
                    args["command"] = _auto_repair_command(args["command"])
                return {"type": "function", "function": {"name": "execute", "arguments": args}}

            if name_str in known_binaries:
                cmd_part = args.get("command") or args.get("target") or args.get("domain") or args.get("url") or default_target or ""
                full_cmd = _auto_repair_command(f"{name_str} {cmd_part}".strip())
                return {"type": "function", "function": {"name": "execute", "arguments": {"command": full_cmd}}}

            valid_native = {
                "read_memory", "update_memory", "query_playbook", "save_playbook",
                "search_cve", "create_finding", "stash_artifact", "read_file",
                "create_file", "browser_action", "web_search",
                "audit_security_headers", "audit_dns_email_security", "scan_exposed_secrets",
                "audit_tls_ssl", "audit_api_spec", "query_whois_rdap", "enrich_ip_intel",
                "search_historical_urls", "search_cert_transparency", "enrich_cve_threat",
                "audit_well_known_security", "audit_cloud_storage",
                "audit_subdomain_takeover", "detect_waf_firewall", "audit_cors_advanced",
                "audit_http_methods",
                "map_mitre_attack", "generate_detection_rules", "audit_jwt_security",
                "audit_rate_limiting", "audit_websocket_security", "audit_supply_chain_libs",
                "audit_compliance_matrix",
                "generate_atomic_test", "simulate_attack_path", "audit_graphql_security",
                "audit_oauth_sso", "generate_ir_playbook", "audit_dnsbl_reputation",
                "generate_canary_tokens",
                "audit_ssrf_cloud_metadata", "calculate_cvss_vector", "audit_api_idor_matrix",
                "audit_prototype_pollution", "generate_hardening_baseline", "audit_dkim_bimi",
                "query_threat_feeds",
                "audit_waf_bypass_heuristics", "audit_sbom_dependencies", "audit_saml_xml_security",
                "generate_yara_rule", "audit_dockerfile_security", "audit_kubernetes_rbac",
                "calculate_breach_risk_cost",
                "audit_iac_misconfigurations", "audit_cicd_pipeline_security",
                "audit_web_cache_poisoning", "audit_api_mass_assignment",
                "audit_mta_sts_dane", "audit_identity_access_hygiene",
                "analyze_forensic_artifacts", "audit_binary_protections",
                "audit_http_request_smuggling", "audit_ssti_injection",
                "audit_nosql_injection", "generate_subdomain_permutations",
                "audit_ntlm_relay_coercion", "simulate_cloud_iam_privesc",
                "audit_race_conditions_concurrency", "audit_dom_clobbering",
                "audit_xxe_injection", "audit_open_redirect_bypasses",
                "audit_ldap_injection", "audit_grpc_api_security",
                "audit_insecure_deserialization", "audit_crlf_header_injection",
                "audit_reverse_proxy_path_traversal", "audit_s3_bucket_permissions_deep",
                "audit_git_and_env_leakage", "audit_content_security_policy_deep",
                "audit_api_excessive_data_exposure", "audit_dns_zone_transfer_and_nsec",
                "audit_smtp_open_relay_and_spoofing",
                "audit_server_side_prototype_pollution", "audit_ip_spoofing_access_controls",
                "audit_kerberos_delegation_risks", "audit_http3_quic_exposure",
                "audit_snmp_community_exposure",
                "audit_adcs_certificate_templates", "audit_smb_signing_and_null_sessions",
                "audit_postmessage_messaging_security", "audit_http_parameter_pollution",
                "audit_container_breakout_vectors",
                "audit_clickjacking_and_ui_redressing", "audit_bfla_api_authorization",
                "audit_kerberoasting_surface", "audit_linux_privesc_vectors",
                "audit_llm_prompt_injection_and_jailbreaks", "audit_vector_database_exposure",
                "audit_subresource_integrity_sri", "audit_dependency_confusion_and_namespaces",
                "audit_webhook_ssrf_and_dns_rebinding",
                "audit_ad_dacl_abuse_paths", "audit_windows_token_privileges",
                "audit_cicd_workflow_poisoning", "audit_mtls_and_mesh_security",
                "audit_ebpf_integrity_and_rootkits",
            }
            if name_str in valid_native:
                # If the arguments dict only has "command" because the model provided a scalar string:
                if isinstance(args, dict) and "command" in args and len(args) == 1:
                    scalar_val = args.pop("command")
                    mapped = False
                    for param_name, tool_list in TOOL_DEFAULT_PARAM.items():
                        if name_str in tool_list:
                            args[param_name] = scalar_val
                            mapped = True
                            break
                    if not mapped:
                        args["target"] = scalar_val

                if default_target and isinstance(args, dict):
                    target_clean = re.sub(r'^https?://', '', default_target).split('/')[0].split(':')[0]
                    target_url = default_target if default_target.startswith(('http://', 'https://')) else f"https://{default_target}"
                    for param_name, tool_list in TOOL_DEFAULT_PARAM.items():
                        if name_str in tool_list and param_name not in args:
                            if "url" in param_name:
                                args[param_name] = target_url
                            elif param_name in ("host", "domain"):
                                args[param_name] = target_clean
                            else:
                                args[param_name] = default_target
                return {"type": "function", "function": {"name": name_str, "arguments": args}}

        # Fallback: if data or args has a non-empty "command", map to execute
        if "command" in args and isinstance(args["command"], str) and args["command"].strip():
            args["command"] = _auto_repair_command(args["command"])
            return {"type": "function", "function": {"name": "execute", "arguments": args}}
        if "command" in data and isinstance(data["command"], str) and data["command"].strip():
            cmd = _auto_repair_command(data["command"].strip())
            return {"type": "function", "function": {"name": "execute", "arguments": {"command": cmd}}}

        return None

    @classmethod
    def _extract_tool_calls_from_text(cls, content: str, default_target: str = "") -> list[dict]:
        """Fallback extractor when local models return tool call JSON, python syntax, or bare tool names directly in text content."""
        if not content:
            return []
        text = content.strip()

        # 1. Whole text is valid JSON object
        try:
            data = json.loads(text)
            norm = cls._normalize_tool_call_dict(data, default_target=default_target)
            if norm:
                return [norm]
        except Exception:
            pass

        # 2. Markdown ```json ... ``` blocks
        calls = []
        for match in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
            try:
                data = json.loads(match.group(1))
                norm = cls._normalize_tool_call_dict(data, default_target=default_target)
                if norm:
                    calls.append(norm)
            except Exception:
                pass
        if calls:
            return calls

        # 3. <tool_call>...</tool_call> tags
        tc_matches = re.findall(r"<tool_call>(.*?)</tool_call>", text, re.DOTALL)
        for m in tc_matches:
            try:
                data = json.loads(m.strip())
                norm = cls._normalize_tool_call_dict(data, default_target=default_target)
                if norm:
                    calls.append(norm)
            except Exception:
                pass
        if calls:
            return calls

        # 4. Scan for inline JSON objects with JSONDecoder. Collect ALL of them:
        #    weak local models often emit several newline-delimited tool calls
        #    at once (observed with qwen2.5-coder). Returning only the first
        #    silently dropped the rest.
        decoder = json.JSONDecoder()
        pos = 0
        while pos < len(text):
            idx = text.find("{", pos)
            if idx == -1:
                break
            try:
                data, end_idx = decoder.raw_decode(text[idx:])
                pos = idx + end_idx
                norm = cls._normalize_tool_call_dict(data, default_target=default_target)
                if norm:
                    calls.append(norm)
            except Exception:
                pos = idx + 1
        if calls:
            return calls

        # 5. Function call syntax: tool_name(param='val') or tool_name("target")
        fn_matches = re.finditer(r'([a-zA-Z0-9_]{3,})\s*\((.*?)\)', text)
        for m in fn_matches:
            raw_name = m.group(1).lower()
            args_str = m.group(2).strip()
            args = {}
            if '=' in args_str:
                for kv in re.finditer(r'([a-zA-Z0-9_]+)\s*=\s*[\'"]([^\'"]*)[\'"]', args_str):
                    args[kv.group(1)] = kv.group(2)
            elif args_str:
                clean_val = args_str.strip('\'"')
                if clean_val:
                    args['target'] = clean_val
            norm = cls._normalize_tool_call_dict({"name": raw_name, "arguments": args}, default_target=default_target)
            if norm:
                calls.append(norm)
        if calls:
            return calls

        # 6. Standalone or prefixed tool name on a line (e.g. "audit_waf_normalization_bypasses" or "[AÇÃO] audit_security_headers")
        for line in [l.strip() for l in text.splitlines() if l.strip()]:
            tokens = re.findall(r'[a-zA-Z0-9_]{3,}', line)
            for tok in tokens:
                raw_tok = tok.lower()
                norm = cls._normalize_tool_call_dict({"name": raw_tok, "arguments": {}}, default_target=default_target)
                if norm and norm.get("function", {}).get("name") not in ("execute", "read_memory", "update_memory"):
                    calls.append(norm)
                    return calls

        return calls

    @staticmethod
    def _humanize_final_text(text: str) -> str:
        """If ``text`` is a JSON object (a side effect of format=json), return a
        human-readable field instead of raw JSON; otherwise return it as-is."""
        if not text:
            return text
        t = text.strip()
        if not (t.startswith("{") and t.endswith("}")):
            return text
        try:
            data = json.loads(t)
        except Exception:
            return text
        if not isinstance(data, dict):
            return text
        for key in ("message", "content", "response", "resposta", "mensagem",
                    "summary", "resumo", "conclusao", "conclusão", "text", "answer"):
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        # Fall back to joining any string values; else a friendly default.
        strings = [v.strip() for v in data.values() if isinstance(v, str) and v.strip()]
        return " ".join(strings) if strings else "Análise concluída."

    def _clean_explanatory_text(self, content: str) -> str:
        """Strip raw JSON tool call blocks and <think> tags to leave genuine human-readable text."""
        if not content:
            return ""
        text = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
        text = re.sub(r'```(?:json)?\s*\{.*?\}\s*```', '', text, flags=re.DOTALL).strip()
        text = re.sub(r'<tool_call>.*?</tool_call>', '', text, flags=re.DOTALL).strip()
        if text.startswith("{") and text.endswith("}"):
            try:
                json.loads(text)
                return ""
            except Exception:
                pass
        return text.strip()

    def _explain_tool_action(self, tool_name: str, arguments: dict) -> dict[str, str]:
        """Generate pedagogical, educational explanations in pt-BR for every tool and command."""
        session = getattr(self, "session", None) or {}
        target = session.get("target", "o alvo") if isinstance(session, dict) else getattr(session, "target", "o alvo")

        if tool_name == "read_memory":
            section = arguments.get("section", "target_map")
            sec_desc = {
                "target_map": "o mapa de hosts, IPs, portas abertas e serviços identificados",
                "attack_surface": "a superfície de ataque, tecnologias e vetores de risco catalogados",
                "operation_log": "o histórico cronológico das etapas e comandos executados",
            }.get(section, f"a seção {section}")
            return {
                "what": f"Consulta a memória operacional persistente ({section}.md).",
                "why": f"Permite analisar {sec_desc} sem gerar tráfego de rede redundante no alvo ({target}).",
                "params": f"Parâmetro 'section': '{section}' define qual caderno de memória da operação será lido.",
            }

        if tool_name == "update_memory":
            section = arguments.get("section", "target_map")
            return {
                "what": f"Atualiza o arquivo de memória viva ({section}.md).",
                "why": "Salva as descobertas mais recentes para manter o contexto persistente entre as fases da avaliação.",
                "params": f"Registra novos nós, portas ou anotações na seção '{section}'.",
            }

        if tool_name == "query_playbook":
            query = arguments.get("query", "")
            return {
                "what": "Pesquisa táticas e procedimentos na base de conhecimento (Playbooks).",
                "why": f"Busca métodos comprovados, contornos de WAF/403 e comandos recomendados para '{query}'.",
                "params": f"Consulta '{query}': busca textual via SQLite FTS5 por técnicas correlatas.",
            }

        if tool_name == "save_playbook":
            title = arguments.get("title", "")
            return {
                "what": "Registra uma nova técnica ou tática na base de aprendizado contínuo.",
                "why": "Garante que técnicas bem-sucedidas nesta operação fiquem disponíveis para operações futuras.",
                "params": f"Título: '{title}'. Armazena gatilhos, ferramentas e procedimentos passo a passo.",
            }

        if tool_name == "search_cve":
            query = arguments.get("query", "")
            return {
                "what": "Pesquisa na base global de vulnerabilidades conhecidas (CVE/NVD).",
                "why": f"Verifica se softwares ou versões descobertas em '{target}' possuem vulnerabilidades públicas documentadas.",
                "params": f"Termo de busca '{query}': identifica falhas com pontuação de severidade CVSS e disponibilidade de exploits.",
            }

        if tool_name == "create_finding":
            title = arguments.get("title", "")
            sev = arguments.get("severity", "info").upper()
            cvss = arguments.get("cvss_score", "N/A")
            return {
                "what": f"Registra oficialmente uma vulnerabilidade verificada (Severidade: {sev}, CVSS: {cvss}).",
                "why": f"Documenta a falha '{title}' com prova de conceito (PoC) para o relatório executivo e técnico.",
                "params": f"Severidade {sev} | CVSS {cvss}. Inclui evidências, impacto e recomendação de remediação.",
            }

        if tool_name == "stash_artifact":
            atype = arguments.get("type", "dado")
            note = arguments.get("note", "")
            return {
                "what": f"Guarda um artefato sensível ({atype}) no cofre protegido da operação.",
                "why": "Preserva credenciais, hashes, tokens ou chaves coletadas durante os testes para reutilização autorizada ou auditoria.",
                "params": f"Tipo '{atype}': {note or 'valor mascarado para evitar exposição indevida'}.",
            }

        if tool_name in ("read_file", "create_file"):
            path = arguments.get("path", "")
            action = "Lê conteúdo de" if tool_name == "read_file" else "Cria/modifica"
            return {
                "what": f"{action} arquivo no ambiente de trabalho seguro ({path}).",
                "why": "Gerencia arquivos de apoio, listas de alvos, scripts auxiliares ou evidências brutas.",
                "params": f"Caminho do arquivo: '{path}'.",
            }

        if tool_name == "audit_security_headers":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de cabeçalhos de segurança HTTP e cookies ({url_arg}).",
                "why": "Avalia a conformidade com as diretrizes defensivas da OWASP (CSP, HSTS, X-Frame-Options e cookies seguros) sem sobrecarregar o alvo.",
                "params": f"URL inspecionada: '{url_arg}'. Analisa políticas defensivas e vazamento de versão do servidor.",
            }

        if tool_name == "audit_dns_email_security":
            dom_arg = arguments.get("domain", target)
            return {
                "what": f"Auditoria de registros de segurança DNS e proteção de e-mail ({dom_arg}).",
                "why": "Avalia as políticas anti-spoofing e anti-phishing (SPF, DMARC, MX e restrição CAA de certificados).",
                "params": f"Domínio avaliado: '{dom_arg}'. Consulta registros DNS oficiais via DNS over HTTPS.",
            }

        if tool_name == "scan_exposed_secrets":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Varredura defensiva de segredos e chaves de API expostas em scripts clientes ({url_arg}).",
                "why": "Identifica tokens de acesso, chaves de API ou credenciais inadvertidamente publicadas em arquivos HTML ou bundles JavaScript.",
                "params": f"URL inspecionada: '{url_arg}'. Analisa scripts estáticos carregados pelo frontend.",
            }

        if tool_name == "audit_tls_ssl":
            host_arg = arguments.get("hostname", target)
            port_arg = arguments.get("port", 443)
            return {
                "what": f"Auditoria de configuração criptográfica TLS/SSL e certificados ({host_arg}:{port_arg}).",
                "why": "Verifica validade, expiração, cadeia de autoridade certificadora e protocolos criptográficos suportados.",
                "params": f"Host: '{host_arg}', Porta: {port_arg}. Avalia força dos ciphers e integridade do canal TLS.",
            }

        if tool_name == "audit_api_spec":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de conformidade e segurança de contratos de API (OpenAPI/Swagger) ({url_arg}).",
                "why": "Descobre endpoints expostos, rotas sensíveis ou administrativas e verifica ausência de esquemas de autenticação.",
                "params": f"URL/Host inspecionado: '{url_arg}'. Analisa especificações de API e superfícies contratuais.",
            }

        if tool_name == "query_whois_rdap":
            dom_arg = arguments.get("domain", target)
            return {
                "what": f"Consulta de inteligência cadastral WHOIS/RDAP (BrasilAPI & Global) ({dom_arg}).",
                "why": "Obtém dados cadastrais estruturados em JSON (titular, CNPJ, status, registrar oficial e servidores DNS autoritativos).",
                "params": f"Domínio: '{dom_arg}'. Consulta direta à BrasilAPI para domínios .br e RDAP global para gTLDs.",
            }

        if tool_name == "enrich_ip_intel":
            tgt_arg = arguments.get("target", target)
            return {
                "what": f"Enriquecimento de inteligência de rede, ASN e detecção de CDN/WAF ({tgt_arg}).",
                "why": "Identifica se o alvo está protegido por CDN/Cloudflare, provedor de nuvem (AWS/Azure/GCP) ou IP dedicado.",
                "params": f"Alvo: '{tgt_arg}'. Mapeia ASN, organização, geolocalização e infraestrutura de borda.",
            }

        if tool_name == "search_historical_urls":
            dom_arg = arguments.get("domain", target)
            limit_arg = arguments.get("limit", 50)
            return {
                "what": f"Descoberta passiva de URLs históricas e parâmetros via Wayback Machine & AlienVault OTX ({dom_arg}).",
                "why": "Identifica rotas esquecidas, versões legadas de API, endpoints administrativos e arquivos sensíveis sem tocar no servidor alvo.",
                "params": f"Domínio: '{dom_arg}', Limite: {limit_arg} registros. Varredura 100% passiva via Internet Archive e OTX.",
            }

        if tool_name == "search_cert_transparency":
            dom_arg = arguments.get("domain", target)
            return {
                "what": f"Descoberta passiva de subdomínios via Certificate Transparency Logs ({dom_arg}).",
                "why": "Consulta registros criptográficos públicos (crt.sh) para identificar subdomínios históricos, staging, dev e VPNs esquecidas sem enviar pacotes ao alvo.",
                "params": f"Domínio: '{dom_arg}'. Enumera todos os certificados SSL/TLS emitidos por Autoridades Certificadoras públicas.",
            }

        if tool_name == "enrich_cve_threat":
            cve_arg = arguments.get("cve_id", "CVE")
            return {
                "what": f"Enriquecimento de inteligência de exploração armada CISA KEV & EPSS ({cve_arg}).",
                "why": "Verifica se a vulnerabilidade está no catálogo CISA KEV (exploração ativa no mundo real / ransomware) e calcula probabilidade de exploração armada (EPSS).",
                "params": f"CVE: '{cve_arg}'. Avalia criticidade tática com base em campanhas reais de ataque.",
            }

        if tool_name == "audit_well_known_security":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de políticas de segurança RFC 9116 e metadados web ({url_arg}).",
                "why": "Avalia o canal oficial de reporte /.well-known/security.txt, chaves PGP de contato e diretórios sensíveis desindexados em robots.txt e sitemaps.",
                "params": f"URL inspecionada: '{url_arg}'. Analisa arquivos de configuração estática e diretrizes para robôs.",
            }

        if tool_name == "audit_cloud_storage":
            tgt_arg = arguments.get("target", target)
            return {
                "what": f"Auditoria defensiva de exposição de buckets em nuvem AWS S3, GCS e Azure ({tgt_arg}).",
                "why": "Detecta se existem buckets de armazenamento em nuvem com nomes derivados da organização que estejam com listagem pública irrestrita.",
                "params": f"Alvo/Marca: '{tgt_arg}'. Testa permutações de nomes de armazenamento contra endpoints de nuvem pública.",
            }

        if tool_name == "audit_subdomain_takeover":
            dom_arg = arguments.get("domain", target)
            return {
                "what": f"Auditoria defensiva de risco de Subdomain Takeover ({dom_arg}).",
                "why": "Detecta registros CNAME órfãos apontando para serviços em nuvem (GitHub, S3, Heroku, Netlify, Azure) que foram desprovisionados e podem ser usurpados.",
                "params": f"Domínio: '{dom_arg}'. Analisa respostas DNS CNAME e checa assinaturas de erro do provedor.",
            }

        if tool_name == "detect_waf_firewall":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Detecção e fingerprinting de WAF / Firewall de Aplicação Web ({url_arg}).",
                "why": "Mapeia defesas de borda (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity) para calibrar taxa de testes e orientar estratégias de varredura.",
                "params": f"URL/Host: '{url_arg}'. Analisa cabeçalhos HTTP, cookies e respostas a sondas benignas.",
            }

        if tool_name == "audit_cors_advanced":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria avançada de políticas Cross-Origin Resource Sharing (CORS) ({url_arg}).",
                "why": "Identifica violações da política de mesma origem (SOP), como reflexão cega de Origin, confiança em 'null' origin e exposição indevida de credenciais autenticadas.",
                "params": f"URL: '{url_arg}'. Envia origens não confiáveis e examina cabeçalhos Access-Control-Allow-*.",
            }

        if tool_name == "audit_http_methods":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria defensiva de métodos e verbos HTTP suportados ({url_arg}).",
                "why": "Verifica métodos inseguros habilitados, especialmente o método TRACE (suscetível a Cross-Site Tracing - XST) e verbos de modificação não autorizada.",
                "params": f"URL: '{url_arg}'. Envia sondas OPTIONS e TRACE para avaliar cabeçalhos Allow e eco de payloads.",
            }

        if tool_name == "map_mitre_attack":
            return {
                "what": "Mapeamento tático de achados e superfície para o framework MITRE ATT&CK Enterprise.",
                "why": "Classifica vulnerabilidades em Táticas e Técnicas (Reconhecimento, Acesso Inicial, Evasão de Defesa, Coleta) para identificar gaps de cobertura defensiva.",
                "params": f"Findings analisados: {len(arguments.get('findings', []))}. Tecnologias: {len(arguments.get('technologies', []))}.",
            }

        if tool_name == "generate_detection_rules":
            ft = arguments.get("finding_type", "vulnerability")
            tp = arguments.get("target_path", "/")
            return {
                "what": f"Geração de regras de detecção defensiva (Sigma, ModSecurity WAF e Suricata IDS) para '{ft}'.",
                "why": "Capacidade de Purple Team para entregar regras imediatas de bloqueio e monitoramento no SIEM e WAF contra os vetores identificados.",
                "params": f"Tipo: '{ft}'. Endpoint/Rota: '{tp}'.",
            }

        if tool_name == "audit_jwt_security":
            return {
                "what": "Auditoria criptográfica e de configuração de JSON Web Token (JWT).",
                "why": "Identifica falhas críticas de autenticação, como algoritmo 'none', chave simétrica HMAC fraca (HS256), ausência de claim de expiração e vazamento de dados sensíveis.",
                "params": "Analisa estrutura header.payload.signature, decodifica claims e testa entropia de chave.",
            }

        if tool_name == "audit_rate_limiting":
            url_arg = arguments.get("url", target)
            cnt = arguments.get("probes_count", 10)
            return {
                "what": f"Auditoria de resiliência a força bruta e rate limiting ({url_arg}).",
                "why": "Verifica se endpoints de autenticação e APIs impõem limitação de taxa (HTTP 429) e cabeçalhos de controle de requisição.",
                "params": f"URL: '{url_arg}'. Dispara série controlada de {cnt} sondas de verificação.",
            }

        if tool_name == "audit_websocket_security":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de segurança em endpoints WebSocket ({url_arg}).",
                "why": "Identifica vulnerabilidade de Cross-Site WebSocket Hijacking (CSWSH) e tráfego desprotegido sem TLS ('ws://').",
                "params": f"URL: '{url_arg}'. Envia handshake HTTP Upgrade com origens não autorizadas.",
            }

        if tool_name == "audit_supply_chain_libs":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de supply chain e bibliotecas JavaScript de front-end ({url_arg}).",
                "why": "Mapeia dependências de terceiros no cliente (jQuery, Lodash, Bootstrap) com CVEs conhecidos de XSS/Prototype Pollution e ausência de SRI.",
                "params": f"URL: '{url_arg}'. Inspeciona tags de script e assinaturas de versões.",
            }

        if tool_name == "audit_compliance_matrix":
            tgt = arguments.get("target", target)
            return {
                "what": f"Matriz de conformidade técnica OWASP Top 10 e LGPD ({tgt}).",
                "why": "Mapeia as vulnerabilidades contra os 10 pilares da OWASP (2021) e exigências de segurança e sigilo de dados da LGPD (Art. 46 e 48).",
                "params": f"Alvo: '{tgt}'. Sintetiza conformidade técnica executiva.",
            }

        if tool_name == "generate_atomic_test":
            tid = arguments.get("technique_id", "T1190")
            plat = arguments.get("platform", "powershell")
            return {
                "what": f"Geração de teste de simulação de adversário Atomic Red Team ({tid}).",
                "why": "Permite ao Blue Team testar se o EDR/SIEM alerta frente a essa técnica específica do MITRE ATT&CK.",
                "params": f"Técnica: '{tid}'. Plataforma/Executor: '{plat}'.",
            }

        if tool_name == "simulate_attack_path":
            ep = arguments.get("entry_point", "Internet Externa")
            ta = arguments.get("target_asset", "Banco de Dados / Crown Jewels")
            return {
                "what": f"Simulação de cadeia de ataque (Attack Path) de '{ep}' até '{ta}'.",
                "why": "Encadeia as vulnerabilidades descobertas em múltiplos saltos e calcula os pontos de estrangulamento (choke points) para contenção prioritária.",
                "params": f"Ponto de Entrada: '{ep}'. Alvo Crítico: '{ta}'.",
            }

        if tool_name == "audit_graphql_security":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de segurança em endpoint GraphQL ({url_arg}).",
                "why": "Verifica vazamento de schema por Introspection em produção, sugestão automática de campos e vulnerabilidade a DoS por query batching.",
                "params": f"URL: '{url_arg}'. Envia query de introspecção e sondas de erro de sintaxe.",
            }

        if tool_name == "audit_oauth_sso":
            url_arg = arguments.get("authorization_url", target)
            return {
                "what": f"Auditoria de segurança em fluxos OAuth 2.0 e OpenID Connect ({url_arg}).",
                "why": "Identifica falhas de validação de 'redirect_uri' (Account Takeover), ausência de parâmetro 'state' (CSRF) e fluxos implícitos obsoletos.",
                "params": f"Authorization URL: '{url_arg}'. Testa redirecionamento e integridade de estado.",
            }

        if tool_name == "generate_ir_playbook":
            inc = arguments.get("incident_type", "compromise")
            asset = arguments.get("affected_asset", target)
            return {
                "what": f"Geração de Playbook de Resposta a Incidentes NIST 800-61 / SANS para '{inc}'.",
                "why": "Estrutura as fases de contenção imediata, erradicação e comandos de coleta de evidências para o time de SOC e resposta a incidentes.",
                "params": f"Incidente: '{inc}'. Ativo afetado: '{asset}'.",
            }

        if tool_name == "audit_dnsbl_reputation":
            tgt = arguments.get("target", target)
            return {
                "what": f"Auditoria de reputação e verificação em blacklists globais DNSBL/RBL ({tgt}).",
                "why": "Verifica se o IP ou domínio está listado em bases de bloqueio (Spamhaus, Barracuda, SpamCop) como origem de malware, phishing ou spam.",
                "params": f"Alvo: '{tgt}'. Consulta provedores DNSBL via DNS reverso.",
            }

        if tool_name == "generate_canary_tokens":
            tt = arguments.get("token_type", "canary")
            return {
                "what": f"Geração de Honeytoken e ativo de decepção cibernética ({tt}).",
                "why": "Cria credenciais falsas monitoradas (AWS keys, JWT honeytoken, URLs canário) para armar armadilhas e detectar invasores imediatamente.",
                "params": f"Tipo: '{tt}'. Contexto: '{arguments.get('memo', 'Ambiente de produção/staging')}'.",
            }

        if tool_name == "audit_ssrf_cloud_metadata":
            url_arg = arguments.get("url", target)
            param_arg = arguments.get("param", "url")
            return {
                "what": f"Auditoria de vulnerabilidade SSRF e exposição de metadados em nuvem ({url_arg}).",
                "why": "Testa se a aplicação reflete metadados de nuvem (AWS IMDSv2, GCP, Azure) ou endereços de loopback RFC 1918, prevenindo roubo de credenciais IAM.",
                "params": f"URL: '{url_arg}'. Parâmetro testado: '{param_arg}'.",
            }

        if tool_name == "calculate_cvss_vector":
            av = arguments.get("av", "N")
            c = arguments.get("c", "H")
            return {
                "what": "Cálculo matemático e padronização do score de vulnerabilidade CVSS v3.1.",
                "why": "Produz pontuação base, nível de severidade e vetor canônico preciso para documentação executiva e técnica de descobertas.",
                "params": f"Vetor base: AV:{av}/AC:{arguments.get('ac', 'L')}/PR:{arguments.get('pr', 'N')}/UI:{arguments.get('ui', 'N')}/S:{arguments.get('scope', 'U')}/C:{c}.",
            }

        if tool_name == "audit_api_idor_matrix":
            ep_count = len(arguments.get("endpoints", []))
            return {
                "what": f"Auditoria de controle de acesso e vulnerabilidades IDOR/BOLA em APIs ({ep_count} endpoints).",
                "why": "Mapeia parâmetros de identificação de objeto (OWASP API1:2023) e gera matriz de controle de acesso para identificar falhas de autorização de nível de objeto.",
                "params": f"Endpoints analisados: {ep_count}. Avalia parâmetros de recurso (ex: user_id, doc_id, account_id).",
            }

        if tool_name == "audit_prototype_pollution":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de vulnerabilidade Prototype Pollution no JavaScript cliente ({url_arg}).",
                "why": "Identifica padrões perigosos de mesclagem recursiva (deep merge, extend, query parsing) suscetíveis a injeção em Object.prototype e RCE/XSS.",
                "params": f"URL: '{url_arg}'. Inspeciona scripts frontend em busca de vetores de poluição de protótipo.",
            }

        if tool_name == "generate_hardening_baseline":
            tech = arguments.get("technology", "nginx")
            prof = arguments.get("profile", "production")
            return {
                "what": f"Geração de baseline de endurecimento defensivo (Hardening CIS Benchmarks) para '{tech}'.",
                "why": "Fornece configurações prontas de produção para mitigação imediata de vulnerabilidades descobertas em servidores web, SSH ou kernel Linux.",
                "params": f"Tecnologia: '{tech}'. Perfil: '{prof}'. Gera arquivo de configuração seguro e testado.",
            }

        if tool_name == "audit_dkim_bimi":
            dom_arg = arguments.get("domain", target)
            sel = arguments.get("selector", "default")
            return {
                "what": f"Auditoria avançada de criptografia DKIM e validação visual BIMI ({dom_arg}).",
                "why": "Valida o tamanho da chave pública RSA do seletor DKIM (>= 2048 bits) e a presença de registro BIMI com certificado VMC contra personificação de marca.",
                "params": f"Domínio: '{dom_arg}'. Seletor DKIM: '{sel}'.",
            }

        if tool_name == "query_threat_feeds":
            ioc = arguments.get("ioc", target)
            feed = arguments.get("feed", "all")
            return {
                "what": f"Consulta a feeds de Threat Intelligence abertos para o IOC '{ioc}'.",
                "why": "Correlaciona domínios, URLs e IPs suspeitos com bases de inteligência de ameaças conhecidas (URLhaus, AbuseIPDB) para detecção de C2 e malware.",
                "params": f"IOC: '{ioc}'. Feed consultado: '{feed}'.",
            }

        if tool_name == "audit_waf_bypass_heuristics":
            url_arg = arguments.get("url", target)
            param_arg = arguments.get("param_name", "q")
            return {
                "what": f"Auditoria de resiliência e evasão de WAF via normalização ({url_arg}).",
                "why": "Testa se o WAF inspeciona tráfego após normalização Unicode (NFKD), desofuscação percentual dupla e quebras de token, identificando brechas de bypass.",
                "params": f"URL: '{url_arg}'. Parâmetro testado: '{param_arg}'.",
            }

        if tool_name == "audit_sbom_dependencies":
            eco = arguments.get("ecosystem", "PyPI")
            return {
                "what": f"Auditoria de vulnerabilidades de supply chain e SBOM no banco Google OSV.dev ({eco}).",
                "why": "Cruza dependências e bibliotecas do projeto contra a base aberta de vulnerabilidades conhecidas para identificar CVEs críticos e versões corrigidas.",
                "params": f"Ecossistema: '{eco}'. Analisa dependências do manifesto ou lista declarada.",
            }

        if tool_name == "audit_saml_xml_security":
            url_arg = arguments.get("metadata_url", target)
            return {
                "what": f"Auditoria criptográfica e estrutural de SSO corporativo SAML 2.0 ({url_arg}).",
                "why": "Verifica uso de algoritmos fracos (SHA-1), ausência de assinatura em asserções (risco de XML Signature Wrapping - XSW) e suscetibilidade a XXE.",
                "params": f"Metadados inspecionados: '{url_arg}'.",
            }

        if tool_name == "generate_yara_rule":
            rn = arguments.get("rule_name", "threat_pattern")
            sev = arguments.get("severity", "HIGH")
            return {
                "what": f"Geração de regra YARA padronizada para detecção de ameaças ({rn}).",
                "why": "Permite ao Blue Team alimentar EDRs, SIEMs e scanners de disco (Thor, ClamAV) com assinaturas de caça a ameaças e contenção forense.",
                "params": f"Regra: '{rn}'. Severidade: {sev}. Padrões de string: {len(arguments.get('strings_to_match', []))}.",
            }

        if tool_name == "audit_dockerfile_security":
            img = arguments.get("image_name", "container-image")
            return {
                "what": f"Análise estática de segurança e DevSecOps linter para Dockerfile ({img}).",
                "why": "Detecta execução insegura como root, segredos expostos em ENV/ARG, imagens base ':latest' e ausência de HEALTHCHECK.",
                "params": f"Imagem: '{img}'. Analisa instruções e diretivas de construção de contêiner.",
            }

        if tool_name == "audit_kubernetes_rbac":
            cl = arguments.get("cluster_name", "k8s-cluster")
            return {
                "what": f"Auditoria de privilégios RBAC e vetores de escape em Kubernetes ({cl}).",
                "why": "Identifica permissões coringa ('*'), acesso indevido a Secrets e contêineres privilegiados ('privileged: true', hostPID, hostNetwork).",
                "params": f"Cluster: '{cl}'. Analisa manifestos Role, ClusterRole, PodSpec e Deployment.",
            }

        if tool_name == "calculate_breach_risk_cost":
            rc = arguments.get("records_count", 0)
            ind = arguments.get("industry_sector", "finance")
            return {
                "what": f"Cálculo de impacto financeiro e sanções regulatórias da LGPD ({rc} registros, setor {ind}).",
                "why": "Projeta multas da LGPD (Art. 52 até 2% do faturamento / R$ 50M), despesas forenses, PR e custo por registro vazado (IBM Cost of a Data Breach).",
                "params": f"Registros afetados: {rc}. Setor: '{ind}'. Categorias: {arguments.get('data_types', ['pii'])}.",
            }

        if tool_name == "audit_iac_misconfigurations":
            tt = arguments.get("template_type", "terraform")
            return {
                "what": f"Auditoria de segurança estática em Infraestrutura como Código - IaC ({tt}).",
                "why": "Detecta Security Groups abertos para a Internet (0.0.0.0/0 nas portas 22/3389), buckets S3 públicos, bancos de dados RDS expostos e ausência de criptografia em repouso.",
                "params": f"Tipo de template: '{tt}'. Inspeciona definições de recursos e conformidade com CIS Benchmarks de nuvem.",
            }

        if tool_name == "audit_cicd_pipeline_security":
            plat = arguments.get("platform", "github_actions")
            return {
                "what": f"Auditoria de segurança DevSecOps em pipelines de CI/CD ({plat}).",
                "why": "Identifica riscos de Pwn Request via 'pull_request_target', injeção de comandos em steps bash por variáveis de contexto não sanitizadas e ações sem pinning por hash SHA.",
                "params": f"Plataforma: '{plat}'. Inspeciona gatilhos, permissões de token e passos de execução.",
            }

        if tool_name == "audit_web_cache_poisoning":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de vulnerabilidades de Web Cache Poisoning e Cache Deception ({url_arg}).",
                "why": "Testa se a CDN ou camada de proxy reflete cabeçalhos não-chaveados (X-Forwarded-Host, X-Rewrite-URL) em respostas cacheadas e avalia risco de cache deception em extensões estáticas.",
                "params": f"URL inspecionada: '{url_arg}'. Envia sondas controladas de cabeçalhos de encaminhamento.",
            }

        if tool_name == "audit_api_mass_assignment":
            url_arg = arguments.get("url", target)
            m = arguments.get("method", "POST")
            return {
                "what": f"Auditoria de vulnerabilidade Mass Assignment / Atribuição em Massa (OWASP API3:2023) ({url_arg}).",
                "why": "Verifica se a API aceita e processa campos de controle de acesso (ex: isAdmin, role, is_verified) injetados na carga útil sem validação de esquema.",
                "params": f"URL: '{url_arg}'. Método: {m}. Injeta propriedades administrativas para testar validação de DTOs.",
            }

        if tool_name == "audit_mta_sts_dane":
            dom_arg = arguments.get("domain", target)
            return {
                "what": f"Auditoria de políticas de criptografia SMTP MTA-STS e DANE TLSA ({dom_arg}).",
                "why": "Valida se o domínio impõe conexões TLS estritas entre servidores de e-mail (MTA-STS mode: enforce e registros DANE), prevenindo ataques de downgrade e interceptação man-in-the-middle.",
                "params": f"Domínio: '{dom_arg}'. Consulta registros DNS _mta-sts e arquivo HTTPS de política.",
            }

        if tool_name == "audit_identity_access_hygiene":
            dom = arguments.get("domain_name", "corp.local")
            acc_count = len(arguments.get("accounts_data", []))
            return {
                "what": f"Auditoria de higiene de identidades e Active Directory / Entra ID ({acc_count} contas, domínio '{dom}').",
                "why": "Detecta vulnerabilidades a Kerberoasting (SPNs com cifras fracas RC4), AS-REP Roasting (pré-autenticação desabilitada), delegação irrestrita e senhas que nunca expiram em administradores.",
                "params": f"Contas analisadas: {acc_count}. Avalia flags de controle de conta (UserAccountControl).",
            }

        if tool_name == "analyze_forensic_artifacts":
            lt = arguments.get("log_type", "generic")
            return {
                "what": f"Análise pericial forense e triagem de logs de incidentes cibernéticos ({lt}).",
                "why": "Processa logs de segurança (Windows EVTX, Syslog do Linux ou logs web) para reconstruir linhas do tempo, detectar força bruta (Event ID 4625), execução de processos maliciosos e movimentação lateral.",
                "params": f"Tipo de log: '{lt}'. Extrai indicadores de comprometimento e monta linha do tempo de eventos.",
            }

        if tool_name == "audit_binary_protections":
            bn = arguments.get("binary_name", "executavel")
            return {
                "what": f"Auditoria checksec de mitigações e proteções de binário compilado ({bn}).",
                "why": "Verifica se o binário ELF/PE foi compilado com proteções modernas de mitigação de corrupção de memória: ASLR/PIE, Stack Canaries, NX/DEP e Full RELRO.",
                "params": f"Binário: '{bn}'. Analisa cabeçalhos e seções de segurança do executável.",
            }

        if tool_name == "audit_http_request_smuggling":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de HTTP Request Smuggling e descompasso de proxies CL.TE/TE.CL ({url_arg}).",
                "why": "Identifica discrepâncias na interpretação de cabeçalhos Transfer-Encoding e Content-Length entre o proxy reverso e o backend, permitindo sequestro de requisições e bypass de WAF.",
                "params": f"URL: '{url_arg}'. Sonda respostas com cabeçalhos duplos e mutações de Transfer-Encoding.",
            }

        if tool_name == "audit_ssti_injection":
            url_arg = arguments.get("url", target)
            p = arguments.get("parameter", "q")
            return {
                "what": f"Auditoria de Server-Side Template Injection (SSTI) e SpEL no parâmetro '{p}' ({url_arg}).",
                "why": "Detecta interpolação direta de dados do usuário em engines de template (Jinja2, Twig, FreeMarker, SpEL) através de avaliação de expressões matemáticas, com risco crítico de RCE.",
                "params": f"URL: '{url_arg}'. Parâmetro testado: '{p}'. Envia polyglots de interpolação não destrutivos.",
            }

        if tool_name == "audit_nosql_injection":
            url_arg = arguments.get("url", target)
            fp = arguments.get("field_to_probe", "password")
            return {
                "what": f"Auditoria de injeção NoSQL e adulteração de operadores ($ne, $gt, $regex) ({url_arg}).",
                "why": "Verifica se a API processa objetos MongoDB/NoSQL diretamente no payload JSON, permitindo bypass de autenticação e vazamento de documentos.",
                "params": f"URL: '{url_arg}'. Campo testado: '{fp}'. Injeta operadores condicionais estruturados.",
            }

        if tool_name == "generate_subdomain_permutations":
            dom_arg = arguments.get("domain", target)
            return {
                "what": f"Geração ofensiva de permutações de subdomínio e descoberta de Shadow IT ({dom_arg}).",
                "why": "Gera mutações léxicas inteligentes (estilo altdns: dev-, stg-, uat-, -v2) e resolve ativamente via DNS para descobrir ambientes de teste desprotegidos e legados esquecidos.",
                "params": f"Domínio: '{dom_arg}'. Mutação de prefixos e sufixos de infraestrutura com resolução DNS.",
            }

        if tool_name == "audit_ntlm_relay_coercion":
            tgt = arguments.get("target", target)
            return {
                "what": f"Auditoria de superfície de ataque NTLM Relay e coerção de autenticação ({tgt}).",
                "why": "Avalia ausência de assinatura de pacotes SMB, falta de exigência de assinatura LDAP/CBT e exposição a coerção de autenticação (MS-RPRN / WebDAV) no Active Directory.",
                "params": f"Alvo: '{tgt}'. Inspeciona políticas de assinatura de rede e serviços vulneráveis.",
            }

        if tool_name == "simulate_cloud_iam_privesc":
            prov = arguments.get("provider", "AWS")
            ent = arguments.get("entity_name", "unprivileged_entity")
            return {
                "what": f"Mapeamento de caminhos de escalação de privilégios IAM em nuvem ({prov.upper()} - {ent}).",
                "why": "Analisa permissões de políticas IAM para identificar combinações perigosas (ex: iam:PassRole + ec2:RunInstances, iam:CreatePolicyVersion) que permitem assumir controle administrativo irrestrito.",
                "params": f"Provedor: '{prov}'. Entidade: '{ent}'. Mapeia grafo de escalação contra as 21 rotas conhecidas.",
            }

        if tool_name == "audit_race_conditions_concurrency":
            url_arg = arguments.get("url", target)
            c = arguments.get("concurrency_level", 5)
            return {
                "what": f"Auditoria de concorrência e condições de corrida (Race Conditions) ({url_arg}).",
                "why": "Identifica vulnerabilidades de lógica de negócios (TOCTOU) e limit overrun através de rajadas sincronizadas de requisições simultâneas em ações de uso único.",
                "params": f"URL: '{url_arg}'. Concorrência: {c} disparos assíncronos paralelos.",
            }

        if tool_name == "audit_dom_clobbering":
            url_arg = arguments.get("url", "código client-side")
            return {
                "what": f"Auditoria de DOM Clobbering e sequestro de escopo client-side ({url_arg}).",
                "why": "Analisa se tags HTML com IDs/nomes reservados podem sobrescrever propriedades e variáveis globais do JavaScript, redirecionando fluxos de execução e abrindo portas para XSS.",
                "params": "Analisa código-fonte HTML/JS e padrões de acesso a objetos do navegador.",
            }

        if tool_name == "audit_xxe_injection":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de XML External Entity (XXE) e resolução de DTDs ({url_arg}).",
                "why": "Testa se o parser XML do backend expande entidades arbitrárias, prevenindo leitura de arquivos locais confidenciais (LFI) e ataques de SSRF.",
                "params": f"URL: '{url_arg}'. Envia carga útil XML segura com entidade parametrizada de teste.",
            }

        if tool_name == "audit_open_redirect_bypasses":
            url_arg = arguments.get("url", target)
            p = arguments.get("parameter", "redirect")
            return {
                "what": f"Auditoria avançada de Open Redirect e evasão de filtros ({url_arg}).",
                "why": "Valida se o parâmetro de redirecionamento pode ser burlado utilizando truques de sintaxe de URL (backslash, userinfo, scheme manipulation) para ataques de phishing ou OAuth 2.0 Account Takeover.",
                "params": f"URL: '{url_arg}'. Parâmetro: '{p}'. Avalia os 12 padrões modernos de bypass de filtro.",
            }

        if tool_name == "audit_ldap_injection":
            url_arg = arguments.get("url", target)
            pf = arguments.get("probe_field", "username")
            return {
                "what": f"Auditoria de injeção de filtros LDAP e Active Directory ({url_arg}).",
                "why": "Verifica se os campos de consulta permitem adulteração de consultas de diretório (*, )(&, |), prevenindo bypass de autenticação e enumeração cega de usuários corporativos.",
                "params": f"URL: '{url_arg}'. Campo testado: '{pf}'. Injeta caracteres reservados da RFC 4515.",
            }

        if tool_name == "audit_grpc_api_security":
            tgt = arguments.get("target", target)
            return {
                "what": f"Auditoria de segurança em endpoints de microsserviços gRPC ({tgt}).",
                "why": "Verifica exposição do protocolo Server Reflection, suporte a conexões h2c sem TLS e métodos RPC acessíveis sem autenticação.",
                "params": f"Alvo: '{tgt}'. Testa transporte HTTP/2 e reflexão de esquemas Protobuf.",
            }

        if tool_name == "audit_insecure_deserialization":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de desserialização insegura de objetos ({url_arg}).",
                "why": "Inspeciona cookies, tokens e payloads em busca de assinaturas de serialização binária (Java, Pickle, PHP, .NET) que permitam Execução Remota de Código (RCE).",
                "params": f"URL: '{url_arg}'. Analisa assinaturas mágicas (rO0AB, gAN, TypeNameHandling, O:).",
            }

        if tool_name == "audit_crlf_header_injection":
            url_arg = arguments.get("url", target)
            param = arguments.get("parameter", "redirect")
            return {
                "what": f"Auditoria de injeção de cabeçalhos CRLF e HTTP Response Splitting ({url_arg}).",
                "why": "Testa parâmetros de redirecionamento contra caracteres de quebra de linha (CRLF / \\r\\n) para prevenir Cookie Tossing, Session Fixation e Response Splitting.",
                "params": f"URL: '{url_arg}'. Parâmetro: '{param}'. Testa sondas padrão, dupla codificação e UTF-8 overlong.",
            }

        if tool_name == "audit_reverse_proxy_path_traversal":
            url_arg = arguments.get("url", target)
            bp = arguments.get("base_path", "/static")
            return {
                "what": f"Auditoria de discrepâncias de normalização e Path Traversal em proxies reversos ({url_arg}).",
                "why": "Avalia vulnerabilidades arquiteturais como Nginx alias off-by-slash e normalização de ponto-e-vírgula em Tomcat/Spring (/..;/) para burlar regras de API Gateway.",
                "params": f"URL: '{url_arg}'. Prefixo base: '{bp}'. Testa vetores de evasão de roteamento e diretório pai.",
            }

        if tool_name == "audit_s3_bucket_permissions_deep":
            b_name = arguments.get("bucket_name", target)
            prov = arguments.get("cloud_provider", "aws")
            return {
                "what": f"Auditoria profunda de políticas e ACLs em buckets de nuvem ({b_name}).",
                "why": "Analisa políticas IAM, permissões públicas anônimas de escrita/leitura, risco de escalação PutObjectAcl e perigo de Dangling Bucket Takeover.",
                "params": f"Bucket: '{b_name}'. Provedor: '{prov}'. Inspeciona políticas e testa acesso anônimo.",
            }

        if tool_name == "audit_git_and_env_leakage":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de exposição de repositórios Git e arquivos de ambiente ({url_arg}).",
                "why": "Verifica se pastas ocultas de versionamento (/.git/HEAD) ou arquivos com segredos mestres (.env, docker-compose.yml) estão acessíveis publicamente.",
                "params": f"URL: '{url_arg}'. Sonda dotfiles e arquivos de configuração sensíveis.",
            }

        if tool_name == "audit_content_security_policy_deep":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria aprofundada de Content-Security-Policy (CSP) ({url_arg}).",
                "why": "Avalia a robustez das diretivas da CSP contra bypasses modernos de XSS, Clickjacking (frame-ancestors) e sequestro de base URI.",
                "params": f"URL: '{url_arg}'. Analisa script-src, nonces, unsafe-inline/eval e gadgets JSONP.",
            }

        if tool_name == "audit_api_excessive_data_exposure":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de Exposição Excessiva de Dados em APIs (OWASP API3:2023) ({url_arg}).",
                "why": "Inspeciona payloads JSON de resposta para identificar vazamento de campos confidenciais (hashes de senha, tokens, PII, flags de administração) pelo backend.",
                "params": f"URL: '{url_arg}'. Analisa recursivamente chaves e padrões de valores sensíveis.",
            }

        if tool_name == "audit_dns_zone_transfer_and_nsec":
            dom = arguments.get("domain", target)
            return {
                "what": f"Auditoria de Transferência de Zona DNS (AXFR) e NSEC Walk ({dom}).",
                "why": "Verifica se os servidores de nomes autoritativos permitem despejo total da zona DNS ou enumeração sequencial de subdomínios via DNSSEC NSEC.",
                "params": f"Domínio: '{dom}'. Testa AXFR sobre TCP porta 53 e registros NSEC.",
            }

        if tool_name == "audit_smtp_open_relay_and_spoofing":
            host_arg = arguments.get("host", target)
            port_arg = arguments.get("port", 25)
            return {
                "what": f"Auditoria de Open Mail Relay e transporte SMTP ({host_arg}:{port_arg}).",
                "why": "Verifica se o servidor de e-mail permite relay aberto não autenticado de mensagens externas (RFC 5321) e se impõe criptografia STARTTLS.",
                "params": f"Host: '{host_arg}:{port_arg}'. Sonda comando RCPT TO sem envio de dados.",
            }

        if tool_name == "audit_server_side_prototype_pollution":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de Server-Side Prototype Pollution (SSPP) em backend Node.js ({url_arg}).",
                "why": "Testa se o backend mescla objetos JSON recursivos de forma insegura, poluindo Object.prototype e permitindo elevação de privilégios ou RCE.",
                "params": f"URL: '{url_arg}'. Injeta propriedades __proto__ e constructor.prototype.",
            }

        if tool_name == "audit_ip_spoofing_access_controls":
            url_arg = arguments.get("url", target)
            tip = arguments.get("trusted_ip", "127.0.0.1")
            return {
                "what": f"Auditoria de evasão de controle de acesso por cabeçalhos de IP ({url_arg}).",
                "why": "Verifica se rotas administrativas restritas podem ser acessadas forjando cabeçalhos de proxy reverso (X-Forwarded-For, X-Real-IP).",
                "params": f"URL: '{url_arg}'. IP confiável testado: '{tip}'.",
            }

        if tool_name == "audit_kerberos_delegation_risks":
            dom = arguments.get("domain", target)
            return {
                "what": f"Auditoria de riscos de delegação Kerberos no Active Directory ({dom}).",
                "why": "Identifica contas com Unconstrained Delegation (roubo de TGT), Constrained Delegation com transição S4U e Resource-Based Constrained Delegation (RBCD).",
                "params": f"Domínio: '{dom}'. Analisa flags userAccountControl e atributos de delegação.",
            }

        if tool_name == "audit_http3_quic_exposure":
            url_arg = arguments.get("url", target)
            p = arguments.get("port", 443)
            return {
                "what": f"Auditoria de HTTP/3, protocolo QUIC e riscos de WAF bypass ({url_arg}).",
                "why": "Avalia anúncios de Alt-Svc h3, exposição na porta UDP 443 para evasão de WAFs baseados em TCP e riscos de replay 0-RTT.",
                "params": f"URL: '{url_arg}'. Porta UDP: {p}.",
            }

        if tool_name == "audit_snmp_community_exposure":
            host_arg = arguments.get("host", target)
            port_arg = arguments.get("port", 161)
            return {
                "what": f"Auditoria de serviços SNMP e comunidades padrão ({host_arg}:{port_arg}).",
                "why": "Sonda portas UDP 161 em equipamentos de rede contra comunidades públicas (public/private), prevenindo vazamento de MIBs e topologia interna.",
                "params": f"Host: '{host_arg}:{port_arg}'. Testa requisição GetRequest sysDescr.",
            }

        if tool_name == "audit_adcs_certificate_templates":
            dom = arguments.get("domain", target)
            return {
                "what": f"Auditoria de Active Directory Certificate Services e templates de certificados ({dom}).",
                "why": "Identifica templates de certificados vulneráveis a abuso de SAN (ESC1), Any Purpose EKU (ESC2), Enrollment Agent (ESC3), ACLs fracas (ESC4) e HTTP Web Enrollment (ESC8) para escalação total de domínio.",
                "params": f"Domínio: '{dom}'. Analisa flags de Subject Name, aprovação de gerente e permissões de inscrição.",
            }

        if tool_name == "audit_smb_signing_and_null_sessions":
            host_arg = arguments.get("host", target)
            p = arguments.get("port", 445)
            return {
                "what": f"Auditoria de assinatura SMB Signing, SMBv1 e sessões nulas ({host_arg}:{p}).",
                "why": "Verifica se o servidor SMB não exige assinatura de pacotes (permitindo ataques de NTLM Relay), se executa o protocolo obsoleto SMBv1 e se aceita conexões IPC$ sem credenciais.",
                "params": f"Host: '{host_arg}:{p}'. Negociação de dialetos SMB2/SMB1.",
            }

        if tool_name == "audit_postmessage_messaging_security":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de segurança em listeners HTML5 postMessage ({url_arg}).",
                "why": "Inspeciona scripts em busca de manipuladores addEventListener('message') sem validação estrita de event.origin, uso de targetOrigin '*' e sinks perigosos de DOM XSS.",
                "params": f"URL: '{url_arg}'. Análise estática e dinâmica de scripts JavaScript.",
            }

        if tool_name == "audit_http_parameter_pollution":
            url_arg = arguments.get("url", target)
            p_name = arguments.get("param_name", "automático")
            return {
                "what": f"Auditoria de poluição de parâmetros HTTP / HPP ({url_arg}).",
                "why": "Avalia o comportamento de precedência (primeiro, último ou concatenação) em chaves duplicadas entre proxies reversos e servidores de aplicação para identificar riscos de bypass de WAF.",
                "params": f"URL: '{url_arg}'. Parâmetro testado: '{p_name}'.",
            }

        if tool_name == "audit_container_breakout_vectors":
            t_name = arguments.get("target_name", "container-workload")
            return {
                "what": f"Auditoria de vetores de fuga e escape de containers ({t_name}).",
                "why": "Analisa manifestos Pod/Docker procurando privileged: true, Linux Capabilities perigosas (CAP_SYS_ADMIN), namespaces do host (hostPID) e montagem de /var/run/docker.sock.",
                "params": f"Workload: '{t_name}'. Varredura de configurações de isolamento e contexto de segurança.",
            }

        if tool_name == "audit_clickjacking_and_ui_redressing":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria contra Clickjacking e enquadramento UI Redressing ({url_arg}).",
                "why": "Verifica cabeçalhos X-Frame-Options, diretiva CSP frame-ancestors e scripts falhos de frame-busting que permitam embutimento malicioso em iframes transparentes.",
                "params": f"URL: '{url_arg}'. Checagem de cabeçalhos de defesa e atributos sandbox.",
            }

        if tool_name == "audit_bfla_api_authorization":
            url_arg = arguments.get("url", target)
            return {
                "what": f"Auditoria de Broken Function Level Authorization / BFLA em APIs ({url_arg}).",
                "why": "Testa se rotas administrativas e de métricas/diagnóstico (/admin, /actuator) aceitam requisições de usuários comuns ou anônimos via Method Swapping (HEAD/OPTIONS).",
                "params": f"URL: '{url_arg}'. Varredura de endpoints administrativos com token fornecido.",
            }

        if tool_name == "audit_kerberoasting_surface":
            dom = arguments.get("domain", target)
            return {
                "what": f"Auditoria de superfície de Kerberoasting no Active Directory ({dom}).",
                "why": "Mapeia contas de usuário com ServicePrincipalNames (SPNs) e criptografia fraca RC4-HMAC suscetíveis à requisição de TGS e quebra offline de hashes.",
                "params": f"Domínio: '{dom}'. Análise de atributos de SPNs e tipos de cifragem.",
            }

        if tool_name == "audit_linux_privesc_vectors":
            t_name = arguments.get("target_name", "linux-host")
            return {
                "what": f"Auditoria de escalação de privilégios local em Linux / GTFOBins ({t_name}).",
                "why": "Inspeciona binários com SUID bit, regras NOPASSWD no sudoers, contas não-root com UID 0 e arquivos de sistema com permissões graváveis frouxas.",
                "params": f"Target: '{t_name}'. Cruzamento de binários contra o catálogo GTFOBins.",
            }

        if tool_name == "audit_llm_prompt_injection_and_jailbreaks":
            u = arguments.get("url", target)
            return {
                "what": f"Auditoria de Prompt Injection, Jailbreak e vazamento de instruções em LLM ({u}).",
                "why": "Testa a resiliência de guardrails cognitivos e isolamento de contexto contra injeção direta de comandos e bypass DAN (OWASP LLM01/LLM07).",
                "params": f"Endpoint LLM: '{u}'. Probes de jailbreak, canary de instrução e extração de system prompt.",
            }

        if tool_name == "audit_vector_database_exposure":
            h = arguments.get("host", target)
            return {
                "what": f"Auditoria de exposição e autenticação de Bancos de Dados Vetoriais ({h}).",
                "why": "Verifica se instâncias de ChromaDB, Qdrant, Milvus ou Weaviate estão expostas sem credenciais, vazando embeddings e bases de conhecimento RAG.",
                "params": f"Host: '{h}'. Sondagem de portas padrão (8000, 6333, 19530, 8080) e assinaturas de API REST.",
            }

        if tool_name == "audit_subresource_integrity_sri":
            u = arguments.get("url", target)
            return {
                "what": f"Auditoria de Subresource Integrity (SRI) em assets externos ({u}).",
                "why": "Identifica scripts e folhas de estilo carregados de CDNs terceiras sem hash criptográfico de integridade, prevenindo ataques Magecart e supply chain.",
                "params": f"URL: '{u}'. Verificação de atributos 'integrity' e 'crossorigin' em tags <script> e <link>.",
            }

        if tool_name == "audit_dependency_confusion_and_namespaces":
            m_type = arguments.get("manifest_type", "npm")
            return {
                "what": f"Auditoria de Dependency Confusion e namespaces privados em manifesto ({m_type}).",
                "why": "Detecta bibliotecas internas sem escopo organizacional (@corp/) suscetíveis a substituição de pacotes maliciosos em registros públicos.",
                "params": f"Tipo de manifesto: '{m_type}'. Mapeamento de candidatos não escopados contra registros públicos.",
            }

        if tool_name == "audit_webhook_ssrf_and_dns_rebinding":
            u = arguments.get("url", target)
            return {
                "what": f"Auditoria de SSRF e DNS Rebinding em registro de Webhooks ({u}).",
                "why": "Testa se callbacks aceitam endereços de loopback, redes privadas RFC 1918 ou metadados de nuvem IMDSv2 sem validação restritiva.",
                "params": f"Endpoint Webhook: '{u}'. Vetores de injeção de callback para IP privado e evasão de DNS.",
            }

        if tool_name == "audit_ad_dacl_abuse_paths":
            dom = arguments.get("domain", target)
            return {
                "what": f"Auditoria de caminhos de ataque por abuso de permissões DACL/ACL no AD ({dom}).",
                "why": "Detecta relações de controle discricionário abusáveis (GenericAll, WriteDacl, WriteOwner, ForceChangePassword) que permitem escalação de privilégios para Domain Admins.",
                "params": f"Domínio: '{dom}'. Mapeamento de ACEs fracas e cruzamento com nós de alto privilégio.",
            }

        if tool_name == "audit_windows_token_privileges":
            acc = arguments.get("account_name", "process-token")
            return {
                "what": f"Auditoria de privilégios de token Windows e escalação local ({acc}).",
                "why": "Inspeciona permissões perigosas (SeImpersonatePrivilege, SeBackupPrivilege, SeDebugPrivilege) suscetíveis a ataques da família Potato (PrintSpoofer, GodPotato) para elevação a SYSTEM.",
                "params": f"Conta: '{acc}'. Análise de direitos de personificação de token e vetores de dump LSASS.",
            }

        if tool_name == "audit_cicd_workflow_poisoning":
            wf = arguments.get("workflow_name", "pipeline.yml")
            return {
                "what": f"Auditoria de pipeline poisoning e injeção de contexto em CI/CD ({wf}).",
                "why": "Identifica injeção direta de comandos via expressões não sanitizadas de contexto, checkout perigoso em pull_request_target e actions de terceiros sem pinning por commit SHA.",
                "params": f"Workflow: '{wf}'. Varredura estática de blocos 'run:', gatilhos e tags de actions.",
            }

        if tool_name == "audit_mtls_and_mesh_security":
            u = arguments.get("url", target)
            return {
                "what": f"Auditoria de robustez mTLS e injeção de cabeçalhos de certificado ({u}).",
                "why": "Verifica se malhas de serviço e proxies reversos aceitam ou refletem cabeçalhos forjados de certificado de cliente (X-Forwarded-Client-Cert) para contornar autenticação mTLS.",
                "params": f"URL: '{u}'. Probes de injeção de identidade de certificado Envoy/Nginx/Istio.",
            }

        if tool_name == "audit_ebpf_integrity_and_rootkits":
            h = arguments.get("host_name", "linux-host")
            return {
                "what": f"Auditoria de integridade e detecção de rootkits eBPF no kernel Linux ({h}).",
                "why": "Inspeciona programas eBPF carregados (kprobes, tracepoints, xdp) em busca de hooks furtivos em chamadas de sistema críticas e ocultação de processos.",
                "params": f"Host: '{h}'. Análise de metadados de programas eBPF, hooks de syscalls e namespaces.",
            }

        if tool_name == "execute":
            cmd = arguments.get("command", "").strip()
            return self._explain_shell_command(cmd, target)

        return {
            "what": f"Executa a ferramenta especializada '{tool_name}'.",
            "why": f"Avança a análise de segurança na fase de {self.current_phase}.",
            "params": f"Argumentos fornecidos: {json.dumps(arguments, ensure_ascii=False)}",
        }

    def _explain_shell_command(self, cmd: str, target: str) -> dict[str, str]:
        """Provide detailed pedagogical breakdown of shell commands and their arguments."""
        cmd_lower = cmd.lower()
        parts = cmd.split()
        binary = parts[0] if parts else "comando"

        # 1. Nmap
        if binary == "nmap" or "nmap" in parts:
            flags = []
            if "-sv" in cmd_lower:
                flags.append("-sV (determina a versão e nome do serviço rodando em cada porta)")
            if "-sc" in cmd_lower:
                flags.append("-sC (executa scripts padrão seguros de detecção e enumeração)")
            if "-p" in cmd_lower:
                flags.append("-p (define portas específicas, ex: 80,443 para web ou 1-65535)")
            if "-pn" in cmd_lower:
                flags.append("-Pn (ignora verificação de ping, ideal quando firewalls bloqueiam ICMP)")
            if "-oa" in cmd_lower or "-on" in cmd_lower:
                flags.append("-oA/-oN (salva os resultados estruturados em arquivo)")
            if "-t4" in cmd_lower or "-t" in cmd_lower:
                flags.append("-T (ajusta velocidade/agressividade do escaneamento)")
            flags_str = "; ".join(flags) if flags else "Varredura padrão de portas TCP"
            return {
                "what": "Varredura de portas e identificação de serviços com Nmap.",
                "why": f"Descobre quais portas de rede estão abertas no alvo ({target}) e quais aplicações específicas estão escutando nelas.",
                "params": f"Parâmetros: {flags_str}. Exemplo: detecta se a porta 80 roda Apache, Nginx ou IIS e qual a versão exata.",
            }

        # 2. Subfinder
        if "subfinder" in cmd_lower:
            return {
                "what": "Enumeração passiva de subdomínios (Subfinder).",
                "why": f"Descobre subdomínios vinculados ao alvo ({target}) através de dezenas de fontes públicas (OSINT) sem enviar tráfego direto ao alvo.",
                "params": "Flags comuns: -d (domínio principal), -all (todas as fontes de inteligência), -o (arquivo de saída).",
            }

        # 3. DNSX
        if "dnsx" in cmd_lower:
            return {
                "what": "Resolução e validação rápida de DNS em massa (DNSX).",
                "why": "Confirma quais subdomínios encontrados realmente resolvem para IPs válidos e descobre registros DNS (A, CNAME, MX).",
                "params": "Flags comuns: -l (lista de subdomínios), -a (registros IPv4), -resp (exibe resposta do servidor DNS).",
            }

        # 4. HTTPX
        if "httpx" in cmd_lower:
            return {
                "what": "Sonda HTTP e detecção de tecnologias web (HTTPX).",
                "why": "Verifica quais URLs e portas estão com servidores web ativos, identificando códigos de status (200, 301, 403), títulos e tecnologias.",
                "params": "Flags comuns: -tech-detect (detecta frameworks e servidores), -status-code (código HTTP retornado).",
            }

        # 5. Nuclei
        if "nuclei" in cmd_lower:
            return {
                "what": "Varredura de vulnerabilidades baseada em templates da comunidade (Nuclei).",
                "why": "Testa o alvo contra milhares de verificações de segurança conhecidas, CVEs recentes, painéis expostos e desconfigurações.",
                "params": "Flags comuns: -severity critical,high (foca em falhas de alto impacto), -t (templates específicos).",
            }

        # 6. FFUF / Feroxbuster / Gobuster
        if any(tool in cmd_lower for tool in ("ffuf", "feroxbuster", "gobuster")):
            return {
                "what": "Fuzzing e força-bruta de diretórios e arquivos web.",
                "why": "Localiza caminhos ocultos no servidor web, como painéis administrativos (/admin), arquivos de backup (.bak, .env) ou rotas de API.",
                "params": "Flags comuns: -u (URL alvo com FUZZ), -w (wordlist de termos), -mc (códigos de status aceitos).",
            }

        # 7. Katana
        if "katana" in cmd_lower:
            return {
                "what": "Web crawler e aranha de endpoints (Katana).",
                "why": "Navega automaticamente pelas páginas e scripts JavaScript do alvo para mapear links, formulários e rotas de API.",
                "params": "Mapeia a árvore de navegação e descobre parâmetros ocultos para teste.",
            }

        # 8. SQLmap
        if "sqlmap" in cmd_lower:
            return {
                "what": "Detecção e exploração automatizada de Injeção de SQL (SQLmap).",
                "why": "Testa parâmetros de entrada em busca de vulnerabilidades que permitam leitura ou alteração de dados no banco de dados.",
                "params": "Executa testes controlados de injeção booleana, baseada em tempo ou baseada em erro.",
            }

        # 9. Curl / Wget
        if any(tool in cmd_lower for tool in ("curl", "wget")):
            return {
                "what": "Requisição HTTP direta via terminal (cURL/Wget).",
                "why": "Inspeciona cabeçalhos de resposta HTTP, cookies de segurança ou testa métodos HTTP específicos (GET, POST, OPTIONS).",
                "params": "Envia requisição com parâmetros controlados para análise de resposta e cabeçalhos.",
            }

        # 10. Whois / Dig / Host
        if any(tool in cmd_lower for tool in ("whois", "dig", "host")):
            return {
                "what": "Consulta de informações de registro e infraestrutura de rede.",
                "why": "Coleta dados de proprietário do domínio, blocos de IP ASN e servidores DNS autoritativos.",
                "params": "Utiliza protocolos padrão de diretório de rede e DNS.",
            }

        # 11. WPScan
        if "wpscan" in cmd_lower:
            return {
                "what": "Auditoria especializada em CMS WordPress (WPScan).",
                "why": f"Examina {target} em busca de falhas no core, plugins e temas desatualizados ou vulneráveis, além de enumerar nomes de usuários reais.",
                "params": "Flags comuns: --enumerate vp (plugins vulneráveis), --enumerate u (usuários expostos), --no-banner.",
            }

        # Default fallback
        return {
            "what": f"Execução do utilitário de terminal '{binary}'.",
            "why": f"Comando acionado para coletar dados técnicos e avançar a análise de segurança contra {target}.",
            "params": f"Comando completo: {cmd}",
        }

    # -- Self-Evaluation -------------------------------------------------------

    async def _self_evaluate(self) -> dict:
        """Ask the LLM to evaluate its own progress and adjust strategy."""
        target = self.session.get("target", "unknown") if isinstance(self.session, dict) else "unknown"
        eval_prompt = (
            f"Você está na iteração {self.iteration} de uma avaliação de segurança contra '{target}'. "
            f"Fase atual: {self.current_phase}. Vulnerabilidades encontradas: {self.findings_count}.\n\n"
            "Avalie brevemente em português:\n"
            "1. Progresso: Está havendo progresso adequado? (sim/não + motivo)\n"
            "2. Cobertura: Quais áreas ou portas ainda não foram testadas?\n"
            "3. Próximos passos: Quais são as 2-3 ações mais importantes a seguir?\n"
            "4. Devemos avançar para a próxima fase? (sim/não)\n\n"
            "Responda em 3-5 frases diretas e profissionais."
        )
        try:
            # Use the FAST tier for the periodic self-check: it's a short progress
            # reflection, and routing it to the 32B model stalled the loop ~3 min
            # every 10 iterations. Keep the loop responsive.
            response = await self.llm.chat(
                messages=[
                    {"role": "system", "content": "Você é um avaliador técnico especialista em testes de intrusão e segurança cibernética."},
                    {"role": "user", "content": eval_prompt},
                ],
            )
            content = response.get("content", "")
            _, clean = self._extract_thinking(content)
            return {"status": "ok", "evaluation": clean or content}
        except Exception as e:
            return {"status": "error", "evaluation": f"Auto-avaliação falhou: {e}"}

    # -- Phase Management ----------------------------------------------------

    async def _evaluate_phase(self) -> dict | None:
        """Evaluate whether we should transition to the next phase."""
        phase_idx = PHASES.index(self.current_phase) if self.current_phase in PHASES else 0

        # Simple heuristic: check tool calls in recent messages
        recent_tools = []
        for msg in self.messages[-10:]:
            for tc in msg.get("tool_calls", []):
                fn = tc.get("function", {})
                recent_tools.append(fn.get("name", ""))

        # Phase transition logic
        new_phase = self.current_phase
        if self.current_phase == "recon":
            recon_tools = {"execute"}  # subfinder, nmap etc run via execute
            if len(recent_tools) >= 3:
                new_phase = "analysis"
        elif self.current_phase == "analysis":
            # Only move to exploit if there is actually something to exploit.
            # With zero findings after enough analysis, go straight to report
            # (conclude) instead of a pointless, slow exploit phase.
            if self.findings_count >= 1 or any(t == "create_finding" for t in recent_tools):
                new_phase = "exploit"
            elif len(recent_tools) >= 5:
                new_phase = "report"
        elif self.current_phase == "exploit":
            if self.findings_count >= 1:
                new_phase = "report"

        if new_phase != self.current_phase:
            old_phase = self.current_phase
            self.completed_phases.append(old_phase)
            self.current_phase = new_phase
            phase_map = {
                "recon": "RECONHECIMENTO",
                "analysis": "ANÁLISE DE VULNERABILIDADES",
                "exploit": "EXPLORAÇÃO CONTROLADA",
                "report": "RELATÓRIO FINAL",
            }
            old_str = phase_map.get(old_phase, old_phase.upper())
            new_str = phase_map.get(new_phase, new_phase.upper())
            return {
                "type": "phase_change",
                "from": old_phase,
                "to": new_phase,
                "completed_phases": self.completed_phases,
                "content": f"Transição de fase: {old_str} ➔ {new_str}",
            }
        return None

    # -- Context Compression -------------------------------------------------

    def _compress_context(self) -> tuple[int, int] | None:
        """Compress conversation history to avoid OOM or context overflow.
        Keeps system prompt + last 8 messages, summarizes the rest."""
        if len(self.messages) <= 12:
            return None

        before = len(self.messages)
        system_msg = self.messages[0] if self.messages[0].get("role") == "system" else None
        recent = self.messages[-8:]

        # Build summary of compressed messages
        compressed_msgs = self.messages[1:-8] if system_msg else self.messages[:-8]
        tool_calls = []
        for msg in compressed_msgs:
            for tc in msg.get("tool_calls", []):
                fn = tc.get("function", {})
                tool_calls.append(f"{fn.get('name', '?')}({json.dumps(fn.get('arguments', {}), default=str)[:80]})")

        summary = {
            "role": "system",
            "content": f"[CONTEXT COMPRESSED] Previous {len(compressed_msgs)} messages summarized:\n"
                       f"- Tool calls executed: {', '.join(tool_calls[:15]) or 'none'}\n"
                       f"- Findings so far: {self.findings_count}\n"
                       f"- Current phase: {self.current_phase}\n"
                       f"- Completed phases: {', '.join(self.completed_phases) or 'none'}\n"
                       f"Living operational memory is preserved in TARGET_MAP.md.",
        }

        self.messages = ([system_msg] if system_msg else []) + [summary] + recent
        return (before, len(self.messages))

    # -- Deep Recon Autostart -----------------------------------------------

    @staticmethod
    def _is_bare_domain(text: str) -> bool:
        """Check if input looks like just a bare domain."""
        text = text.strip().lower()
        # Match patterns like "example.com", "sub.example.com", "10.0.0.1"
        if re.match(r'^[a-z0-9]([a-z0-9\-]*\.)+[a-z]{2,}$', text):
            return True
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', text):
            return True
        return False

    @staticmethod
    def _expand_to_full_recon(target: str) -> str:
        return (
            f"Perform a comprehensive security assessment on {target}.\n\n"
            f"Execute the full reconnaissance pipeline:\n"
            f"1. Subdomain enumeration: subfinder -d {target} -all -o /workspace/output/subdomains.txt\n"
            f"2. DNS resolution: dnsx -l /workspace/output/subdomains.txt -a -resp -o /workspace/output/dns.txt\n"
            f"3. Live host detection: httpx-toolkit -l /workspace/output/subdomains.txt -tech-detect -status-code -o /workspace/output/live.txt\n"
            f"4. Port scanning: nmap -sT -Pn -sV -iL /workspace/output/live.txt -oA /workspace/output/nmap\n"
            f"5. Vulnerability scanning: nuclei -l /workspace/output/live.txt -severity critical,high -rl 50 -o /workspace/output/vulns.txt\n"
            f"6. For any discovered web apps, test for SQLi, XSS, and other common vulns\n"
            f"7. Create findings for all confirmed vulnerabilities\n\n"
            f"Analyze all output at each step. Chain results between steps."
        )

    @classmethod
    def _detect_explicit_requested_tools(cls, user_input: str) -> list[str]:
        """Extract specific targeted tools if the operator asked for explicit checks."""
        if not user_input:
            return []
        text = user_input.lower()
        tools = []

        # Strip URLs and domain names to prevent target names from falsely triggering keyword detection
        # (e.g. 'analysislaudo.ddns.net' containing 'dns', or 'waf.corp.com' containing 'waf')
        text_clean = re.sub(r'https?://\S+', ' ', text)
        text_clean = re.sub(r'\b[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-\.]+\b', ' ', text_clean)

        def _match_any(words: tuple[str, ...]) -> bool:
            for w in words:
                if len(w) <= 4:
                    if re.search(r'\b' + re.escape(w) + r'\b', text_clean):
                        return True
                else:
                    if w in text_clean:
                        return True
            return False

        # Security headers / CSP / HSTS / Cookies
        if _match_any(("cabeçalho", "cabecalho", "header", "csp", "hsts", "cookie")):
            tools.append("audit_security_headers")
        # SSL / TLS / Certificate
        if _match_any(("ssl", "tls", "certificado", "cipher", "criptografia")):
            tools.append("audit_tls_ssl")
        # DNS / SPF / DMARC / MX / Email security
        if _match_any(("spf", "dmarc", "dkim", "mx", "dns_email", "anti-spoofing", "spoofing de e-mail")) or (
            re.search(r'\b(registros? dns|servidor dns|auditoria dns|zona dns|consulta dns)\b', text_clean)
            or (re.search(r'\bdns\b', text_clean) and "ddns" not in text_clean and "passivo" not in text_clean and "subdom" not in text_clean and "reputação" not in text_clean and "blacklist" not in text_clean and "dnsbl" not in text_clean)
        ):
            tools.append("audit_dns_email_security")
        # Certificate Transparency
        if _match_any(("certificate transparency", "cert transparency", "crt.sh", "certificados passivos")):
            tools.append("search_cert_transparency")
        # Subdomain Takeover
        if _match_any(("subdomain takeover", "takeover", "cname órfão", "cname orfao", "subdomínio órfão")):
            tools.append("audit_subdomain_takeover")
        # IP Intelligence & Enrichment
        if _match_any(("enrich_ip", "ip intel", "inteligência de ip", "asn", "geolocalização", "geolocalizacao")):
            tools.append("enrich_ip_intel")
        # WHOIS / RDAP / Domain registration / CNPJ
        if _match_any(("whois", "rdap", "titular", "cnpj", "registro.br", "registrar")):
            tools.append("query_whois_rdap")
        # WAF / Firewall detection
        if _match_any(("waf", "firewall", "cloudflare", "imperva", "modsecurity")):
            tools.append("detect_waf_firewall")
        # Git / Env leakage / Sensitive files
        if _match_any((".git", ".env", "arquivo sensível", "arquivos sensíveis", "backup", "vazamento de código")):
            tools.append("audit_git_and_env_leakage")
        # Reputation / DNSBL / Blacklists
        if _match_any(("dnsbl", "blacklist", "spamhaus", "reputação", "reputacao")):
            tools.append("audit_dnsbl_reputation")
        # Threat feeds / IOCs
        if _match_any(("threat feed", "ioc", "urlhaus", "abuseipdb", "inteligência de ameaças")):
            tools.append("query_threat_feeds")
        # Compliance / OWASP / LGPD
        if _match_any(("compliance", "lgpd", "owasp", "conformidade", "matriz")):
            tools.append("audit_compliance_matrix")

        # Cloud Storage / S3 / Buckets
        if _match_any(("bucket", "s3", "cloud storage", "azure blob", "blob storage", "armazenamento em nuvem")):
            tools.append("audit_cloud_storage")
            tools.append("audit_s3_bucket_permissions_deep")

        # SSRF / Cloud Metadata / IMDS
        if _match_any(("imds", "imdsv2", "imdsv1", "metadados", "ssrf")):
            tools.append("audit_ssrf_cloud_metadata")

        # Hardening Baseline / IAM Policies
        if _match_any(("políticas iam", "politicas iam", "hardening baseline", "baseline cis", "guia de hardening", "guia executivo de hardening")):
            tools.append("generate_hardening_baseline")

        # Containers / Docker / K8s Breakout
        if _match_any(("dockerfile", "imagem de contêiner", "imagem de conteiner")):
            tools.append("audit_dockerfile_security")
        if _match_any(("rbac", "clusterrole", "kubernetes", "k8s")):
            tools.append("audit_kubernetes_rbac")
        if _match_any(("breakout", "fuga de contêiner", "fuga de conteiner", "container breakout")):
            tools.append("audit_container_breakout_vectors")

        # CI/CD & Supply Chain
        if _match_any(("ci/cd", "cicd", "pipeline", "github actions", "gitlab ci", "runner")):
            tools.append("audit_cicd_pipeline_security")
        if _match_any(("dependency confusion", "namespaces órfãos", "namespaces orfaos", "npm", "pypi")):
            tools.append("audit_dependency_confusion_and_namespaces")
        if _match_any(("sbom", "dependências vulneráveis", "dependencias vulneraveis")):
            tools.append("audit_sbom_dependencies")

        # AI / LLM Guardrails & Vector DB
        if _match_any(("prompt injection", "jailbreak", "guardrail", "llm")):
            tools.append("audit_llm_prompt_injection_and_jailbreaks")
        if _match_any(("vector db", "banco vetorial", "pinecone", "chroma", "qdrant", "rag")):
            tools.append("audit_vector_database_exposure")

        # Forensic / DFIR / Incident Response
        if _match_any(("forense", "forensic", "artefato forense", "artefatos forenses", "conexões ativas", "conexoes ativas", "beaconing")):
            tools.append("analyze_forensic_artifacts")
        if _match_any(("yara", "regra yara", "assinatura yara")):
            tools.append("generate_yara_rule")
        if _match_any(("playbook", "resposta a incidentes", "ir playbook")):
            tools.append("generate_ir_playbook")

        # BAS & MITRE & Atomic Tests
        if _match_any(("atomic test", "teste atômico", "teste atomico", "t1003", "t1059", "t1082")):
            tools.append("generate_atomic_test")
        if _match_any(("scorecard", "picus", "eficácia defensiva", "eficacia defensiva")):
            tools.append("evaluate_defensive_efficacy")
        if _match_any(("mitre attack", "matriz mitre", "táticas mitre", "taticas mitre")):
            tools.append("map_mitre_attack")
        if _match_any(("sigma", "regra de detecção", "regras de detecção", "regras sigma", "kql", "spl")):
            tools.append("generate_detection_rules")

        # Active Directory & Kerberos
        if _match_any(("active directory", "ad dacl", "choke point", "tier zero")):
            tools.append("analyze_active_directory")
            tools.append("audit_ad_dacl_abuse_paths")
        if _match_any(("kerberoast", "kerberoasting", "spn")):
            tools.append("audit_kerberoasting_surface")

        # Identity Hygiene / MTA-STS / BIMI
        if _match_any(("higiene de identidade", "governança iam", "governanca iam", "mfa")):
            tools.append("audit_identity_access_hygiene")
        if _match_any(("mta-sts", "dane", "tlsrpt", "tls-rpt")):
            tools.append("audit_mta_sts_dane")
        if _match_any(("bimi", "dkim e bimi")):
            tools.append("audit_dkim_bimi")

        # CORS & HTTP Methods & Rate Limiting & APIs
        if _match_any(("cors", "cross-origin")):
            tools.append("audit_cors_advanced")
        if _match_any(("métodos http", "metodos http", "verbos http")):
            tools.append("audit_http_methods")
        if _match_any(("rate limit", "rate limiting", "throttling")):
            tools.append("audit_rate_limiting")
        if _match_any(("api spec", "openapi", "swagger")):
            tools.append("audit_api_spec")
        if _match_any(("idor", "bola", "bfla")):
            tools.append("audit_api_idor_matrix")

        # Reverse Proxy & Binary Protections
        if _match_any(("proxy reverso", "reverse proxy")):
            tools.append("audit_reverse_proxy_path_traversal")
        if _match_any(("proteções binárias", "protecoes binarias", "aslr", "dep", "runasppl", "lsass")):
            tools.append("audit_binary_protections")

        # WAF Bypass Heuristics
        if _match_any(("waf bypass", "normalização de payloads", "normalizacao de payloads")):
            tools.append("audit_waf_bypass_heuristics")

        # Zero Trust & mTLS & Service Mesh
        if _match_any(("zero trust", "mtls", "service mesh", "istio", "envoy", "client cert", "mutual tls")):
            tools.append("audit_mtls_and_mesh_security")

        # ADCS / PKI / Certificate Templates
        if _match_any(("adcs", "pki", "esc1", "template de certificado", "certificados de domínio", "certificados corporativos")):
            tools.append("audit_adcs_certificate_templates")
            tools.append("audit_kerberos_delegation_risks")

        # JWT & Tokens
        if _match_any(("jwt", "json web token", "alg none", "token jwt")):
            tools.append("audit_jwt_security")

        # OAuth 2.0 / SSO / SAML
        if _match_any(("oauth", "openid", "sso", "saml", "xml signature", "asserções saml", "assercoes saml")):
            tools.append("audit_oauth_sso")
            tools.append("audit_saml_xml_security")

        # NTLM Relay & SMB Signing & Coercion
        if _match_any(("ntlm relay", "petitpotam", "spoolsample", "coerção ntlm", "coercao ntlm")):
            tools.append("audit_ntlm_relay_coercion")
        if _match_any(("smb signing", "assinatura smb", "sessões nulas", "sessoes nulas", "null session")):
            tools.append("audit_smb_signing_and_null_sessions")

        # HTTP Request Smuggling & Web Cache Poisoning
        if _match_any(("request smuggling", "smuggling", "cl.te", "te.cl", "dessincronização http", "dessincronizacao http")):
            tools.append("audit_http_request_smuggling")
        if _match_any(("cache poisoning", "envenenamento de cache")):
            tools.append("audit_web_cache_poisoning")

        # Linux Local PrivEsc & eBPF
        if _match_any(("privesc linux", "escalação de privilégios linux", "escalacao de privilegios linux", "suid perigoso")):
            tools.append("audit_linux_privesc_vectors")
        if _match_any(("ebpf", "rootkit linux", "tracepoint")):
            tools.append("audit_ebpf_integrity_and_rootkits")


        # Any native tool explicitly named in the prompt (e.g. `audit_security_headers`, `search_cert_transparency`, etc.)
        for t in NATIVE_TOOLS:
            t_name = t["function"]["name"]
            if t_name == "execute":
                continue
            if t_name in text:
                tools.append(t_name)

        return list(dict.fromkeys(tools))

    @classmethod
    def _user_requested_summary(cls, user_input: str) -> bool:
        """Check if operator requested a summary, explanation, or Portuguese report."""
        if not user_input:
            return False
        text = user_input.lower()
        return any(w in text for w in (
            "resumo", "resuma", "explique", "explicar", "mostre", "mostrar",
            "apresente", "relatorio", "relatório", "diagnóstico", "diagnostico",
            "qual é", "quais são", "o que encontrou", "em português", "em portugues",
            "tabela", "compile", "quadro", "score", "resultado", "conclusão", "conclua"
        ))

    # -- Scope enforcement --------------------------------------------------

    # File extensions that look like hostnames (end in a dotted suffix) but are
    # really file paths — must NOT be treated as scan targets.
    _FILE_EXT_DENY = {
        "txt", "json", "html", "htm", "php", "js", "css", "xml", "csv", "md",
        "log", "sh", "py", "conf", "cfg", "ini", "yaml", "yml", "bak", "sql",
        "zip", "tar", "gz", "tgz", "png", "jpg", "jpeg", "gif", "hprof", "pem",
        "key", "crt", "pdf", "out", "list", "dic", "jsonl", "ttf",
    }

    # Public DNS resolvers and localhost interfaces used by diagnostic tools (dig, nslookup, curl)
    # that must NEVER be misidentified as out-of-scope targets.
    _COMMON_INFRASTRUCTURE_IPS = {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "127.0.0.1", "0.0.0.0", "::1"
    }

    @staticmethod
    def _is_cidr(s: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_network(s, strict=False)
            return "/" in s
        except ValueError:
            return False

    def _auto_repair_target_arguments(self, tool_name: str, arguments: dict) -> dict:
        """If a small local model accidentally copied documentation example domains
        (such as 'corp.com.br' or 'example.com') from tool schemas, or used public DNS
        resolvers (like '8.8.8.8') as the audit target, automatically substitute them
        with the session's actual authorized target and normalize parameter names."""
        if not isinstance(arguments, dict):
            return arguments
        s = self.session
        target = (s.get("target") if isinstance(s, dict) else getattr(s, "target", "")) or ""
        if not target or target == "*":
            return arguments
        clean_target = re.sub(r'^https?://', '', target.lower()).split('/')[0].split(':')[0]
        if not clean_target:
            return arguments

        repaired = dict(arguments)

        # 1. Parameter name aliases for known native tools
        if tool_name in ("audit_tls_ssl", "audit_smb_signing_and_null_sessions"):
            if "host" not in repaired:
                for alt in ("hostname", "target", "domain", "url"):
                    if alt in repaired:
                        repaired["host"] = repaired.pop(alt)
                        break
        elif tool_name in ("query_whois_rdap", "audit_dns_email_security", "audit_dkim_bimi",
                           "audit_subdomain_takeover", "search_cert_transparency", "search_historical_urls",
                           "audit_dns_zone_transfer_and_nsec", "audit_mta_sts_dane",
                           "audit_adcs_certificate_templates", "audit_kerberos_delegation_risks"):
            if "domain" not in repaired:
                for alt in ("target", "host", "hostname", "url"):
                    if alt in repaired:
                        repaired["domain"] = repaired.pop(alt)
                        break
        elif tool_name in ("audit_security_headers", "detect_waf_firewall", "audit_well_known_security",
                           "audit_git_and_env_leakage", "audit_http_methods", "scan_exposed_secrets",
                           "audit_cors_advanced", "audit_rate_limiting", "audit_websocket_security",
                           "audit_supply_chain_libs", "audit_waf_bypass_heuristics", "audit_graphql_security",
                           "audit_ssrf_cloud_metadata", "audit_mtls_and_mesh_security",
                           "audit_http_request_smuggling", "audit_web_cache_poisoning",
                           "audit_reverse_proxy_path_traversal"):
            if "url" not in repaired:
                for alt in ("target", "host", "hostname", "domain"):
                    if alt in repaired:
                        repaired["url"] = repaired.pop(alt)
                        break
        elif tool_name in ("audit_dnsbl_reputation", "query_threat_feeds", "enrich_ip_intel",
                           "audit_cloud_storage", "audit_compliance_matrix", "audit_ntlm_relay_coercion"):
            if "target" not in repaired:
                for alt in ("host", "domain", "ioc", "ip", "url"):
                    if alt in repaired:
                        repaired["target"] = repaired.pop(alt)
                        break
        elif tool_name == "audit_jwt_security":
            if "token" not in repaired:
                repaired["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            if "url" not in repaired:
                repaired["url"] = f"https://{clean_target}"
        elif tool_name == "audit_oauth_sso":
            if "authorization_url" not in repaired:
                repaired["authorization_url"] = f"https://{clean_target}/oauth/authorize"
        elif tool_name == "audit_saml_xml_security":
            if "metadata_url" not in repaired:
                repaired["metadata_url"] = f"https://{clean_target}/saml/metadata"
        elif tool_name == "audit_linux_privesc_vectors":
            if "target_name" not in repaired:
                repaired["target_name"] = clean_target
            if "system_info" not in repaired:
                repaired["system_info"] = {
                    "os": "linux", "kernel": "5.15.0",
                    "sudo_l": "ALL=(ALL) NOPASSWD: /usr/bin/find",
                    "suid_binaries": ["/usr/bin/pkexec", "/usr/bin/find"]
                }
        elif tool_name == "audit_ebpf_integrity_and_rootkits":
            if "host_name" not in repaired:
                repaired["host_name"] = clean_target
            if "ebpf_programs" not in repaired:
                repaired["ebpf_programs"] = [{"id": 1, "type": "kprobe", "name": "trace_exec", "tag": "d570b56f3547ec59"}]


        # 2. Value substitutions: replace placeholders and rogue infrastructure IPs
        placeholders = ("corp.com.br", "example.com", "target.com", "example.org", "test.com", "example.net")
        is_clean_infra = clean_target in self._COMMON_INFRASTRUCTURE_IPS

        for k, v in list(repaired.items()):
            if isinstance(v, str):
                v_clean = v.strip().lower()
                # If value is an infrastructure IP (e.g. 8.8.8.8) and the session target is not that IP, replace it!
                if not is_clean_infra and v_clean in self._COMMON_INFRASTRUCTURE_IPS:
                    repaired[k] = clean_target
                else:
                    for placeholder in placeholders:
                        if placeholder in v_clean:
                            repaired[k] = re.sub(re.escape(placeholder), clean_target, v, flags=re.I)
                            break
            elif isinstance(v, list):
                new_list = []
                for item in v:
                    if isinstance(item, str):
                        item_clean = item.strip().lower()
                        if not is_clean_infra and item_clean in self._COMMON_INFRASTRUCTURE_IPS:
                            item = clean_target
                        else:
                            for placeholder in placeholders:
                                if placeholder in item_clean:
                                    item = re.sub(re.escape(placeholder), clean_target, item, flags=re.I)
                                    break
                    new_list.append(item)
                repaired[k] = new_list

        # 3. Format normalization: URL prefix vs bare domain/host
        for k, v in list(repaired.items()):
            if isinstance(v, str):
                if k == "url":
                    if not v.startswith(("http://", "https://", "ws://", "wss://")):
                        repaired[k] = f"https://{v}"
                elif k in ("host", "hostname", "domain"):
                    repaired[k] = re.sub(r'^https?://', '', v).split('/')[0].split(':')[0]

        return repaired

    def _extract_target_hosts(self, text: str) -> set:
        """Pull candidate target hosts/IPs from a shell command or URL, while
        avoiding false positives from file paths (e.g. wordlist.txt, -oA out)
        and public infrastructure resolvers (e.g. 8.8.8.8, 1.1.1.1)."""
        hosts = set()
        if not text:
            return hosts
        for h in re.findall(r'https?://([A-Za-z0-9._\-]+)', text):
            hosts.add(h.split(':')[0].lower().rstrip('.'))
        for ip in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text):
            if ip not in self._COMMON_INFRASTRUCTURE_IPS:
                hosts.add(ip)
        # bare domains: exclude when preceded by '/', '.', '-', '@' or a word char
        # so we never match a path component or a SUFFIX inside a larger host.
        for m in re.finditer(r'(?<![/\w.\-@])([A-Za-z0-9][A-Za-z0-9\-]*(?:\.[A-Za-z0-9\-]+)+)', text):
            tok = m.group(1).lower().rstrip('.')
            if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', tok):
                if tok not in self._COMMON_INFRASTRUCTURE_IPS:
                    hosts.add(tok)
                continue
            if tok.rsplit('.', 1)[-1] in self._FILE_EXT_DENY:
                continue
            hosts.add(tok)
        return hosts

    def _scope_spec(self):
        """Return (include_globs, exclude_globs, cidrs) derived from the session
        scope and target. Empty includes+cidrs means 'no scope defined'."""
        s = self.session
        target = (s.get("target") if isinstance(s, dict) else getattr(s, "target", "")) or ""
        scope = s.get("scope") if isinstance(s, dict) else getattr(s, "scope", None)
        if isinstance(scope, str):
            try:
                scope = json.loads(scope)
            except Exception:
                scope = None if scope.strip() in ("", "*") else {"include": [scope]}
        includes, excludes, cidrs = [], [], []
        if isinstance(scope, dict):
            for x in (scope.get("include") or []):
                x = str(x).lower()
                (cidrs if self._is_cidr(x) else includes).append(x)
            excludes = [str(x).lower() for x in (scope.get("exclude") or [])]
        target = target.strip()
        if target and target != "*":
            if self._is_cidr(target):
                cidrs.append(target.lower())
            else:
                t = re.sub(r'^https?://', '', target.lower()).split('/')[0].split(':')[0]
                if t:
                    if not includes and not cidrs:
                        includes = [t, f"*.{t}"]
                    elif t not in includes:
                        includes.append(t)
        return includes, excludes, cidrs

    def _scope_label(self) -> str:
        inc, exc, cidrs = self._scope_spec()
        parts = inc + cidrs
        return ", ".join(parts) if parts else "não definido"

    def _host_in_scope(self, host: str, includes, excludes, cidrs) -> bool:
        import fnmatch
        import ipaddress
        h = host.lower()
        if h in ("localhost", "127.0.0.1", "::1") or h.startswith("127."):
            return True  # sandbox loopback is internal, not the target
        for ex in excludes:
            if h == ex or fnmatch.fnmatch(h, ex):
                return False
        try:
            ip = ipaddress.ip_address(h)
            for c in cidrs:
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
        except ValueError:
            pass
        for inc in includes:
            if h == inc or fnmatch.fnmatch(h, inc):
                return True
        return False

    def _scope_violation(self, tool_name: str, arguments: dict):
        """Return the first out-of-scope host for a target-touching tool, else None."""
        target_touching = (
            "execute", "browser_action", "audit_security_headers",
            "audit_dns_email_security", "scan_exposed_secrets",
            "audit_tls_ssl", "audit_api_spec", "query_whois_rdap",
            "enrich_ip_intel", "search_historical_urls",
            "search_cert_transparency", "audit_well_known_security",
            "audit_cloud_storage", "audit_subdomain_takeover",
            "detect_waf_firewall", "audit_cors_advanced", "audit_http_methods",
            "audit_rate_limiting", "audit_websocket_security",
            "audit_supply_chain_libs", "audit_compliance_matrix",
            "audit_graphql_security", "audit_oauth_sso",
            "audit_dnsbl_reputation", "generate_atomic_test",
            "simulate_attack_path",
            "audit_ssrf_cloud_metadata", "audit_api_idor_matrix",
            "audit_prototype_pollution", "audit_dkim_bimi", "query_threat_feeds",
            "audit_waf_bypass_heuristics", "audit_saml_xml_security",
            "audit_web_cache_poisoning", "audit_api_mass_assignment",
            "audit_mta_sts_dane",
            "audit_http_request_smuggling", "audit_ssti_injection",
            "audit_nosql_injection", "generate_subdomain_permutations",
            "audit_ntlm_relay_coercion",
            "audit_race_conditions_concurrency", "audit_xxe_injection",
            "audit_open_redirect_bypasses", "audit_ldap_injection",
            "audit_grpc_api_security", "audit_insecure_deserialization",
            "audit_crlf_header_injection", "audit_reverse_proxy_path_traversal",
            "audit_s3_bucket_permissions_deep",
            "audit_git_and_env_leakage", "audit_content_security_policy_deep",
            "audit_api_excessive_data_exposure", "audit_dns_zone_transfer_and_nsec",
            "audit_smtp_open_relay_and_spoofing",
            "audit_server_side_prototype_pollution", "audit_ip_spoofing_access_controls",
            "audit_kerberos_delegation_risks", "audit_http3_quic_exposure",
            "audit_snmp_community_exposure",
            "audit_adcs_certificate_templates", "audit_smb_signing_and_null_sessions",
            "audit_postmessage_messaging_security", "audit_http_parameter_pollution",
            "audit_container_breakout_vectors",
            "audit_clickjacking_and_ui_redressing", "audit_bfla_api_authorization",
            "audit_kerberoasting_surface", "audit_linux_privesc_vectors",
            "audit_llm_prompt_injection_and_jailbreaks", "audit_vector_database_exposure",
            "audit_subresource_integrity_sri", "audit_dependency_confusion_and_namespaces",
            "audit_webhook_ssrf_and_dns_rebinding",
            "audit_ad_dacl_abuse_paths", "audit_windows_token_privileges",
            "audit_cicd_workflow_poisoning", "audit_mtls_and_mesh_security",
            "audit_ebpf_integrity_and_rootkits",
        )
        if tool_name not in target_touching:
            return None
        text = arguments.get("command", "") if tool_name == "execute" else (
            arguments.get("url") or arguments.get("domain") or arguments.get("hostname") or
            arguments.get("target") or arguments.get("authorization_url") or
            arguments.get("target_url") or arguments.get("entry_point") or
            arguments.get("metadata_url") or arguments.get("bucket_name") or
            arguments.get("host") or arguments.get("ioc") or ""
        )
        includes, excludes, cidrs = self._scope_spec()
        if not includes and not cidrs:
            return None  # no scope configured — cannot enforce (operator-driven)
        for host in self._extract_target_hosts(text):
            if not self._host_in_scope(host, includes, excludes, cidrs):
                return host
        return None

    # -- Risk Assessment for Copilot ----------------------------------------

    @staticmethod
    def _assess_risk(tool_name: str, arguments: dict) -> str:
        """Assess risk level for copilot mode suggestions."""
        cmd = arguments.get("command", "").lower()

        high_risk = ["sqlmap", "metasploit", "hydra", "hashcat", "exploit", "pwncat", "sliver",
                      "bettercap", "mimikatz", "--risk 3", "--level 5"]
        medium_risk = ["nuclei", "ffuf", "feroxbuster", "dalfox", "wpscan", "nikto",
                       "nmap -sV", "nmap -sC", "arjun"]
        low_risk = ["subfinder", "dnsx", "httpx", "katana", "theHarvester", "whois",
                     "dig", "host", "curl", "wget", "sherlock", "holehe", "exiftool"]

        if any(r in cmd for r in high_risk):
            return "HIGH"
        if any(r in cmd for r in medium_risk):
            return "MEDIUM"
        if any(r in cmd for r in low_risk):
            return "LOW"

        # Default based on tool name
        if tool_name == "execute":
            return "MEDIUM"
        # Internal/bookkeeping and passive defensive audit tools carry no or minimal target-facing risk.
        if tool_name in ("browser_action", "web_search", "read_file", "create_file",
                         "search_cve", "read_memory", "update_memory",
                         "query_playbook", "save_playbook", "create_finding",
                         "audit_security_headers", "audit_dns_email_security",
                         "scan_exposed_secrets", "audit_tls_ssl", "audit_api_spec",
                         "query_whois_rdap", "enrich_ip_intel", "search_historical_urls",
                         "search_cert_transparency", "enrich_cve_threat",
                         "audit_well_known_security", "audit_cloud_storage",
                         "audit_subdomain_takeover", "detect_waf_firewall",
                         "audit_cors_advanced", "audit_http_methods",
                         "map_mitre_attack", "generate_detection_rules",
                         "audit_jwt_security", "audit_rate_limiting",
                         "audit_websocket_security", "audit_supply_chain_libs",
                         "audit_compliance_matrix",
                         "generate_atomic_test", "simulate_attack_path",
                         "audit_graphql_security", "audit_oauth_sso",
                         "generate_ir_playbook", "audit_dnsbl_reputation",
                         "generate_canary_tokens",
                         "audit_ssrf_cloud_metadata", "calculate_cvss_vector",
                         "audit_api_idor_matrix", "audit_prototype_pollution",
                         "generate_hardening_baseline", "audit_dkim_bimi",
                         "query_threat_feeds",
                         "audit_waf_bypass_heuristics", "audit_sbom_dependencies",
                         "audit_saml_xml_security", "generate_yara_rule",
                         "audit_dockerfile_security", "audit_kubernetes_rbac",
                         "calculate_breach_risk_cost",
                         "audit_iac_misconfigurations", "audit_cicd_pipeline_security",
                         "audit_web_cache_poisoning", "audit_api_mass_assignment",
                         "audit_mta_sts_dane", "audit_identity_access_hygiene",
                         "analyze_forensic_artifacts", "audit_binary_protections",
                         "audit_http_request_smuggling", "audit_ssti_injection",
                         "audit_nosql_injection", "generate_subdomain_permutations",
                         "audit_ntlm_relay_coercion", "simulate_cloud_iam_privesc",
                         "audit_race_conditions_concurrency", "audit_dom_clobbering",
                         "audit_xxe_injection", "audit_open_redirect_bypasses",
                         "audit_ldap_injection", "audit_grpc_api_security",
                         "audit_insecure_deserialization", "audit_crlf_header_injection",
                         "audit_reverse_proxy_path_traversal", "audit_s3_bucket_permissions_deep",
                         "audit_git_and_env_leakage", "audit_content_security_policy_deep",
                         "audit_api_excessive_data_exposure", "audit_dns_zone_transfer_and_nsec",
                         "audit_smtp_open_relay_and_spoofing",
                         "audit_server_side_prototype_pollution", "audit_ip_spoofing_access_controls",
                         "audit_kerberos_delegation_risks", "audit_http3_quic_exposure",
                         "audit_snmp_community_exposure",
                         "audit_adcs_certificate_templates", "audit_smb_signing_and_null_sessions",
                         "audit_postmessage_messaging_security", "audit_http_parameter_pollution",
                         "audit_container_breakout_vectors",
                         "audit_clickjacking_and_ui_redressing", "audit_bfla_api_authorization",
                         "audit_kerberoasting_surface", "audit_linux_privesc_vectors",
                         "audit_llm_prompt_injection_and_jailbreaks", "audit_vector_database_exposure",
                         "audit_subresource_integrity_sri", "audit_dependency_confusion_and_namespaces",
                         "audit_webhook_ssrf_and_dns_rebinding",
                         "audit_ad_dacl_abuse_paths", "audit_windows_token_privileges",
                         "audit_cicd_workflow_poisoning", "audit_mtls_and_mesh_security",
                         "audit_ebpf_integrity_and_rootkits",
                         "verify_detection_active"):
            return "LOW"
        return "MEDIUM"

    # -- Operational Memory & Living Scratchpad -------------------------------

    def _get_living_memory_summary(self) -> str:
        """Extract a high-density, compact summary of discovered assets (max 250 tokens)."""
        if not hasattr(self, "tool_executor") or not self.tool_executor:
            return ""
        try:
            target_map_file = self.tool_executor._get_wiki_path("target_map")
            if target_map_file.exists():
                lines = target_map_file.read_text(encoding="utf-8").splitlines()
                table_lines = [l for l in lines if l.startswith("|") and not l.startswith("| Host") and not l.startswith("| :--")][:10]
                if table_lines:
                    summary = "\n".join(table_lines)
                    return f"""
## Living Operational Memory (Discovered Topology & Ports)
| Host / IP | Port | Service | Product / Version | Notes |
| :--- | :--- | :--- | :--- | :--- |
{summary}
*(Use read_memory/update_memory for full records. Use query_playbook for attack techniques.)*
"""
        except Exception:
            pass
        return ""

    # -- System Prompt -------------------------------------------------------

    async def _build_system_prompt(self) -> str:
        s = self.session
        name = s.get("name", "unknown") if isinstance(s, dict) else getattr(s, "name", "unknown")
        target = s.get("target", "*") if isinstance(s, dict) else getattr(s, "target", "*")
        scope = s.get("scope", "*") if isinstance(s, dict) else getattr(s, "scope", "*")

        tools_list = ", ".join(t["function"]["name"] for t in NATIVE_TOOLS)
        mode_val = getattr(self, "mode", "offensive")

        return f"""Você é o Arcanum, um agente autônomo profissional de reconhecimento de segurança e testes de intrusão (pentest).
Você realiza avaliações de segurança autorizadas utilizando ferramentas profissionais dentro de um ambiente sandbox isolado.

## Operação Atual
- Sessão: {name}
- Alvo: {target}
- Modo: {mode_val}
- Escopo: {scope}

## Diretrizes de Idioma e Execução de Ferramentas (OBRIGATÓRIO)
1. Toda a sua comunicação e raciocínio textual com o operador DEVE ser em Português do Brasil (pt-BR).
2. Para interagir com o alvo '{target}', INVOQUE A FERRAMENTA DIRETAMENTE (chame 'execute' com comandos reais como nmap, subfinder, httpx, nuclei, ou ferramentas nativas como read_memory). NUNCA apenas escreva tutoriais longos ou blocos de código JSON simulado em markdown: chame a ferramenta imediatamente.
3. Proponha ou execute UMA AÇÃO TÁTICA POR VEZ adequada à fase atual ({self.current_phase}). Não tente listar múltiplos passos futuros de uma vez só.
4. Mantenha seus comentários textuais breves e objetivos (1 a 2 frases), pois o motor Arcanum já gera automaticamente a explicação técnica detalhada e pedagógica (O que faz, Por que executar e Parâmetros) de cada comando para o operador.

## Regra Fundamental de Alvo e Parâmetros (CRÍTICO)
1. O ALVO REAL E EXCLUSIVO DESTA OPERAÇÃO É: '{target}'.
2. AO CHAMAR QUALQUER FERRAMENTA NATIVA OU COMANDO ('execute'):
   - SEMPRE forneça '{target}' (ou subdomínios descobertos pertencentes a '{target}').
   - NUNCA copie ou use exemplos genéricos de documentação como 'corp.com.br', 'example.com' ou '8.8.8.8'.
   - Exemplos corretos para este alvo:
     * Para cabeçalhos: audit_security_headers(url="https://{target}")
     * Para SSL/TLS: audit_tls_ssl(host="{target}")
     * Para DNS: audit_dns_email_security(domain="{target}")
     * Para arquivos sensíveis: audit_git_and_env_leakage(url="https://{target}")
     * Para subdomínios: execute(command="subfinder -d {target} -silent")
3. PRIORIZAÇÃO DE SOLICITAÇÕES EXPLÍCITAS DO OPERADOR:
   - Se o operador solicitar expressamente cabeçalhos de segurança HTTP, chame audit_security_headers(url="https://{target}").
   - Se o operador solicitar certificado SSL/TLS, chame audit_tls_ssl(host="{target}").
   - Se o operador pedir um "resumo em português", após executar as ferramentas necessárias, apresente uma síntese técnica didática em Português do Brasil (pt-BR) explicando as notas, os riscos e as recomendações defensivas.

## Regras Operacionais
1. NUNCA opere fora do escopo definido ({scope}).
2. Sempre verifique se os alvos estão dentro do escopo antes de executar qualquer ferramenta.
3. Documente CADA descoberta com evidências claras e prova de conceito (PoC).
4. Siga o princípio do menor privilégio.
5. Se descobrir credenciais, chaves de API ou dados sensíveis, guarde-os no cofre (stash_artifact) e mascare nas saídas.
6. Apenas crie vulnerabilidades (create_finding) para falhas VERIFICADAS com PoC funcional.
7. Mantenha consciência situacional: consulte a memória viva (read_memory), o grafo do alvo (query_graph) e playbooks (query_playbook).
8. Use query_graph para ver hosts/portas/serviços/tecnologias já mapeados e os achados candidatos (serviços sensíveis expostos) antes de decidir o próximo passo — não re-escaneie o que já está no grafo.

## Modos de Operação
- **autopilot**: Executa ferramentas automaticamente em cadeia. Avança pelas fases.
- **copilot**: Sugere chamadas de ferramentas com avaliação de risco e explicações didáticas. Aguarda confirmação do operador.
- **manual**: Executa ferramentas somente quando solicitado explicitamente pelo operador. Fornece orientação técnica especialista e explicações.

## Regras de Seleção de Ferramentas
1. As ferramentas disponíveis para a fase atual chegam no parâmetro de ferramentas, cada uma com sua descrição — escolha a mais adequada ao pedido do operador e à fase atual. Prefira ferramentas nativas (audit_*, query_*, search_*, enrich_*) e use 'execute' para comandos reais no sandbox (nmap, subfinder, httpx-toolkit, nuclei, wpscan, ffuf, curl, sqlmap).
2. NUNCA rode crawlers abertos (katana) em portais de notícias/blogs — foque no cerne da aplicação (login, APIs, arquivos de config, plugins).
3. O sandbox roda SEM root: use 'nmap -sT -Pn -sV' (NUNCA -sS, que exige root e FALHA). Use 'httpx-toolkit', nunca 'httpx'.
4. Se detectar CMS (ex.: WordPress): 'wpscan --url https://{target} --enumerate vp,u --no-banner' e 'curl -s https://{target}/wp-json/wp/v2/users'.
5. Se o alvo estiver atrás de Cloudflare/CDN: priorize subdomínios (painel, staging, dev, api) do recon passivo; use taxa moderada (-rl 50).

## Metodologia por Fase (chame UMA ação por vez, adequada à fase)
- RECON: inteligência passiva e superfície — query_whois_rdap, enrich_ip_intel (ASN/CDN), search_cert_transparency (subdomínios), search_historical_urls, audit_dns_email_security (SPF/DMARC), audit_tls_ssl, audit_security_headers, detect_waf_firewall; e via execute: 'subfinder -d {target}', 'nmap -sT -Pn -sV -p 80,443,8080,8443 {target}', 'httpx-toolkit -u {target} -tech-detect -status-code'.
- ANALYSIS: vulnerabilidades e configuração — 'nuclei -u {target} -severity critical,high -rl 50'; audit_cors_advanced, audit_http_methods, audit_api_spec, scan_exposed_secrets, audit_cloud_storage, audit_ssrf_cloud_metadata e demais audit_* conforme a stack detectada; correlacione CVEs com search_cve, enrich_cve_threat e check_cisa_kev.
- EXPLOIT: validação controlada com PoC ANTES de qualquer finding (ex.: 'sqlmap -u http://{target}/endpoint?param=1 --batch'). Só registre findings VERIFICADOS.
- REPORT: consolide achados com create_finding (CVSS), gere o relatório e resuma riscos e mitigação.

## Conclusão
Após executar as ferramentas necessárias ao pedido, conclua com um resumo executivo em pt-BR (notas/Score, achados confirmados, recomendações de mitigação). NÃO repita ferramentas já executadas; se não houver próxima ação útil, finalize com o resumo.
"""

    _ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
    _NOISE_RE = re.compile(
        r'found unresponsive permanently|Using Interactsh|Templates clustered|'
        r'Templates loaded|New templates added|HTTP connections:|UI Dashboard|'
        r'projectdiscovery\.io|Current .*version|Started .*crawling|Executing \d+',
        re.I,
    )

    @classmethod
    def _clean_scan_text(cls, text: str, max_lines: int = 60) -> str:
        """Strip ANSI and collapse scanner log noise so the model sees the signal
        (open ports, matches, endpoints, status codes) instead of a wall of
        repeated '[INF] ... found unresponsive permanently' lines that made it
        re-run finished scans."""
        if not text:
            return text
        text = cls._ANSI_RE.sub('', text)
        kept, noise = [], 0
        for ln in text.splitlines():
            s = ln.rstrip()
            if not s.strip():
                continue
            if cls._NOISE_RE.search(s):
                noise += 1
                continue
            kept.append(s)
        if noise:
            kept.append(f"...[{noise} linhas de log/ruído de scanner omitidas]...")
        if len(kept) > max_lines:
            half = max_lines // 2
            kept = kept[:half] + [f"...[{len(kept) - max_lines} linhas intermediárias omitidas]..."] + kept[-half:]
        return "\n".join(kept)

    @classmethod
    def _format_tool_result(cls, name: str, result: dict) -> dict:
        r = dict(result) if isinstance(result, dict) else {"output": result}
        out = r.get("output")
        if isinstance(out, dict):
            out = dict(out)
            for k in ("stdout", "stderr"):
                if isinstance(out.get(k), str) and out[k]:
                    out[k] = cls._clean_scan_text(out[k])
            r["output"] = out
        content = json.dumps(r, default=str)
        # Cap tool output length to prevent context explosion on 8k local models
        if len(content) > 6000:
            content = content[:6000] + "\n...[truncated — output exceeds 6000 chars. Full log preserved in operation workspace]"
        return {"role": "tool", "name": name, "content": content}
