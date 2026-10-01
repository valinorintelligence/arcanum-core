"""Core agent engine for Arcanum — drives the LLM tool-calling loop with
extended thinking, phase checkpoints, context compression, and self-evaluation."""

from __future__ import annotations

import json
import re
from typing import Any, AsyncGenerator

from .llm import OllamaClient
from .tools import NATIVE_TOOLS, ToolExecutor, get_tools_for_phase, _auto_repair_command

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
        # Stagnation guard: how many times each exact `execute` command has run.
        self._exec_signatures: dict[str, int] = {}
        self._stagnation_aborted = False

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
        prompt_with_context = user_input
        if mem_summary:
            prompt_with_context = f"{user_input}\n\n[Context: Phase={self.current_phase}]\n{mem_summary}"
        elif self.current_phase != "recon":
            prompt_with_context = f"{user_input}\n\n[Context: Phase={self.current_phase}]"

        self.messages.append({"role": "user", "content": prompt_with_context})

        # Deep recon autostart: bare domain triggers full pipeline
        if self.mode == MODE_AUTOPILOT and self._is_bare_domain(user_input):
            expanded = self._expand_to_full_recon(user_input)
            self.messages[-1]["content"] = expanded

        async for event in self._run_loop():
            yield event

    async def _run_loop(self) -> AsyncGenerator[dict, None]:
        """Internal execution loop driven by LLM tool-calling."""
        while self.iteration < MAX_ITERATIONS:
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

                # Hybrid routing: fast tactical tier for recon/scan tools, deep tier for exploit/report
                active_llm = self.deep_llm if self.current_phase in ("exploit", "report") else self.llm
                active_tools = get_tools_for_phase(self.current_phase)
                response_msg = await active_llm.chat(
                    messages=self.messages,
                    tools=active_tools,
                )

                # --- Extended thinking extraction ---
                content = response_msg.get("content", "")
                raw_thinking = response_msg.get("thinking", "")
                extracted_thinking, clean_content = self._extract_thinking(content)
                thinking = (raw_thinking.strip() if raw_thinking else "") or extracted_thinking
                if thinking:
                    yield {"type": "thinking", "content": thinking}

                tool_calls: list[dict] = response_msg.get("tool_calls", [])

                # Fallback: extract tool call from content if model emitted JSON in text
                if not tool_calls and content:
                    extracted_calls = self._extract_tool_calls_from_text(content)
                    if extracted_calls:
                        tool_calls = extracted_calls

                # No tool calls — final text response
                if not tool_calls:
                    final_text = clean_content or content or thinking or "Análise concluída."
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
                    normalized = self._normalize_tool_call_dict({"name": tool_name, "arguments": arguments})
                    if normalized:
                        tool_name = normalized["function"]["name"]
                        arguments = normalized["function"]["arguments"]

                    if tool_name == "execute" and isinstance(arguments, dict) and "command" in arguments:
                        arguments["command"] = _auto_repair_command(arguments["command"])

                        # Stagnation guard: a weak local model can propose the
                        # same command over and over (observed in the field).
                        # After 2 identical runs, inject a corrective hint; on
                        # the 3rd, abort the run so it can't spin to MAX_ITERATIONS.
                        sig = arguments["command"].strip()
                        seen = self._exec_signatures.get(sig, 0)
                        if seen >= 2:
                            self.messages.append({
                                "role": "user",
                                "content": (
                                    "[SISTEMA] Você repetiu o mesmo comando várias vezes sem progresso: "
                                    f"'{sig}'. Pare de repetir. Analise a última saída e escolha uma AÇÃO "
                                    "DIFERENTE (outra ferramenta, outro alvo/porta) ou finalize com um resumo."
                                ),
                            })
                            yield {
                                "type": "error",
                                "error": (
                                    f"Execução interrompida: comando repetido {seen} vezes sem progresso "
                                    f"('{sig}'). Redirecione a operação ou tente outra abordagem."
                                ),
                                "iteration": self.iteration,
                            }
                            self._stagnation_aborted = True
                            return
                        self._exec_signatures[sig] = seen + 1

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
                    requires_approval = False
                    if self.mode == MODE_MANUAL:
                        requires_approval = tool_name not in ("read_memory", "query_playbook")
                    elif self.mode == MODE_COPILOT:
                        requires_approval = risk in ("MEDIUM", "HIGH")

                    if requires_approval:
                        self.pending_action = {"tool": tool_name, "arguments": arguments}
                        risk_pt = {"LOW": "BAIXO", "MEDIUM": "MÉDIO", "HIGH": "ALTO"}.get(risk, risk)
                        yield {
                            "type": "suggestion",
                            "tool": tool_name,
                            "arguments": arguments,
                            "risk": risk,
                            "explanation": explanation,
                            "message": (
                                f"Modo {self.mode.capitalize()}: aprovação do operador necessária (Risco: {risk_pt}).\n\n"
                                f"📌 O QUE FAZ:\n{explanation['what']}\n\n"
                                f"🎯 POR QUE EXECUTAR:\n{explanation['why']}\n\n"
                                f"⚙️ PARÂMETROS / EXEMPLO:\n{explanation['params']}"
                            ),
                        }
                        return  # Pause loop until operator approves or cancels

                    # Execute the tool
                    result = await self.tool_executor.execute_tool(tool_name, arguments)

                    tool_msg = self._format_tool_result(tool_name, result)
                    self.messages.append(tool_msg)

                    tool_out = result.get("output") or result.get("stdout") or result.get("error") or "Sucesso"
                    yield {
                        "type": "tool_result",
                        "tool": tool_name,
                        "result": result,
                        "output": tool_out,
                        "content": json.dumps(tool_out, default=str) if isinstance(tool_out, (dict, list)) else str(tool_out),
                        "iteration": self.iteration,
                    }

                    # Surface findings
                    if tool_name == "create_finding" and result.get("success"):
                        self.findings_count += 1
                        output = result.get("output", {})
                        if output.get("status") != "duplicate":
                            yield {"type": "finding", "finding": output}

            except Exception as exc:
                yield {"type": "error", "error": str(exc), "iteration": self.iteration}
                return

        yield {"type": "error", "error": f"Limite máximo de iterações ({MAX_ITERATIONS}) atingido", "iteration": self.iteration}

    async def execute_approved(self) -> AsyncGenerator[dict, None]:
        """Execute a tool action previously held for operator approval."""
        if not self.pending_action:
            yield {"type": "info", "content": "Nenhuma ação pendente de aprovação."}
            return

        action = self.pending_action
        self.pending_action = None
        tool_name = action["tool"]
        arguments = action["arguments"]

        yield {"type": "thinking", "content": f"Executando ação aprovada pelo operador: {tool_name}"}
        try:
            result = await self.tool_executor.execute_tool(tool_name, arguments)
        except Exception as exc:
            yield {"type": "error", "error": f"Falha na execução da ferramenta {tool_name}: {exc}", "iteration": self.iteration}
            return

        tool_msg = self._format_tool_result(tool_name, result)
        self.messages.append(tool_msg)

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
    def _normalize_tool_call_dict(data: dict) -> dict | None:
        """Normalize various LLM tool call schemas (e.g. OpenAI, Anthropic, Qwen, Ollama, plain JSON)."""
        if not isinstance(data, dict):
            return None

        name = data.get("name") or data.get("function", {}).get("name") or data.get("tool") or data.get("action")
        args = data.get("arguments") or data.get("function", {}).get("arguments") or data.get("params") or data.get("parameters") or {}

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

        if name:
            name_str = str(name).strip().lower()
            if name_str in exec_aliases:
                if "command" in args and isinstance(args["command"], str):
                    args["command"] = _auto_repair_command(args["command"])
                return {"type": "function", "function": {"name": "execute", "arguments": args}}

            if name_str in known_binaries:
                cmd_part = args.get("command") or args.get("target") or args.get("domain") or args.get("url") or ""
                full_cmd = _auto_repair_command(f"{name_str} {cmd_part}".strip())
                return {"type": "function", "function": {"name": "execute", "arguments": {"command": full_cmd}}}

            valid_native = {
                "read_memory", "update_memory", "query_playbook", "save_playbook",
                "search_cve", "create_finding", "stash_artifact", "read_file",
                "create_file", "browser_action", "web_search",
            }
            if name_str in valid_native:
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
    def _extract_tool_calls_from_text(cls, content: str) -> list[dict]:
        """Fallback extractor when local models return tool call JSON directly in text content."""
        if not content:
            return []
        text = content.strip()

        # 1. Whole text is valid JSON object
        try:
            data = json.loads(text)
            norm = cls._normalize_tool_call_dict(data)
            if norm:
                return [norm]
        except Exception:
            pass

        # 2. Markdown ```json ... ``` blocks
        calls = []
        for match in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
            try:
                data = json.loads(match.group(1))
                norm = cls._normalize_tool_call_dict(data)
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
                norm = cls._normalize_tool_call_dict(data)
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
                norm = cls._normalize_tool_call_dict(data)
                if norm:
                    calls.append(norm)
            except Exception:
                pos = idx + 1
        return calls

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
            response = await self.deep_llm.chat(
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
            if any(t == "create_finding" for t in recent_tools):
                new_phase = "exploit"
            elif len(recent_tools) >= 5:
                new_phase = "exploit"
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
            f"3. Live host detection: httpx -l /workspace/output/subdomains.txt -tech-detect -status-code -o /workspace/output/live.txt\n"
            f"4. Port scanning: nmap -sV -sC -iL /workspace/output/live.txt -oA /workspace/output/nmap\n"
            f"5. Vulnerability scanning: nuclei -l /workspace/output/live.txt -severity critical,high -o /workspace/output/vulns.txt\n"
            f"6. For any discovered web apps, test for SQLi, XSS, and other common vulns\n"
            f"7. Create findings for all confirmed vulnerabilities\n\n"
            f"Analyze all output at each step. Chain results between steps."
        )

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
        if tool_name in ("browser_action", "web_search", "read_file", "search_cve", "read_memory", "query_playbook"):
            return "LOW"
        if tool_name == "create_finding":
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

        return f"""Você é o Arcanum, um agente autônomo profissional de reconhecimento de segurança e testes de intrusão (pentest).
Você realiza avaliações de segurança autorizadas utilizando ferramentas profissionais dentro de um ambiente sandbox isolado.

## Operação Atual
- Sessão: {name}
- Alvo: {target}
- Modo: {self.mode}
- Escopo: {scope}

## Diretrizes de Idioma e Execução de Ferramentas (OBRIGATÓRIO)
1. Toda a sua comunicação e raciocínio textual com o operador DEVE ser em Português do Brasil (pt-BR).
2. Para interagir com o alvo '{target}', INVOQUE A FERRAMENTA DIRETAMENTE (chame 'execute' com comandos reais como nmap, subfinder, httpx, nuclei, ou ferramentas nativas como read_memory). NUNCA apenas escreva tutoriais longos ou blocos de código JSON simulado em markdown: chame a ferramenta imediatamente.
3. Proponha ou execute UMA AÇÃO TÁTICA POR VEZ adequada à fase atual ({self.current_phase}). Não tente listar múltiplos passos futuros de uma vez só.
4. Mantenha seus comentários textuais breves e objetivos (1 a 2 frases), pois o motor Arcanum já gera automaticamente a explicação técnica detalhada e pedagógica (O que faz, Por que executar e Parâmetros) de cada comando para o operador.

## Regras Operacionais
1. NUNCA opere fora do escopo definido ({scope}).
2. Sempre verifique se os alvos estão dentro do escopo antes de executar qualquer ferramenta.
3. Documente CADA descoberta com evidências claras e prova de conceito (PoC).
4. Siga o princípio do menor privilégio.
5. Se descobrir credenciais, chaves de API ou dados sensíveis, guarde-os no cofre (stash_artifact) e mascare nas saídas.
6. Apenas crie vulnerabilidades (create_finding) para falhas VERIFICADAS com PoC funcional.
7. Mantenha consciência situacional: consulte a memória viva (read_memory) e playbooks (query_playbook).

## Modos de Operação
- **autopilot**: Executa ferramentas automaticamente em cadeia. Avança pelas fases.
- **copilot**: Sugere chamadas de ferramentas com avaliação de risco e explicações didáticas. Aguarda confirmação do operador.
- **manual**: Executa ferramentas somente quando solicitado explicitamente pelo operador. Fornece orientação técnica especialista e explicações.

## Metodologia e Sintaxe Correta de Ferramentas
### Fase 1: Reconhecimento (Recon)
- Enumerar subdomínios: execute com 'subfinder -d {target}'
- Resolver DNS: execute com 'dnsx -d {target} -resp'
- Sondar HTTP e tecnologias: execute com 'httpx -u {target} -tech-detect -status-code'
- Escaneamento de portas: execute com 'nmap -sV -p 80,443,8080,8443 {target}' (ou portas específicas)
- Rastreamento web: execute com 'katana -u http://{target}'

### Fase 2: Análise (Analysis)
- Varredura de vulnerabilidades: execute com 'nuclei -u {target} -severity critical,high'
- Força-bruta de diretórios: execute com 'ffuf -u http://{target}/FUZZ -w /workspace/wordlists/common.txt'
- Descoberta de parâmetros: execute com 'arjun -u http://{target}'
- Pesquisa de CVEs conhecidos: search_cve com query da tecnologia detectada

### Fase 3: Exploração (Exploit)
- Testes controlados de SQL injection: execute com 'sqlmap -u http://{target}/endpoint?param=1 --batch'
- Validação com PoC antes de criar qualquer finding.

### Fase 4: Relatório (Report)
- Criar findings para todas as vulnerabilidades confirmadas com pontuação CVSS (create_finding).
- Guardar artefatos no cofre (stash_artifact).
- Resumir a avaliação de segurança e recomendações de mitigação.
"""

    @staticmethod
    def _format_tool_result(name: str, result: dict) -> dict:
        content = json.dumps(result, default=str)
        # Cap tool output length to prevent context explosion on 8k local models
        if len(content) > 6000:
            content = content[:6000] + f"\n...[truncated — output exceeds 6000 chars. Full log preserved in operation workspace]"
        return {"role": "tool", "name": name, "content": content}
