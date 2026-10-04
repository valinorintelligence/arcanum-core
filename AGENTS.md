# AGENTS.md — Arcanum Architecture & Antigravity Operating Guidelines

> Este arquivo é carregado automaticamente pelo Antigravity em todas as sessões deste workspace para garantir integridade, padrões arquiteturais e continuidade de aprendizados.

---

## 1. Diretrizes de Ambiente e Plataforma (Windows)

- **Codificação de Arquivos (UTF-8 Obrigatório):**
  - No Windows, o Python adota o charset do sistema (`cp1252`) por padrão caso não seja especificado.
  - **Regra:** Toda e qualquer chamada de leitura ou escrita de arquivo (`Path.write_text`, `Path.read_text`, `open(...)`) **DEVE** utilizar obrigatoriamente `encoding="utf-8"`. Strings com acentuação em português ou caracteres de logs quebram imediatamente se essa regra for violada.

- **Geração de PDF no Windows (Zero Dependências Externas):**
  - **Nunca** utilizar ou depender de `WeasyPrint` no Windows (requer bibliotecas GTK/Cairo/Pango compiladas em C).
  - **Solução Padrão:** Utilizar a engine headless nativa do **Microsoft Edge** (`msedge.exe --headless --disable-gpu --print-to-pdf=<dest> <origem_html>`), com fallback para Chromium/Chrome ou HTML.

- **Ciclo de Vida do Servidor FastAPI (Uvicorn):**
  - O servidor web roda em `arcanum/api/main.py` via `arcanum serve` com `reload=False`.
  - **Arquivos Python (`.py`):** Requerem reinicialização do processo para terem efeito.
  - **Frontend (`frontend/index.html`):** É lido dinamicamente a cada requisição em `GET /`. Mudanças no HTML entram em vigor imediatamente após um refresh (`F5`) no navegador.

- **Rotas de Download de Relatórios:**
  - Em `arcanum/api/routes/reports.py`, nunca responder com `HTTP 404` cego se um formato como PDF falhar na geração. O sistema deve aplicar fallback gracioso entregando a versão HTML correspondente.

---

## 2. Cérebro ReAct & Modelos Locais Menores (SLM 7B / 32B)

- **Supressão de Alucinações de Sintaxe:**
  - Modelos locais menores (ex: Qwen 7B) tendem a emitir nomes de ferramentas internas em texto puro (ex: `generate_report`) em vez de gerar o JSON de tool call ou uma mensagem conversacional.
  - O motor em `arcanum/agent/engine.py` possui um interceptador no `_run_loop` que converte essa intenção diretamente na compilação do relatório com confirmação amigável em pt-BR.

- **Prevenção de Estagnação (Stagnation Guard):**
  - O agente não deve executar a mesma ferramenta com parâmetros idênticos consecutivamente na mesma iteração (ex: `audit_security_headers`).
  - Caso detectado, a execução repetida é pulada e o agente avança para a próxima fase.

- **Roteamento Adaptativo a WAF / CDN:**
  - Ao detectar cabeçalhos de proxy reverso como Cloudflare (`server: cloudflare`), o agente não deve insistir em varreduras de portas ou ping de rede, redirecionando o esforço para subdomínios mapeados e análise de rotas web.

---

## 3. Padrões do Frontend (Alpine.js & Tailwind)

- **Seleção de Formatos de Relatório:**
  - O estado `reportFormats` deve sempre inicializar pré-marcado com os 4 formatos suportados: `['html', 'pdf', 'md', 'json']`.
  - O botão de geração deve herdar automaticamente a `currentSession` se `reportSession` não estiver preenchido.
  - Ao concluir a geração, `await this.fetchReports()` deve ser invocado imediatamente para sincronizar a lista de downloads na interface.

---

## 4. Memória em 3 Camadas & Playbooks

- **Camada 1 (Working Memory):** Contexto enxuto mantido abaixo de 8.192 tokens.
- **Camada 2 (Episodic Wiki):** Documentos persistidos por operação em `~/.arcanum/ops/<session>/workspace/wiki/` (`TARGET_MAP.md`, `ATTACK_SURFACE.md`, `OPERATION_LOG.md`).
- **Camada 3 (Playbooks FTS5):** Catálogo de técnicas comprovadas em SQLite (`~/.arcanum/arcanum.db`) para reutilização cross-operation.

---

## 5. Invariantes de Integridade & Aprendizados de Auditoria

> Diagnóstico completo, inventário de bugs e roadmap vivem em [`docs/MASTERPLAN.md`](docs/MASTERPLAN.md)
> — atualize-o a cada nova descoberta/correção (seção 4 + Log de descobertas).

- **Desembrulhar resultados de ferramenta (`["output"]`).** `ToolExecutor.execute_tool` retorna
  `{"success", "output", "error"}`. Todo consumidor de resultado de ferramenta DEVE ler os dados
  em `result["output"]` (não no nível raiz). *(A violação disso zerava a ingestão automática de
  findings de todas as ~116 ferramentas — BUG N, corrigido em `engine.py:_auto_ingest_native_findings`.)*
- **Re-teste é conservador por princípio.** Um finding só vira `remediated` com confirmação positiva
  (score≥90 / grade A / flag segura e sem vetores). Erro, mock, ou resultado inconclusivo ⇒ mantém
  `confirmed`. **Nunca** marcar "corrigido" sem testar de verdade. *(BUG K — `core/retest.py`.)*
- **System prompt enxuto (cabe na Camada 1).** O catálogo de ferramentas vive nos **schemas**
  (`NATIVE_TOOLS`, escopados por fase em `get_tools_for_phase`), **não** em prosa no system prompt.
  Manter o prompt em ~1–2k tokens. *(Catálogo de ~7k tokens derrubado — prefill ~110s→~49s; BUG Perf.)*
- **Reset de orçamento por run.** `AgentEngine.run()` zera `self.iteration` no início (o engine é
  reutilizado via `active_engines`). *(Sem isso, a sessão falhava após 50 iterações somadas — BUG A.)*
- **Cancelar runs órfãos.** Ao cair a última conexão WebSocket da sessão, abortar o run
  (`websocket.py:finally`). Com `OLLAMA_NUM_PARALLEL=1`, runs abandonados enfileiram e travam tudo. *(BUG M.)*
- **Cada view do frontend é um container auto-fechado.** As views (`x-show="currentView === '...'"`)
  são irmãs; nunca aninhe uma dentro de outra (um `</div>` faltante escondia 5 telas — BUG G).
- **Regra anti-"mock silencioso".** Features que dependem de recurso ausente (Playwright no Agente Web,
  executor no Retest) devem sinalizar "indisponível/simulado" e **nunca persistir dados simulados como
  reais**.
- **Hardening a preservar:** `_handle_execute` recusa rodar sem sandbox (sem RCE no host); escopo é
  verificado de forma determinística; reports usam autoescape anti-XSS; API/WS exigem token.

### Estado (ver MASTERPLAN §9)
P0 ✅, P1 ✅ (exceto TUI), P2 ✅ (valor). Lentidão/freeze: mitigado (flash-attn+KV q8 no Ollama,
`keep_alive=30m`, `num_thread` auto deixando ~2 núcleos livres). `orchestrator.py` removido.
**Skills:** as 57 skills de `agent/skills.py` agora são **semeadas no PlaybookManager**
(`ensure_skill_playbooks`) e usadas via **recall semântico (RAG/FTS)** — não injetadas no prompt.
**TUI:** ainda é stub experimental — o **Web UI é o produto** (a TUI não conecta o engine).
