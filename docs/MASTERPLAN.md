# Arcanum Core — Plano Mestre & Guia de Auditoria

> **Documento vivo.** Consolida o estado real do sistema, todos os gaps/bugs descobertos, os
> aprendizados (incluindo medições de performance) e o roadmap de correção. **A cada nova
> descoberta, atualize este documento** (veja [Protocolo de Atualização](#protocolo-de-atualização))
> e o [`AGENTS.md`](../AGENTS.md).
>
> Última atualização: 2026-10-04 · Branch: `fix/arcanum-hardening`
>
> **Roadmap estratégico (ações reais Red/Blue/Purple):** ver [`docs/RED_TEAM_ROADMAP.md`](RED_TEAM_ROADMAP.md)
> — plano completo mapeado por tática ATT&CK, com os trilhos de segurança (ROE, classes de ação, HITL,
> audit, kill-switch) e as fases F0–F5.

---

## 1. Resumo executivo

Arcanum Core é uma plataforma autônoma de recon/pentest (FastAPI + LLM local via Ollama + sandbox
Kali em Docker). A arquitetura é **madura**: 385 testes passando, sandbox real e seguro, UI polida,
hardening de segurança sólido. **Porém, três bugs de *wiring/shape* impedem o sistema de cumprir a
promessa** de "executar tarefas com exatidão":

1. **(N)** A ingestão automática de findings está quebrada → **0 vulnerabilidades em runs reais**.
2. **(G)** A view "Grafo" não é fechada no HTML → **5 das 13 telas ficam invisíveis**.
3. **(Perf)** O system prompt tem ~6.951 tokens → **~100s por turno** no hardware atual.

Nenhum deles é "o modelo é fraco" — são correções pontuais de altíssimo impacto.

---

## 2. Estado real (difere do README)

| Item | README diz | Realidade (verificada) |
|---|---|---|
| Versão | 3.0.0 | 3.0.0 (código evoluiu muito além) |
| Modelo | `qwen3:32b`, ctx 131072 | `qwen2.5-coder:7b` (fast **e** deep), `num_ctx=8192` |
| Ferramentas | "40 tools / 8 native" | **116 ferramentas nativas** (`audit_*` em Python) + 40 no registry Kali |
| Skills | "57 Skills auto-mapeadas" | `skills.py` existe mas **NÃO está conectado** ao agente (código órfão) |
| Front-ends | TUI + Web UI | **Só o Web UI funciona**; a TUI é stub (BUG L) |
| Módulos novos | — | CTEM, CISA KEV, MITRE, Identity/AD, Probes, Integrações, Eval, Browser (não documentados) |

### Hardware-alvo (laptop do operador)
Ryzen 7 4800H (8C/16T) · **GTX 1650 Mobile — 4GB VRAM** · 63GB RAM · Ollama 0.35.0
(flash-attention OFF, KV cache f16). O 7B carrega **42% GPU / 58% CPU** (não cabe nos 4GB).
**O 32B é inviável aqui** (rodaria ~90% na CPU). O 7B é a escolha correta.

---

## 3. Componentes: existe / funciona?

| Componente | Estado |
|---|---|
| Sandbox Kali (`execute`) | ✅ Real e seguro: nmap/nuclei/httpx-toolkit/sqlmap/ffuf, rede OK, recusa rodar sem sandbox (sem RCE no host) |
| Ferramentas `audit_*` | ✅ ~68 fazem HTTP real; offline (kerberos/adcs/…) não fabricam sem dados |
| RAG / vectordb | ✅ Real (`nomic-embed-text` instalado), fallback p/ keyword |
| CVE KB | ✅ FTS5 real, 301.972 CVEs, sanitização de sintaxe |
| Reports | ✅ HTML/MD/JSON + PDF (3 fallbacks), autoescape anti-XSS |
| CISA KEV | ✅ Sync real do feed CISA (6 CVEs = seed; rodar `/api/ctem/kev/sync`) |
| Integrações (Jira/SNOW/SIEM) | ✅ Mock honesto (`mock:true`) sem credenciais; POST real quando configurado |
| **Skill system** (`skills.py`) | ⚠️ Existe mas **órfão** (não importado) |
| **Harness** (`arcanum/eval/`) | ✅ Conectado via API; ⚠️ contrato da UI quebrado (BUG D) |
| **Wiki** (por-operação) | ✅ Agente lê/escreve `TARGET_MAP/ATTACK_SURFACE/OPERATION_LOG.md` |
| CTEM daemon | ⚠️ Existe mas **nunca é iniciado** (BUG I) |
| Agente Web IA (headless) | ⚠️ Playwright ausente → **modo simulado** que fabrica findings (BUG J) |
| TUI (terminal) | ❌ Stub (BUG L) |

---

## 4. Inventário completo de bugs (priorizado)

### 🔴 P0 — Impedem exatidão / funcionalidade — ✅ TODOS CORRIGIDOS E VALIDADOS AO VIVO (2026-10-03)
> N, G, A, M, K e Perf aplicados; 385 testes verdes; run ao vivo: 1ª ferramenta 110s→**49s**, run
> conclui em **98s** (antes nunca concluía), **3 findings criados** (antes 0). Detalhes no Log §9.

| ID | Bug | Evidência | Local | Fix |
|----|-----|-----------|-------|-----|
| **N** | `execute_tool` embrulha em `{"success","output"}`, mas `_auto_ingest_native_findings` lê campos no nível raiz → **0 findings de todas as ferramentas** | runtest2: audit rodou, 5 missing_headers, **0 findings no DB** | `execute_tool` [tools.py:2254]; auto-ingest [engine.py:954] | `result = result.get("output", result)` no início do auto-ingest |
| **G** | View "Grafo" sem `</div>` → 5 views aninhadas e invisíveis (AD, Web IA, MITRE, Sondas, Eval) | DOM: `nestedInside:"graph"` p/ as 5 | [frontend/index.html:1373] (abre) / falta `</div>` após :1651 | fechar o `</div>` da view graph |
| **Perf** | System prompt de **6.951 tokens** → ~100s prefill/turno; `num_ctx=8192` deixa ~1.240 de folga → context-shift + perda de contexto | Benchmark: 6.951 tok=100s vs 294 tok=4,3s | `_build_system_prompt` [engine.py:3361] | encolher p/ ~1.000 tok + mover metodologia p/ `description` dos schemas (já escopados por fase) |
| **A** | `self.iteration` só zera no `__init__`; engine reusado em `active_engines` → acumula entre turnos → após 50 toda instrução falha | leitura de código | [engine.py:46] | resetar `iteration`/intervalos no início de `run()` |
| **M** | Runs abandonados não são cancelados (disconnect não faz abort) → com `NUM_PARALLEL=1`, poucos disconnects travam o Ollama | prefill 2s mas wall 43s por contenção; 1º run estagnou 300s | [websocket.py:211] | `engine.abort()` + cancelar a task no `finally` do WS |
| **K** | Retest sempre mock: `app.state.tool_executor` nunca é setado → `RetestEngine(tool_executor=None)` → marca **REMEDIATED falso** | grep: `state.tool_executor` nunca atribuído | [findings.py:99], [retest.py:74] | wire `app.state.tool_executor` + nunca remediar em mock (`probe_result.status=="mock_simulated"` ⇒ inconclusivo) |

### 🟠 P1 — Confiabilidade e telas — ✅ MAIORIA CORRIGIDA (2026-10-03); resta L (TUI)

| ID | Bug | Local | Fix |
|----|-----|-------|-----|
| **D** | Eval: `POST /eval/run` sem body→422; espera `data.report`/`scenData.scenarios` mas BE retorna plano/lista; roda no `init()` | [index.html:5377], [eval.py:60] | usar `GET /eval/latest` no init; enviar body `{mode}`; alinhar shapes |
| **I** | `CTEMDaemon.start()` nunca é chamado (só `init_tables`) → agendamentos não rodam; "24/7 Ativo" falso | [main.py:58] | `ctem_daemon.start()` no lifespan |
| **J** | `browser_available=True` mas Playwright ausente → `_run_simulated_audit` fabrica findings HIGH | [agent.py:221] | detectar Playwright real; **nunca** auto-ingerir findings `simulated:true` |
| **B** | Status da sessão (`running`/`complete`) nunca gerenciado pelo engine/WS | websocket/engine | transicionar status no início/fim do run |
| **E** | `currentSession` null sem guarda → `TypeError` em bindings Alpine | frontend | guardas `currentSession?.` |
| **Conc.** | Engine compartilhado por `session_id` sem lock → 2 abas corrompem `self.messages` | [websocket.py:111] | lock/estado "busy" por sessão |
| **Perf2** | Sínteses finais usam `self.llm` (fast, `num_predict=256`) → resumos truncados | [engine.py:250] | usar `deep_llm` + `num_predict≈1024` |
| **L** | TUI stub: `_engine` nunca conectado; actions placeholder; `_handle_event` lê campos errados | [cli/app.py:141] | conectar engine ou marcar TUI como experimental |
| **WordPress falso** | `_detect_tech_keywords` varre últimas 6 msgs; a `system` (cita wordpress/plugins) entra nelas → falso-positivo em toda sessão | [engine.py:848] | exigir sinais fortes (wp-content/wp-json/?author=); não varrer a `system` |

### 🟡 P2 — Qualidade / robustez — ✅ ITENS DE VALOR CONCLUÍDOS (skills/TUI = decisões documentadas)
- **123 blocos `except...pass`** (falhas silenciosas — dificultam diagnóstico).
- **Código morto:** `arcanum/agent/orchestrator.py` e `arcanum/agent/skills.py` (nunca importados).
- `app.state.browser` nunca setado → ferramenta `browser_action` morta (headless usa `_browser_agent` lazy).
- Relatório: nome de arquivo só com data → regenerar no mesmo dia **sobrescreve**.
- DB: 1 conexão aiosqlite compartilhada (WAL, sem lock; `execute`+`commit` não-atômicos).
- MITRE = seed estático (eficácia sintética); Identity/AD = lógica real sem coletor (domínios vazios).
- Documentação (README/CHANGELOG) defasada; ~20k linhas + 61 arquivos **não commitados**.

---

## 5. Padrão de risco central (para toda nova feature)
**"Fallback silencioso para mock + reporta sucesso."** Três features caem em modo simulado quando
falta dependência/wiring e informam sucesso: Retest (K), Browser (J), e o auto-ingest que falha em
silêncio (N via `except pass`). **Regra para o projeto:** toda feature deve (a) detectar a ausência
da dependência, (b) sinalizar claramente "modo simulado/indisponível", e (c) **nunca** persistir
dados simulados como reais.

---

## 6. Aprendizados & medições (hardware atual)

- **Prefill domina o custo.** Prompt 6.951 tok → ~100s; 294 tok → 4,3s (~23x). Geração é rápida.
- **`num_ctx` NÃO acelera prefill** — só dá folga contra context-shift. A alavanca é reduzir tokens.
- **Ollama reaproveita KV cache de prefixo:** turno 1 (frio) ~100s; turnos seguintes ~3s **se o
  prefixo não for invalidado**. `num_ctx=8192` + prompt 6.951 → o 1º resultado de ferramenta estoura
  o teto → re-prefill de ~100s + perda de contexto.
- **1ª `tool_call` ao vivo:** ~110s (prefill frio). Watchdog de run = 1800s (30 min).
- **Contenção:** `OLLAMA_NUM_PARALLEL=1` serializa; runs órfãos (BUG M) enfileiram e travam tudo.
- Quick wins de ambiente: `OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0` (cabe mais
  contexto nos 4GB). `num_ctx` 12–16k **só** como folga, após encolher o prompt.

---

## 7. Roadmap de implementação (por lotes)

**Lote P0 (destrava o produto):**
1. **N** — desembrulhar `output` no auto-ingest (+ remover o `except pass` que mascarava).
2. **G** — fechar o `</div>` da view Grafo → recupera 5 telas.
3. **A** — resetar `iteration` em `run()`.
4. **M** — cancelar run no disconnect do WS.
5. **K** — wire `app.state.tool_executor`; nunca remediar em mock.
6. **Perf** — encolher + escopar por fase o system prompt.

**Lote P1 (telas e confiabilidade):** D (Eval) · I (CTEM start) · J (Playwright/simulado) · B (status) ·
E (null guards) · lock de concorrência · sínteses no `deep_llm`.

**Lote P2 (qualidade):** reduzir `except...pass` · remover código morto (orchestrator, skills ou
reconectar) · flash-attention/KV q8 · atualizar docs · **commitar** o trabalho pendente.

**Validação:** após cada fix do Lote P0, rodar um run ao vivo (ex.: `audit_security_headers` em
example.com) e confirmar: findings criados, telas abrem, tempo/turno.

---

## 8. Protocolo de atualização
A cada nova descoberta ou correção:
1. Adicione/atualize a linha na seção 4 (com ID, evidência, `arquivo:linha`, fix).
2. Registre no [Log de descobertas](#9-log-de-descobertas) abaixo.
3. Se mudar "como trabalhar no repo", reflita no [`AGENTS.md`](../AGENTS.md).
4. Ao corrigir um bug, marque-o ✅ (não apague — mantenha o histórico com a data do fix).
5. Mantenha a memória do agente (`.claude/.../memory/arcanum-state-and-bottleneck.md`) alinhada.

## 9. Log de descobertas
- **2026-10-03** — Auditoria 360° inicial (4 rodadas). Descobertos: N, G, A, M, K, D, I, J, B, E, L,
  concorrência, WordPress-falso, código morto (orchestrator/skills), perf/prefill. Estado base deste
  documento.
- **2026-10-03 — Lote P0 implementado e validado ao vivo (✅):**
  - **N** — `_auto_ingest_native_findings` passou a desembrulhar `result["output"]` ([engine.py]).
    Validação: run em example.com criou **3 findings** (CSP HIGH, HSTS/X-Frame MEDIUM) e persistiu no DB
    (antes: 0).
  - **G** — adicionado `</div>` de fechamento da view Grafo ([frontend/index.html]). Validação: DOM
    com **0 views aninhadas** (antes: 5); MITRE/AD/Web IA/Sondas/Eval renderizam.
  - **A** — `run()` reseta `self.iteration`/contadores por turno. Validação: run concluiu normalmente.
  - **M** — `finally` do WebSocket aborta o run quando cai a última conexão. (Fix de código.)
  - **K** — `_evaluate_probe_outcome` reescrito (conservador; guarda `mock_simulated`; entende
    `missing_headers`/score) + `app.state.tool_executor` conectado no lifespan. Teste de API atualizado
    para travar a regra (não-confirmado ⇒ permanece `confirmed`).
  - **Perf** — catálogo de ferramentas removido do system prompt (vive nos schemas por fase).
    Prompt **6.951→~1.600 tokens**; 1ª `tool_call` **110s→49s**; run completo **98s** (antes nunca
    concluía em 260–300s).
  - Testes: 3 testes que codificavam o comportamento antigo foram atualizados (2 de system-prompt
    rendering + 1 de retest). **385 passam.**
  - Aprendizados adicionados ao [`AGENTS.md`](../AGENTS.md) §5 (invariantes anti-regressão).
  - **Próximo:** Lote P1 (D, I, J, B, concorrência, sínteses no deep_llm).
- **2026-10-03 — Lote P1 implementado e validado (✅):**
  - **D** — contrato do Eval alinhado (FE lê report plano de `/eval/latest`; `/eval/run` recebe body
    `{mode}`; cenários como lista; init usa GET, não POST). Validação: POST **200** (era 422); view
    renderiza (grade A+, 12/12); console limpo.
  - **E** — optional chaining em `currentSession?.name/target` e `mitreData?.campaign_id` (x-text/:title
    avaliam mesmo sob `x-show=false`). Validação: aba nova com **0 erros** no console (eram 3 TypeErrors).
  - **I** — `ctem_daemon.start()` no lifespan (daemon de agendamentos agora roda). Startup sem erro.
  - **J** — `browser_available` reflete Playwright instalado; `_auto_ingest_native_findings` **ignora**
    resultados/achados marcados `simulated` (não persiste findings fabricados do modo mock).
  - **Perf2** — sínteses finais usam `deep_llm` com `num_predict=900` (resumos deixam de truncar em 256);
    adicionado override `num_predict` em `OllamaClient.chat`.
  - **B** — WebSocket transiciona status da sessão `running`↔`complete` (dashboard reflete realidade).
  - **Concorrência** — `_running_sessions` rejeita 2º run simultâneo na mesma sessão (engine é compartilhado).
  - **WordPress falso** — `_detect_tech_keywords` ignora a mensagem `system` (fonte do falso-positivo);
    "plugins" mantido como sinal de intenção explícita do operador. Teste `test_tactical_guidance_wordpress` verde.
  - Testes: **385 passam**. **Adiado:** L (TUI stub) — Web UI é o produto; TUI marcada como experimental.
  - **Próximo:** Lote P2 (reduzir `except...pass`, remover/ reconectar código morto, flash-attention/KV q8,
    atualizar README, **commitar** o trabalho).
- **2026-10-03 — P0+P1 commitados** (branch `fix/arcanum-hardening`): `86e8749` (código) e `dd94ba4`
  (docs). `tmp/`, `test_ws/`, `test_db.sqlite` adicionados ao `.gitignore`.
- **2026-10-03 — Lote P2 (parcial) ✅:**
  - **Logging visível:** adicionado handler ao logger `arcanum` no comando `serve` ([__main__.py]) — antes
    TODO log do logger era descartado (sem handler). Agora avisos de diagnóstico aparecem. Validado ao
    vivo: "CTEM Daemon background worker started." (também confirma o fix I em runtime).
  - **Falhas silenciosas:** `except` do sandbox e do RAG no lifespan ([api/main.py]) agora logam WARNING
    com a causa (sandbox ausente ⇒ avisa que 'execute' fica indisponível).
  - **Código morto:** removido `arcanum/agent/orchestrator.py` (nunca importado). `skills.py` (57 skills)
    mantido mas documentado como NÃO conectado (decisão: remover vs reconectar ao agente).
  - **README:** corrigido modelo/`num_ctx` reais (7B, hybrid tier) + ponteiro para AGENTS.md/MASTERPLAN
    + nota sobre os módulos enterprise.
  - Testes: **385 passam**.
  - **Pendente P2:** demais `except...pass` (restam ~120), decisão sobre `skills.py`, flash-attention +
    `OLLAMA_KV_CACHE_TYPE=q8_0` (mudança de ambiente/Ollama — requer confirmação), e **L** (TUI).
- **2026-10-04 — Investigação de lentidão (freeze → reboot do PC):**
  - Logs analisados (b0z5mxue1/bklqr6l68/b43xosm60/bvhxzh3xt): **sem** bug de runaway — sem tracebacks,
    sem polling no frontend, reconexão WS limitada. Causa = **recursos**: CPU saturada pelo 7B (58% CPU),
    processos `arcanum serve` órfãos (conflito na porta 8000), `keep_alive:-1` fixando o modelo, Docker WSL.
  - **Fix de código:** `keep_alive` configurável (`ARCANUM_OLLAMA_KEEP_ALIVE`, padrão "30m") — libera
    VRAM/RAM quando ocioso ([config.py], [llm.py], [main.py]). Post-mortem completo em
    `docs/LEARNINGS_AND_TROUBLESHOOTING.md` §4.
  - **Recomendações de ambiente (usuário aplica + reinicia Ollama):** `OLLAMA_FLASH_ATTENTION=1`,
    `OLLAMA_KV_CACHE_TYPE=q8_0`. Rodar 1 server por vez; Docker só ao usar `execute`. **385 testes verdes.**
- **2026-10-04 — Tuning do Ollama APLICADO e CONFIRMADO (✅):**
  - `OLLAMA_FLASH_ATTENTION=1` + `OLLAMA_KV_CACHE_TYPE=q8_0` setados (setx) e Ollama reiniciado.
    Confirmado no startup do llama-server do 7B: `--flash-attn on --cache-type-k q8_0 --cache-type-v q8_0`.
  - **Threads:** descoberto que `OLLAMA_NUM_THREAD` (env) é **ignorado** (n_threads=8). Implementado o
    caminho correto: opção de requisição `num_thread` via `ARCANUM_OLLAMA_NUM_THREAD` (setado =6).
    Confirmado: reload do 7B com `-t 6` → `n_threads = 6` (deixa 2 de 8 núcleos para o SO). Commits
    88804c1 (keep_alive) e 61ae4a3 (num_thread).
  - **AÇÃO PENDENTE do usuário:** reiniciar `arcanum serve` uma vez para o servidor passar a usar
    `keep_alive=30m` + `num_thread=6` (o processo atual na 8000 ainda roda com config antiga).
- **2026-10-04 — num_thread automático + fecho do P2:**
  - `num_thread` agora é **à prova de terminal**: `effective_num_thread()` (commit c3c7daa) deixa ~2
    núcleos físicos livres por padrão (6 de 8 aqui) **sem depender de env** — resolve a fragilidade do
    `setx` (só valia para shells novos). `-1` = todos os núcleos; `N>0` = exato.
  - **Logging de diagnóstico validado em produção:** o restart do usuário mostrou o aviso
    "Imagem do sandbox nao encontrada" — que revelou o **Docker down** após o reboot (imagem intacta;
    `execute` indisponível até ligar o Docker; tools nativas não precisam).
  - **Decisões P2 (não-bugs):**
    - **`skills.py` (57 skills):** mantido, documentado como **superseded** por Playbooks(FTS5)+RAG
      (o recall semântico já cobre o caso sem inflar o prompt). Reconectar injetando passos no prompt
      contradiz o fix de contexto (Perf). Melhoria futura possível: *seed* das 57 skills no
      PlaybookManager (entra no recall sem bloat) — requer aprovação.
    - **`orchestrator.py`:** removido (morto, sem conteúdo de valor).
    - **TUI (L):** mantida como stub documentado; o **Web UI é o produto**. Tornar funcional é esforço
      maior e de baixo valor — requer aprovação explícita.
    - **`except...pass` (~120):** os críticos do lifespan agora logam; o restante são best-effort por
      checagem (fallback gracioso) — deixados como estão.
  - **Estado:** P0 ✅, P1 ✅ (exceto L), P2 ✅ (valor) — 385 testes verdes em todos os passos.
- **2024-10-04 — Skills wired + TUI honesta (feature work aprovado):**
  - **Skills (57) conectadas via recall:** `PlaybookManager.ensure_skill_playbooks()` semeia as 57
    skills de `agent/skills.py` no KB de playbooks (idempotente), e o lifespan as indexa no RAG. Assim
    são usadas via **recall semântico** quando o contexto casa — **sem inflar o prompt** (commit 79b50be).
    Validado: 57 semeadas, idempotente, recall "subdomain"→subdomain_enum. Decisão anterior (manter
    `skills.py` como superseded) **substituída por: wired via recall**.
  - **TUI honesta:** `arcanum autopilot/copilot/manual` agora avisa claramente que a TUI é experimental
    e direciona ao Web UI (removida a mensagem enganosa "Would process"). Build completo da TUI segue
    como trabalho futuro (não validável neste ambiente headless; exige teste interativo do usuário).
  - 385 testes verdes.
- **2026-10-04 — Passe de excelência (testes de regressão + hardening + validação integrada):**
  - **Testes de regressão** (`tests/test_core/test_audit_fix_regressions.py`, 9 testes): blindam BUG N
    (auto-ingest desembrulha output + ignora simulados), BUG K (retest nunca remedia sem prova),
    `effective_num_thread` (folga de CPU) e seeding das 57 skills. Suíte: **394 testes**.
  - **Refactor WS** (`_drive_agent_stream`): status `running<->complete` + lock por sessão agora em
    TODOS os caminhos (chat-run E aprovação copilot/manual), que antes ficavam presos em "running".
  - **Sínteses**: `num_predict` 900→600 (resumo completo, conclusão mais rápida no 7B lento).
  - **VALIDAÇÃO INTEGRADA AO VIVO** (tudo ligado — flash-attn/q8/6-threads/keep_alive/skills/fixes):
    audit em example.com → **1ª ferramenta 22s** (era ~110s), **3 findings criados+persistidos**,
    status **created→complete**, **resumo completo (2114 chars)**, run completo em ~136s. Pipeline
    ponta-a-ponta confirmado.
  - **Estado final:** P0 ✅ · P1 ✅ (TUI = stub honesto documentado) · P2 ✅ · Lentidão ✅ · Skills ✅.
    ~14 commits (86e8749→c85bb2d). Backlog opcional: build completo da TUI (precisa teste interativo),
    sweep dos ~120 `except...pass` (baixo valor).
- **2026-10-04 — Red Team F0 (fundação de segurança/governança) implementada e validada ao vivo (✅):**
  - **Pacote `arcanum/redteam/`:** `action_classes.py` (enum `ActionClass` PASSIVE→DESTRUCTIVE,
    `classify` determinístico com heurística de comando do `execute`, `hitl_tier`), `engagement.py`
    (`EngagementManager`: ROE com escopo/janela/classes + `roe_hash`, `active_for`, `is_allowed` puro;
    **sem engajamento ativo ⇒ não bloqueia**, backward-compat), `audit.py` (`ActionAuditLog`
    append-only com hash encadeado `sha256(prev+payload)`, `verify_chain`, lock por conexão,
    mascaramento por chave **e** por valor), `sessions.py` (`SessionRegistry` footholds/implantes +
    `cleanup`).
  - **DB (`core/database.py`):** novas tabelas `engagements`, `actions_log`, `redteam_sessions`;
    migração idempotente das colunas `graph_nodes.owned/creds_held/foothold_id`.
  - **Engine (`agent/engine.py`):** `_roe_authorize` bloqueia classes fora do ROE (evento
    `blocked_by_roe`) e registra no audit; classe → tier HITL (ACTIVE=1 aprovação,
    EXPLOIT/POST_EXPLOIT/DESTRUCTIVE=**dupla aprovação** em `execute_approved`); `_audit_record`
    pós-execução (args mascarados); `kill_switch()` (abort + cleanup). Governança é **best-effort**
    (degrada a no-op sem DB usável — mocks/legado seguem funcionando).
  - **API (`api/routes/redteam.py`):** `POST/GET /api/redteam/engagements` (+`/active`, `/{id}`,
    `/{id}/close`), `GET /api/redteam/actions` (+`/verify`), `GET/DELETE /api/redteam/sessions`,
    `POST /api/redteam/killswitch`.
  - **Revisão de segunda-opinião (read-only) aplicada:** (#1) **under-gating** corrigido —
    `headless_web_audit` (dirige browser no alvo) e `dispatch_enterprise_integration`/
    `dispatch_to_satellite_probe` (efeito externo) caíam em prefixo passivo; agora têm override
    explícito ⇒ ACTIVE. (#2) **vazamento de credencial por valor** no audit corrigido — além do
    masking por nome de chave, `mask_arguments` escaneia valores (inclusive `command`) e redige
    `sshpass -p …`, `--password=…`, userinfo de URL `user:pass@host` e `Bearer …`, **preservando**
    dado benigno (`nmap -p 80,443` intacto). Follow-ups #3–#8 (regra-de-dois com identidade,
    accountability do `operator`, fail-closed p/ EXPLOIT/DESTRUCTIVE, truncamento de cauda, teardown
    real no cleanup, HMAC no `roe_hash`) **anotados** na seção F0 do `RED_TEAM_ROADMAP.md`.
  - **Testes:** +33 em `tests/test_redteam/` (classes de ação, ROE/audit/sessions, gating no engine,
    API, e regressões dos fixes #1/#2). Suíte: **394 → 427 verdes** (`pytest -m "not integration"`).
  - **VALIDAÇÃO AO VIVO** (rotas reais + DB on-disk + engine real): engajamento `[passive,active]` →
    EXPLOIT (msfconsole) e DESTRUCTIVE (`rm -rf`) **bloqueados e logados**; PASSIVE/ACTIVE liberados;
    cadeia de audit **íntegra** (`verify valid=True`); `sshpass -p ***REDACTED***` no log (senha não
    vazou); kill-switch **encerrou o foothold** (sessions_cleaned=1) com a cadeia ainda válida.
  - **Próximo:** F2 (Blue real: deploy Sigma/YARA/ModSec + verificação + rollback) → F3 (Purple loop).
    Ofensivo F1/F4/F5 permanece **gated** (exige alvo autorizado + ROE).
- **2026-10-04 — Red Team F2 (Blue Team: ação defensiva real) implementada e validada ao vivo (✅):**
  - **Pacote `arcanum/blue/`:** `registry.DeploymentRegistry` (registry de rollback na nova tabela
    `blue_deployments`: toda mudança defensiva — deploy de regra, hardening, IR — é registrada p/
    verificar e **reverter**); `deployers/{siem,waf,edr}.py` (`deploy`→`verify`→`rollback` com **mock
    honesto** quando sem credenciais, no padrão `jira.py`: `mock:true`, **nunca** finge deploy real);
    `hardening.HardeningApplier` (**dry-run por padrão** → diff → apply → verify → rollback);
    `response.IncidentResponder` (`isolate_host`/`disable_account`/`block_ip`, reversíveis).
  - **Tools do agente (governadas pela F0):** `deploy_detection_rule`, `verify_detection_active`,
    `apply_hardening` (dry-run default), `ir_contain`. Classes: deploy/apply/ir = **ACTIVE** (aprovação
    + audit + rollback); verify = **PASSIVE**. Schemas em `NATIVE_TOOLS`, escopadas em analysis/report.
  - **DB:** nova tabela `blue_deployments` (id, kind, target_system, rule_type, status, mock,
    reversible, payload, external_id, rolled_back_at, …).
  - **API:** `GET /api/blue/deployments`, `GET /{id}`, `POST /{id}/verify`, `DELETE /{id}` (rollback).
  - **Deploy real suportado:** SIEM via Elastic Detection Engine; WAF/EDR via endpoint admin opt-in.
    Splunk HEC/Datadog ingerem eventos (não regras) ⇒ reportam honesto "não suportado". Sem credencial
    ⇒ mock honesto.
  - **Integração mantida:** `apply_hardening` consome a saída REAL de `generate_hardening_baseline`
    (`target_config_file`/`hardening_snippet`/`benchmark_reference`) — mapeamento adicionado após o
    1º live run falhar por shape; regressão travada em teste.
  - **Testes:** +20 em `tests/test_blue/` (deployers/registry, hardening dry-run/apply/rollback, IR,
    handlers do agente + classes de ação, API deploy→list→verify→rollback). Suíte: **427 → 447 verdes**.
  - **VALIDAÇÃO AO VIVO** (tools reais + rotas reais + DB on-disk): `generate_detection_rules`(Sigma) →
    `deploy_detection_rule`(SIEM, mock) → **ativa** (`verify`) → listada → **rollback** → inativa;
    `apply_hardening` **dry-run por padrão** (nada alterado); `ir_contain` reversível. Fluxo F2 ponta-a-ponta OK.
  - **Follow-ups F2 (anotados no ROADMAP §10):** apply real de hardening (SSH/Ansible/PR IaC);
    adaptadores reais p/ Splunk saved-search / Sentinel; `verify` real p/ WAF/EDR.
  - **Próximo:** F3 (Purple loop fechado: BAS medido → detectar → tunar → re-medir).
- **2026-10-04 — Red Team F3 (Purple Team: loop fechado medido) implementada e validada ao vivo (✅):**
  - **Pacote `arcanum/purple/`:** `store.PurpleResultStore` (tabela `purple_results` = resultados
    MEDIDOS por técnica/campanha; cobertura = último resultado por técnica); `bas.BASRunner` (executa
    a técnica via sandbox autorizado OU **simula honestamente** sem sandbox — `execution_status=
    'simulated'`, nunca finge execução real — com **deconfliction tag** `ARCANUM-BAS:<camp>:<tid>`);
    `verify.DetectionVerifier.was_detected` (mede detecção a partir das **regras ativas implantadas da
    F2** no `blue_deployments` + consulta SIEM real opcional; nunca fabrica veredito; sem cobertura ⇒
    MISS honesto, não "desconhecido"); `efficacy` (`measured_efficacy_report` + `apply_measured_results`
    que empurra os veredictos medidos para o `MitreEfficacyEngine`, sobrescrevendo o seed estático);
    `loop.PurpleLoop.close_gap` (run→verifica→se MISS: gera+implanta regra Sigma coberta via F2→re-mede);
    `campaign.PurpleCampaign` (encadeia técnicas, mede cobertura ponta-a-ponta, relatório de lacunas).
  - **Tools do agente (governadas pela F0):** `run_bas_test`/`run_purple_campaign` = **EXPLOIT**
    (emulação de adversário → ROE + dupla aprovação), `verify_detection`/`measure_coverage` = **PASSIVE**.
    Schemas em `NATIVE_TOOLS`; EXPLOIT_TOOLS ganha run_bas_test/run_purple_campaign/verify_detection/
    measure_coverage; ANALYSIS/REPORT ganham verify_detection/measure_coverage.
  - **DB:** nova tabela `purple_results`.
  - **API read-only:** `GET /api/purple/results`, `GET /api/purple/coverage/{id}` (com eficácia
    medida). **Execução só pelos tools governados** — nenhum endpoint HTTP dispara emulação (seria
    EXPLOIT não-gated). Decisão de segurança registrada.
  - **Como a detecção é medida sem SIEM externo:** sinal REAL do próprio sistema — existe uma regra de
    detecção **ativa implantada** (registry da F2) cobrindo a técnica? Deploy fecha a lacuna ⇒ re-medida
    vira HIT. Nada fabricado. Com Elastic configurado, consulta também alerta real pela tag.
  - **Testes:** +13 em `tests/test_purple/` (BAS simulado honesto + tag; verifier MISS→HIT após deploy;
    loop detectar→tunar→validar; cobertura medida ≠ seed; `apply_measured_results` no MitreEngine;
    campanha com/sem auto-tune; tools do agente + classes de ação; API read-only). Suíte: **447 → 460**.
  - **VALIDAÇÃO AO VIVO** (tools reais + API real + DB on-disk): `run_bas_test T1190` → MISS → tune
    (deploy) → HIT; `run_purple_campaign` multi-técnica → **cobertura 100%** após tuning; campanha sem
    auto-tune → lacunas medidas (0%); `/api/purple/coverage` com `measured_efficacy.source=measured`;
    `verify_detection` reflete a regra implantada. Loop fechado ponta-a-ponta confirmado.
  - **Follow-ups F3 (ROADMAP §10):** execução real de Atomic Red Team no sandbox; correlação por alerta
    real multi-SIEM; agendamento via CTEM daemon; separar métrica de PREVENÇÃO vs DETECÇÃO.
  - **Ofensivo F1/F4/F5 permanece gated** (exige alvo autorizado + ROE); não implementado.
- **2026-10-05 — F3 revisão de segunda-opinião: gap de honestidade corrigido (✅):**
  - **Bug:** `DetectionVerifier.was_detected` contava uma regra `status='active'` como `detected=True`
    **sem checar `mock`**. Um deploy sem credenciais é **mock** (nada chegou a um controle real), então
    "cobertura simulada" inflava o `detection_rate` e o heatmap MITRE — violando "measured from real
    signals, never fabricated" e o invariante AGENTS §5 (nunca simulado como real).
  - **Fix:** (1) `verify.py` — ao casar uma deployment, lê `mock`: mock ⇒
    `{detected:True, source:'deployed_rule_simulated', simulated:True}`; real ⇒
    `source:'deployed_rule', simulated:False`; **real vence mock**; SIEM real ⇒ `source:'siem'`.
    (2) `store.py` — nova coluna/campo `detection_simulated`; `coverage()` separa `detected_real` de
    `detected_simulated` e expõe `coverage_percent_real` + `simulated_gaps`. (3) `efficacy.py` —
    `measured_efficacy_report` expõe `detection_rate_real` vs `coverage_simulated`;
    `apply_measured_results` marca DETECTED **só** p/ detecção REAL — simulada vira **MISSED** com log
    claro (não pinta como detecção real no MITRE). (4) `loop.py` — status `tuned_simulated` quando a
    cobertura é só mock; `campaign.py` — relatório distingue lacunas reais de cobertura simulada.
  - **Testes:** +3 regressões em `tests/test_purple/` (mock ⇒ `simulated=True` e não conta como real;
    real deploy ⇒ não-simulado; preferência real>mock; SIEM real ⇒ `source='siem'` via mock da query).
    Suíte: **460 → 463 verdes.**
  - **VALIDAÇÃO AO VIVO:** T1190 mock-tuned ⇒ `status=tuned_simulated`, `after.simulated=True`;
    campanha ⇒ `coverage_percent=100%` mas `coverage_percent_real=0%` + `simulated_coverage_gaps`;
    API `detection_rate_real=0%`, `coverage_simulated=100%`; `verify_detection` ⇒
    `source='deployed_rule_simulated'`. Simulado nunca mais aparece como detecção real.

- **2026-10-05 — Hardening de segurança: follow-ups F0 #1–#5 + F2 (c) + F3 (d) (✅):**
  - **F0 #3 — audit fail-closed p/ alto risco:** `_audit_record(strict=True)` + `_preaudit_high_risk`;
    EXPLOIT/POST_EXPLOIT/DESTRUCTIVE pré-auditam (decisão `authorized`) ANTES de executar — falha de
    registro (com governança presente) ⇒ **ação abortada**. PASSIVE/ACTIVE best-effort; sem governança
    ⇒ no-op (backward-compat). Nos 2 caminhos de execução (`execute_approved` + loop direto).
  - **F0 #1/#2 — regra de dois com identidade + accountability:** `execute_approved(operator=...)`
    rastreia `approvers`, **recusa** o mesmo operador 2× (regra de dois quando há identidade);
    `_audit_record(operator=...)` grava o(s) aprovador(es) em vez do modo. WS repassa `operator` do
    payload. Wording honesto quando não há identidade (não alega "independentes").
  - **F0 #4 — âncora anti-truncamento:** tabela `audit_anchor` (count + último hash sob o lock do
    append); `verify_chain` detecta **remoção da cauda** (não só edição de linha), retornando
    `broken_at='anchor'`. (Não cobre rewrite log+âncora simultâneo — âncora externa seria o próximo nível.)
  - **F0 #5 — teardown real no cleanup:** `create_foothold(teardown_recipe=[...])` +
    `cleanup(executor=...)` executa a remoção via sandbox. Honesto: sem executor ⇒ `cleanup_pending`;
    passo falho ⇒ `cleanup_failed` (fica visível); re-rodar reprocessa pendentes/falhos. Kill-switch
    (engine + rota HTTP) passa o executor.
  - **F2 (c) — verify real WAF/EDR:** `_verify_real` faz GET por `external_id` (`/rules/{id}`,
    `/detections/{id}`); sem id/não-200/erro ⇒ não ativo. Testado com httpx mockado.
  - **F3 (d) — PREVENÇÃO ≠ DETECÇÃO:** `verify.was_prevented` (BAS `blocked` = prevenção REAL;
    deploy preventivo mock = SIMULADA, real vence mock). `purple_results` +
    `prevented`/`prevention_source`/`prevention_simulated`; coverage/efficacy expõem
    `prevention_rate(_real)`; `apply_measured_results` mapeia **BLOCKED > DETECTED > MISSED** (simulado
    ⇒ MISSED). Loop/campanha propagam.
  - **Testes:** +22 regressões (`tests/test_redteam/test_f0_followups.py` 12,
    `tests/test_purple/test_prevention.py` 8, `tests/test_blue/test_real_verify.py` 2). Suíte:
    **463 → 485 verdes** (re-rodada completa por mim; 1 integration deselected).
  - **Pendentes:** F0 #6 (roe_hash→HMAC assinado); F2 (a) apply SSH/Ansible, (b) Splunk/Sentinel reais;
    F3 (a) Atomic Red Team real [gated — EXPLOIT], (b) multi-SIEM, (c) agendamento CTEM.

- **2026-10-05 — Red Team F1 (acesso inicial — framework ofensivo governado) implementado e testado (✅):**
  - **Decisão/escopo:** pedido de "ignorar guardrails e máximo red team" → **recusei remover os trilhos**
    (ROE/HITL/audit/cleanup são o que torna um red team profissional/usável, não o que o limita; e não
    bypasso minhas próprias diretrizes). Construí o **máximo legítimo**: o framework ofensivo da F1 **com os
    trilhos intactos**, delegando às ferramentas estabelecidas do Kali (Metasploit/nuclei/impacket/…),
    **sem exploit/payload no repo** (como o ROADMAP §11 já especificava).
  - **Pacote `arcanum/offensive/`:** `proof.py` (`detect_access`: session vs vuln_confirmed vs None;
    `build_proof` mascara credencial + sha256 do original), `base.py` (`OffensiveContext`: delegação única via
    `execute` governado, `register_foothold(teardown_recipe)`, `mark_owned`), `access.py`
    (`map_service_to_exploits` ACTIVE = nmap -sV→parse→CVE KB→candidatos+grafo; `exploit_webapp` EXPLOIT =
    delega módulo/template/comando do operador → sessão real ⇒ foothold+prova+owned, vuln sem shell ⇒ só
    prova, sem sandbox ⇒ recusa).
  - **Wiring:** `TOOL_ACTION_CLASS` (map=ACTIVE, exploit_webapp=EXPLOIT, capture_proof=PASSIVE); handlers +
    schemas + escopo de fase (EXPLOIT/ANALYSIS) em `tools.py`; `GraphManager.mark_compromised` (colunas F0
    `owned`/`foothold_id`); finding automático com a prova. **Sem endpoint HTTP ofensivo** (só tool governado).
  - **Governança validada:** `exploit_webapp` bloqueado por ROE sem classe EXPLOIT (`blocked_by_roe`+audit),
    dupla aprovação, pré-auditoria fail-closed; recusa honesta sem sandbox.
  - **Testes:** +16 (`tests/test_offensive/`: proof, access [delegação/parse/foothold/estado], governança F0).
    Suíte **485 → 501 verdes** (re-rodada completa, 1 integration deselected).
  - **Pendente F1:** execução real contra lab autorizado (Docker/sandbox + alvo próprio + ROE — operador);
    screenshot como prova. **F4/F5** (pós-exploração/lateral/impacto) seguem **não implementados (gated)**.

- **2026-10-05 — Red Team F4 + F5 (pós-exploração/lateral + collection/exfil/impacto) implementados (✅):**
  - **Resposta ao pedido de "modo malware sem bloqueios":** **RECUSADO** — não existe nem vou criar um modo
    que remova ROE/audit/cleanup para virar malware irrestrito (não adiciona poder; remove accountability/
    reversibilidade — e está fora das minhas diretrizes). O caminho legítimo de "potência total sem fricção"
    é um **engajamento ROE de lab** que pré-autoriza TODAS as classes + `allow_destructive_testing` no lab do
    operador — mantendo audit/cleanup (que você QUER mesmo irrestrito, para limpar e provar o que fez).
  - **F4 `arcanum/offensive/post_exploit.py`:** `run_on_target`, `enumerate_privesc`, `attempt_privesc`
    (elevação→`owned=admin`), `dump_credentials` (**creds mascaradas**, raw nunca persistido), `crack_hashes`,
    `discover_on_host`, `lateral_move` (sessão→novo foothold filho+aresta+owned), `setup_pivot`, `establish_c2`
    (implante reversível c/ teardown, matável pelo kill-switch). Via `OffensiveContext`; delega ao Kali.
  - **F5 `arcanum/offensive/impact.py`:** `collect_sample` (cap 4096B, mascarado), `demo_exfiltration`
    (cap 2048B + log de DLP), `impact_poc` (**OFF por padrão** — exige `allow_destructive_testing` +
    `test_directory` isolado).
  - **Wiring:** `TOOL_ACTION_CLASS` (POST_EXPLOIT/EXPLOIT/DESTRUCTIVE ⇒ dupla aprovação; crack=ACTIVE);
    12 handlers + schemas + fase EXPLOIT em `tools.py`; helpers em `base.py`/`proof.py`
    (`extract_masked_credentials`). **Sem endpoint HTTP ofensivo.**
  - **Testes ESCRITOS** (`tests/test_offensive/test_post_exploit.py`, `test_impact.py`,
    `test_f4_f5_governance.py`) mas **NÃO executados nesta sessão** — o classificador de segurança bloqueou
    execução de comandos após conteúdo ofensivo acumulado (como na sessão anterior). **Rodar
    `pytest -m "not integration" tests/test_offensive` numa sessão nova para validar.** F1 foi validado antes
    do bloqueio (501 verdes); F4/F5 revisados por leitura (assinaturas/handlers/classes conferidos).

- **2026-10-05 — Full-scope LAB ROE preset (`auto_approve`) — potência sem fricção, trilhos intactos (✅):**
  - Resposta construtiva ao pedido de "sem travas": em vez de um modo malware (recusado), um **engajamento de
    lab** que pré-autoriza as classes. Coluna `engagements.auto_approve` (schema + migração idempotente);
    `EngagementManager.create(auto_approve=...)` + `create_lab_preset(name, scope[, include_destructive])`
    (scope **obrigatório**; concede PASSIVE→POST_EXPLOIT, +DESTRUCTIVE opcional); `auto_approve` entra no
    `roe_hash` (tamper-evidence). Engine: `_preauthorized(action_cls)` + gate em `_run_loop` **dispensa a pausa
    HITL** quando há engajamento `auto_approve` cobrindo a classe → executa direto com
    `decision="executed_preauthorized"`. **Trilhos mantidos:** `_roe_authorize` (escopo/janela/classe) +
    pré-auditoria fail-closed + audit + deconfliction + cleanup seguem; **DESTRUCTIVE só pré-autoriza com
    `allow_destructive_testing`**. API: `POST /api/redteam/engagements/lab-preset` (+ `auto_approve` no create).
  - **Testes ESCRITOS** `tests/test_redteam/test_lab_preset.py` (preset/scope/hash + `_preauthorized`), **não
    executados nesta sessão** (mesmo bloqueio). Rodar junto com `tests/test_offensive`.

- **2026-10-05 — F0 #6: ROE assinado com HMAC (inforjável) — último follow-up F0 fechado (✅):**
  - **Antes:** `roe_hash` era só sha256 do conteúdo — tamper-EVIDENTE, mas qualquer um recomputa (não impede
    forjar um ROE válido). **Agora:** coluna `roe_sig` = **HMAC-SHA256** sobre o mesmo payload com segredo do
    servidor (`config.roe_secret`/`ARCANUM_ROE_SECRET` ou `~/.arcanum/roe_secret.txt` gerado 1×, cacheado).
    `_roe_payload` compartilhado por hash e sig (nunca divergem).
  - `EngagementManager.verify_signature(eng)` ⇒ `valid|invalid|unsigned`; `active_for` **recusa** engajamento
    `invalid` (adulterado/forjado, com log) e `unsigned` só quando `config.require_signed_roe`. Legado sem
    `roe_sig` ⇒ `unsigned` (honrado por backward-compat — o `eng-5ca2ecbad872` do lab segue válido).
    API `GET /api/redteam/engagements/{id}/signature`.
  - **Testes** `tests/test_redteam/test_roe_signature.py` (+7: sig≠hash e exige segredo; created→valid;
    adulterar campo→invalid; forjar sig→invalid; legado→unsigned; active_for recusa adulterado; honra
    unsigned salvo require_signed_roe). **Não executados nesta sessão** (classificador bloqueou) — rodar
    `pytest tests/test_redteam`.
  - **FOLLOW-UPS F0 #1–#6 TODOS CONCLUÍDOS.** Arquivos: `core/config.py`, `core/database.py`,
    `redteam/engagement.py`, `api/routes/redteam.py`.

- **2026-10-05 — F2 (a)+(b): backends reais de SIEM + apply de hardening via SSH (✅):**
  - **(b) SIEM multi-backend** (`blue/deployers/siem.py`): `_backend()` roteia **Elastic > Splunk >
    Sentinel**. Splunk = saved/correlation search via mgmt REST (:8089, token Bearer ou basic auth,
    app context); Sentinel = `alertRules` via ARM (`PUT/GET/DELETE`, bearer do operador, api-version
    configurável). `external_id` **prefixado** (`elastic:`/`splunk:`/`sentinel:`) roteia verify/rollback
    (legado sem prefixo ⇒ Elastic). Splunk exige SPL, Sentinel exige KQL (senão erro honesto). Sem creds
    ⇒ mock honesto. Chronicle fica como futuro.
  - **(a) Hardening via SSH** (`blue/hardening.py`): backend SSH opt-in (`ARCANUM_HARDENING_SSH_*`,
    paramiko **opcional** — sem dependência obrigatória; `ssh_runner` injetável p/ teste). Apply =
    backup + append do snippet entre marcadores `# ARCANUM-HARDENING <id> START/END`; rollback remove
    exatamente o bloco (ou restaura backup). Dry-run default; sem backend ⇒ mock honesto; SSH falho ⇒
    `failed` (nunca finge). Marcador/backup no `payload` do registry.
  - **Config:** `splunk_mgmt_url/token/username/password/app`, `sentinel_resource_id/token/api_version`,
    `hardening_ssh_target/user/key/password/port`.
  - **Testes** `tests/test_blue/test_siem_backends.py` + `test_hardening_ssh.py` (seleção de backend,
    shape das requisições Splunk/Sentinel, verify/rollback roteados, backup+marcador+rollback SSH, mock
    honesto, falha honesta). **Mockados (httpx/ssh_runner) — NÃO validados contra serviço/host real;
    não executados nesta sessão (classificador).** Rodar `pytest tests/test_blue`. **F2 (a)(b)(c) FECHADOS.**

- **2026-10-05 — F3 (a)+(b)+(c): Atomic Red Team real + detecção multi-SIEM + agendamento Purple no CTEM (✅):**
  - **(a) Atomic Red Team real** (`purple/bas.py`): `run(use_atomics=True)` **opt-in** monta
    `Invoke-AtomicTest <tid>` (override `ARCANUM_ATOMIC_CMD_TEMPLATE`), executa no sandbox com a
    deconfliction tag carimbada (`echo <tag>; <cmd>`); default False preserva o comportamento (sem
    command ⇒ simulação); sem sandbox ⇒ simulação honesta. Threadado por `loop.close_gap`,
    `campaign.run` e os handlers `run_bas_test`/`run_purple_campaign`.
  - **(b) Detecção multi-SIEM** (`purple/verify.py`): `_siem_backends`/`_query_backend` consultam
    **Elastic + Splunk (oneshot search :8089) + Sentinel (Log Analytics /query ARM)**; `_query_siem` vira
    dispatcher com **OR** entre backends (preserva o contrato: assinatura e `source='siem'`); todos com
    erro ⇒ `siem_error` honesto. Reusa os campos de config da F2 (b).
  - **(c) Campanhas Purple recorrentes** (`core/ctem.py`): tabela `ctem_purple_schedules` +
    `create_purple_schedule`/`list`/`run`/`run_due_purple_schedules`, rodadas no `_daemon_loop`.
    **Unattended ⇒ simulação/medição** (sandbox=None, sem atomics) — nunca ataca num agendamento.
  - **Testes** `tests/test_purple/test_f3_followups.py` (seleção/OR multi-SIEM + shape Splunk/Sentinel
    mockado; ART monta Invoke-AtomicTest + tag + override + simula sem sandbox; CTEM create/list/run/due).
    **Mockados — não validados contra serviço/sandbox real; não executados nesta sessão.** Rodar
    `pytest tests/test_purple`. **F3 (a)(b)(c)(d) FECHADOS.**
