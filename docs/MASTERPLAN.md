# Arcanum Core — Plano Mestre & Guia de Auditoria

> **Documento vivo.** Consolida o estado real do sistema, todos os gaps/bugs descobertos, os
> aprendizados (incluindo medições de performance) e o roadmap de correção. **A cada nova
> descoberta, atualize este documento** (veja [Protocolo de Atualização](#protocolo-de-atualização))
> e o [`AGENTS.md`](../AGENTS.md).
>
> Última atualização: 2026-10-03 · Branch: `fix/arcanum-hardening`

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

### 🟡 P2 — Qualidade / robustez — ⏳ EM ANDAMENTO (2026-10-03)
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
  - **Recomendações de ambiente (usuário aplica + reinicia Ollama):** `OLLAMA_NUM_THREAD=6` (deixa
    núcleos para o SO), `OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0`. Rodar 1 server por vez;
    Docker só ao usar `execute`. **385 testes verdes.**
