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

### Governança de ação (F0 — `arcanum/redteam/`)
- **Classificação determinística, nunca confiada ao modelo.** Toda tool call é classificada por
  `redteam/action_classes.classify` em `PASSIVE|ACTIVE|EXPLOIT|POST_EXPLOIT|DESTRUCTIVE`. Regra:
  `audit_*/query_*/search_*/…` → PASSIVE; `execute` → ACTIVE com upgrade por heurística de comando
  (sqlmap `--dump`/hydra/metasploit/mimikatz… → EXPLOIT; `rm -rf`/`mkfs`/`shutdown`… → DESTRUCTIVE);
  tool desconhecida ⇒ ACTIVE (nunca PASSIVE silencioso).
  **Side-effect vence o prefixo:** `headless_web_audit` (dirige browser no alvo) e `dispatch_*`
  (Jira/SIEM, probe remoto) têm override explícito em `TOOL_ACTION_CLASS` ⇒ **ACTIVE** (apesar do
  nome parecer passivo). Ao adicionar tool com efeito externo, **adicione o override** — não confie
  no prefixo.
- **ROE bloqueia determinismicamente.** Se há engajamento ativo (`EngagementManager.active_for`) e a
  classe/janela/escopo não são permitidos, `engine._roe_authorize` **bloqueia** (evento
  `blocked_by_roe`) e **registra** no audit. **Sem engajamento ativo ⇒ não bloqueia** (backward-compat;
  o escopo determinístico do engine continua valendo em separado).
- **HITL por classe.** PASSIVE=auto · ACTIVE=1 aprovação · EXPLOIT/POST_EXPLOIT/DESTRUCTIVE=**dupla
  aprovação** (`execute_approved` re-arma o pending até 2 confirmações). *(Follow-up: ainda não há
  identidade p/ "aprovadores independentes" — ver ROADMAP §10 F0.)*
- **Audit log imutável e encadeado.** `redteam/audit.ActionAuditLog.record` é **append-only** com
  `entry_hash=sha256(prev_hash+payload)` (lock por conexão garante a seção crítica). **Nunca** fazer
  `UPDATE`/`DELETE` em `actions_log`; `verify_chain()` detecta adulteração.
- **Mascaramento por chave E por valor.** `mask_arguments` redige por nome de chave **e** escaneia
  valores (inclusive `command`) por credencial inline (`sshpass -p`, `--password=`, userinfo de URL
  `user:pass@`, `Bearer …`), **sem** destruir dado benigno (`nmap -p 80` é preservado). Segredo nunca
  entra em claro no log.
- **Kill-switch global.** `POST /api/redteam/killswitch` aborta todos os runs + `SessionRegistry.cleanup()`
  encerra todos os footholds/implantes; `engine.kill_switch()` faz o mesmo p/ um engajamento. Cleanup
  é **obrigatório** no encerramento.
- **Audit fail-closed p/ alto risco (follow-up #3).** EXPLOIT/POST_EXPLOIT/DESTRUCTIVE passam por
  `engine._preaudit_high_risk` → `_audit_record(strict=True)` ANTES de executar; se o registro imutável
  falhar (com governança presente), a ação é **abortada**. PASSIVE/ACTIVE seguem best-effort (recon não
  morre por hiccup de DB); **sem governança ⇒ no-op** (backward-compat). Nunca executar ofensiva sem auditoria.
- **Regra de dois real + accountability (follow-up #1/#2).** `execute_approved(operator=...)` rastreia
  `approvers` e **recusa** o mesmo operador aprovando 2×; `_audit_record(operator=...)` grava o(s)
  aprovador(es). Sem identidade (ainda sem auth) ⇒ contagem de confirmações e a mensagem diz isso
  honestamente — **não** alegar "aprovadores independentes" sem identidade.
- **Âncora anti-truncamento (follow-up #4).** `audit_anchor` (count + último hash, atualizada sob o lock
  do append) faz `verify_chain` detectar **remoção da cauda**, não só edição de linha. **Nunca**
  `UPDATE/DELETE` em `actions_log` nem em `audit_anchor`.
- **ROE assinado com HMAC (follow-up #6).** Engajamento tem `roe_hash` (conteúdo) **e** `roe_sig` =
  HMAC-SHA256 com segredo do servidor (`_resolve_roe_secret`: config/env ou `~/.arcanum/roe_secret.txt`),
  inforjável sem o segredo. `EngagementManager.verify_signature` ⇒ `valid|invalid|unsigned`; **`active_for`
  recusa `invalid`** (adulterado/forjado), e `unsigned` só quando `require_signed_roe`. Hash e sig derivam
  do mesmo `_roe_payload` (nunca divergem). **Nunca** editar `engagements` por fora — invalida a assinatura.
- **Teardown real no cleanup (follow-up #5).** `create_foothold(teardown_recipe=[...])` +
  `SessionRegistry.cleanup(executor=...)` **executa** a remoção via sandbox. Honesto: receita sem executor
  ⇒ `cleanup_pending` (nunca finge `cleaned`); passo falho ⇒ `cleanup_failed` (fica visível); re-rodar
  reprocessa pendentes/falhos. Ao criar foothold em F1/F4, **sempre** registrar a `teardown_recipe`.
- **Full-scope LAB ROE (`auto_approve`) — potência sem fricção, trilhos intactos.** Um engajamento com
  `auto_approve=1` (crie via `EngagementManager.create_lab_preset` ou `POST /api/redteam/engagements/lab-preset`)
  **pré-autoriza** suas classes permitidas: `engine._preauthorized` **dispensa a pausa HITL por ação** para
  essas classes. **NÃO remove trilho:** `_roe_authorize` (escopo/janela/classe) continua valendo, tudo é
  auditado (`decision="executed_preauthorized"`), deconflictado e reversível; **escopo é OBRIGATÓRIO** no preset
  (nunca full-scope sem escopo); e **DESTRUCTIVE só é pré-autorizado com `allow_destructive_testing`**. É o
  caminho legítimo de "sem travas" para o lab do próprio operador — não existe modo que desligue ROE/audit/cleanup.
- **Ofensivo (F1/F4/F5) só com alvo autorizado + ROE assinado.** Não implementar wrappers ofensivos
  sem lab autorizado próprio, Docker/sandbox ligados e decisão de HITL/modelo (ver ROADMAP §6/§11).

### Blue Team (F2 — `arcanum/blue/`)
- **Toda ação defensiva real é registrada p/ rollback.** `DeploymentRegistry` (tabela
  `blue_deployments`) é a fonte de verdade do que o Blue mudou e se ainda está ativo. `deploy`→
  `verify`→`rollback` (deployers SIEM/WAF/EDR), `apply`→`verify`→`rollback` (hardening) e `contain`→
  `revert` (IR) **sempre** gravam no registry. Nada de mudança defensiva sem registro reversível.
- **Mock honesto (mesma regra do `jira.py`).** Sem credenciais, o adapter opera em mock
  (`mock:true`, `status:'active'`) e **nunca** finge um deploy real; Splunk HEC/Datadog reportam
  "não suportado" em vez de simular. Deploy real: Elastic (SIEM), endpoints admin opt-in (WAF/EDR).
- **`apply_hardening` é dry-run por padrão.** Só aplica com `dry_run=false` **após** aprovação do
  operador (classe ACTIVE → HITL). Consome a saída de `generate_hardening_baseline`
  (`target_config_file`/`hardening_snippet`) — ao mudar o shape do gerador, atualizar o mapeamento.
- **Classes F0 das tools Blue:** `deploy_detection_rule`/`apply_hardening`/`ir_contain` = **ACTIVE**
  (aprovação + audit + rollback); `verify_detection_active` = **PASSIVE**. Registradas em
  `TOOL_ACTION_CLASS` (override vence prefixo).
- **`verify` real para WAF/EDR (follow-up F2 (c)).** `_verify_real` faz GET por `external_id` no
  endpoint admin (mesmo contrato REST de deploy/rollback: `/rules/{id}`, `/detections/{id}`); sem
  id/não-200/erro ⇒ **não ativo** (honesto, nunca confia cego). Mock continua confiando no registry.
  *(Testado com httpx mockado — não validado contra WAF/EDR real.)*

### Purple Team (F3 — `arcanum/purple/`)
- **Eficácia é MEDIDA, não seed.** O loop grava cada run+veredito em `purple_results`
  (`PurpleResultStore`); `measured_efficacy_report` e `apply_measured_results` derivam a eficácia da
  medição real e sobrescrevem o seed estático do `MitreEfficacyEngine`. Nunca reportar o seed como
  se fosse medição.
- **Detecção nunca é fabricada — e simulado nunca vira real.** `DetectionVerifier.was_detected` mede
  a partir de **regras ativas implantadas (registry F2)** cobrindo a técnica + consulta SIEM real
  opcional. Sem cobertura ⇒ MISS honesto. **Regra crítica (fix F3 2ª opinião):** um deploy sem
  credenciais é **mock** — conta como `source='deployed_rule_simulated'`, `simulated=True`
  (cobertura SIMULADA), **nunca** como detecção real; um deploy real vence o mock. `detection_rate_real`
  (controles reais) é separado de `coverage_simulated` (mock); `apply_measured_results` só marca
  DETECTED no MITRE para detecção REAL (simulada ⇒ MISSED, com log). Ao tocar verify/efficacy/loop,
  preserve essa separação real-vs-simulado (invariante anti-"mock silencioso").
- **BAS não finge execução.** `BASRunner` executa no sandbox autorizado OU **simula honestamente**
  (`execution_status='simulated'`) sem sandbox — nunca alega execução real nem cria artefatos falsos.
  Toda execução carimba **deconfliction tag** (`ARCANUM-BAS:<camp>:<tid>`).
- **PREVENÇÃO ≠ DETECÇÃO (follow-up F3 (d)).** `DetectionVerifier.was_prevented` mede **bloqueio**:
  BAS run `execution_status='blocked'` ⇒ prevenção **REAL** (`source='bas_blocked'`); controle
  preventivo mock (WAF/EDR/firewall/IR/hardening) cobrindo a técnica ⇒ prevenção **SIMULADA**
  (`deployed_control_simulated`), nunca real; real vence mock. `purple_results` tem
  `prevented`/`prevention_source`/`prevention_simulated`; coverage/efficacy expõem `prevention_rate(_real)`
  ao lado de `detection_rate(_real)`; `apply_measured_results` mapeia **BLOCKED** (prevenção real) >
  **DETECTED** (detecção real) > **MISSED** (simulado ⇒ MISSED). Ao tocar verify/efficacy/loop/campaign,
  preserve os dois eixos (prevenção/detecção) e a separação real-vs-simulado.
- **Emulação é EXPLOIT (gated).** `run_bas_test`/`run_purple_campaign` = EXPLOIT (ROE + dupla
  aprovação); `verify_detection`/`measure_coverage` = PASSIVE. A API Purple é **read-only** — execução
  só pelos tools governados (nunca um endpoint HTTP dispara emulação).

### Ofensivo F1 (`arcanum/offensive/`) — acesso inicial, framework governado
- **ZERO exploit/payload no repo.** `arcanum/offensive/` é só **orquestração + governança**: delega a
  técnica às ferramentas estabelecidas do Kali (Metasploit/nuclei/comando escolhido pelo operador). Ao
  adicionar capacidade ofensiva, **nunca** embutir exploit/payload/evasão aqui — só o wrapper governado.
- **Uma via de delegação.** `OffensiveContext.delegate` roda o comando (do operador/ferramenta) no
  **sandbox via `execute` governado** — único ponto que toca o alvo. Sem sandbox ⇒ **recusa honesta**.
- **Foothold só com prova real.** `proof.detect_access` separa **session** (shell/sessão ⇒ registra
  foothold) de **vuln_confirmed** (só prova, **sem** foothold) — nunca assume acesso. `build_proof`
  mascara credencial inline e carimba `sha256` do original.
- **Classes F0:** `map_service_to_exploits`=**ACTIVE** (nmap→CVE, sem ataque), `exploit_webapp`=**EXPLOIT**
  (ROE + **dupla aprovação** + pré-auditoria fail-closed), `capture_proof`=**PASSIVE**. `exploit_webapp`
  é bloqueado por ROE se o engajamento não permite EXPLOIT. **Execução só por tool governado — nenhum
  endpoint HTTP dispara exploração.**
- **Estado + cleanup:** sucesso ⇒ `register_foothold(teardown_recipe=...)` + `GraphManager.mark_compromised`
  (`owned`/`foothold_id`); o foothold já entra no kill-switch/cleanup real (F0 #5). Finding automático com
  a prova como evidência. **Nada roda sem sandbox autorizado + ROE** (lab próprio — responsabilidade do operador).
- **F4/F5 (`post_exploit.py`, `impact.py`) seguem o MESMO contrato:** operam **através de um foothold**
  registrado, delegam ao Kali, capturam prova, atualizam estado (novo foothold em `lateral_move`, `owned`
  em `attempt_privesc`, **creds MASCARADAS** em `dump_credentials`/`crack_hashes` — segredo bruto **nunca**
  persistido), implantes reversíveis (`setup_pivot`/`establish_c2`) com teardown. Classes: POST_EXPLOIT/
  EXPLOIT/DESTRUCTIVE ⇒ **dupla aprovação**. **`impact_poc` é OFF por padrão** (exige
  `allow_destructive_testing` + `test_directory` isolado); `collect_sample`/`demo_exfiltration` têm **caps
  rígidos** (4096B/2048B). Ao estender o ofensivo, nunca contornar esses gates nem persistir segredo em claro.

### Estado (ver MASTERPLAN §9)
P0 ✅, P1 ✅ (exceto TUI), P2 ✅ (valor). Lentidão/freeze: mitigado (flash-attn+KV q8 no Ollama,
`keep_alive=30m`, `num_thread` auto deixando ~2 núcleos livres). `orchestrator.py` removido.
**Skills:** as 57 skills de `agent/skills.py` agora são **semeadas no PlaybookManager**
(`ensure_skill_playbooks`) e usadas via **recall semântico (RAG/FTS)** — não injetadas no prompt.
**TUI:** ainda é stub experimental — o **Web UI é o produto** (a TUI não conecta o engine).
**Red Team F0 ✅** (governança: ROE + classes de ação + HITL + audit imutável + kill-switch) +
**F2 ✅** (Blue real: deploy/verify/rollback, hardening dry-run, IR reversível) + **F3 ✅** (Purple
loop fechado: BAS medido → detectar → tunar → re-medir, eficácia medida ≠ seed) implementadas e
validadas ao vivo (ROADMAP §10; seções "Governança de ação (F0)", "Blue Team (F2)" e "Purple Team
(F3)" acima). **501 testes verdes** (até F1; F4/F5 com testes escritos mas não re-executados na sessão
do classificador — rodar `pytest tests/test_offensive`). **Ofensivo F1+F4+F5 ✅ implementados** (framework
governado `arcanum/offensive/`, delega ao Kali, gated por ROE/dupla aprovação; `impact_poc` OFF por padrão).
Execução real exige lab autorizado + Docker/sandbox + ROE (operador).
**Hardening de segurança (2026-10-05):** **follow-ups F0 #1–#6 TODOS resolvidos** (fail-closed audit,
regra de dois com identidade, âncora anti-truncamento, teardown real, **ROE assinado com HMAC**) +
F2 (c) verify real WAF/EDR + F3 (d) prevenção≠detecção. **F1/F4/F5 ✅** (`arcanum/offensive/`) +
**lab-preset auto_approve**. Validado AO VIVO contra DVWA (foothold `uid=www-data`, audit
`executed_preauthorized` + chain `valid`, kill-switch cleanup). Pendentes: F2 (a)/(b) (apply SSH,
Splunk/Sentinel reais), F3 (a)/(b)/(c) (Atomic Red Team real [gated], multi-SIEM, agendamento CTEM);
screenshot como prova (F1); lab multi-host (AD) p/ exercitar F4 lateral/C2 e F5 a fundo.
