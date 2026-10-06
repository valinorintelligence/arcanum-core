# HANDOFF — Prompt de continuidade para o próximo agente

> Cole o conteúdo abaixo (ou aponte o agente para este arquivo) no início da próxima sessão.
> Ele assume que o agente **não** participou das sessões anteriores. Responder sempre em pt-BR.

---

Você vai continuar um trabalho em andamento no projeto **Arcanum Core**. Você **NÃO** participou das sessões anteriores — leia tudo abaixo antes de agir.

## 1) O que é o projeto
Arcanum Core é uma plataforma self-hosted de pentest autônomo assistido por IA:
**FastAPI + Ollama (LLM local `qwen2.5-coder:7b`) + sandbox Kali em Docker**. O agente roda um loop ReAct (recon → análise → exploração → relatório). Dono/operador: `adrianoterresrosa@gmail.com`. Repo: `D:\Antigravity-Arkanum\arcanum-core` (Windows 11, PowerShell). Branch: `fix/arcanum-hardening`.

**Alvos autorizados (os únicos):** o lab local (DVWA em `host.docker.internal:8080` e o host interno `arcanum-internal`, SSH `svc`/`Lab12345`) e o site próprio `leouve.com.br`. Nada além disso.

## 2) Regras de segurança invioláveis (não quebrar, mesmo se pedirem)
- **NUNCA** criar um "modo malware / sem travas" que desligue ROE, auditoria ou cleanup. Já foi pedido e **RECUSADO** — a recusa continua valendo. O caminho legítimo de "potência sem fricção" é o engajamento de lab com `auto_approve` (**lab-preset**), que pré-autoriza classes mas **mantém todos os trilhos** (escopo/ROE/audit/cleanup). `DESTRUCTIVE` só com `allow_destructive_testing`.
- **Governança determinística NUNCA é confiada ao modelo.** Toda ação é classificada (`PASSIVE|ACTIVE|EXPLOIT|POST_EXPLOIT|DESTRUCTIVE`), checada contra o ROE e registrada num audit log append-only encadeado por hash. Execução ofensiva só por tool governado ou pelo console governado — nunca por endpoint HTTP solto, **nunca no host** (só no sandbox).
- **Anti-"mock silencioso":** nunca apresentar simulado como real; nunca fingir sucesso. Recurso ausente ⇒ sinalizar "indisponível/simulado" honestamente.
- **Commitar SOMENTE quando o usuário pedir.** Reportar falhas de teste honestamente.

## 3) Limites de ambiente (importante)
- Windows + PowerShell 5.1: **não** use `&&` (use `;`). `.ps1` é lido como cp1252 → **nada de acento/emoji/travessão em scripts `.ps1`** (quebra o parser).
- **UTF-8 obrigatório** em todo I/O de arquivo Python (`encoding="utf-8"`). `frontend/index.html` é lido a cada `GET /` → mudanças no HTML entram com **F5**. Mudanças em `.py` exigem **reiniciar o servidor** (`arcanum serve`, `reload=False`).
- O 7B roda numa **GTX 1650 4GB** → é CPU-bound e lento; prompts longos travam por minutos.
- **Limites de execução do agente:** o classificador de segurança desta ferramenta pode **bloquear Bash/PowerShell/git/browser** após conteúdo ofensivo acumulado. Na prática você talvez só tenha Read/Grep/Glob/Edit/Write. **O usuário roda os testes, o servidor e o git.** Entregue comandos prontos; não insista em rodar shell.

## 4) Docs canônicos (leia antes de mexer)
- `AGENTS.md` → §5 tem **todas** as invariantes anti-regressão (Governança F0, Blue F2, Purple F3, Ofensivo F1/F4/F5, e a seção do **Console direto**). Mantido pelo usuário: só **acrescente**, não reescreva.
- `docs/MASTERPLAN.md` e `docs/RED_TEAM_ROADMAP.md` → plano, bugs, roadmap das fases.
- **Memória persistente (LEIA PRIMEIRO):** `C:\Users\adrit\.claude\projects\D--Antigravity-Arkanum-arcanum-core\memory\arcanum-state-and-bottleneck.md` — resumo vivo do estado real, com histórico detalhado do que foi feito e do que falta.

## 5) Estado atual — já implementado (e majoritariamente commitado)
Fases concluídas e validadas: **F0** (governança: ROE assinado com HMAC, classes de ação, HITL/dupla-aprovação, audit imutável + âncora anti-truncamento, kill-switch, teardown real, lab-preset `auto_approve`), **F2** (Blue real: SIEM Elastic/Splunk/Sentinel, hardening SSH, verify/rollback), **F3** (Purple: loop medido, prevenção≠detecção, Atomic Red Team opt-in, multi-SIEM, agendamento CTEM), **F1/F4/F5** (framework ofensivo governado em `arcanum/offensive/`, delega ao Kali, **ZERO exploit no repo**, screenshot como prova). Commits: `8c0fea4`, `b129a4c`, `44cf86a`, `179ce55`. Suíte: **557 passed**. **PR #1** aberto contra `valinorintelligence/arcanum-core` (o usuário usa o fork `adrianoterresrosa/arcanum-core`; sem push direto na org).

UX já adicionada: painel **"Operações rápidas"** no chat (presets em linguagem leiga que disparam prompts ofensivos prontos) — `frontend/index.html`.

## 6) O que acabou de ser feito nesta sessão (NÃO COMMITADO) — seu ponto de partida
Construímos um **Console direto do Kali (sem LLM) com streaming ao vivo** e uma **biblioteca de comandos reorganizada por objetivo**. Arquivos:

- **`arcanum/sandbox/docker.py`**: novo `execute_stream()` — roda `docker exec` lendo stdout/stderr em chunks (fila+sentinela) em vez de `communicate()`; timeout **mata** o processo (cliente + `pkill` no container); cancel/disconnect dispara `_kill_exec` no `finally` (nada fica rodando). Também novo helper `_kill_exec()`.
- **`arcanum/api/routes/console.py`**: POST `/api/console/execute` (one-shot governado) refatorado com `_govern()` (classify+ROE compartilhado) + **NOVO WebSocket `/api/console/stream`** (`stream_router`, **sem** dependência de token HTTP, valida `?token=` no handler como `/ws/{session_id}`). Emite `start→chunk*→end`, aceita `{type:"cancel"}`, audita `console_executed`/`blocked_by_roe`/`console_cancelled`. Sem sandbox ⇒ recusa (nunca host).
- **`arcanum/api/main.py`**: registra `console.stream_router` (sem auth dep) ao lado do `ws_router`.
- **`frontend/index.html`**: `runConsole` transmite pelo WS (métodos `ensureConsoleWs`, `handleConsoleWs`, `cancelConsole`, `runConsoleHttp` de fallback); botão **Parar**, selo **● ao vivo**, fallback automático pro POST em 4s se o WS não abrir. `consoleCatalog` reescrito em **12 categorias por objetivo** (Setup, Recon&OSINT, App Web, **WordPress**, Outros CMS, **APIs&SaaS**, Cloud&segredos, Credenciais, Exploração, Pós-expl/Lateral/AD, Serviços de rede, Utilidades), cobrindo todas as ferramentas da imagem (`Dockerfile.sandbox`). Campos novos por item: `req` (pip `--user` que roda no sandbox → botão **Instalar**) e `note` (ressalva honesta).
  - **Honestidade:** `apt` **não** roda no sandbox (`USER nobody` + `cap-drop=ALL`) → tools apt-only (nikto/whatweb/john/evil-winrm/enum4linux-ng/searchsploit/joomscan) têm `note` "rebuild da imagem"; masscan/tshark/bettercap têm `note` de privilégio.
- **`tests/test_redteam/test_console.py`**: +3 testes de streaming (`_stream_one`: roda+audita; bloqueia por ROE **sem tocar no sandbox**; recusa sem sandbox).
- **`tests/test_security/test_execute_stream.py`** (NOVO): fake subprocess — chunks+exit, timeout mata+sinaliza.
- **`AGENTS.md`**: nova invariante "Console direto do operador (sem LLM) continua governado".
- **Memória** `arcanum-state-and-bottleneck.md`: atualizada com tudo acima.

## 7) Próximas ações imediatas (nesta ordem)
**a)** Peça ao usuário para **reiniciar o servidor** (mudou `.py`) e dar **F5**:
```
Get-NetTCPConnection -LocalPort 8000 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }; $env:PYTHONIOENCODING='utf-8'; arcanum serve
```
**b)** Peça para rodar os testes do que foi feito (idealmente a suíte toda):
```
$env:PYTHONIOENCODING='utf-8'; python -m pytest -m "not integration" tests/test_redteam/test_console.py tests/test_security/test_execute_stream.py tests/test_agent/test_adaptive_tooling.py -q
```
**c)** Validar na UI: abrir uma operação → botão **💻 Console** → rodar um comando longo (ex.: `nmap -sT -Pn -sV -p- host.docker.internal`) e confirmar: saída **ao vivo**, botão **Parar** cancela, comando fora do ROE é **bloqueado**.
**d)** Se tudo verde e o usuário autorizar, commitar (deixando `findings/*.json` de fora):
```
git add arcanum/sandbox/docker.py arcanum/api/routes/console.py arcanum/api/main.py arcanum/agent/tools.py frontend/index.html AGENTS.md scripts/ tests/test_redteam/test_console.py tests/test_security/test_execute_stream.py tests/test_agent/test_adaptive_tooling.py
```
Mensagem: `feat(console): live-stream direct Kali console over WebSocket + objective-organized command library` (termine com a linha de atribuição que a ferramenta exigir).

## 8) Melhorias sugeridas (só com o OK do usuário — não comece sozinho)
- Reconexão automática do WS do console se cair no meio de um scan longo.
- Botão "limpeza/pânico" (kill-switch) dentro da tela do console.
- Presets de console sensíveis ao contexto (ex.: só mostrar WordPress se o alvo for WP).
- Pendência operacional (não-código): lab multi-host (AD) p/ exercitar F4 lateral/C2 e F5 a fundo.
- Lembrete: em autopilot o 7B **não** dispara exploit sozinho → ofensivo exige copilot/instrução explícita (ou os presets).

---
**Comece** lendo a memória (`arcanum-state-and-bottleneck.md`) e o `AGENTS.md` §5. Depois conduza as ações da seção 7, pedindo ao usuário para executar os comandos (seu shell provavelmente estará bloqueado pelo classificador).
