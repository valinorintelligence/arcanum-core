# Arcanum Core — Roadmap de Red Team (e integração Blue/Purple)

> **Documento vivo.** Plano completo para evoluir o Arcanum de "analisa e recomenda" (recon +
> auditoria passiva + geração de artefatos) para **tomar ações reais de Red/Blue/Purple Team** em
> engajamentos **autorizados**, com segurança como espinha dorsal. Atualize a cada entrega.
>
> Escopo deste doc: **profundidade em Red Team** (pedido do usuário), com os pontos de integração
> Blue/Purple. Última atualização: 2026-10-04.

---

## 0. Princípios inegociáveis (valem para TODA capability abaixo)

1. **Somente engajamentos autorizados.** Cada ação exige um **contrato de engajamento (ROE)** ativo,
   com escopo, janela temporal e **classe de ação** permitida. Fora disso, a ação é bloqueada
   deterministicamente (como o scope enforcement atual, estendido).
2. **Classes de ação graduadas:** `PASSIVA` → `ATIVA` → `EXPLORAÇÃO` → `PÓS-EXPLORAÇÃO` →
   `DESTRUTIVA`. Cada classe tem gate de autorização próprio.
3. **Human-in-the-loop (HITL) por tier:** auto (passiva) · aprovação simples (ativa) · **dupla
   aprovação** (exploração/destrutiva/mudança em prod). Reusa `copilot`/`manual` + `_assess_risk`.
4. **Trilha de auditoria imutável:** toda ação real logada (o quê, alvo, quem autorizou, timestamp,
   resultado, hash do ROE). Append-only, exportável para o cliente.
5. **Kill-switch global:** um comando aborta TODOS os runs, sessões e implantes ativos e os limpa.
6. **Captura de evidência, não dano:** provar impacto com o mínimo necessário (amostra mascarada,
   screenshot, shell confirmado) — nunca destruir/exfiltrar além do PoC autorizado.
7. **Deconfliction:** marcar toda ação com um identificador de engajamento para o Blue distinguir
   atividade do Arcanum de ataque real (essencial em Purple).
8. **Este repositório não inclui exploits/payloads prontos** — o roadmap descreve *arquitetura e
   gates*; a execução usa ferramentas estabelecidas (Metasploit, impacket, nuclei, etc.) dentro da
   sandbox, acionadas sob autorização.

---

## 1. Estado atual (fundamentado no código)

| Capacidade | Hoje | Lacuna |
|---|---|---|
| Recon passivo | ✅ 116 `audit_*`, subfinder/CT/OSINT | OSINT estruturado (sherlock/holehe no Kali, não wired) |
| Recon ativo | ⚠️ via `execute` (nmap) | sem mapeamento serviço→exploit estruturado |
| Exploração | ⚠️ só `execute` (sqlmap/nuclei string) | `EXPLOIT_TOOLS` mínimo; metasploit/hydra/netexec **não são tools** |
| Pós-exploração | ❌ | sem C2/implante/sessão em runtime |
| Estado de comprometimento | ❌ | grafo rastreia topologia/findings, **não** hosts owned/creds/acesso |
| Gestão de sessões/loot | ⚠️ stash (credenciais) | sem registro de footholds/pivôs/implantes |
| Evasão / OPSEC | ⚠️ `detect_waf`, rate-limit | sem medição de evasão de EDR/WAF em ação real |
| Arsenal Kali | ✅ metasploit, impacket, pwncat, hydra, hashcat, crackmapexec, chisel, bettercap, sherlock, holehe, trufflehog | **nenhum** é tool estruturada do agente |
| Kill-switch | ⚠️ `engine.abort()` (um run) | não aborta sessões/implantes; não é global |
| Auditoria | ⚠️ findings + reports | sem log imutável de **ações** |

**Resumo:** a fundação existe (sandbox Kali, `execute`, grafo, stash, retest, mitre, integrations,
probes), mas o Red Team real exige: (a) os trilhos da seção 0, (b) tools ofensivas estruturadas,
(c) um **modelo de estado de engajamento/comprometimento**, (d) gestão de sessões/implantes.

---

## 2. Red Team por tática ATT&CK (o núcleo do plano)

> Formato: **Atual → Lacuna → Construir → Gate de segurança → Critério de aceite.**
> "Construir" indica os módulos a estender (`tools.py` = novos handlers + schemas; `engine.py` =
> fases; `graph.py` = estado; etc.).

### TA0043 Reconnaissance
- **Atual:** passivo forte (CT, WHOIS/RDAP, DNS, subdomínios, OSINT parcial).
- **Lacuna:** OSINT de pessoas/credenciais estruturado; recon ativo com fingerprint→CVE.
- **Construir:** tools `osint_people` (sherlock/holehe/theHarvester wrapped), `enrich_breach_data`,
  `map_service_to_exploits` (nmap -sV → search_cve → candidatos). Alimentam o grafo.
- **Gate:** PASSIVA (auto). OSINT de PII sob ROE + minimização de dados.
- **Aceite:** dado um domínio, produzir superfície + pessoas + CVEs candidatos no grafo.

### TA0042 Resource Development *(hoje inexistente)*
- **Lacuna:** geração/staging de payload, infraestrutura (redirector/C2 domain), kit de phishing.
- **Construir:** `generate_payload` (msfvenom wrapper, catálogo de tipos), `stage_payload`
  (servir no workspace da sandbox), `provision_c2_listener`. Artefatos ficam no workspace isolado.
- **Gate:** EXPLORAÇÃO (aprovação). Payloads só para alvos do ROE; assinatura de engajamento embutida.
- **Aceite:** gerar payload parametrizado + listener, registrados no log de ações.

### TA0001 Initial Access *(o maior salto — hoje detecta vuln, não ganha acesso)*
- **Atual:** acha vulns (nuclei/sqlmap via execute); não weaponiza.
- **Lacuna:** exploração de app público → **acesso**; phishing; cred stuffing; valid accounts.
- **Construir:** `exploit_webapp` (metasploit RPC / nuclei -tags + confirmação de RCE/shell),
  `cred_stuffing` (netexec/hydra contra serviços do escopo), `phishing_campaign` (gerar+enviar via
  integrations, só com opt-in explícito e lista autorizada). Sucesso → **cria um foothold** (seção 3).
- **Gate:** EXPLORAÇÃO + **dupla aprovação** para phishing e cred attacks.
- **Aceite:** de uma vuln confirmada, obter sessão/foothold com prova (não só finding).

### TA0002 Execution
- **Atual:** `execute` roda na **sandbox atacante**, não no alvo.
- **Construir:** `run_on_target` (executa comando via sessão/foothold estabelecido — seção 3),
  roteando pelo C2/pwncat. Distinguir claramente "comando na sandbox" vs "comando no alvo".
- **Gate:** PÓS-EXPLORAÇÃO (aprovação; dupla para comandos destrutivos).
- **Aceite:** executar comando num host comprometido e capturar saída como evidência.

### TA0003 Persistence *(hoje inexistente)*
- **Lacuna:** instalar persistência (cron/serviço/registry/SSH key/webshell) para testar detecção.
- **Construir:** `install_persistence` (catálogo por OS) + **registro reversível** (toda persistência
  anotada para remoção garantida no fim do engajamento).
- **Gate:** PÓS-EXPLORAÇÃO + dupla aprovação. **Cleanup obrigatório** no encerramento.
- **Aceite:** instalar + listar + **remover** persistência; Blue mede se detectou.

### TA0004 Privilege Escalation
- **Atual:** `audit_linux_privesc_vectors` / `audit_windows_token_privileges` só **analisam** dados.
- **Construir:** `enumerate_privesc` (linpeas/winpeas no host via sessão) → `attempt_privesc`
  (SUID/sudo/GTFOBins, token/UAC — por catálogo, não exploit custom) com confirmação de elevação.
- **Gate:** PÓS-EXPLORAÇÃO (aprovação). Kernel exploits = dupla aprovação (risco de crash).
- **Aceite:** de user→root/SYSTEM em host autorizado, com prova; atualiza acesso no grafo.

### TA0005 Defense Evasion *(para MEDIR o Blue, não para dano)*
- **Atual:** `audit_waf_bypass_heuristics` (passivo).
- **Construir:** executar técnicas de evasão **durante** ações reais e **medir** se o controle pegou
  (via integração SIEM/EDR — ângulo Purple). Ex.: ofuscação de comando, timing, bypass de WAF.
- **Gate:** EXPLORAÇÃO; **sempre logado e deconflictado** (nunca "evasão furtiva" sem registro).
  *Objetivo é medir detecção, não evadir impunemente.*
- **Aceite:** relatório "técnica X — detectada? (sim/não) pelo controle Y".

### TA0006 Credential Access
- **Atual:** stash guarda creds; `audit_kerberoasting/adcs` analisam.
- **Construir:** `dump_credentials` (mimikatz/LSASS/SAM/shadow via sessão), `roast_accounts`
  (kerberoast/AS-REP real), `crack_hashes` (hashcat/hydra na sandbox) → creds vão ao cofre + grafo.
- **Gate:** PÓS-EXPLORAÇÃO + dupla aprovação (dump de memória). Creds **mascaradas** nas saídas.
- **Aceite:** capturar → crackear → reusar (loop) com rastreio no cofre e no grafo.

### TA0007 Discovery (on-host)
- **Construir:** `discover_on_host` (rede/contas/serviços/compartilhamentos a partir do foothold),
  alimentando o grafo com novos alvos internos (expande a superfície pós-acesso).
- **Gate:** PÓS-EXPLORAÇÃO (aprovação). **Aceite:** mapa interno pós-foothold no grafo.

### TA0008 Lateral Movement
- **Construir:** `lateral_move` (pass-the-hash/ticket, RDP/SMB/WinRM via impacket/netexec/evil-winrm),
  `setup_pivot` (chisel/tunneling). Cada salto = novo foothold + aresta no grafo (prova).
- **Gate:** EXPLORAÇÃO + aprovação por salto (HITL por hop). **Aceite:** executar um caminho
  multi-hop do grafo (hoje só `simulate_attack_path`) com prova por hop.

### TA0009 Collection + TA0010 Exfiltration *(prova de impacto, limitada)*
- **Construir:** `collect_sample` (coleta mínima de arquivo sensível, mascarado), `demo_exfiltration`
  (DNS/HTTPS, **limitado por tamanho/taxa**, para testar DLP) — nunca dados reais além do PoC.
- **Gate:** DESTRUTIVA-adjacente → **dupla aprovação** + limites rígidos + log do que saiu.
- **Aceite:** demonstrar exfil detectável/bloqueável sem vazar dado real relevante.

### TA0011 Command & Control
- **Construir:** `establish_c2` (sliver/pwncat — sessão mTLS), gestão de beacon/canais, redirector.
  Integra com o registro de sessões (seção 3).
- **Gate:** PÓS-EXPLORAÇÃO + dupla aprovação. **Aceite:** sessão C2 estável, listável, matável.

### TA0040 Impact *(máximo gate; só quando o ROE exigir)*
- **Construir:** PoCs **não-destrutivos por padrão** (ransomware sim em diretório de teste isolado,
  defacement em página de staging). Nunca em produção sem ROE explícito + dupla aprovação + backup.
- **Gate:** DESTRUTIVA — o tier mais alto; desligado por padrão (`allow_destructive_testing`).

---

## 3. Fundação operacional (o que falta para "agir" com segurança)

1. **Modelo de estado de engajamento & comprometimento** *(novo — estender `graph.py` + DB):*
   - Nós do grafo ganham estado: `owned` (nível de acesso: none/user/admin/system), `creds_held`,
     `foothold_id`. Arestas registram COMO (ex.: `via pass-the-hash`).
   - Tabela `engagements` (ROE: escopo, janela, classes permitidas, hash assinado) e `actions_log`
     (append-only). `findings` já existe; ligar ação→finding→evidência.
2. **Registro de sessões/implantes** *(novo módulo `arcanum/redteam/sessions.py`):*
   - CRUD de footholds/implantes (host, tipo, acesso, pivô-pai, criado_em, status), com **cleanup**
     garantido no encerramento (persistências, implantes, contas de teste).
3. **Kill-switch global** *(estender `engine.abort` + novo endpoint):* aborta runs + encerra todas as
   sessões/implantes + dispara cleanup. Botão vermelho único na UI.
4. **Classes de ação + ROE enforcement** *(estender `_scope_violation`/`_assess_risk`):* cada tool
   declara sua classe; o engine bloqueia se o ROE não permite ou a janela expirou.
5. **Audit log imutável** *(novo):* toda ação real → `actions_log` (append-only, hash encadeado),
   exportável no relatório final (narrativa de kill-chain).
6. **OPSEC/ritmo:** perfis de engajamento (`stealth` vs `loud`); rate/timing configuráveis; reaproveitar
   a detecção de WAF/CDN para ajustar ritmo.
7. **Confiabilidade da sandbox** *(estender `sandbox/docker.py`):* Docker auto-start/health + **re-detecção
   em runtime** (hoje `ensure_image` só no boot) — sem sandbox, nenhuma ação ofensiva real roda.

---

## 4. O "cérebro" — decisão autônoma vs HITL

- O **7B não é confiável** para encadear exploração multi-passo sozinho (e o hardware limita subir).
- **Near-term:** Red em **copilot** (humano aprova cada ação ofensiva; agente executa + documenta +
  mantém estado). É o modo seguro e já suportado.
- **Médio:** tier híbrido — escalar o **planejamento de exploit** para um modelo maior (`deep_llm`,
  nuvem opcional/GPU melhor), mantendo o 7B para rotina. Ponto de extensão já existe (fast/deep).
- **Autonomia plena** (autopilot ofensivo) só após métricas de confiabilidade altas + gates maduros.

---

## 5. Integração Blue & Purple (o Red alimenta a medição)

- **Blue (ação real):** deploy de detecções geradas (`generate_detection_rules`/`yara`) para SIEM/EDR/WAF
  via `integrations/hub.py`; aplicar hardening (dry-run→aprovar); contenção de IR via APIs.
- **Purple (loop fechado):** cada ação Red (deconflictada) → consultar SIEM/EDR se **detectou** →
  alimentar o `MitreEfficacyEngine` com eficácia **medida** (não seed) → se não detectou, auto-tunar a
  regra (retest engine) → re-executar → confirmar. É o diferencial do produto.
- **BAS real:** trocar o seed estático do `mitre/` por execução de Atomic Red Team medida.

---

## 6. Plano faseado (ordem = valor/risco)

**Entregar Blue/Purple antes do Red destrutivo** (valor com risco controlado + cria os trilhos de
medição/audit que tornam o Red seguro).

- **F0 — Segurança & fundação (bloqueia tudo):** ROE+classes de ação, HITL em tiers, audit log imutável,
  kill-switch global, estado de comprometimento no grafo, registro de sessões, sandbox resiliente.
- **F1 — Red estruturado não-destrutivo:** wrappers estruturados (nmap→CVE, nuclei, sqlmap gated,
  OSINT), captura de prova, `exploit_webapp`→foothold (classe exploração, copilot).
- **F2 — Blue real:** deploy de Sigma/YARA/ModSec + verificação de disparo; hardening apply (dry-run).
- **F3 — Purple loop fechado:** BAS real (atomic tests medidos) + detectar→tunar→validar.
- **F4 — Pós-exploração & lateral:** sessões/C2, discovery on-host, privesc, lateral por hop (HITL),
  credential access (dump→crack→reuse). Dupla aprovação.
- **F5 — Collection/Exfil/Impact (PoC):** sob ROE explícito, limites rígidos, dupla aprovação.

Cada fase: tools com schema + classe de ação + testes (unit + regressão) + atualização dos docs vivos
(MASTERPLAN §9, AGENTS §5) + validação ao vivo em alvo autorizado.

---

## 7. Riscos & mitigações
- **Ação fora de escopo/janela** → ROE enforcement determinístico + kill-switch.
- **Dano acidental** → classes de ação, dry-run, PoC mínimo, backups para destrutivo.
- **Persistência/implante esquecido** → registro + cleanup obrigatório no encerramento + auditoria.
- **Modelo decide errado** → HITL (copilot) para toda ação ofensiva; stagnation guards.
- **Vazamento de credenciais/PII** → cofre + mascaramento + minimização + audit.
- **Confusão Red vs ataque real** → deconfliction tag em toda ação.

## 8. Métricas de sucesso
- % do ciclo ATT&CK coberto por ações **reais** (vs simulação).
- Tempo de foothold→objetivo (com HITL) e taxa de prova capturada por finding.
- Cobertura de detecção medida (Purple): % de técnicas detectadas pelos controles do cliente.
- Zero ações fora de escopo; 100% das ações no audit log; 100% de cleanup pós-engajamento.

## 9. Log de evolução
- **2026-10-04** — Documento criado. Estado atual mapeado; plano F0–F5 definido. Nada de ação real
  implementado ainda (base: recon/auditoria passiva + artefatos). Próximo sugerido: **F0** (ROE +
  classes de ação + HITL tiers + audit log + kill-switch) por destravar com segurança todo o resto.
- **2026-10-04** — Anexadas specs de implementação de F0/F2/F3 (seção 10) para execução em sessão nova.

---

## 10. Specs de implementação (prontas para codar) — F0 · F2 · F3

> Ordem de dependência: **F0 → F2 → F3**. Cada fase: módulos + modelos de dados + tools do agente
> (governadas pela F0) + endpoints + testes + critério de aceite. Manter os 394 testes existentes verdes.

### F0 — Fundação de segurança/governança (keystone)
**Pacote `arcanum/redteam/`:**
- `action_classes.py`: enum `PASSIVE|ACTIVE|EXPLOIT|POST_EXPLOIT|DESTRUCTIVE`; `TOOL_ACTION_CLASS`
  (audit_*/query_*/search_* → PASSIVE; `execute` → ACTIVE, com upgrade por heurística do comando:
  sqlmap --dump/hydra/metasploit → EXPLOIT; rm/mkfs/encrypt → DESTRUCTIVE); `classify(tool,args)`.
- `engagement.py` — `EngagementManager`: `create(name,scope,allowed_classes,window)` (gera `roe_hash`),
  `active_for(session)`, `is_allowed(engagement,cls,target) -> (bool,reason)` (janela + classe + escopo).
  **Backward-compat:** sem engajamento ativo, não bloqueia por classe (mantém comportamento atual).
- `audit.py` — `ActionAuditLog`: `record(...)` append-only com **hash encadeado** (`sha256(prev+payload)`),
  `verify_chain()`, `list()`.
- `sessions.py` — `SessionRegistry`: CRUD de footholds/implantes + `cleanup(engagement)`.
**DB (`core/database.py`):** tabelas `engagements`, `actions_log`, `redteam_sessions`; colunas em
`graph_nodes`: `owned` (none/user/admin/system), `creds_held`, `foothold_id` (migration idempotente).
**Engine (`engine.py` no dispatch):** `cls=classify(...)`; se engajamento ativo e `not is_allowed` →
bloquear (evento `blocked_by_roe`); classe → tier HITL em `_assess_risk` (PASSIVE auto · ACTIVE aprova ·
EXPLOIT/DESTRUCTIVE dupla aprovação); pós-execução `audit.record(...)` (args mascarados); `abort()` →
**kill-switch global** (aborta run + `SessionRegistry.cleanup`).
**API:** `engagements` (POST/GET), `actions` (GET log/verify), `redteam/sessions` (GET/DELETE), `POST /killswitch`.
**Aceite:** engajamento `[PASSIVE,ACTIVE]` → tool EXPLOIT bloqueada+logada; audit chain íntegro;
kill-switch encerra sessões; 394 + novos testes verdes.

#### F0 — Status: ✅ IMPLEMENTADO E VALIDADO AO VIVO (2026-10-04)
Pacote `arcanum/redteam/` (`action_classes`, `engagement`, `audit`, `sessions`), tabelas
`engagements`/`actions_log`/`redteam_sessions` + colunas `graph_nodes.owned/creds_held/foothold_id`,
wiring no `engine.py` (`_roe_authorize` → `blocked_by_roe`, HITL por classe com **dupla aprovação**
em `execute_approved`, `_audit_record`, `kill_switch`) e rotas `/api/redteam/*`. Revisão de
segunda-opinião aplicada: (#1) overrides `headless_web_audit`/`dispatch_*` ⇒ ACTIVE (não PASSIVE);
(#2) scrubbing de credencial inline por **valor** no audit (sshpass/`--password`/userinfo de URL/
`Bearer`), preservando dados benignos (ex.: `nmap -p 80`). **427 testes verdes.** Detalhes: MASTERPLAN §9.

**Follow-ups da F0 — status (hardening de segurança, 2026-10-05):**
1. ✅ **Regra de dois (identidade de operador):** `execute_approved(operator=...)` rastreia
   `approvers` e **recusa** o mesmo operador aprovando duas vezes (regra de dois real quando há
   identidade). Sem identidade (ainda não há auth), cai em contagem de confirmações e a mensagem
   diz isso honestamente ("aprovadores independentes quando houver identidade"). WS repassa
   `operator` opcional do payload.
2. ✅ **Accountability do `operator`:** `_audit_record(operator=...)` grava o(s) aprovador(es)
   (`"alice, bob"`) quando há identidade; cai no modo só como fallback.
3. ✅ **Fail-closed para alto risco:** `_audit_record(strict=True)` + `_preaudit_high_risk` —
   EXPLOIT/POST_EXPLOIT/DESTRUCTIVE fazem **pré-auditoria estrita** antes de executar; se o
   registro imutável falhar (com governança presente), a ação é **abortada**. PASSIVE/ACTIVE
   seguem best-effort (recon não morre por hiccup de DB). Sem governança ⇒ no-op (backward-compat).
4. ✅ **Âncora anti-truncamento:** tabela `audit_anchor` (contador + último hash, atualizada sob o
   mesmo lock do append). `verify_chain` detecta **remoção da cauda** (count/last-hash mismatch),
   não só adulteração de linha. (Não cobre rewrite simultâneo de log+âncora — p/ isso, âncora
   externa; documentado.)
5. ✅ **Teardown real no cleanup:** `create_foothold(teardown_recipe=[...])` + `cleanup(executor=...)`
   **executa** a receita de remoção via sandbox. Honesto: receita sem executor ⇒ `cleanup_pending`
   (nunca finge `cleaned`); passo falho ⇒ `cleanup_failed` (fica visível); re-rodar reprocessa
   pendentes/falhos. Kill-switch (engine + HTTP) passa o executor.
6. ⬜ **`roe_hash` é hash de conteúdo, não assinatura.** (Pendente) Para "ROE assinado", usar HMAC
   com segredo do servidor (ou assinatura real).

### F2 — Blue Team: ação defensiva real (deploy + verificação)
**Pacote `arcanum/blue/`:**
- `deployers/siem.py` · `edr.py` · `waf.py` — cada adapter: `deploy(rule)->{id,status}`, `verify(id)->bool`,
  `rollback(id)`. Reusar `integrations/hub.py` + credenciais (Splunk/Elastic/Datadog; ModSecurity/Suricata).
  **Mock honesto** sem credenciais (padrão `jira.py`): retorna `{mock:true}`, nunca finge deploy real.
- `hardening.py` — aplica saída de `generate_hardening_baseline` via Ansible/SSH/PR de IaC: **dry-run →
  diff → aprovar → aplicar → verificar**, com `rollback`.
- `response.py` — IR: `isolate_host`, `disable_account`, `block_ip` (via APIs EDR/firewall), reversíveis.
**Tools do agente (gov. F0):** `deploy_detection_rule`, `verify_detection_active`, `apply_hardening`
(dry-run por padrão), `ir_contain`. Classe: ACTIVE/mudança-blue → HITL + audit + **rollback registry**.
**Fluxo:** `generate_detection_rules`(Sigma/YARA/ModSec) → `deploy_detection_rule` → `verify_detection_active`.
**Testes:** adapters com SIEM/WAF mockados; dry-run gera diff sem aplicar; rollback funciona; audit grava.
**Aceite:** gerar uma regra Sigma, fazer deploy (mock ou real), confirmar que está **ativa**, e dar rollback.
**Depende de:** F0 (+ SIEM/EDR/WAF reais ou mock p/ testes).

#### F2 — Status: ✅ IMPLEMENTADO E VALIDADO AO VIVO (2026-10-04)
Pacote `arcanum/blue/` (`registry.DeploymentRegistry` = registry de rollback na tabela
`blue_deployments`; `deployers/{siem,waf,edr}.py` com `deploy/verify/rollback` + **mock honesto**
sem credenciais; `hardening.HardeningApplier` com **dry-run por padrão**→diff→apply→verify→rollback;
`response.IncidentResponder` com `isolate_host`/`disable_account`/`block_ip` reversíveis). Tools do
agente **governadas pela F0**: `deploy_detection_rule`, `verify_detection_active`, `apply_hardening`
(dry-run default), `ir_contain` — classe ACTIVE (`verify`=PASSIVE), com HITL + audit + rollback. API
`/api/blue/deployments` (GET/verify/DELETE-rollback). **Validação ao vivo:** `generate_detection_rules`
(Sigma) → `deploy_detection_rule`(SIEM, mock) → **ativa** → rollback → inativa; hardening dry-run não
altera nada; IR reversível. **447 testes verdes** (+20 em `tests/test_blue/`). Detalhes: MASTERPLAN §9.

- **Deploy real suportado hoje:** SIEM via **Elastic Detection Engine** (`ARCANUM_ELASTIC_URL`+
  `ARCANUM_ELASTIC_API_KEY`); WAF/EDR via endpoint admin opt-in (`ARCANUM_WAF_ADMIN_URL/TOKEN`,
  `ARCANUM_EDR_API_URL/TOKEN`). Splunk HEC/Datadog **ingerem eventos, não regras** → reportam honesto
  "não suportado" em vez de fingir deploy. Sem credenciais ⇒ **mock honesto** (`mock:true`), nunca
  finge deploy real.
- **Follow-ups F2:** (a) ⬜ apply real de hardening via SSH/Ansible/PR de IaC (hoje mock honesto,
  reversível, só registra o diff); (b) ⬜ adaptadores reais p/ Splunk saved-search (REST mgmt 8089) e
  Sentinel/Chronicle; (c) ✅ **`verify` real para WAF/EDR** (2026-10-05): `_verify_real` faz GET por
  external id no endpoint admin (mesmo contrato REST de deploy/rollback); sem id/não-200/erro ⇒ não
  ativo (honesto). Mock continua confiando no registry. (Testado com httpx mockado — não validado
  contra WAF/EDR real.)

### F3 — Purple Team: loop fechado (BAS medido)
**Pacote `arcanum/purple/`:**
- `bas.py` — `run_bas_test(technique_id)`: executa Atomic Red Team (via sandbox/host autorizado) com
  **deconfliction tag** + gates F0.
- `verify.py` — `was_detected(technique, tag, window)`: consulta SIEM/EDR (via integrations) por alerta
  correspondente na janela → detectado sim/não.
- efficacy: alimentar `mitre/engine.py` (`MitreEfficacyEngine`) com resultados **medidos** (substituindo o
  seed estático) por técnica.
- `loop.py` — orquestra: run técnica → verifica detecção → se MISS: `generate_detection_rules` + F2
  `deploy` → re-run → re-verifica → relatório. Reusa padrões do `retest.py`.
- `campaign.py` — encadeia técnicas ATT&CK (plano de emulação), mede cobertura ponta-a-ponta, gera
  **relatório de lacunas**. CTEM daemon pode agendar campanhas recorrentes.
**Tools do agente:** `run_bas_test`, `verify_detection`, `measure_coverage`, `run_purple_campaign`.
**Testes:** BAS com execução mockada; verifier com SIEM mock (hit/miss); loop detectar→tunar→validar;
relatório de cobertura; audit.
**Aceite:** rodar técnica T → medir detecção (sim/não) → se não, tunar+re-deploy+re-medir → cobertura %
no relatório. Eficácia MEDIDA, não seed.
**Depende de:** F0 + F2 (+ SIEM/EDR reais ou mock p/ testes).

#### F3 — Status: ✅ IMPLEMENTADO E VALIDADO AO VIVO (2026-10-04)
Pacote `arcanum/purple/` (`store.PurpleResultStore` na tabela `purple_results` = resultados MEDIDOS;
`bas.BASRunner` executa a técnica via sandbox autorizado OU **simula honestamente** sem sandbox —
nunca finge execução real — com **deconfliction tag**; `verify.DetectionVerifier.was_detected` mede
detecção a partir de **regras de detecção ativas implantadas (F2)** + consulta SIEM real opcional,
nunca fabrica veredito; `efficacy` alimenta `MitreEfficacyEngine` com resultados medidos
(substituindo o seed); `loop.PurpleLoop.close_gap` = run→verifica→se MISS: gera+implanta regra (F2)→
re-mede; `campaign.PurpleCampaign` encadeia técnicas, mede cobertura e gera relatório de lacunas).
Tools governadas pela F0: `run_bas_test`/`run_purple_campaign` = **EXPLOIT** (emulação de adversário →
ROE + dupla aprovação), `verify_detection`/`measure_coverage` = **PASSIVE**. API **read-only**
`/api/purple/results` e `/api/purple/coverage/{id}` (execução só pelos tools governados, nunca por HTTP
não-gated). **Validação ao vivo:** T1190 → MISS → tune (deploy de regra) → HIT; campanha multi-técnica →
cobertura 100% após tuning; campanha sem auto-tune → lacunas medidas honestamente; eficácia
`source=measured`. **463 testes verdes** (+16 em `tests/test_purple/`). Detalhes: MASTERPLAN §9.

- **Sinal de detecção sem SIEM externo:** o verificador usa as **regras implantadas no registry da F2**
  (regra ativa cobrindo a técnica ⇒ detectável) — sinal real do próprio sistema, não fabricado. Com
  SIEM configurado (Elastic), também consulta alerta real pela deconfliction tag na janela.
- **Honestidade real-vs-simulado (fix 2ª opinião, 2026-10-05):** um deploy **sem credenciais** é
  **mock** — `was_detected` o rotula `source='deployed_rule_simulated'`/`simulated=True` (cobertura
  SIMULADA), **nunca** detecção real; um deploy real vence o mock. As métricas separam
  `detection_rate_real` (controles reais) de `coverage_simulated` (mock); `apply_measured_results` só
  marca DETECTED no MITRE para detecção real (simulada ⇒ MISSED). Sem isso, cobertura mock inflava o
  detection_rate/heatmap.
- **Follow-ups F3:** (a) ⬜ execução real de Atomic Red Team no sandbox autorizado (hoje simulação
  honesta sem sandbox; **gated** — EXPLOIT); (b) ⬜ correlação de detecção por alerta real multi-SIEM
  (Splunk/Sentinel/Chronicle); (c) ⬜ agendar campanhas recorrentes via CTEM daemon; (d) ✅
  **PREVENÇÃO distinta de DETECÇÃO** (2026-10-05): `verify.was_prevented` mede bloqueio (BAS run
  `blocked` = prevenção REAL; deploy preventivo mock = prevenção SIMULADA, nunca real). `purple_results`
  ganha `prevented`/`prevention_source`/`prevention_simulated`; coverage/efficacy expõem
  `prevention_rate(_real)` ao lado de `detection_rate(_real)`; `apply_measured_results` marca **BLOCKED**
  (prevenção real) > **DETECTED** (detecção real) > **MISSED** (simulado ⇒ MISSED, honesto). Loop/campanha
  propagam.

---

## 11. Specs do ofensivo (F1 · F4 · F5) — **apenas framework gated**

> **Escopo e limite:** esta seção especifica **só a estrutura de governança/orquestração** — schema das
> tools, classe de ação, tier de HITL, auditoria, estado de comprometimento, captura de prova e o
> **ponto de delegação** para ferramentas estabelecidas (Metasploit, impacket, netexec, sliver, linpeas,
> hashcat — já na imagem Kali). **Não contém código de exploit, payloads, técnicas de evasão nem
> comandos de ataque.** A execução real é delegada à ferramenta estabelecida, invocada pelo operador
> **autorizado** através do `execute`/RPC governado. Nada aqui roda sem engajamento (ROE) válido, classe
> de ação permitida, aprovação HITL e registro em auditoria.

### Contrato comum a TODA tool ofensiva (fornecido pela F0)
Cada handler ofensivo é um "wrapper governado" com o mesmo esqueleto:
1. `classify()` define a classe (EXPLOIT/POST_EXPLOIT/DESTRUCTIVE) → o engine checa ROE + janela + HITL.
2. Opera **através de um foothold** do `SessionRegistry` (exceto o de acesso inicial).
3. **Delega** a ação à ferramenta estabelecida (não implementa a técnica).
4. Captura **prova mínima** (saída/screenshot/amostra mascarada) → evidência do finding.
5. **Registra** em `actions_log` (deconfliction tag), atualiza **estado de comprometimento** no grafo e o
   **cofre** (creds mascaradas), e anota **obrigação de cleanup**.

### F1 — Acesso inicial / red estruturado (base não-destrutiva)
- `map_service_to_exploits` (ACTIVE): orquestra `nmap -sV` → `search_cve`/`enrich_cve_threat` → candidatos
  no grafo. Sem ataque — só correlação.
- `exploit_webapp` (EXPLOIT, dupla aprovação): **delega** a confirmação de acesso a uma ferramenta
  estabelecida (ex.: Metasploit RPC) contra alvo do ROE; em sucesso → `SessionRegistry.create_foothold`
  + `capture_proof`. O "como explorar" é da ferramenta, não deste repo.
- `capture_proof` (utilitário): padroniza evidência (shell confirmado / output / amostra mascarada).
- **Aceite:** de uma vuln confirmada + aprovação, registrar um foothold com prova (não só finding).

#### F1 — Status: ✅ IMPLEMENTADO E TESTADO (2026-10-05)
Pacote `arcanum/offensive/` — **framework governado, zero exploit no repo** (delega ao arsenal Kali):
- `proof.py` — `detect_access(output)` classifica a saída da ferramenta delegada em **session**
  (⇒ justifica foothold) vs **vuln_confirmed** (⇒ prova, mas **sem** foothold) vs None; `build_proof`
  padroniza evidência mascarada (scrub de credencial inline) + `sha256` do original.
- `base.py` — `OffensiveContext`: **uma** via de delegação (`delegate` → `execute` governado no sandbox),
  `register_foothold(teardown_recipe=...)` (F0 #5) e `mark_owned` (estado de comprometimento no grafo).
- `access.py` — `map_service_to_exploits` (ACTIVE: `nmap -sV` → parse serviços → CVE KB → candidatos,
  alimenta o grafo; sem ataque) e `exploit_webapp` (EXPLOIT, dupla aprovação: **delega** a um módulo
  Metasploit / template nuclei / comando escolhido pelo operador; sessão real ⇒ foothold+prova+owned;
  vuln confirmada sem shell ⇒ só prova, **sem** foothold; sem sandbox ⇒ recusa honesta).
- Wiring: `TOOL_ACTION_CLASS` (`map_service_to_exploits`=ACTIVE, `exploit_webapp`=EXPLOIT,
  `capture_proof`=PASSIVE); handlers + schemas + escopo de fase (EXPLOIT) em `tools.py`;
  `GraphManager.mark_compromised` (colunas F0 `owned`/`foothold_id`). Finding automático com a prova.
- Governança (herdada da F0, **validada**): `exploit_webapp` é **bloqueado por ROE** se o engajamento não
  permite EXPLOIT (evento `blocked_by_roe` + audit), exige **dupla aprovação** e **pré-auditoria fail-closed**;
  **a API é só por tool governado** (sem endpoint HTTP que dispara exploração). **+16 testes**
  (`tests/test_offensive/`). Nada executa sem sandbox autorizado + ROE.
- **Pendentes F1:** execução real contra lab autorizado (precisa Docker/sandbox + alvo próprio + ROE
  assinado — responsabilidade do operador); captura de screenshot como prova; `enrich_cve_threat` no mapper.

### F4 — Pós-exploração & movimento lateral (via foothold)
Todas operam **através de um foothold existente** e **delegam** à ferramenta estabelecida:
- `run_on_target` (POST_EXPLOIT): roteia um comando pela sessão/C2 ao host comprometido (distinto do
  `execute` na sandbox). Comando destrutivo → DESTRUCTIVE + dupla aprovação.
- `enumerate_privesc` / `attempt_privesc` (POST_EXPLOIT; kernel → dupla aprovação): delega a linpeas/winpeas
  e a catálogos estabelecidos; em elevação, atualiza `owned` no grafo.
- `dump_credentials` (POST_EXPLOIT, **dupla aprovação**): delega a impacket/ferramenta de dump; creds →
  cofre **mascaradas** + grafo.
- `crack_hashes` (ACTIVE): delega a hashcat/hydra na sandbox.
- `discover_on_host` (POST_EXPLOIT): enumeração interna pós-foothold → novos alvos no grafo.
- `lateral_move` (EXPLOIT, **aprovação por hop**): delega a impacket/netexec/evil-winrm; cada salto →
  novo foothold + aresta "via X" no grafo.
- `setup_pivot` (EXPLOIT): delega a chisel/tunneling.
- `establish_c2` (POST_EXPLOIT, **dupla aprovação**): delega a sliver/pwncat; sessão registrada,
  listável e **matável** pelo kill-switch.
- **Aceite:** executar um caminho multi-hop do grafo (hoje só `simulate_attack_path`) com prova por hop e
  tudo no audit log; kill-switch encerra todas as sessões.

#### F4 — Status: ✅ IMPLEMENTADO (2026-10-05) · testes escritos (rodar `pytest tests/test_offensive`)
`arcanum/offensive/post_exploit.py` — todas as 9 capacidades acima como wrappers governados
(delegam ao Kali, zero técnica no repo), via `OffensiveContext` (F1): `run_on_target`, `enumerate_privesc`,
`attempt_privesc` (elevação confirmada → `owned=admin`), `dump_credentials` (**creds MASCARADAS** no grafo,
segredo bruto **nunca** persistido), `crack_hashes` (ACTIVE, mascarado), `discover_on_host` (ingere no grafo),
`lateral_move` (sessão confirmada → **novo foothold filho** + aresta `pivoted_to` + `owned`), `setup_pivot`
(implante reversível c/ teardown), `establish_c2` (implante `c2` listável/matável pelo kill-switch). Classes
F0: POST_EXPLOIT/EXPLOIT ⇒ **dupla aprovação** + ROE + audit; exige foothold + sandbox (recusa honesta sem).
`GraphManager.mark_compromised`. Testes: `tests/test_offensive/test_post_exploit.py` + `test_f4_f5_governance.py`.
**Nota:** o classificador de segurança bloqueou a execução de testes nesta sessão — **testes escritos mas
não re-executados aqui**; rodar `pytest -m "not integration" tests/test_offensive`.

### F5 — Collection / Exfiltration / Impact (gate máximo; maioria OFF)
- `collect_sample` (POST_EXPLOIT): coleta **mínima** de arquivo sensível, **mascarada**, só p/ prova.
- `demo_exfiltration` (DESTRUCTIVE-adjacent, **dupla aprovação**): canal limitado por **tamanho/taxa**,
  para testar DLP; **loga exatamente o que saiu**; nunca dado real relevante.
- `impact_poc` (DESTRUCTIVE, **desligado por padrão** via `allow_destructive_testing`): só com ROE
  explícito + dupla aprovação + **backup** + diretório de teste isolado. Ransomware-sim/defacement só em
  staging que o cliente autorizou.
- **Aceite:** demonstrar exfil detectável/bloqueável sem vazamento real; `impact_poc` permanece OFF salvo
  ROE que o exija.

#### F5 — Status: ✅ IMPLEMENTADO (2026-10-05) · testes escritos
`arcanum/offensive/impact.py`: `collect_sample` (cap **4096B**, mascarado), `demo_exfiltration`
(cap **2048B**, loga destino/tamanho p/ teste de DLP, nunca massa real), `impact_poc` (**DESLIGADO por
padrão** — recusa sem `ARCANUM_ALLOW_DESTRUCTIVE_TESTING` **e** sem `test_directory` isolado). Classes F0:
`collect_sample`=POST_EXPLOIT, `demo_exfiltration`/`impact_poc`=DESTRUCTIVE (dupla aprovação). Testes:
`tests/test_offensive/test_impact.py`. (Mesma nota do F4: testes não re-executados nesta sessão.)

### Governança transversal do ofensivo (responsabilidade do framework)
- **Deconfliction:** toda ação carimba o `engagement_id` para o Blue separar do ataque real (vital em Purple).
- **OPSEC profile** (`stealth`|`loud`): afeta ritmo/timing; reusa detecção de WAF/CDN.
- **Cleanup obrigatório** no encerramento: `SessionRegistry.cleanup` remove implantes, persistência e
  contas de teste; auditoria confirma 100% de limpeza.
- **Kill-switch** cobre runs + sessões + implantes.
- **Modelo:** ofensivo em **copilot** (humano aprova cada ação); autonomia só após métricas de confiança.

### Ordem e pré-requisitos (recap)
`F0 → F2 → F3 → F1 → F4 → F5`. O ofensivo (F1/F4/F5) exige, além da F0: **Docker/sandbox ligados**, **lab
autorizado próprio** (DVWA/Metasploitable/AD de teste — nunca produção/terceiros), **ROE assinado** e
decisão de **HITL/modelo**. Implementar **por capacidade, com revisão humana** — não em passe autônomo.
