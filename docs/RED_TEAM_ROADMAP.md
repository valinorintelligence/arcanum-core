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
