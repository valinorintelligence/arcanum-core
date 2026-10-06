"""Engine for MITRE ATT&CK Mapping & Defensive Control Efficacy Evaluation (Picus-Style BAS)."""
import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from arcanum.mitre.database import DEFAULT_MITRE_TECHNIQUES
from arcanum.mitre.models import (
    DefenseStatus,
    DefensiveEfficacyReport,
    TacticEnum,
    TacticSummary,
    TechniqueEvaluation,
)


class MitreEfficacyEngine:
    """
    Picus-Style Breach and Attack Simulation (BAS) & Defensive Efficacy Engine.
    Evaluates defensive security posture, calculates prevention and detection rates,
    and provides Sigma detection rules and Blue Team remediation guidance.
    """

    def __init__(self, techniques: Optional[List[TechniqueEvaluation]] = None):
        """Initializes the engine with default or custom MITRE techniques."""
        if techniques:
            self._techniques = {t.technique_id: copy.deepcopy(t) for t in techniques}
        else:
            self._techniques = {t.technique_id: copy.deepcopy(t) for t in DEFAULT_MITRE_TECHNIQUES}
        self.last_campaign_id: str = "initial-baseline"
        self.target_environment: str = "Corporate Enterprise Network"

    def get_all_techniques(self) -> List[TechniqueEvaluation]:
        """Returns all evaluated techniques."""
        return list(self._techniques.values())

    def get_technique(self, technique_id: str) -> Optional[TechniqueEvaluation]:
        """Returns a specific technique by ID."""
        return self._techniques.get(technique_id)

    def get_matrix(self) -> Dict[str, Any]:
        """
        Returns the MITRE ATT&CK Enterprise Matrix grouped by Tactic,
        including defensive status counts and color codes for the frontend Heatmap.
        """
        tactics_map: Dict[str, List[Dict[str, Any]]] = {}
        for tactic in TacticEnum:
            tactics_map[tactic.value] = []

        for tech in self._techniques.values():
            tactics_map[tech.tactic.value].append(tech.model_dump())

        report = self.calculate_efficacy()
        return {
            "campaign_id": self.last_campaign_id,
            "target_environment": self.target_environment,
            "overall_efficacy_score": report.overall_efficacy_score,
            "prevention_rate": report.prevention_rate,
            "detection_rate": report.detection_rate,
            "total_techniques": report.total_techniques,
            "tested_techniques": report.tested_techniques,
            "blocked_count": report.blocked_count,
            "detected_count": report.detected_count,
            "missed_count": report.missed_count,
            "untested_count": report.untested_count,
            "matrix": tactics_map,
            "tactics_summary": [s.model_dump() for s in report.tactics_breakdown],
        }

    def evaluate_technique(
        self,
        technique_id: str,
        status: DefenseStatus,
        prevention_control: Optional[str] = None,
        detection_event: Optional[str] = None,
        execution_log: str = "",
    ) -> Optional[TechniqueEvaluation]:
        """Updates the evaluation state of a single technique."""
        tech = self._techniques.get(technique_id)
        if not tech:
            return None

        tech.status = status
        tech.simulated_at = datetime.now(timezone.utc).isoformat()
        if prevention_control:
            tech.prevention_control = prevention_control
        if detection_event:
            tech.detection_event = detection_event
        if execution_log:
            tech.execution_log = execution_log
        return tech

    def simulate_campaign(
        self,
        target_name: str = "Corporate Enterprise Network",
        scenario: str = "full_adversary",
    ) -> DefensiveEfficacyReport:
        """
        Runs a comprehensive Breach and Attack Simulation (BAS) campaign,
        simulating adversary techniques against defensive controls (WAF, EDR, SIEM, Firewalls).
        """
        self.last_campaign_id = f"bas-{uuid.uuid4().hex[:8]}"
        self.target_environment = target_name
        now_iso = datetime.now(timezone.utc).isoformat()

        # Preset simulation outcomes replicating a real corporate posture
        simulation_outcomes = {
            # Reconnaissance
            "T1595.002": {
                "status": DefenseStatus.BLOCKED,
                "control": "Palo Alto NGFW / Cloudflare Rate Limiter",
                "event": "Event ID 4001: Excessive Port Scan Blocked (100 req/s)",
                "log": "Varredura SYN/UDP interrompida pelo firewall perimetral após 15 pacotes.",
            },
            "T1592.002": {
                "status": DefenseStatus.DETECTED,
                "control": None,
                "event": "Splunk WAF Alert: Software Banner Discovery Request",
                "log": "Requisição HTTP HEAD respondeu com cabeçalhos de versão. Alertado no SIEM, sem bloqueio.",
            },
            # Resource Development
            "T1583.001": {
                "status": DefenseStatus.MISSED,
                "control": None,
                "event": None,
                "log": "Consulta RDAP para domínio lookalike executada com êxito sem alerta de proxy/DNS.",
            },
            # Initial Access
            "T1190": {
                "status": DefenseStatus.BLOCKED,
                "control": "Cloudflare WAF / ModSecurity Core Rule Set (CRS 942100)",
                "event": "WAF Block Rule #942100: SQL Injection Payload Matched",
                "log": "Payload SQLi 'UNION SELECT' bloqueado com HTTP 403 Forbidden na borda.",
            },
            "T1078": {
                "status": DefenseStatus.DETECTED,
                "control": None,
                "event": "Microsoft Entra ID: Sign-in Risk 'Medium' (Unusual Location)",
                "log": "Autenticação bem-sucedida com credencial de teste. Logado no Entra ID, MFA não exigido.",
            },
            # Execution
            "T1059.001": {
                "status": DefenseStatus.BLOCKED,
                "control": "CrowdStrike Falcon / Windows Defender ASR Rule",
                "event": "CrowdStrike Event: Blocked Obfuscated PowerShell EncodedCommand",
                "log": "Processo powershell.exe com switch -EncodedCommand terminado pelo EDR em 12ms.",
            },
            "T1059.003": {
                "status": DefenseStatus.DETECTED,
                "control": None,
                "event": "Sysmon Event ID 1: Process Creation cmd.exe spawned by w3wp.exe",
                "log": "Comando cmd.exe executado com sucesso e registrado no log do Sysmon.",
            },
            # Persistence
            "T1053.005": {
                "status": DefenseStatus.DETECTED,
                "control": None,
                "event": "Windows Security Event ID 4698: A scheduled task was created",
                "log": "Tarefa 'SystemMaintenanceTask' criada com sucesso no TaskScheduler. Alerta gerado.",
            },
            # Privilege Escalation
            "T1068": {
                "status": DefenseStatus.BLOCKED,
                "control": "SentinelOne EDR Behavioral Engine",
                "event": "SentinelOne Threat Alert: Kernel Exploit Attempt Terminated",
                "log": "Tentativa de injeção de driver vulnerável bloqueada pelo mecanismo heurístico.",
            },
            "T1548.002": {
                "status": DefenseStatus.MISSED,
                "control": None,
                "event": None,
                "log": "Bypass de UAC via chave de registro ms-settings executado sem bloqueio ou alerta.",
            },
            # Defense Evasion
            "T1562.001": {
                "status": DefenseStatus.BLOCKED,
                "control": "Windows Defender Tamper Protection",
                "event": "Defender Alert: Unauthorized modification of DisableRealtimeMonitoring blocked",
                "log": "Set-MpPreference rejeitado pelo kernel do sistema operacional (Tamper Protection ativo).",
            },
            "T1070.001": {
                "status": DefenseStatus.DETECTED,
                "control": None,
                "event": "Windows Security Event ID 1102: The audit log was cleared",
                "log": "wevtutil cl Security executado. O log foi limpo localmente, mas o evento 1102 foi para o SIEM.",
            },
            # Credential Access
            "T1003.001": {
                "status": DefenseStatus.MISSED,
                "control": None,
                "event": None,
                "log": "CRÍTICO: Dump de memória do LSASS via comsvcs.dll realizado sem detecção do EDR.",
            },
            "T1558.003": {
                "status": DefenseStatus.DETECTED,
                "control": None,
                "event": "Active Directory Event ID 4769: Kerberos Ticket RC4 Request (TGS)",
                "log": "Ticket Kerberos com criptografia fraca (RC4) emitido para conta de serviço. Detectado no AD.",
            },
            "T1110.003": {
                "status": DefenseStatus.BLOCKED,
                "control": "Azure AD Smart Lockout / Cisco ISE",
                "event": "Smart Lockout Alert: 10 Failed Logons within 60s",
                "log": "Password Spray interrompido após 8 tentativas. Bloqueio automático de IP ativado.",
            },
            # Discovery
            "T1087.002": {
                "status": DefenseStatus.MISSED,
                "control": None,
                "event": None,
                "log": "Enumeração de 'Domain Admins' via consulta LDAP executada sem qualquer restrição.",
            },
            # Lateral Movement
            "T1021.002": {
                "status": DefenseStatus.BLOCKED,
                "control": "Fortinet Internal Segmentation Firewall (ISFW)",
                "event": "ISFW Rule Drop: Lateral SMB Port 445 Workstation-to-Workstation",
                "log": "Tráfego SMB entre estações de trabalho bloqueado pela política de micro-segmentação.",
            },
            # Collection
            "T1560.001": {
                "status": DefenseStatus.DETECTED,
                "control": None,
                "event": "EDR Process Event: 7z.exe executed with password parameter",
                "log": "Arquivo compactado criado com senha. Gerou log de telemetria no SIEM.",
            },
            # Command and Control
            "T1071.001": {
                "status": DefenseStatus.MISSED,
                "control": None,
                "event": None,
                "log": "Beaconing HTTPS periódico para servidor C2 externo transitou livremente pelo proxy.",
            },
            # Exfiltration
            "T1048.003": {
                "status": DefenseStatus.MISSED,
                "control": None,
                "event": None,
                "log": "Túnel DNS com dados codificados em consultas recursivas operou sem detecção de entropia.",
            },
            # Impact
            "T1490": {
                "status": DefenseStatus.BLOCKED,
                "control": "Carbon Black EDR / ASR Rule",
                "event": "ASR Rule Match: Blocked vssadmin shadow deletion",
                "log": "Comando vssadmin.exe delete shadows bloqueado instantaneamente pela regra de ASR.",
            },
        }

        # Apply simulation results
        for tech_id, outcome in simulation_outcomes.items():
            if tech_id in self._techniques:
                tech = self._techniques[tech_id]
                tech.status = outcome["status"]
                tech.simulated_at = now_iso
                tech.prevention_control = outcome.get("control")
                tech.detection_event = outcome.get("event")
                tech.execution_log = outcome.get("log", "")

        return self.calculate_efficacy()

    def calculate_efficacy(self) -> DefensiveEfficacyReport:
        """
        Calculates the Picus-grade Defensive Efficacy Metrics:
        - Prevention Rate (% of tested techniques blocked)
        - Detection Rate (% of tested techniques detected)
        - Overall Efficacy Score = (Prevention Rate * 0.6) + (Detection Rate * 0.4)
        """
        all_techs = list(self._techniques.values())
        total_techs = len(all_techs)

        tested_techs = [t for t in all_techs if t.status != DefenseStatus.UNTESTED]
        tested_count = len(tested_techs)

        blocked = [t for t in tested_techs if t.status == DefenseStatus.BLOCKED]
        detected = [t for t in tested_techs if t.status == DefenseStatus.DETECTED]
        missed = [t for t in tested_techs if t.status == DefenseStatus.MISSED]
        untested_count = total_techs - tested_count

        blocked_count = len(blocked)
        detected_count = len(detected)
        missed_count = len(missed)

        if tested_count > 0:
            prevention_rate = round((blocked_count / tested_count) * 100.0, 1)
            detection_rate = round((detected_count / tested_count) * 100.0, 1)
            overall_score = round((prevention_rate * 0.6) + (detection_rate * 0.4), 1)
        else:
            prevention_rate = 0.0
            detection_rate = 0.0
            overall_score = 0.0

        # Tactics breakdown
        tactics_breakdown: List[TacticSummary] = []
        for tactic in TacticEnum:
            tactic_techs = [t for t in all_techs if t.tactic == tactic]
            t_total = len(tactic_techs)
            t_tested = [t for t in tactic_techs if t.status != DefenseStatus.UNTESTED]
            t_blocked = len([t for t in t_tested if t.status == DefenseStatus.BLOCKED])
            t_detected = len([t for t in t_tested if t.status == DefenseStatus.DETECTED])
            t_missed = len([t for t in t_tested if t.status == DefenseStatus.MISSED])
            t_untested = t_total - len(t_tested)

            if len(t_tested) > 0:
                t_prev = round((t_blocked / len(t_tested)) * 100.0, 1)
                t_det = round((t_detected / len(t_tested)) * 100.0, 1)
                t_score = round((t_prev * 0.6) + (t_det * 0.4), 1)
            else:
                t_prev = 0.0
                t_det = 0.0
                t_score = 0.0

            t_id = tactic_techs[0].tactic_id if tactic_techs else "TA0000"
            tactics_breakdown.append(
                TacticSummary(
                    tactic=tactic,
                    tactic_id=t_id,
                    total_techniques=t_total,
                    blocked=t_blocked,
                    detected=t_detected,
                    missed=t_missed,
                    untested=t_untested,
                    prevention_rate=t_prev,
                    detection_rate=t_det,
                    efficacy_score=t_score,
                )
            )

        # Sort critical gaps: MISSED with CRITICAL risk first, then HIGH, etc.
        risk_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        critical_gaps = sorted(
            missed,
            key=lambda t: risk_weight.get(t.risk_level.upper(), 0),
            reverse=True,
        )

        return DefensiveEfficacyReport(
            campaign_id=self.last_campaign_id,
            target_environment=self.target_environment,
            total_techniques=total_techs,
            tested_techniques=tested_count,
            blocked_count=blocked_count,
            detected_count=detected_count,
            missed_count=missed_count,
            untested_count=untested_count,
            prevention_rate=prevention_rate,
            detection_rate=detection_rate,
            overall_efficacy_score=overall_score,
            tactics_breakdown=tactics_breakdown,
            critical_gaps=critical_gaps,
            resilient_controls=blocked,
            evaluated_techniques=all_techs,
        )

    def map_findings_to_mitre(self, findings: List[Dict[str, Any]]) -> List[TechniqueEvaluation]:
        """
        Automatically correlates raw Arcanum findings to MITRE ATT&CK techniques,
        updating their defensive status.
        """
        updated = []
        for finding in findings:
            title = finding.get("title", "").lower()
            category = finding.get("category", "").lower()
            status = finding.get("status", "").upper()

            # Correlate
            matched_id = None
            if "sql injection" in title or "sqli" in title or "xss" in title or "idor" in title:
                matched_id = "T1190"
            elif "credential" in title or "lsass" in title or "dump" in title:
                matched_id = "T1003.001"
            elif "kerberoast" in title:
                matched_id = "T1558.003"
            elif "powershell" in title:
                matched_id = "T1059.001"
            elif "uac" in title:
                matched_id = "T1548.002"
            elif "scheduled task" in title:
                matched_id = "T1053.005"
            elif "port scan" in title or "open port" in title:
                matched_id = "T1595.002"

            if matched_id and matched_id in self._techniques:
                target_status = DefenseStatus.MISSED
                if status == "REMEDIATED":
                    target_status = DefenseStatus.BLOCKED
                elif status == "VERIFYING":
                    target_status = DefenseStatus.DETECTED

                tech = self.evaluate_technique(
                    technique_id=matched_id,
                    status=target_status,
                    execution_log=f"Correlacionado automaticamente com finding: {finding.get('title')}",
                )
                if tech:
                    updated.append(tech)

        return updated

    def get_remediation(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Returns the Sigma detection rule and Blue Team remediation guidance."""
        tech = self._techniques.get(technique_id)
        if not tech:
            return None

        return {
            "technique_id": tech.technique_id,
            "name": tech.name,
            "tactic": tech.tactic.value,
            "tactic_id": tech.tactic_id,
            "status": tech.status.value,
            "risk_level": tech.risk_level,
            "sigma_rule_yaml": tech.sigma_rule_yaml,
            "remediation_guidance": tech.remediation_guidance,
            "prevention_control": tech.prevention_control,
            "detection_event": tech.detection_event,
        }
