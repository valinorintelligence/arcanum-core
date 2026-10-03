"""Pydantic models for MITRE ATT&CK Matrix & Defensive Efficacy (Picus-Style BAS)."""
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class TacticEnum(str, Enum):
    """The 14 Enterprise Tactics of the MITRE ATT&CK Matrix."""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class DefenseStatus(str, Enum):
    """Defensive outcome status based on Breach and Attack Simulation (BAS)."""
    BLOCKED = "blocked"       # Ação prevenida ativamente por controles de segurança (WAF, EDR, IPS)
    DETECTED = "detected"     # Ação executada mas registrada/alertada em SIEM/EDR sem bloqueio
    MISSED = "missed"         # Ação executada com sucesso total sem qualquer alerta ou bloqueio
    UNTESTED = "untested"     # Técnica não avaliada na simulação atual


class TechniqueEvaluation(BaseModel):
    """Evaluation of a specific MITRE ATT&CK Technique against defensive controls."""
    technique_id: str = Field(..., description="ID oficial MITRE (ex: T1059.001)")
    name: str = Field(..., description="Nome da técnica (ex: PowerShell)")
    tactic: TacticEnum = Field(..., description="Tática primária associada")
    tactic_id: str = Field(..., description="ID da Tática (ex: TA0002)")
    status: DefenseStatus = Field(default=DefenseStatus.UNTESTED, description="Resultado da validação defensiva")
    description: str = Field(..., description="Descrição técnica da ameaça")
    simulation_payload: str = Field(default="", description="Payload seguro ou comando usado no teste BAS")
    simulated_at: Optional[str] = Field(default=None, description="Data/hora UTC do teste")
    prevention_control: Optional[str] = Field(default=None, description="Controle responsável pelo bloqueio (se bloqueado)")
    detection_event: Optional[str] = Field(default=None, description="Evidência ou evento de log (se detectado)")
    execution_log: str = Field(default="", description="Log detalhado da execução da simulação")
    risk_level: str = Field(default="HIGH", description="Nível de severidade: CRITICAL, HIGH, MEDIUM, LOW")
    sigma_rule_yaml: Optional[str] = Field(default=None, description="Regra Sigma pronta para importação no SIEM")
    remediation_guidance: str = Field(..., description="Orientações acionáveis de remediação para o Blue Team")


class TacticSummary(BaseModel):
    """Summary of defensive efficacy aggregated by MITRE Tactic."""
    tactic: TacticEnum
    tactic_id: str
    total_techniques: int
    blocked: int
    detected: int
    missed: int
    untested: int
    prevention_rate: float = Field(default=0.0, description="% de técnicas bloqueadas em relação às testadas")
    detection_rate: float = Field(default=0.0, description="% de técnicas detectadas em relação às testadas")
    efficacy_score: float = Field(default=0.0, description="Score composto Picus da tática (0 a 100)")


class DefensiveEfficacyReport(BaseModel):
    """Complete Security Control Validation (Picus-grade) Efficacy Assessment."""
    campaign_id: str
    target_environment: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_techniques: int
    tested_techniques: int
    blocked_count: int
    detected_count: int
    missed_count: int
    untested_count: int
    prevention_rate: float = Field(..., description="% de prevenção global: (blocked / tested) * 100")
    detection_rate: float = Field(..., description="% de detecção global: (detected / tested) * 100")
    overall_efficacy_score: float = Field(..., description="Score Global de Eficácia Defensiva (0 a 100)")
    tactics_breakdown: List[TacticSummary]
    critical_gaps: List[TechniqueEvaluation] = Field(default_factory=list, description="Técnicas críticas em estado MISSED")
    resilient_controls: List[TechniqueEvaluation] = Field(default_factory=list, description="Técnicas em estado BLOCKED com sucesso")
    evaluated_techniques: List[TechniqueEvaluation] = Field(default_factory=list)
