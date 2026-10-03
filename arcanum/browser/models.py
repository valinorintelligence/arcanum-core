"""
Modelos de dados para o Agente de Navegador Headless Web.
Representa sessões de auditoria, achados de falhas de lógica de negócios,
e resultados de testes autônomos de aplicações web.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class FlawCategory(str, Enum):
    """Categorias de falhas de lógica de negócios detectadas pelo agente."""
    IDOR = "idor"                           # Insecure Direct Object Reference
    AUTH_BYPASS = "auth_bypass"             # Bypass de autenticação
    PRICE_MANIPULATION = "price_manipulation"  # Manipulação de preço/quantidade
    STATE_TRANSITION = "state_transition"   # Transição de estado não autorizada
    MASS_ASSIGNMENT = "mass_assignment"     # Atribuição em massa
    RACE_CONDITION = "race_condition"       # Condição de corrida
    BUSINESS_LOGIC = "business_logic"      # Falha genérica de lógica de negócios
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Escalada de privilégio horizontal
    PARAMETER_POLLUTION = "parameter_pollution"    # Poluição de parâmetros HTTP


class Severity(str, Enum):
    """Severidade de achados de segurança."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class BrowserFinding:
    """Representa um achado de segurança detectado pelo agente de navegador."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    category: FlawCategory = FlawCategory.BUSINESS_LOGIC
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    url: str = ""
    method: str = "GET"
    # Parâmetros manipulados (original → testado)
    parameter_original: dict[str, Any] = field(default_factory=dict)
    parameter_tested: dict[str, Any] = field(default_factory=dict)
    # Evidências: status codes, diferenças de resposta, etc.
    evidence: dict[str, Any] = field(default_factory=dict)
    # Passo no fluxo em que a falha foi detectada (ex: "checkout_step_2")
    workflow_step: str = ""
    # Reprodução: sequência de ações para reproduzir
    reproduction_steps: list[str] = field(default_factory=list)
    # Mapeamento OWASP / CWE
    cwe_id: str = ""
    owasp_category: str = ""
    # Timestamp
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "method": self.method,
            "parameter_original": self.parameter_original,
            "parameter_tested": self.parameter_tested,
            "evidence": self.evidence,
            "workflow_step": self.workflow_step,
            "reproduction_steps": self.reproduction_steps,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "discovered_at": self.discovered_at,
        }


@dataclass
class BusinessLogicFlaw(BrowserFinding):
    """Subclasse específica para falhas de lógica de negócios (compatibilidade)."""
    pass


@dataclass
class AuditStep:
    """Um passo de auditoria executado pelo agente (clique, formulário, requisição)."""
    step_index: int = 0
    action: str = ""          # "navigate", "click", "fill", "api_request", "assert"
    target: str = ""          # URL, seletor CSS, ou chave de API
    value: str = ""           # Valor preenchido (se aplicável)
    result: str = ""          # Resultado observado
    screenshot_path: str = "" # Caminho para print de tela (se capturado)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_index": self.step_index,
            "action": self.action,
            "target": self.target,
            "value": self.value,
            "result": self.result,
            "screenshot_path": self.screenshot_path,
            "timestamp": self.timestamp,
        }


@dataclass
class BrowserAuditSession:
    """Sessão completa de auditoria de navegador headless."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str = ""
    workflow_description: str = ""
    # Estado da sessão
    status: str = "pending"    # pending | running | completed | failed
    started_at: str = ""
    completed_at: str = ""
    # Resultados
    pages_visited: list[str] = field(default_factory=list)
    forms_tested: int = 0
    api_calls_intercepted: int = 0
    findings: list[BrowserFinding] = field(default_factory=list)
    steps: list[AuditStep] = field(default_factory=list)
    # Sumário por severidade
    finding_counts: dict[str, int] = field(default_factory=dict)
    # Evasão e Furtividade Antifraude (Stealth Engine)
    stealth_profile: str = "windows_desktop"
    stealth_evasions_applied: list[str] = field(default_factory=list)
    honeypots_avoided: int = 0
    # Erro (se falhou)
    error: str = ""

    def add_finding(self, finding: BrowserFinding) -> None:
        finding.session_id = self.id
        self.findings.append(finding)
        sev = finding.severity.value
        self.finding_counts[sev] = self.finding_counts.get(sev, 0) + 1

    def add_step(self, step: AuditStep) -> None:
        step.step_index = len(self.steps)
        self.steps.append(step)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "workflow_description": self.workflow_description,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "pages_visited": self.pages_visited,
            "forms_tested": self.forms_tested,
            "api_calls_intercepted": self.api_calls_intercepted,
            "stealth_profile": self.stealth_profile,
            "stealth_evasions_applied": self.stealth_evasions_applied,
            "honeypots_avoided": self.honeypots_avoided,
            "finding_counts": self.finding_counts,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "steps": [s.to_dict() for s in self.steps],
            "error": self.error,
        }

