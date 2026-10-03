"""FastAPI REST API routes for MITRE ATT&CK Matrix & Defensive Efficacy (Picus-Style BAS)."""
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from arcanum.mitre.engine import MitreEfficacyEngine
from arcanum.mitre.models import DefensiveEfficacyReport, DefenseStatus


router = APIRouter(prefix="/api/mitre", tags=["mitre-efficacy"])

# Global singleton engine instance for runtime state persistence
_mitre_engine = MitreEfficacyEngine()


def get_mitre_engine() -> MitreEfficacyEngine:
    """Returns the singleton MitreEfficacyEngine instance."""
    return _mitre_engine


class SimulateCampaignRequest(BaseModel):
    """Payload to trigger an automated Breach and Attack Simulation (BAS) campaign."""
    target_environment: str = Field(default="Corporate Enterprise Network", description="Alvo da validação")
    scenario: str = Field(default="full_adversary", description="Cenário de ataque: full_adversary, cloud_perimeter, ransomware_attack")


class UpdateTechniqueRequest(BaseModel):
    """Payload to update the defensive status of a single technique."""
    status: DefenseStatus
    prevention_control: Optional[str] = None
    detection_event: Optional[str] = None
    execution_log: Optional[str] = None


@router.get(
    "/matrix",
    summary="Obter Matriz MITRE ATT&CK Completa (Heatmap Data)",
    response_model=Dict[str, Any],
)
async def get_mitre_matrix(
    engine: MitreEfficacyEngine = Depends(get_mitre_engine),
):
    """
    Retorna a matriz empresarial MITRE ATT&CK agrupada pelas 14 táticas,
    incluindo status defensivo de cada técnica (blocked, detected, missed, untested)
    e resumo quantitativo para renderização de Heatmap.
    """
    return engine.get_matrix()


@router.get(
    "/efficacy",
    summary="Obter Relatório de Eficácia Defensiva (Picus Score)",
    response_model=DefensiveEfficacyReport,
)
async def get_defensive_efficacy(
    engine: MitreEfficacyEngine = Depends(get_mitre_engine),
):
    """
    Retorna o cálculo oficial de Eficácia de Controles de Segurança:
    - Taxa de Prevenção (% bloqueado)
    - Taxa de Detecção (% alertado)
    - Score Global de Eficácia Defensiva (0 a 100)
    - Lacunas Críticas (Critical Gaps) e Controles Resilientes.
    """
    return engine.calculate_efficacy()


@router.post(
    "/simulate",
    summary="Executar Simulação de Ataque e Validação de Controles (BAS)",
    response_model=DefensiveEfficacyReport,
)
async def simulate_bas_campaign(
    payload: SimulateCampaignRequest,
    engine: MitreEfficacyEngine = Depends(get_mitre_engine),
):
    """
    Dispara uma campanha automatizada de Breach and Attack Simulation (BAS)
    contra o ambiente alvo, testando controles de segurança em todas as táticas MITRE.
    """
    report = engine.simulate_campaign(
        target_name=payload.target_environment,
        scenario=payload.scenario,
    )
    return report


@router.get(
    "/techniques/{technique_id}",
    summary="Obter Detalhes da Técnica MITRE",
    response_model=Dict[str, Any],
)
async def get_technique_details(
    technique_id: str,
    engine: MitreEfficacyEngine = Depends(get_mitre_engine),
):
    """Retorna os detalhes de execução, evidência e controle da técnica especificada."""
    tech = engine.get_technique(technique_id)
    if not tech:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Técnica MITRE '{technique_id}' não encontrada.",
        )
    return tech.model_dump()


@router.get(
    "/remediation/{technique_id}",
    summary="Obter Regra Sigma e Orientação de Remediação Blue Team",
    response_model=Dict[str, Any],
)
async def get_technique_remediation(
    technique_id: str,
    engine: MitreEfficacyEngine = Depends(get_mitre_engine),
):
    """Retorna a regra Sigma oficial (YAML) e o plano de ação de mitigação para o Blue Team."""
    rem = engine.get_remediation(technique_id)
    if not rem:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediação para técnica '{technique_id}' não encontrada.",
        )
    return rem


@router.patch(
    "/techniques/{technique_id}",
    summary="Atualizar Status de Técnica Manualmente",
    response_model=Dict[str, Any],
)
async def update_technique_status(
    technique_id: str,
    payload: UpdateTechniqueRequest,
    engine: MitreEfficacyEngine = Depends(get_mitre_engine),
):
    """Atualiza o resultado da avaliação de uma técnica (blocked/detected/missed)."""
    tech = engine.evaluate_technique(
        technique_id=technique_id,
        status=payload.status,
        prevention_control=payload.prevention_control,
        detection_event=payload.detection_event,
        execution_log=payload.execution_log or "",
    )
    if not tech:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Técnica '{technique_id}' não encontrada.",
        )
    return tech.model_dump()
