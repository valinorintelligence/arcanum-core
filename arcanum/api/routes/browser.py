"""
Rotas da API FastAPI para o Agente de Navegador Headless Web (Estilo XBOW).
Permite iniciar auditorias, consultar status de sessões e listar achados de lógica de negócios.
"""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/browser", tags=["Agente Web Headless"])


class AuditRequest(BaseModel):
    """Requisição para iniciar uma nova auditoria de navegador."""
    target_url: str = Field(..., description="URL base da aplicação a auditar", examples=["https://app.exemplo.com"])
    workflow_description: str = Field(
        default="",
        description="Descrição em linguagem natural do fluxo a testar (ex: 'fluxo de checkout', 'login e perfil')",
        examples=["fluxo de checkout de e-commerce e carrinho de compras"],
    )
    auth_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Cabeçalhos de autenticação (ex: Bearer token, cookies)",
    )
    max_depth: int = Field(default=3, ge=1, le=10, description="Profundidade máxima de crawling")
    stealth_profile: str = Field(
        default="windows_desktop",
        description="Perfil de identidade stealth e hardware antifraude (windows_desktop, mac_laptop, iphone_mobile)",
    )


class SimulatedAuditRequest(BaseModel):
    """Requisição para rodar auditoria em modo simulado (rápida, sem Playwright)."""
    target_url: str = Field(..., description="URL base da aplicação a auditar", examples=["https://loja.exemplo.com/produto/1"])
    workflow_description: str = Field(
        default="checkout e-commerce com carrinho",
        description="Descrição do fluxo de negócio",
    )
    stealth_profile: str = Field(
        default="windows_desktop",
        description="Perfil de hardware stealth (windows_desktop, mac_laptop, iphone_mobile)",
    )


@router.get("/profiles", summary="Listar perfis de identidade stealth de hardware")
async def list_stealth_profiles() -> list[dict[str, Any]]:
    """Retorna os perfis de evasão e fingerprint disponíveis no Stealth Engine."""
    from arcanum.browser.stealth import DEVICE_PROFILES
    return [
        {
            "id": p.name,
            "label": p.label,
            "platform": p.platform,
            "user_agent": p.user_agent,
            "viewport": p.viewport,
            "is_mobile": p.is_mobile,
            "has_touch": p.has_touch,
            "webgl_vendor": p.webgl_vendor,
            "webgl_renderer": p.webgl_renderer,
            "hardware_concurrency": p.hardware_concurrency,
            "device_memory": p.device_memory,
        }
        for p in DEVICE_PROFILES.values()
    ]


@router.post("/audit", summary="Iniciar auditoria de navegador headless")
async def start_browser_audit(req: AuditRequest, request: Request) -> dict[str, Any]:
    """
    Inicia uma sessão de auditoria com o Agente de Navegador Headless (XBOW-style).
    Tenta usar Playwright se disponível, com fallback automático para modo simulado.
    """
    agent = getattr(request.app.state, "browser_agent", None)
    if not agent:
        from arcanum.browser.agent import HeadlessBrowserAgent
        agent = HeadlessBrowserAgent(browser_available=False)
        request.app.state.browser_agent = agent

    session = await agent.audit(
        target_url=req.target_url,
        workflow_description=req.workflow_description,
        auth_headers=req.auth_headers or None,
        max_depth=req.max_depth,
        stealth_profile=req.stealth_profile,
    )
    return session.to_dict()


@router.post("/simulate", summary="Executar auditoria simulada rápida")
async def run_simulated_audit(req: SimulatedAuditRequest, request: Request) -> dict[str, Any]:
    """
    Executa uma auditoria simulada determinística e rápida, útil para testes e CI.
    Gera achados com base em heurísticas estáticas e fluxo de negócio indicado.
    """
    from arcanum.browser.agent import HeadlessBrowserAgent
    agent = getattr(request.app.state, "browser_agent", None)
    if not agent:
        agent = HeadlessBrowserAgent(browser_available=False)
        request.app.state.browser_agent = agent

    sim_agent = HeadlessBrowserAgent(browser_available=False)
    session = await sim_agent.audit(
        target_url=req.target_url,
        workflow_description=req.workflow_description,
        stealth_profile=req.stealth_profile,
    )
    # Registra no agente principal do app para visibilidade uniforme
    agent._sessions[session.id] = session
    return session.to_dict()



@router.get("/sessions", summary="Listar todas as sessões de auditoria")
async def list_browser_sessions(request: Request) -> list[dict[str, Any]]:
    """Retorna todas as sessões de auditoria executadas nesta instância."""
    agent = getattr(request.app.state, "browser_agent", None)
    if not agent:
        return []
    return [s.to_dict() for s in agent.list_sessions()]


@router.get("/sessions/{session_id}", summary="Consultar detalhes de uma sessão")
async def get_browser_session(session_id: str, request: Request) -> dict[str, Any]:
    """Retorna os detalhes completos de uma sessão de auditoria por ID."""
    agent = getattr(request.app.state, "browser_agent", None)
    if not agent:
        raise HTTPException(status_code=404, detail="Nenhum agente de navegador ativo")

    data = agent.get_session_summary(session_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Sessão '{session_id}' não encontrada")

    return data


@router.get("/sessions/{session_id}/findings", summary="Listar achados de uma sessão")
async def get_session_findings(session_id: str, request: Request) -> list[dict[str, Any]]:
    """Retorna apenas os achados (falhas de lógica) de uma sessão específica."""
    agent = getattr(request.app.state, "browser_agent", None)
    if not agent:
        raise HTTPException(status_code=404, detail="Nenhum agente de navegador ativo")

    session = agent.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Sessão '{session_id}' não encontrada")

    return [f.to_dict() for f in session.findings]
