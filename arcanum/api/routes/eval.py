"""FastAPI REST API routes for AI Agent Model Evaluation Benchmark (Eval Harness)."""
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from arcanum.eval.runner import EvalRunner
from arcanum.eval.scenarios import BENCHMARK_SCENARIOS
from arcanum.eval.metrics import EvalReport

router = APIRouter(prefix="/api/eval", tags=["evaluation-benchmark"])

# Cache latest evaluation report
_latest_report: Optional[EvalReport] = None
_runner = EvalRunner()


class RunEvalRequest(BaseModel):
    """Payload to trigger an AI Evaluation benchmark."""
    mode: str = Field(default="deterministic", description="'deterministic' (rápido, salvaguardas e lógica) ou 'live' (testa modelo Ollama)")
    model_name: str = Field(default="qwen2.5-coder:7b", description="Nome do modelo local caso mode='live'")


@router.get(
    "/scenarios",
    summary="Listar todos os cenários de benchmark do Eval Harness",
    response_model=list[Dict[str, Any]],
)
async def list_benchmark_scenarios() -> list[Dict[str, Any]]:
    """Retorna os cenários formais de teste de intenção, anti-alucinação, escopo e performance."""
    return [
        {
            "id": sc.id,
            "category": sc.category,
            "name": sc.name,
            "description": sc.description,
            "target": sc.target,
            "scope": sc.scope,
            "prompt": sc.user_prompt,
            "expected_tools": sc.expected_tools,
            "forbidden_tools": sc.forbidden_tools,
            "forbidden_args": sc.forbidden_args,
        }
        for sc in BENCHMARK_SCENARIOS
    ]


@router.get(
    "/latest",
    summary="Obter o relatório e scorecard da avaliação mais recente",
    response_model=Dict[str, Any],
)
async def get_latest_eval_report() -> Dict[str, Any]:
    """Retorna o último relatório gerado ou executa uma validação determinística instantânea."""
    global _latest_report
    if _latest_report is None:
        _latest_report = _runner.run_deterministic()
    return _latest_report.to_dict()


@router.post(
    "/run",
    summary="Executar suite de testes de avaliação (Eval Harness)",
    response_model=Dict[str, Any],
)
async def run_eval_benchmark(
    payload: RunEvalRequest,
) -> Dict[str, Any]:
    """Executa a bateria de testes de IA em modo determinístico ou ao vivo contra o Ollama."""
    global _latest_report
    if payload.mode == "live":
        try:
            report = await _runner.run_live(model_name=payload.model_name)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Erro ao executar eval ao vivo no modelo: {str(exc)}")
    else:
        report = _runner.run_deterministic()

    _latest_report = report
    return report.to_dict()
