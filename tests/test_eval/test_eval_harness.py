"""Unit and Integration Tests for Arcanum Evaluation and Benchmarking Harness."""
import pytest
from unittest.mock import MagicMock, AsyncMock

from arcanum.eval.scenarios import BENCHMARK_SCENARIOS, BenchmarkScenario
from arcanum.eval.metrics import ScenarioResult, compute_eval_report
from arcanum.eval.runner import EvalRunner
from arcanum.api.main import create_app


def test_eval_benchmark_scenarios_integrity():
    """Verify that all scenarios have unique IDs, required fields, and valid targets."""
    assert len(BENCHMARK_SCENARIOS) >= 8
    ids = [sc.id for sc in BENCHMARK_SCENARIOS]
    assert len(ids) == len(set(ids)), "All benchmark scenario IDs must be unique"

    for sc in BENCHMARK_SCENARIOS:
        assert sc.id.startswith("EVAL-")
        assert sc.name and len(sc.name) > 5
        assert sc.target and "." in sc.target
        assert sc.category in ("intent", "hallucination", "scope", "routing", "normalization", "stagnation", "gating", "language", "blue", "purple", "red")


def test_eval_runner_deterministic_scorecard():
    """Verify that the deterministic benchmark passes 100% with Grade A+."""
    runner = EvalRunner()
    report = runner.run_deterministic()

    assert report.total_scenarios == len(BENCHMARK_SCENARIOS)
    assert report.passed_scenarios == len(BENCHMARK_SCENARIOS)
    assert report.failed_scenarios == 0
    assert report.success_rate == 100.0
    assert report.grade == "A+"
    assert report.overall_score == 100.0
    assert report.intent_accuracy_rate == 100.0
    assert report.hallucination_resistance_rate == 100.0
    assert report.scope_protection_rate == 100.0
    assert report.stagnation_resistance_rate == 100.0
    assert report.avg_latency_ms < 50.0  # Fast execution under 50ms total


def test_eval_metrics_scoring_rubric():
    """Test custom metrics calculations and grading logic."""
    # 1. Perfect results
    results_perfect = [
        ScenarioResult("S1", "Test Intent", True, "intent", 10.0),
        ScenarioResult("S2", "Test Scope", True, "scope", 12.0, scope_violations_attempted=1, scope_violations_blocked=1),
    ]
    rep_perfect = compute_eval_report(results_perfect)
    assert rep_perfect.grade == "A+"
    assert rep_perfect.overall_score == 100.0

    # 2. Results with a hallucination penalty
    results_hallucinated = [
        ScenarioResult("S1", "Test Hallucination", False, "hallucination", 10.0, hallucinations_detected=["8.8.8.8"]),
    ]
    rep_hal = compute_eval_report(results_hallucinated)
    assert rep_hal.hallucination_resistance_rate == 0.0
    assert rep_hal.grade in ("D", "F")
    assert any("auto-reparo" in rec for rec in rep_hal.recommendations)


@pytest.mark.asyncio
async def test_eval_api_endpoints():
    """Test the /api/eval REST endpoints using FastAPI test client."""
    from httpx import AsyncClient, ASGITransport

    app = create_app()
    # Mock database and token for test client
    app.state.api_token = "test-eval-token"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": "Bearer test-eval-token"}

        # 1. Test scenarios list
        r_scenarios = await client.get("/api/eval/scenarios", headers=headers)
        assert r_scenarios.status_code == 200
        scenarios_data = r_scenarios.json()
        assert len(scenarios_data) >= 8

        # 2. Test run deterministic eval
        r_run = await client.post("/api/eval/run", json={"mode": "deterministic"}, headers=headers)
        assert r_run.status_code == 200
        data = r_run.json()
        assert data["grade"] == "A+"
        assert data["success_rate"] == 100.0
        assert data["total_scenarios"] >= 8

        # 3. Test get latest
        r_latest = await client.get("/api/eval/latest", headers=headers)
        assert r_latest.status_code == 200
        assert r_latest.json()["grade"] == "A+"
