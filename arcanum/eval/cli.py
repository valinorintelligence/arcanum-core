"""CLI Interface for running Arcanum AI Agent Evaluation Benchmark."""
from __future__ import annotations

import sys
import asyncio
from .runner import EvalRunner

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def main():
    json_mode = "--json" in sys.argv
    live_mode = "--live" in sys.argv
    model_name = "qwen2.5-coder:7b"
    for arg in sys.argv:
        if arg.startswith("--model="):
            model_name = arg.split("=", 1)[1]

    runner = EvalRunner()

    if not json_mode:
        print("\n" + "=" * 70)
        print("ARCANUM AI AGENT EVALUATION BENCHMARK (EVAL HARNESS) v3.0")
        print(f"Modo: {'AO VIVO (Ollama: ' + model_name + ')' if live_mode else 'DETERMINISTICO (Guardioes, Escopo & Logica)'}")
        print("=" * 70 + "\n")

    if live_mode:
        if not json_mode:
            print("Executando cenarios contra o modelo local Ollama...")
        report = asyncio.run(runner.run_live(model_name=model_name))
    else:
        if not json_mode:
            print("Executando validacao de salvaguardas, anti-alucinacao e roteamento...")
        report = runner.run_deterministic()

    if json_mode:
        import json
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return 0 if report.failed_scenarios == 0 else 1

    # Display Results Table
    print("\n" + "-" * 70)
    print(f"{'CENARIO':<35} | {'CATEGORIA':<15} | {'STATUS':<8} | {'TEMPO':<8}")
    print("-" * 70)
    for res in report.scenario_results:
        status_str = "[OK] PASS" if res.passed else "[!] FAIL"
        time_str = f"{res.duration_ms:.1f}ms"
        print(f"{res.scenario_name[:34]:<35} | {res.category:<15} | {status_str:<8} | {time_str:<8}")
        if not res.passed or res.hallucinations_detected:
            print(f"   * Detalhes: {res.details}")
            if res.hallucinations_detected:
                print(f"   * Alucinacoes: {', '.join(res.hallucinations_detected)}")

    print("-" * 70)
    print("\nSCORECARD FINAL DE DESEMPENHO E CONFIABILIDADE:")
    print(f" - Nota Geral (Grade):              {report.grade} ({report.overall_score:.1f}/100)")
    print(f" - Taxa de Sucesso dos Cenarios:    {report.success_rate:.1f}% ({report.passed_scenarios}/{report.total_scenarios})")
    print(f" - Acuracia de Intencao/Roteamento: {report.intent_accuracy_rate:.1f}%")
    print(f" - Resistencia a Alucinacoes:       {report.hallucination_resistance_rate:.1f}%")
    print(f" - Protecao do Guardiao de Escopo:  {report.scope_protection_rate:.1f}%")
    print(f" - Imunidade a Loops e Stagnation:  {report.stagnation_resistance_rate:.1f}%")
    print(f" - Latencia Media de Execucao:      {report.avg_latency_ms:.1f}ms")

    print("\nRECOMENDACOES DO EVALUATOR:")
    for rec in report.recommendations:
        print(f" - {rec}")

    print("\n" + "=" * 70 + "\n")
    return 0 if report.failed_scenarios == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
