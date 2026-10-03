"""
Testes unitários para o Agente de Navegador Headless Web (Estilo XBOW).
Cobre:
- Detecção e mutação de IDORs (_IDORDetector)
- Classificação de campos e geração de fuzzing (_FormFuzzer)
- Criação e ciclo de vida de BrowserAuditSession
- Auditoria simulada (comércio eletrônico, autenticação, admin, genérica)
- Handler de ferramenta no ToolExecutor
"""
import pytest
from arcanum.browser.models import (
    BrowserAuditSession,
    BrowserFinding,
    FlawCategory,
    Severity,
    AuditStep,
)
from arcanum.browser.agent import HeadlessBrowserAgent, _IDORDetector, _FormFuzzer


# ---------------------------------------------------------------------------
# Testes do Detector de IDOR
# ---------------------------------------------------------------------------

def test_idor_detector_extract_numeric_id():
    """Deve extrair IDs numéricos de caminhos de URL e query parameters."""
    ids = _IDORDetector.extract_ids("https://app.local/api/users/42")
    assert len(ids) >= 1
    assert any(val == "42" for _, val in ids)

    ids_param = _IDORDetector.extract_ids("https://app.local/view?id=108")
    assert len(ids_param) >= 1
    assert any(val == "108" for _, val in ids_param)


def test_idor_detector_extract_uuid():
    """Deve extrair UUIDs de rotas de API."""
    uuid_str = "12345678-1234-1234-1234-123456789abc"
    url = f"https://app.local/api/documents/{uuid_str}"
    ids = _IDORDetector.extract_ids(url)
    assert len(ids) >= 1
    assert any(val == uuid_str for _, val in ids)


def test_idor_detector_mutate_id():
    """Deve mutar IDs para valores adjacentes."""
    assert _IDORDetector.mutate_id("10") == "9"
    assert _IDORDetector.mutate_id("1") == "2"
    uuid_val = "12345678-1234-1234-1234-123456789abc"
    mutated = _IDORDetector.mutate_id(uuid_val)
    assert mutated != uuid_val
    assert len(mutated) == len(uuid_val)


# ---------------------------------------------------------------------------
# Testes do Form Fuzzer
# ---------------------------------------------------------------------------

def test_form_fuzzer_classification():
    """Deve classificar campos de formulário pelo risco."""
    assert _FormFuzzer.classify_field("item_price") == "price"
    assert _FormFuzzer.classify_field("total_amount") == "price"
    assert _FormFuzzer.classify_field("quantity") == "quantity"
    assert _FormFuzzer.classify_field("user_role") == "role"
    assert _FormFuzzer.classify_field("is_admin") == "role"
    assert _FormFuzzer.classify_field("user_description") == "generic"


def test_form_fuzzer_payloads():
    """Deve gerar payloads com severidades corretas."""
    price_payloads = _FormFuzzer.generate_fuzz_values("price", "50")
    assert len(price_payloads) >= 2
    assert any(p["value"] == "-1" for p in price_payloads)
    assert any(p["flaw"] == FlawCategory.PRICE_MANIPULATION for p in price_payloads)

    role_payloads = _FormFuzzer.generate_fuzz_values("role", "user")
    assert len(role_payloads) >= 1
    assert any(p["flaw"] == FlawCategory.PRIVILEGE_ESCALATION for p in role_payloads)


# ---------------------------------------------------------------------------
# Testes do Modelo BrowserAuditSession
# ---------------------------------------------------------------------------

def test_audit_session_lifecycle():
    """Deve registrar achados e atualizar contagens por severidade."""
    session = BrowserAuditSession(target_url="https://app.local", status="running")
    f1 = BrowserFinding(
        category=FlawCategory.PRICE_MANIPULATION,
        severity=Severity.HIGH,
        title="Preço Negativo",
    )
    f2 = BrowserFinding(
        category=FlawCategory.AUTH_BYPASS,
        severity=Severity.CRITICAL,
        title="Bypass de Login",
    )
    session.add_finding(f1)
    session.add_finding(f2)

    assert len(session.findings) == 2
    assert session.finding_counts["high"] == 1
    assert session.finding_counts["critical"] == 1
    assert f1.session_id == session.id

    as_dict = session.to_dict()
    assert as_dict["total_findings"] == 2
    assert as_dict["target_url"] == "https://app.local"


# ---------------------------------------------------------------------------
# Testes do HeadlessBrowserAgent (modo simulado)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_agent_simulated_ecommerce_audit():
    """Auditoria simulada de e-commerce deve detectar manipulação de preço e IDOR."""
    agent = HeadlessBrowserAgent(browser_available=False)
    session = await agent.audit(
        target_url="https://loja.exemplo.com/produto/42",
        workflow_description="fluxo de carrinho de compras e checkout de e-commerce",
    )

    assert session.status == "completed"
    assert len(session.findings) >= 3
    assert session.forms_tested > 0
    categories = [f.category for f in session.findings]
    assert FlawCategory.PRICE_MANIPULATION in categories
    assert FlawCategory.IDOR in categories


@pytest.mark.asyncio
async def test_agent_simulated_auth_audit():
    """Auditoria simulada de autenticação deve detectar bypass e transição de estado."""
    agent = HeadlessBrowserAgent(browser_available=False)
    session = await agent.audit(
        target_url="https://portal.exemplo.com/login",
        workflow_description="fluxo de login e autenticação de usuários",
    )

    assert session.status == "completed"
    categories = [f.category for f in session.findings]
    assert FlawCategory.AUTH_BYPASS in categories
    assert FlawCategory.STATE_TRANSITION in categories


@pytest.mark.asyncio
async def test_agent_simulated_admin_audit():
    """Auditoria simulada de admin deve detectar mass assignment e escalada."""
    agent = HeadlessBrowserAgent(browser_available=False)
    session = await agent.audit(
        target_url="https://admin.exemplo.com/dashboard",
        workflow_description="painel administrativo de gerenciamento de usuários",
    )

    assert session.status == "completed"
    categories = [f.category for f in session.findings]
    assert FlawCategory.MASS_ASSIGNMENT in categories
    assert FlawCategory.PRIVILEGE_ESCALATION in categories


@pytest.mark.asyncio
async def test_agent_tool_executor_integration():
    """O ToolExecutor deve conseguir executar headless_web_audit com sucesso."""
    from arcanum.agent.tools import ToolExecutor, NATIVE_TOOLS

    tool_names = {t["function"]["name"] for t in NATIVE_TOOLS}
    assert "headless_web_audit" in tool_names

    executor = ToolExecutor(sandbox=None, browser=None, workspace_dir=None, db=None)
    assert "headless_web_audit" in executor._handlers

    res = await executor.execute_tool(
        "headless_web_audit",
        {
            "url": "https://shop.local/checkout",
            "workflow_description": "fluxo de checkout e pagamento",
            "max_depth": 2,
        },
    )

    assert res["success"] is True
    out = res["output"]
    assert "session_id" in out
    assert out["total_findings"] > 0
    assert "Auditoria Headless Web" in out["summary"]
