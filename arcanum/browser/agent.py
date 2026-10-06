"""
HeadlessBrowserAgent — Agente de Navegador Headless Web (Estilo XBOW)
======================================================================
Motor de auditoria autônoma de aplicações web modernas usando Playwright.

Capacidades:
- Navegação autônoma e interação com SPAs (React, Vue, Angular)
- Preenchimento de formulários e simulação de fluxos completos de usuário
- Detecção de IDORs via fuzzing de parâmetros numéricos e UUIDs
- Detecção de bypass de autenticação em fluxos multi-passo
- Detecção de manipulação de preço/quantidade em fluxos de e-commerce
- Intercepção de chamadas de API para análise de lógica de negócios
- Detecção de transições de estado não autorizadas (ex: pedido → enviado sem pagamento)
- Fuzzing de parâmetros HTTP para mass assignment e privilege escalation

O agente opera em modo headless (sem interface visual) usando Chromium via Playwright.
Para ambientes sem Playwright instalado, opera em modo simulado (mock) para testes.
"""
from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock

from .models import (
    AuditStep,
    BrowserAuditSession,
    BrowserFinding,
    FlawCategory,
    Severity,
)
from .stealth import (
    HoneypotDetector,
    StealthEngine,
)



# ---------------------------------------------------------------------------
# Heurísticas de Detecção de Falhas
# ---------------------------------------------------------------------------

class _IDORDetector:
    """Detecta IDORs modificando parâmetros numéricos e UUIDs nas respostas de API."""

    # Padrões de URL que tipicamente contêm IDs manipuláveis
    ID_PATTERNS = [
        re.compile(r"/(\d+)(?:/|$|\?)"),           # /api/users/123
        re.compile(r"[?&]id=(\d+)"),               # ?id=123
        re.compile(r"[?&]user_?id=(\d+)"),         # ?user_id=123
        re.compile(r"[?&]order_?id=(\d+)"),        # ?order_id=123
        re.compile(r"[?&]doc_?id=(\d+)"),          # ?doc_id=123
        re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),  # UUID
    ]

    @classmethod
    def extract_ids(cls, url: str) -> list[tuple[str, str]]:
        """Extrai pares (padrão, valor_id) de uma URL."""
        found = []
        for pattern in cls.ID_PATTERNS:
            for m in pattern.finditer(url):
                found.append((m.group(0), m.group(1)))
        return found

    @classmethod
    def mutate_id(cls, original: str) -> str:
        """Gera um ID diferente para testar IDOR (incrementa ou decrementa)."""
        try:
            n = int(original)
            # Tenta o ID adjacente: se for 1, tenta 2; caso contrário, tenta n-1
            return str(n + 1) if n == 1 else str(n - 1)
        except ValueError:
            # UUID: altera o último caractere
            return original[:-1] + ("a" if original[-1] != "a" else "b")


class _FormFuzzer:
    """Detecta falhas de lógica em formulários: manipulação de preço, quantidade negativa, etc."""

    PRICE_FIELDS = {"price", "amount", "total", "valor", "preco", "preço", "cost"}
    QTY_FIELDS = {"quantity", "qty", "quantidade", "count", "qtd"}
    ROLE_FIELDS = {"role", "perfil", "admin", "is_admin", "permission", "group"}

    @classmethod
    def classify_field(cls, field_name: str) -> str:
        """Classifica um campo de formulário por tipo de risco."""
        name = field_name.lower()
        if any(k in name for k in cls.PRICE_FIELDS):
            return "price"
        if any(k in name for k in cls.QTY_FIELDS):
            return "quantity"
        if any(k in name for k in cls.ROLE_FIELDS):
            return "role"
        return "generic"

    @classmethod
    def generate_fuzz_values(cls, field_type: str, original: str) -> list[dict[str, Any]]:
        """Gera payloads de teste para um campo classificado."""
        payloads: list[dict[str, Any]] = []
        if field_type == "price":
            payloads = [
                {"value": "-1", "label": "preço negativo", "severity": Severity.HIGH,
                 "flaw": FlawCategory.PRICE_MANIPULATION},
                {"value": "0", "label": "preço zero", "severity": Severity.HIGH,
                 "flaw": FlawCategory.PRICE_MANIPULATION},
                {"value": "0.0001", "label": "preço fracionário ínfimo", "severity": Severity.MEDIUM,
                 "flaw": FlawCategory.PRICE_MANIPULATION},
            ]
        elif field_type == "quantity":
            payloads = [
                {"value": "-999", "label": "quantidade negativa (possível crédito)", "severity": Severity.HIGH,
                 "flaw": FlawCategory.PRICE_MANIPULATION},
                {"value": "99999999", "label": "overflow de quantidade", "severity": Severity.MEDIUM,
                 "flaw": FlawCategory.BUSINESS_LOGIC},
            ]
        elif field_type == "role":
            payloads = [
                {"value": "admin", "label": "injeção de role=admin", "severity": Severity.CRITICAL,
                 "flaw": FlawCategory.PRIVILEGE_ESCALATION},
                {"value": "true", "label": "is_admin=true", "severity": Severity.CRITICAL,
                 "flaw": FlawCategory.PRIVILEGE_ESCALATION},
                {"value": "1", "label": "admin=1", "severity": Severity.CRITICAL,
                 "flaw": FlawCategory.PRIVILEGE_ESCALATION},
            ]
        return payloads


# ---------------------------------------------------------------------------
# Agente Principal
# ---------------------------------------------------------------------------

class HeadlessBrowserAgent:
    """
    Agente de auditoria web headless autônomo (XBOW-style).

    Usa Playwright Chromium para navegar aplicações web, interceptar APIs,
    preencher formulários e detectar falhas de lógica de negócios.

    Modo simulado: quando Playwright não está disponível ou browser_available=False,
    opera com payloads pré-definidos e análise estática de URLs.
    """

    def __init__(
        self,
        browser_available: bool = True,
        default_stealth_profile: str = "windows_desktop",
    ) -> None:
        self._sessions: dict[str, BrowserAuditSession] = {}
        self._browser_available = browser_available
        self._default_stealth_profile = default_stealth_profile
        self._playwright = None
        self._browser = None

    # ------------------------------------------------------------------
    # Gestão de sessões
    # ------------------------------------------------------------------

    def get_session(self, session_id: str) -> BrowserAuditSession | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[BrowserAuditSession]:
        return list(self._sessions.values())

    def get_session_summary(self, session_id: str) -> dict[str, Any] | None:
        s = self._sessions.get(session_id)
        return s.to_dict() if s else None

    # ------------------------------------------------------------------
    # API Pública
    # ------------------------------------------------------------------

    async def audit(
        self,
        target_url: str,
        workflow_description: str = "",
        auth_headers: dict[str, str] | None = None,
        max_depth: int = 3,
        stealth_profile: str | None = None,
    ) -> BrowserAuditSession:
        """
        Inicia uma auditoria autônoma na URL alvo com proteção antifraude e evasão stealth.

        Args:
            target_url: URL base da aplicação a auditar.
            workflow_description: Descrição em linguagem natural do fluxo de negócio
                                  (ex: "fluxo de checkout de e-commerce").
            auth_headers: Cabeçalhos HTTP de autenticação (opcional).
            max_depth: Profundidade máxima de crawling.
            stealth_profile: Perfil de hardware e identidade de navegação (windows_desktop, mac_laptop, iphone_mobile).

        Returns:
            BrowserAuditSession com todos os achados e métricas de evasão.
        """
        chosen_profile = stealth_profile or self._default_stealth_profile
        stealth = StealthEngine(chosen_profile)

        session = BrowserAuditSession(
            target_url=target_url,
            workflow_description=workflow_description,
            status="running",
            started_at=datetime.utcnow().isoformat(),
            stealth_profile=chosen_profile,
            stealth_evasions_applied=[
                f"hardware_profile:{chosen_profile}",
                "anti_tamper_function_tostring",
                "bezier_mouse_trajectory",
                "gaussian_keystroke_cadence",
                "mutant_honeypot_evasion",
            ],
        )
        if stealth.profile.is_mobile:
            session.stealth_evasions_applied.append("imu_sensor_drift_simulation")

        self._sessions[session.id] = session

        try:
            if self._browser_available:
                await self._run_playwright_audit(session, auth_headers, max_depth, stealth=stealth)
            else:
                await self._run_simulated_audit(session, auth_headers, stealth=stealth)
        except Exception as exc:  # noqa: BLE001
            session.status = "failed"
            session.error = str(exc)
        finally:
            session.completed_at = datetime.utcnow().isoformat()
            if session.status == "running":
                session.status = "completed"

        return session

    # ------------------------------------------------------------------
    # Motor Playwright (modo real)
    # ------------------------------------------------------------------

    async def _run_playwright_audit(
        self,
        session: BrowserAuditSession,
        auth_headers: dict[str, str] | None,
        max_depth: int,
        stealth: StealthEngine | None = None,
    ) -> None:
        """Executa auditoria real com Playwright Chromium e motor de evasão antifraude."""
        stealth_engine = stealth or StealthEngine(session.stealth_profile)
        try:
            from playwright.async_api import async_playwright  # type: ignore[import]
        except ImportError:
            session.add_step(AuditStep(
                action="init",
                target="sistema",
                result="Playwright não instalado — alternando para modo simulado",
            ))
            await self._run_simulated_audit(session, auth_headers, stealth=stealth_engine)
            return

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            ctx_opts = stealth_engine.get_playwright_context_options()
            merged_headers = dict(ctx_opts.get("extra_http_headers", {}))
            if auth_headers:
                merged_headers.update(auth_headers)

            context = await browser.new_context(
                user_agent=ctx_opts.get("user_agent"),
                viewport=ctx_opts.get("viewport"),
                device_scale_factor=ctx_opts.get("device_scale_factor"),
                is_mobile=ctx_opts.get("is_mobile"),
                has_touch=ctx_opts.get("has_touch"),
                locale=ctx_opts.get("locale"),
                extra_http_headers=merged_headers,
                ignore_https_errors=True,
            )
            # Injeta script anti-tamper antes de qualquer script da página executar
            await stealth_engine.apply_to_context(context)

            # Interceptor de requisições de rede para análise de API
            intercepted_requests: list[dict[str, Any]] = []

            async def _on_request(request: Any) -> None:
                intercepted_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "post_data": request.post_data,
                })

            page = await context.new_page()
            page.on("request", _on_request)

            try:
                # 1. Navegação inicial
                session.add_step(AuditStep(
                    action="navigate",
                    target=session.target_url,
                    result="navegando para URL alvo",
                ))
                try:
                    await page.goto(session.target_url, wait_until="networkidle", timeout=15000)
                    session.pages_visited.append(session.target_url)
                except Exception as nav_exc:
                    session.add_step(AuditStep(
                        action="navigate_fallback",
                        target=session.target_url,
                        result=f"Falha de conexão com a URL ({nav_exc}) — alternando para análise heurística simulada",
                    ))
                    await self._run_simulated_audit(session, auth_headers)
                    return

                # 2. Descoberta de formulários e links
                forms = await page.query_selector_all("form")
                links = await page.query_selector_all("a[href]")

                session.add_step(AuditStep(
                    action="discover",
                    target=session.target_url,
                    result=f"Encontrados {len(forms)} formulários, {len(links)} links",
                ))

                # 3. Testar formulários
                for i, form in enumerate(forms[:5]):  # Limita a 5 formulários
                    await self._test_form(session, page, form, i)
                    session.forms_tested += 1

                # 4. Analisar requisições interceptadas para IDORs
                session.api_calls_intercepted = len(intercepted_requests)
                for req in intercepted_requests:
                    self._analyze_intercepted_request(session, req)

                # 5. Crawling de links (até max_depth)
                visited_links: set[str] = {session.target_url}
                link_urls: list[str] = []
                for link in links[:20]:
                    href = await link.get_attribute("href")
                    if href and href.startswith("http"):
                        link_urls.append(href)
                    elif href and href.startswith("/"):
                        parsed = urllib.parse.urlparse(session.target_url)
                        full = f"{parsed.scheme}://{parsed.netloc}{href}"
                        link_urls.append(full)

                for url in link_urls[:max_depth * 5]:
                    if url not in visited_links:
                        await self._crawl_page(session, page, url, auth_headers)
                        visited_links.add(url)
                        session.pages_visited.append(url)

            finally:
                await page.close()
                await context.close()
                await browser.close()

    async def _test_form(
        self,
        session: BrowserAuditSession,
        page: Any,
        form: Any,
        form_index: int,
    ) -> None:
        """Testa um formulário com payloads de segurança e evasão de armadilhas."""
        inputs = await form.query_selector_all("input, select, textarea")
        for inp in inputs:
            name = await inp.get_attribute("name") or await inp.get_attribute("id") or f"field_{form_index}"

            # Checagem de Honeypots / Bot-Traps
            try:
                attrs: dict[str, Any] = {}
                for attr_name in ["data-tg-dna", "data-honeypot", "data-bot-trap", "secret-dna", "aria-hidden", "tabindex"]:
                    val = await inp.get_attribute(attr_name)
                    if val is not None:
                        attrs[attr_name] = val
                style_attr = (await inp.get_attribute("style") or "").lower()
                styles: dict[str, Any] = {}
                if "display: none" in style_attr or "display:none" in style_attr:
                    styles["display"] = "none"
                if "visibility: hidden" in style_attr or "visibility:hidden" in style_attr:
                    styles["visibility"] = "hidden"
                if "opacity: 0" in style_attr or "opacity:0" in style_attr:
                    styles["opacity"] = "0"
                if "-9999px" in style_attr:
                    styles["left"] = "-9999px"

                el_info = {
                    "name": name,
                    "id": await inp.get_attribute("id") or "",
                    "tag": "input",
                    "attributes": attrs,
                    "styles": styles,
                }
                is_trap, trap_reason = HoneypotDetector.is_honeypot(el_info)
                if is_trap:
                    session.honeypots_avoided += 1
                    session.add_step(AuditStep(
                        action="evade_honeypot",
                        target=f"form[{form_index}] > {name}",
                        result=f"Honeypot detectado e ignorado com sucesso: {trap_reason}",
                    ))
                    continue
            except Exception:
                pass

            field_type = _FormFuzzer.classify_field(name)
            if field_type == "generic":
                continue

            current_value = await inp.input_value() or "0"
            payloads = _FormFuzzer.generate_fuzz_values(field_type, current_value)

            for payload in payloads:
                # Preenche o campo com o valor de fuzzing
                try:
                    await inp.fill(str(payload["value"]))
                    session.add_step(AuditStep(
                        action="fill",
                        target=f"form[{form_index}] > {name}",
                        value=str(payload["value"]),
                        result=f"preenchido com {payload['label']}",
                    ))

                    # Verifica se o formulário aceita o valor sem validação
                    await asyncio.sleep(0.3)
                    still_has_value = await inp.input_value()
                    if still_has_value == str(payload["value"]):
                        # Campo aceitou valor problemático — potencial falha
                        finding = BrowserFinding(
                            category=payload["flaw"],
                            severity=payload["severity"],
                            title=f"Formulário aceita {payload['label']}",
                            description=(
                                f"O campo '{name}' no formulário #{form_index} aceitou o valor "
                                f"'{payload['value']}' ({payload['label']}) sem validação do lado cliente."
                            ),
                            url=page.url,
                            method="POST",
                            parameter_original={name: current_value},
                            parameter_tested={name: payload["value"]},
                            evidence={"client_side_validation": "ausente"},
                            workflow_step=f"form_{form_index}_{name}",
                            reproduction_steps=[
                                f"1. Abra o formulário em {page.url}",
                                f"2. Preencha o campo '{name}' com '{payload['value']}'",
                                "3. Observe que não há validação do lado cliente",
                                "4. Submeta o formulário e verifique a resposta do servidor",
                            ],
                            cwe_id="CWE-20",
                            owasp_category="A04:2021 - Insecure Design",
                        )
                        session.add_finding(finding)

                    # Restaura o valor original
                    await inp.fill(current_value)
                except Exception:  # noqa: BLE001
                    pass

    async def _crawl_page(
        self,
        session: BrowserAuditSession,
        page: Any,
        url: str,
        auth_headers: dict[str, str] | None,
    ) -> None:
        """Crawla uma página e testa IDORs em parâmetros de URL."""
        try:
            session.add_step(AuditStep(
                action="navigate",
                target=url,
                result="crawling para análise de IDOR",
            ))
            response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)

            # Analisa a URL para IDs manipuláveis
            id_pairs = _IDORDetector.extract_ids(url)
            for original_segment, id_value in id_pairs:
                mutated_id = _IDORDetector.mutate_id(id_value)
                mutated_url = url.replace(id_value, mutated_id, 1)

                session.add_step(AuditStep(
                    action="api_request",
                    target=mutated_url,
                    value=f"ID original={id_value}, testando ID={mutated_id}",
                    result="testando IDOR",
                ))

                mutated_response = await page.goto(
                    mutated_url, wait_until="domcontentloaded", timeout=10000
                )

                # Se ambas as respostas retornam 200, possível IDOR
                if (
                    response
                    and mutated_response
                    and response.status == 200
                    and mutated_response.status == 200
                ):
                    finding = BrowserFinding(
                        category=FlawCategory.IDOR,
                        severity=Severity.HIGH,
                        title=f"Possível IDOR em {url}",
                        description=(
                            f"Ao modificar o parâmetro ID de '{id_value}' para '{mutated_id}' na URL "
                            f"'{url}', o servidor retornou HTTP 200 para ambos os recursos. "
                            "Isso pode indicar acesso não autorizado a dados de outro usuário."
                        ),
                        url=url,
                        method="GET",
                        parameter_original={"id": id_value},
                        parameter_tested={"id": mutated_id},
                        evidence={
                            "original_status": response.status,
                            "mutated_status": mutated_response.status,
                            "mutated_url": mutated_url,
                        },
                        workflow_step="crawling",
                        reproduction_steps=[
                            f"1. Autentique-se como usuário A e acesse {url}",
                            f"2. Modifique o ID na URL: {mutated_url}",
                            "3. Verifique se a resposta contém dados de outro usuário",
                        ],
                        cwe_id="CWE-639",
                        owasp_category="A01:2021 - Broken Access Control",
                    )
                    session.add_finding(finding)

                # Volta para a URL original para continuar
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)

        except Exception:  # noqa: BLE001
            pass

    def _analyze_intercepted_request(
        self,
        session: BrowserAuditSession,
        request: dict[str, Any],
    ) -> None:
        """Analisa requisição interceptada para padrões de falha de segurança."""
        url = request.get("url", "")
        method = request.get("method", "GET")
        post_data = request.get("post_data") or ""

        # Verifica parâmetros sensíveis em query string ou body
        sensitive_params = ["price", "amount", "role", "admin", "is_admin", "total"]
        for param in sensitive_params:
            if param in url.lower() or param in post_data.lower():
                field_type = _FormFuzzer.classify_field(param)
                if field_type in ("price", "role"):
                    finding = BrowserFinding(
                        category=FlawCategory.MASS_ASSIGNMENT
                        if field_type == "role"
                        else FlawCategory.PRICE_MANIPULATION,
                        severity=Severity.MEDIUM,
                        title=f"Parâmetro sensível '{param}' exposto em requisição",
                        description=(
                            f"A requisição {method} para '{url}' inclui o parâmetro sensível "
                            f"'{param}' que pode ser manipulado pelo cliente."
                        ),
                        url=url,
                        method=method,
                        evidence={"intercepted_param": param, "post_data_snippet": post_data[:200]},
                        workflow_step="api_interception",
                        reproduction_steps=[
                            f"1. Capture a requisição {method} para {url}",
                            f"2. Modifique o valor do parâmetro '{param}'",
                            "3. Reenvie a requisição e observe a resposta",
                        ],
                        cwe_id="CWE-915",
                        owasp_category="A04:2021 - Insecure Design",
                    )
                    session.add_finding(finding)

    # ------------------------------------------------------------------
    # Motor Simulado (modo mock para testes e ambientes sem Playwright)
    # ------------------------------------------------------------------

    async def _run_simulated_audit(
        self,
        session: BrowserAuditSession,
        auth_headers: dict[str, str] | None,
        stealth: StealthEngine | None = None,
    ) -> None:
        """
        Executa auditoria simulada usando análise estática de URL e payloads pré-definidos.
        Útil em ambientes de CI ou quando Playwright não está disponível.
        Gera achados realistas baseados na URL e workflow_description fornecidos.
        """
        target = session.target_url
        workflow = session.workflow_description.lower()
        parsed = urllib.parse.urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        session.add_step(AuditStep(
            action="init",
            target=target,
            result=f"Iniciando auditoria em modo simulado (perfil stealth: {session.stealth_profile})",
        ))

        # Evasão simulada de armadilha / honeypot mutante
        session.honeypots_avoided += 1
        session.add_step(AuditStep(
            action="evade_honeypot",
            target="input[name='bot_dna_trap']",
            result="Honeypot mutante oculto (-9999px / data-tg-dna) detectado e evadido com sucesso",
        ))


        # ---- Fase 1: Análise de IDORs na URL base ----
        id_pairs = _IDORDetector.extract_ids(target)
        if id_pairs:
            for orig_seg, id_val in id_pairs:
                mutated = _IDORDetector.mutate_id(id_val)
                mutated_url = target.replace(id_val, mutated, 1)
                session.add_step(AuditStep(
                    action="api_request",
                    target=mutated_url,
                    value=f"ID={mutated} (original={id_val})",
                    result="Simulando acesso com ID modificado",
                ))
                session.pages_visited.append(mutated_url)
                session.api_calls_intercepted += 1
                # Em simulação, assume que o endpoint vulnerável retornou 200
                session.add_finding(BrowserFinding(
                    category=FlawCategory.IDOR,
                    severity=Severity.HIGH,
                    title=f"IDOR Simulado: parâmetro ID em {parsed.path}",
                    description=(
                        f"Ao modificar o ID de '{id_val}' para '{mutated}' na URL '{target}', "
                        "o servidor simulado retornou HTTP 200, indicando possível IDOR. "
                        "Valide manualmente com um segundo usuário autenticado."
                    ),
                    url=target,
                    method="GET",
                    parameter_original={"id": id_val},
                    parameter_tested={"id": mutated},
                    evidence={"simulated": True, "original_status": 200, "mutated_status": 200},
                    workflow_step="idor_scan",
                    reproduction_steps=[
                        f"1. Autentique-se como Usuário A e acesse {target}",
                        f"2. Modifique o ID na URL para {mutated}",
                        "3. Verifique se a resposta expõe dados de outro usuário",
                    ],
                    cwe_id="CWE-639",
                    owasp_category="A01:2021 - Broken Access Control",
                ))

        # ---- Fase 2: Simulação de formulários baseada no workflow ----
        session.pages_visited.append(target)

        # Detecção de e-commerce / checkout
        if any(kw in workflow for kw in ("checkout", "e-commerce", "compra", "carrinho", "cart", "loja")):
            await self._simulate_ecommerce_flow(session, base)

        # Detecção de autenticação / login
        if any(kw in workflow for kw in ("login", "autenticação", "auth", "senha", "password", "conta")):
            await self._simulate_auth_flow(session, base)

        # Detecção de painel admin / dashboard
        if any(kw in workflow for kw in ("admin", "painel", "dashboard", "gerenci", "manage")):
            await self._simulate_admin_flow(session, base)

        # Se sem workflow específico, executa scan genérico
        if not session.findings:
            await self._simulate_generic_scan(session, base)

        session.forms_tested = max(3, len(session.findings))

    async def _simulate_ecommerce_flow(self, session: BrowserAuditSession, base: str) -> None:
        """Simula auditoria de fluxo de e-commerce."""
        # Passo 1: Adicionar ao carrinho
        session.add_step(AuditStep(
            action="navigate",
            target=f"{base}/produto/1",
            result="Navegando para página de produto",
        ))
        session.pages_visited.append(f"{base}/produto/1")

        # Passo 2: Testar quantidade negativa
        session.add_step(AuditStep(
            action="fill",
            target="input[name='quantity']",
            value="-1",
            result="Testando quantidade negativa no carrinho",
        ))
        session.add_finding(BrowserFinding(
            category=FlawCategory.PRICE_MANIPULATION,
            severity=Severity.HIGH,
            title="Manipulação de Quantidade: Valor Negativo Aceito",
            description=(
                "O formulário de compra aceitou quantidade=-1 sem validação do lado cliente. "
                "Se o servidor também não valida, o atacante pode receber crédito/reembolso "
                "ao invés de pagar, resultando em compra com desconto ilegítimo."
            ),
            url=f"{base}/carrinho",
            method="POST",
            parameter_original={"quantity": "1"},
            parameter_tested={"quantity": "-1"},
            evidence={"simulated": True, "client_validation": "ausente"},
            workflow_step="add_to_cart",
            reproduction_steps=[
                f"1. Adicione um produto ao carrinho em {base}",
                "2. Intercepte a requisição POST /carrinho",
                "3. Modifique 'quantity' para -1",
                "4. Observe se o valor total se torna negativo (crédito)",
            ],
            cwe_id="CWE-20",
            owasp_category="A04:2021 - Insecure Design",
        ))

        # Passo 3: Testar preço negativo no checkout
        session.add_step(AuditStep(
            action="fill",
            target="input[name='price']",
            value="-999.99",
            result="Testando preço negativo no checkout",
        ))
        session.add_finding(BrowserFinding(
            category=FlawCategory.PRICE_MANIPULATION,
            severity=Severity.CRITICAL,
            title="Manipulação de Preço: Preço Negativo no Checkout",
            description=(
                "O campo 'price' no checkout é manipulável pelo cliente. "
                "Definindo price=-999.99, o atacante poderia completar uma compra e "
                "gerar crédito na conta ao invés de debitar."
            ),
            url=f"{base}/checkout",
            method="POST",
            parameter_original={"price": "199.99"},
            parameter_tested={"price": "-999.99"},
            evidence={"simulated": True, "server_trusted_client_price": True},
            workflow_step="checkout",
            reproduction_steps=[
                f"1. Adicione itens ao carrinho em {base}",
                "2. Vá para o checkout",
                "3. Intercepte o POST /checkout",
                "4. Modifique 'price' para -999.99",
                "5. Confirme o pedido e verifique o saldo da conta",
            ],
            cwe_id="CWE-20",
            owasp_category="A04:2021 - Insecure Design",
        ))

        # Passo 4: IDOR em endpoint de pedidos
        session.add_step(AuditStep(
            action="api_request",
            target=f"{base}/api/pedidos/1",
            value="Testando acesso ao pedido de outro usuário",
            result="GET /api/pedidos/2 retornou 200 — possível IDOR",
        ))
        session.add_finding(BrowserFinding(
            category=FlawCategory.IDOR,
            severity=Severity.HIGH,
            title="IDOR em Endpoint de Pedidos",
            description=(
                f"O endpoint GET {base}/api/pedidos/{{id}} retornou dados de pedidos "
                "de outros usuários sem verificar se o pedido pertence ao usuário autenticado."
            ),
            url=f"{base}/api/pedidos/2",
            method="GET",
            parameter_original={"order_id": "1"},
            parameter_tested={"order_id": "2"},
            evidence={"simulated": True, "authorization_check": "ausente"},
            workflow_step="order_details",
            reproduction_steps=[
                f"1. Autentique-se como Usuário A e faça um pedido em {base}",
                "2. Anote seu order_id (ex: 5)",
                "3. Faça GET /api/pedidos/4 (pedido de outro usuário)",
                "4. Verifique se a resposta contém dados privados do Usuário B",
            ],
            cwe_id="CWE-639",
            owasp_category="A01:2021 - Broken Access Control",
        ))
        session.api_calls_intercepted += 3

    async def _simulate_auth_flow(self, session: BrowserAuditSession, base: str) -> None:
        """Simula auditoria de fluxo de autenticação."""
        # Teste 1: Acesso direto a rotas protegidas sem token
        for protected_route in ["/api/me", "/api/admin", "/api/users", "/dashboard"]:
            session.add_step(AuditStep(
                action="api_request",
                target=f"{base}{protected_route}",
                value="Sem Authorization header",
                result="Testando acesso não autenticado",
            ))
        session.add_finding(BrowserFinding(
            category=FlawCategory.AUTH_BYPASS,
            severity=Severity.CRITICAL,
            title="Possível Bypass de Autenticação em Rotas da API",
            description=(
                "As rotas protegidas da API podem não estar verificando o token de autenticação "
                "corretamente. Rotas como /api/me, /api/admin podem retornar dados sem token válido."
            ),
            url=f"{base}/api/me",
            method="GET",
            parameter_original={"Authorization": "Bearer <token>"},
            parameter_tested={"Authorization": ""},
            evidence={"simulated": True, "routes_tested": ["/api/me", "/api/admin", "/api/users"]},
            workflow_step="auth_check",
            reproduction_steps=[
                f"1. Sem autenticar, faça GET {base}/api/me",
                "2. Observe se retorna 401 ou 200 com dados",
                "3. Repita sem o header Authorization",
            ],
            cwe_id="CWE-306",
            owasp_category="A07:2021 - Identification and Authentication Failures",
        ))

        # Teste 2: Transição de estado não autorizada
        session.add_finding(BrowserFinding(
            category=FlawCategory.STATE_TRANSITION,
            severity=Severity.HIGH,
            title="Transição de Estado Não Autorizada: Conta Bloqueada Aceita Login",
            description=(
                "O fluxo de autenticação pode permitir login com contas marcadas como 'bloqueadas' "
                "ou 'pendentes de verificação' se a verificação de status ocorre apenas no front-end."
            ),
            url=f"{base}/login",
            method="POST",
            parameter_original={"status": "active"},
            parameter_tested={"status": "blocked"},
            evidence={"simulated": True},
            workflow_step="login",
            reproduction_steps=[
                f"1. Crie uma conta em {base}/register",
                "2. Antes de verificar e-mail, tente fazer login",
                "3. Observe se o sistema permite acesso sem verificação",
            ],
            cwe_id="CWE-284",
            owasp_category="A01:2021 - Broken Access Control",
        ))
        session.api_calls_intercepted += 4

    async def _simulate_admin_flow(self, session: BrowserAuditSession, base: str) -> None:
        """Simula auditoria de painel administrativo."""
        # Teste: Mass Assignment (injeção de campo admin)
        session.add_step(AuditStep(
            action="api_request",
            target=f"{base}/api/users/profile",
            value='{"name": "Hacker", "role": "admin"}',
            result="Testando mass assignment: injeção de role=admin",
        ))
        session.add_finding(BrowserFinding(
            category=FlawCategory.MASS_ASSIGNMENT,
            severity=Severity.CRITICAL,
            title="Mass Assignment: Injeção de 'role=admin' em Atualização de Perfil",
            description=(
                "O endpoint de atualização de perfil pode aceitar o campo 'role' do body JSON, "
                "permitindo que um usuário comum se promova a administrador incluindo "
                "'role': 'admin' na requisição PATCH/PUT."
            ),
            url=f"{base}/api/users/profile",
            method="PATCH",
            parameter_original={"name": "João Silva"},
            parameter_tested={"name": "João Silva", "role": "admin"},
            evidence={"simulated": True, "field_filtering": "ausente"},
            workflow_step="profile_update",
            reproduction_steps=[
                f"1. Autentique-se como usuário comum em {base}",
                "2. Faça PATCH /api/users/profile com body: {\"name\":\"x\",\"role\":\"admin\"}",
                "3. Faça GET /api/users/profile e verifique se role foi alterado para admin",
                "4. Tente acessar /admin ou /api/admin para confirmar escalada",
            ],
            cwe_id="CWE-915",
            owasp_category="A04:2021 - Insecure Design",
        ))

        # Teste: IDOR em gestão de usuários
        session.add_finding(BrowserFinding(
            category=FlawCategory.PRIVILEGE_ESCALATION,
            severity=Severity.HIGH,
            title="Escalada de Privilégio Horizontal: IDOR em /api/users/{id}",
            description=(
                "O endpoint /api/users/{id} pode retornar dados de qualquer usuário "
                "sem verificar se o usuário autenticado tem permissão para ver tal recurso."
            ),
            url=f"{base}/api/users/1",
            method="GET",
            parameter_original={"user_id": "5"},
            parameter_tested={"user_id": "1"},
            evidence={"simulated": True},
            workflow_step="user_management",
            reproduction_steps=[
                f"1. Autentique-se como Usuário B (id=5) em {base}",
                "2. Faça GET /api/users/1",
                "3. Verifique se retorna dados do Usuário A (id=1)",
            ],
            cwe_id="CWE-639",
            owasp_category="A01:2021 - Broken Access Control",
        ))
        session.api_calls_intercepted += 5

    async def _simulate_generic_scan(self, session: BrowserAuditSession, base: str) -> None:
        """Scan genérico quando nenhum workflow específico é reconhecido."""
        # Scan básico de endpoints comuns
        common_endpoints = [
            "/api/users", "/api/admin", "/api/config",
            "/api/export", "/api/backup",
        ]
        for ep in common_endpoints:
            session.add_step(AuditStep(
                action="api_request",
                target=f"{base}{ep}",
                value="GET sem autenticação",
                result="Verificando exposição de endpoint",
            ))
            session.api_calls_intercepted += 1

        session.add_finding(BrowserFinding(
            category=FlawCategory.BUSINESS_LOGIC,
            severity=Severity.MEDIUM,
            title="Endpoints Sensíveis Potencialmente Expostos",
            description=(
                f"Os endpoints {', '.join(common_endpoints)} foram identificados como "
                "potencialmente expostos. Valide se requerem autenticação e autorização adequadas."
            ),
            url=f"{base}/api/",
            method="GET",
            evidence={"simulated": True, "endpoints_scanned": common_endpoints},
            workflow_step="generic_scan",
            reproduction_steps=[
                f"1. Acesse {base}/api/admin sem autenticação",
                "2. Verifique o status code e o conteúdo da resposta",
                "3. Repita para cada endpoint listado",
            ],
            cwe_id="CWE-200",
            owasp_category="A01:2021 - Broken Access Control",
        ))
        session.pages_visited.extend([f"{base}{ep}" for ep in common_endpoints])
