"""
Testes unitários e de integração para o Motor de Furtividade e Evasão Antifraude (Stealth Engine).
Valida:
1. Perfis de Hardware e Identidade Digital (Windows 11 NVIDIA, Mac M2 Metal, iPhone 16 Pro iOS 18).
2. Trajetórias de Cursor Bézier Cúbicas (Curvatura > 0, Straight Ratio > 1.01, Tremor Gaussiano).
3. Cadência de Digitação Humana (Latência Gaussiana, Variância de Digitação > 50).
4. Detector e Evasão de Honeypots Mutantes (-9999px, links 1px, secret-dna, display:none).
5. Simulador de Sensores Inerciais Mobile (Giroscópio / Acelerômetro com Variância Cumulativa > 0.01).
6. Geração de Scripts Anti-Tampering (Function.prototype.toString -> '[native code]').
7. Integração completa com o HeadlessBrowserAgent.
"""
import pytest
from arcanum.browser.stealth import (
    DEVICE_PROFILES,
    BezierMouse,
    DeviceProfile,
    HoneypotDetector,
    HumanTyping,
    SensorSimulator,
    StealthEngine,
)
from arcanum.browser.agent import HeadlessBrowserAgent
from arcanum.browser.models import BrowserAuditSession


# ---------------------------------------------------------------------------
# 1. Testes de Perfis de Hardware
# ---------------------------------------------------------------------------

def test_device_profiles_configuration():
    """Deve conter perfis de desktop (Windows/Mac) e mobile (iPhone) devidamente calibrados."""
    assert "windows_desktop" in DEVICE_PROFILES
    assert "mac_laptop" in DEVICE_PROFILES
    assert "iphone_mobile" in DEVICE_PROFILES

    win = DEVICE_PROFILES["windows_desktop"]
    assert win.platform == "Win32"
    assert "NVIDIA" in win.webgl_renderer
    assert win.viewport["width"] == 1920
    assert win.viewport["height"] == 1080
    assert win.is_mobile is False
    assert win.has_touch is False

    mac = DEVICE_PROFILES["mac_laptop"]
    assert mac.platform == "MacIntel"
    assert "Apple M2" in mac.webgl_renderer
    assert mac.device_scale_factor == 2.0

    iphone = DEVICE_PROFILES["iphone_mobile"]
    assert iphone.platform == "iPhone"
    assert iphone.is_mobile is True
    assert iphone.has_touch is True
    assert iphone.device_scale_factor == 3.0


# ---------------------------------------------------------------------------
# 2. Testes do Simulador de Mouse Bézier
# ---------------------------------------------------------------------------

def test_bezier_mouse_trajectory_and_metrics():
    """Deve gerar curva de Bézier com curvatura não-linear e desvio em relação à reta."""
    start = (100.0, 100.0)
    end = (800.0, 600.0)

    path = BezierMouse.generate_path(start, end, steps=30, jitter_std=0.15)
    assert len(path) == 30

    # Início e fim devem ser exatos
    assert path[0] == start
    assert path[-1] == end

    metrics = BezierMouse.calculate_metrics(path)
    # Relação comprimento de curva / distância em linha reta deve ser > 1.01
    assert metrics["path_straight_ratio"] > 1.01
    # Curvatura média deve ser estritamente positiva (não é um robô andando em linha reta pura)
    assert metrics["curvature_avg"] > 0.001
    # Velocidade média e variância de movimento devem existir
    assert metrics["speed_mean"] > 0.0
    assert metrics["speed_variance"] >= 0.0


def test_bezier_mouse_short_distance():
    """Distâncias mínimas (< 1px) devem retornar apenas início e fim sem quebrar."""
    path = BezierMouse.generate_path((50.0, 50.0), (50.5, 50.5), steps=10)
    assert len(path) == 2
    assert path[0] == (50.0, 50.0)
    assert path[1] == (50.5, 50.5)


# ---------------------------------------------------------------------------
# 3. Testes do Simulador de Digitação Humana
# ---------------------------------------------------------------------------

def test_human_typing_delays_and_variance():
    """A cadência de digitação deve ter distribuição Gaussiana e variância humana expressiva."""
    sample_text = "SenhaSegura123! Testando comportamento humano."
    delays = HumanTyping.calculate_delays(sample_text, mean_ms=110.0, std_ms=35.0)

    assert len(delays) == len(sample_text)
    metrics = HumanTyping.get_metrics(delays)

    # A média deve estar na faixa humana (~100ms - 180ms considerando pausas)
    assert 90.0 <= metrics["mean_ms"] <= 200.0
    # A variância de digitação deve ser maior que 50 (robôs têm variância 0 ou constante)
    assert metrics["variance_ms"] > 50.0
    # Nenhum caractere deve ser digitado instantaneamente (mínimo > 25ms)
    assert metrics["min_ms"] >= 25.0


# ---------------------------------------------------------------------------
# 4. Testes do Detector de Honeypots Mutantes
# ---------------------------------------------------------------------------

def test_honeypot_detector_catches_traps():
    """Deve identificar elementos com técnicas clássicas e avançadas de bot-trap."""
    # 1. Fora da tela (-9999px)
    trap_offscreen = {
        "name": "email_confirm",
        "styles": {"left": "-9999px", "display": "block"},
        "bounding_box": {"width": 150, "height": 30, "x": -9999, "y": 0},
    }
    is_trap, reason = HoneypotDetector.is_honeypot(trap_offscreen)
    assert is_trap is True
    assert "fora da tela" in reason or "negativas" in reason

    # 2. Display none / visibility hidden / opacidade zero
    trap_hidden = {
        "name": "bot_check",
        "styles": {"display": "none"},
    }
    is_trap, _ = HoneypotDetector.is_honeypot(trap_hidden)
    assert is_trap is True

    trap_transparent = {
        "name": "fake_input",
        "styles": {"opacity": "0.01"},
    }
    is_trap, _ = HoneypotDetector.is_honeypot(trap_transparent)
    assert is_trap is True

    # 3. Dimensão mínima de link de armadilha (1px trap)
    trap_1px = {
        "name": "trap_link",
        "bounding_box": {"width": 1, "height": 1, "x": 10, "y": 10},
    }
    is_trap, reason = HoneypotDetector.is_honeypot(trap_1px)
    assert is_trap is True
    assert "dimensões mínimas" in reason

    # 4. Atributo suspeito de DNA / honeypot
    trap_dna = {
        "name": "username_alt",
        "attributes": {"data-tg-dna": "mutant-token-987"},
        "bounding_box": {"width": 200, "height": 40, "x": 100, "y": 100},
    }
    is_trap, reason = HoneypotDetector.is_honeypot(trap_dna)
    assert is_trap is True
    assert "data-tg-dna" in reason


def test_honeypot_detector_permits_legitimate_input():
    """Inputs de formulários visíveis e legítimos NÃO devem ser classificados como armadilhas."""
    legit_input = {
        "name": "user_email",
        "id": "email_field",
        "tag": "input",
        "styles": {"display": "block", "visibility": "visible", "opacity": "1.0"},
        "bounding_box": {"width": 300, "height": 40, "x": 150, "y": 200},
        "attributes": {"type": "email", "placeholder": "Digite seu e-mail"},
    }
    is_trap, reason = HoneypotDetector.is_honeypot(legit_input)
    assert is_trap is False
    assert reason == ""

    # Filtragem de lista
    safe = HoneypotDetector.filter_safe_elements([legit_input, {"styles": {"display": "none"}}])
    assert len(safe) == 1
    assert safe[0]["name"] == "user_email"


# ---------------------------------------------------------------------------
# 5. Testes do Simulador de Sensores Inerciais Mobile
# ---------------------------------------------------------------------------

def test_sensor_simulator_cumulative_variance():
    """Giroscópio emulado deve ultrapassar o limite de variância cumulativa de 0.01 em 5s."""
    stream = SensorSimulator.generate_sensor_stream(duration_seconds=5.0, sample_rate_hz=30)
    assert len(stream) == 150

    cum_var = SensorSimulator.get_cumulative_variance(stream)
    # A variância cumulativa deve ser > 0.01 (requisito para comprovar mão humana em movimento)
    assert cum_var > 0.01

    js_mock = SensorSimulator.generate_js_sensor_mock()
    assert "deviceorientation" in js_mock
    assert "devicemotion" in js_mock


# ---------------------------------------------------------------------------
# 6. Testes do StealthEngine e Scripts Anti-Tampering
# ---------------------------------------------------------------------------

def test_stealth_engine_init_script_generation():
    """O script anti-tamper deve incluir mascaramento de toString, remoção de webdriver e WebGL."""
    stealth = StealthEngine("windows_desktop")
    script = stealth.generate_init_script()

    # Mascaramento de Function.prototype.toString
    assert "Function.prototype.toString" in script
    assert "[native code]" in script

    # Mascaramento de webdriver
    assert "webdriver" in script

    # Mascaramento de WebGL da NVIDIA
    assert "NVIDIA GeForce GTX 1650" in script
    assert "0x9245" in script  # UNMASKED_VENDOR_WEBGL
    assert "0x9246" in script  # UNMASKED_RENDERER_WEBGL

    opts = stealth.get_playwright_context_options()
    assert opts["viewport"]["width"] == 1920
    assert opts["is_mobile"] is False


def test_stealth_engine_mobile_profile():
    """Perfil mobile deve incluir sensores e configurações touch."""
    stealth = StealthEngine("iphone_mobile")
    script = stealth.generate_init_script()

    assert "deviceorientation" in script
    assert "devicemotion" in script
    assert "Apple GPU (Metal)" in script

    opts = stealth.get_playwright_context_options()
    assert opts["is_mobile"] is True
    assert opts["has_touch"] is True


# ---------------------------------------------------------------------------
# 7. Testes de Integração com HeadlessBrowserAgent
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_headless_browser_agent_with_stealth_profile():
    """Auditoria deve aplicar perfil de stealth e computar métricas de evasão."""
    agent = HeadlessBrowserAgent(browser_available=False)
    session = await agent.audit(
        target_url="https://banco.corp.local/login",
        workflow_description="login corporativo com proteção antibot",
        stealth_profile="iphone_mobile",
    )

    assert session.status == "completed"
    assert session.stealth_profile == "iphone_mobile"
    assert "hardware_profile:iphone_mobile" in session.stealth_evasions_applied
    assert "imu_sensor_drift_simulation" in session.stealth_evasions_applied
    assert "anti_tamper_function_tostring" in session.stealth_evasions_applied
    assert "bezier_mouse_trajectory" in session.stealth_evasions_applied
    assert session.honeypots_avoided >= 1

    # Verifica se os passos registram evasão de honeypot
    step_actions = [s.action for s in session.steps]
    assert "evade_honeypot" in step_actions

    as_dict = session.to_dict()
    assert as_dict["stealth_profile"] == "iphone_mobile"
    assert as_dict["honeypots_avoided"] >= 1
