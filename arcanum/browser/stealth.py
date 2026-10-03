"""
Módulo de Evasão e Furtividade Humana para Agente de Navegador (Stealth Engine).
=============================================================================
Inspirado na engenharia reversa de sistemas antifraude e detecção de tráfego inválido (SIVT),
como o analisado no projeto Serene Nav Forge e bancos de inteligência comportamental.

Funcionalidades:
1. Perfis de Hardware Ultra-Realistas (Desktop Windows NVIDIA D3D11, Mac Apple Silicon Metal, iPhone 16 Pro).
2. Trajetórias de Mouse Não-Lineares via Curvas de Bézier com Jitter Gaussiano Estocástico.
   (Centróides humanos: curvature_avg > 0.01, path_straight_ratio > 1.05, jitter_entropy > 0.30).
3. Cadência de Digitação Humana com Variação Gaussiana e Pausas de Pontuação (keystroke_variance > 50).
4. Cloaking de DOM e Mascaramento de Tampering (Function.prototype.toString -> '[native code]').
5. Detector e Evasão de Honeypots Mutantes e Bot-Traps (elementos invisíveis, -9999px, links 1px, secretDNA).
6. Simulação de Giroscópio e Acelerômetro Mobile (variância cumulativa > 0.01 em 5s).
"""
from __future__ import annotations

import asyncio
import math
import random
import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# 1. Perfis de Hardware e Identidade Digital
# ---------------------------------------------------------------------------

@dataclass
class DeviceProfile:
    """Perfil completo de identidade digital e hardware de navegação."""
    name: str
    label: str
    platform: str
    user_agent: str
    viewport: dict[str, int]
    screen_avail: dict[str, int]
    device_scale_factor: float
    is_mobile: bool
    has_touch: bool
    languages: list[str]
    webgl_vendor: str
    webgl_renderer: str
    hardware_concurrency: int
    device_memory: int
    color_depth: int
    extra_headers: dict[str, str] = field(default_factory=dict)


DEVICE_PROFILES: dict[str, DeviceProfile] = {
    "windows_desktop": DeviceProfile(
        name="windows_desktop",
        label="Windows 11 Desktop — NVIDIA GeForce GTX 1650 (Direct3D11)",
        platform="Win32",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
        ),
        viewport={"width": 1920, "height": 1080},
        screen_avail={"width": 1920, "height": 1040},  # 40px para a barra de tarefas do Windows
        device_scale_factor=1.0,
        is_mobile=False,
        has_touch=False,
        languages=["pt-BR", "pt", "en-US", "en"],
        webgl_vendor="Google Inc. (NVIDIA)",
        webgl_renderer="ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        hardware_concurrency=8,
        device_memory=16,
        color_depth=24,
        extra_headers={
            "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        },
    ),
    "mac_laptop": DeviceProfile(
        name="mac_laptop",
        label="MacBook Pro Apple Silicon M2 Pro (Metal)",
        platform="MacIntel",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
        ),
        viewport={"width": 1440, "height": 900},
        screen_avail={"width": 1440, "height": 875},  # 25px para o menu bar do macOS
        device_scale_factor=2.0,
        is_mobile=False,
        has_touch=False,
        languages=["pt-BR", "pt", "en"],
        webgl_vendor="Apple Inc.",
        webgl_renderer="Apple M2 Pro (Metal)",
        hardware_concurrency=10,
        device_memory=16,
        color_depth=30,
        extra_headers={
            "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "accept-language": "pt-BR,pt;q=0.9,en;q=0.8",
        },
    ),
    "iphone_mobile": DeviceProfile(
        name="iphone_mobile",
        label="Apple iPhone 16 Pro (Mobile Safari iOS 18)",
        platform="iPhone",
        user_agent=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
        ),
        viewport={"width": 393, "height": 852},
        screen_avail={"width": 393, "height": 852},
        device_scale_factor=3.0,
        is_mobile=True,
        has_touch=True,
        languages=["pt-BR", "pt"],
        webgl_vendor="Apple Inc.",
        webgl_renderer="Apple GPU (Metal)",
        hardware_concurrency=6,
        device_memory=8,
        color_depth=32,
        extra_headers={
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"iOS"',
            "accept-language": "pt-BR,pt;q=0.9",
        },
    ),
}


# ---------------------------------------------------------------------------
# 2. Gerador de Trajetórias de Mouse via Curvas de Bézier e Jitter Gaussiano
# ---------------------------------------------------------------------------

class BezierMouse:
    """
    Simulador de movimentação de cursor com características biométricas humanas.
    Gera curvas de Bézier cúbicas com aceleração/desaceleração (Fitts's Law)
    e micro-jitter estocástico simulando tremor motor fisiológico.
    """

    @classmethod
    def generate_path(
        cls,
        start: tuple[float, float],
        end: tuple[float, float],
        steps: int = 30,
        jitter_std: float = 0.15,
    ) -> list[tuple[float, float]]:
        """
        Gera uma lista de pontos (x, y) conectando início e fim com uma curva de Bézier humana.

        Args:
            start: Coordenadas iniciais (x0, y0).
            end: Coordenadas de destino (x1, y1).
            steps: Quantidade de amostras intermediárias.
            jitter_std: Desvio padrão do tremor estocástico gaussiano.
        """
        x0, y0 = start
        x3, y3 = end
        dx = x3 - x0
        dy = y3 - y0
        dist = math.hypot(dx, dy)

        if dist < 1.0 or steps <= 2:
            return [(float(x0), float(y0)), (float(x3), float(y3))]

        # Vetor normal perpendicular à linha reta
        nx = -dy / dist
        ny = dx / dist

        # Desvio lateral aleatório para os pontos de controle (P1 e P2)
        # O arco humano varia entre 10% e 35% da distância total
        arc_deviation = random.uniform(0.12, 0.32) * dist
        arc_direction = random.choice([-1, 1])

        # P1: ~25% do caminho + desvio
        t1 = random.uniform(0.2, 0.4)
        p1_x = x0 + dx * t1 + nx * arc_deviation * arc_direction * random.uniform(0.7, 1.2)
        p1_y = y0 + dy * t1 + ny * arc_deviation * arc_direction * random.uniform(0.7, 1.2)

        # P2: ~75% do caminho + desvio atenuado (preparando para pousar no alvo)
        t2 = random.uniform(0.6, 0.8)
        p2_x = x0 + dx * t2 + nx * arc_deviation * arc_direction * random.uniform(0.3, 0.8)
        p2_y = y0 + dy * t2 + ny * arc_deviation * arc_direction * random.uniform(0.3, 0.8)

        points: list[tuple[float, float]] = []

        for i in range(steps):
            raw_t = i / (steps - 1)
            # Easing cúbico (aceleração inicial suave, desaceleração final suave)
            # Fitts's law: t = 3*t^2 - 2*t^3 (smoothstep)
            t = (raw_t * raw_t * (3.0 - 2.0 * raw_t))

            # Fórmula de Bézier Cúbica: B(t) = (1-t)^3*P0 + 3(1-t)^2*t*P1 + 3(1-t)*t^2*P2 + t^3*P3
            one_minus_t = 1.0 - t
            bx = (
                (one_minus_t ** 3) * x0
                + 3.0 * (one_minus_t ** 2) * t * p1_x
                + 3.0 * one_minus_t * (t ** 2) * p2_x
                + (t ** 3) * x3
            )
            by = (
                (one_minus_t ** 3) * y0
                + 3.0 * (one_minus_t ** 2) * t * p1_y
                + 3.0 * one_minus_t * (t ** 2) * p2_y
                + (t ** 3) * y3
            )

            # Jitter fisiológico (tremor muscular humano): atenuado nos extremos (0 e steps-1)
            edge_factor = math.sin(math.pi * raw_t)
            jx = random.gauss(0, jitter_std * edge_factor)
            jy = random.gauss(0, jitter_std * edge_factor)

            # Primeiro e último ponto são estritamente fiéis
            if i == 0:
                points.append((float(x0), float(y0)))
            elif i == steps - 1:
                points.append((float(x3), float(y3)))
            else:
                points.append((round(bx + jx, 2), round(by + jy, 2)))

        return points

    @classmethod
    def calculate_metrics(cls, path: list[tuple[float, float]]) -> dict[str, float]:
        """
        Calcula as métricas de validação de movimento contra os centróides da tabela traffic_logs.
        Verifica:
        - path_straight_ratio: Comprimento da trajetória sobre distância direta (deve ser > 1.02)
        - curvature_avg: Média angular de deflexão (deve ser > 0.005)
        - jitter_entropy: Variação das acelerações instantâneas (deve ser > 0.05)
        - speed_mean e speed_variance
        """
        if len(path) < 3:
            return {
                "path_straight_ratio": 1.0,
                "curvature_avg": 0.0,
                "jitter_entropy": 0.0,
                "speed_mean": 0.0,
                "speed_variance": 0.0,
            }

        x0, y0 = path[0]
        xn, yn = path[-1]
        direct_dist = math.hypot(xn - x0, yn - y0)

        # Distância percorrida e velocidades parciais
        total_curve_len = 0.0
        curvatures: list[float] = []
        speeds: list[float] = []

        for i in range(len(path) - 1):
            px, py = path[i]
            qx, qy = path[i + 1]
            seg_len = math.hypot(qx - px, qy - py)
            total_curve_len += seg_len
            speeds.append(seg_len)

            if i < len(path) - 2:
                rx, ry = path[i + 2]
                # Ângulo entre vetores (q-p) e (r-q)
                v1x, v1y = qx - px, qy - py
                v2x, v2y = rx - qx, ry - qy
                dot = v1x * v2x + v1y * v2y
                m1 = math.hypot(v1x, v1y)
                m2 = math.hypot(v2x, v2y)
                if m1 > 0.0001 and m2 > 0.0001:
                    cos_theta = max(-1.0, min(1.0, dot / (m1 * m2)))
                    curvatures.append(abs(math.acos(cos_theta)))

        path_straight_ratio = (
            round(total_curve_len / direct_dist, 4) if direct_dist > 0.001 else 1.0
        )
        curv_avg = round(sum(curvatures) / len(curvatures), 4) if curvatures else 0.0
        spd_mean = round(sum(speeds) / len(speeds), 4) if speeds else 0.0

        spd_var = (
            round(sum((s - spd_mean) ** 2 for s in speeds) / len(speeds), 4)
            if speeds
            else 0.0
        )

        # Entropia aproximada do jitter (desvios de velocidade)
        jitter_entropy = round(min(1.0, spd_var / (spd_mean + 0.001) * 0.5), 4)

        return {
            "path_straight_ratio": max(1.0, path_straight_ratio),
            "curvature_avg": curv_avg,
            "jitter_entropy": jitter_entropy,
            "speed_mean": spd_mean,
            "speed_variance": spd_var,
        }

    async def move_mouse(
        self,
        page: Any,
        target_x: float,
        target_y: float,
        start_x: float = 0.0,
        start_y: float = 0.0,
    ) -> list[tuple[float, float]]:
        """Executa a movimentação humana assíncrona no contexto do Playwright."""
        path = self.generate_path((start_x, start_y), (target_x, target_y), steps=random.randint(22, 35))
        for x, y in path:
            if hasattr(page, "mouse") and hasattr(page.mouse, "move"):
                await page.mouse.move(x, y)
                # Pausa infinitesimal simulando taxa de atualização de mouse (125Hz-1000Hz)
                await asyncio.sleep(random.uniform(0.005, 0.015))
        return path


# ---------------------------------------------------------------------------
# 3. Gerador de Cadência de Digitação Humana
# ---------------------------------------------------------------------------

class HumanTyping:
    """
    Simulador de cadência de digitação mecânica e cognitiva humana.
    Incorpora distribuição gaussiana de latência, pausas maiores em espaços
    (processamento sintático) e pontuação (pausas de fim de frase).
    """

    @classmethod
    def calculate_delays(
        cls,
        text: str,
        mean_ms: float = 110.0,
        std_ms: float = 35.0,
        min_ms: float = 30.0,
        max_ms: float = 350.0,
    ) -> list[float]:
        """
        Retorna a lista de tempos de espera em milissegundos para cada caractere do texto.
        """
        delays: list[float] = []
        for char in text:
            # Latência base com distribuição Gaussiana
            delay = random.gauss(mean_ms, std_ms)
            delay = max(min_ms, min(max_ms, delay))

            # Pausas cognitivas específicas
            if char in " .,;:!?":
                # Pausa de pontuação ou transição de palavras
                delay += random.uniform(60.0, 180.0)
            elif char in "\n\r":
                # Nova linha: pausa para pensamento
                delay += random.uniform(150.0, 320.0)
            elif char.isupper():
                # Caractere maiúsculo: pequeno overhead do Shift
                delay += random.uniform(20.0, 50.0)

            delays.append(round(delay, 2))
        return delays

    @classmethod
    def get_metrics(cls, delays: list[float]) -> dict[str, float]:
        """Calcula métricas da amostra de digitação para garantir conformidade humana."""
        if not delays:
            return {"mean_ms": 0.0, "variance_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}

        mean = sum(delays) / len(delays)
        var = sum((d - mean) ** 2 for d in delays) / len(delays)
        return {
            "mean_ms": round(mean, 2),
            "variance_ms": round(var, 2),
            "min_ms": round(min(delays), 2),
            "max_ms": round(max(delays), 2),
        }

    async def type_text(self, target_input: Any, text: str) -> None:
        """Digita o texto caractere a caractere no elemento com delays humanos."""
        delays = self.calculate_delays(text)
        for char, delay_ms in zip(text, delays):
            if hasattr(target_input, "type"):
                await target_input.type(char, delay=delay_ms / 1000.0)
            elif hasattr(target_input, "press"):
                await target_input.press(char)
                await asyncio.sleep(delay_ms / 1000.0)


# ---------------------------------------------------------------------------
# 4. Detector e Evasão de Honeypots Mutantes e Bot-Traps
# ---------------------------------------------------------------------------

class HoneypotDetector:
    """
    Identifica armadilhas colocadas por motores antifraude (Akamai, Cloudflare, DataDome, Serene).
    Detecta elementos fora da tela, links invisíveis de 1px, tokens de DNA ocultos
    e inputs de armadilha projetados para enganar bots descuidados.
    """

    SUSPICIOUS_ATTRIBUTES = {
        "data-tg-dna",
        "data-honeypot",
        "data-bot-trap",
        "secret-dna",
        "dna-token",
        "anti-bot-check",
    }

    SUSPICIOUS_NAMES_OR_IDS = [
        re.compile(r"honey(?:pot)?", re.IGNORECASE),
        re.compile(r"bot(?:_|-)?trap", re.IGNORECASE),
        re.compile(r"secret(?:_|-)?dna", re.IGNORECASE),
        re.compile(r"fake(?:_|-)?input", re.IGNORECASE),
        re.compile(r"chk(?:_|-)?guard", re.IGNORECASE),
    ]

    @classmethod
    def is_honeypot(cls, element_info: dict[str, Any]) -> tuple[bool, str]:
        """
        Avalia se um elemento HTML é uma armadilha antifraude (honeypot).

        Args:
            element_info: Dicionário contendo dados extraídos do elemento
                          (tag, name, id, classes, styles, bounding_box, attributes).

        Returns:
            (True, motivo) se for honeypot, ou (False, "") se for legítimo.
        """
        # 1. Checagem de atributos suspeitos de DNA / Honeypot
        attrs = element_info.get("attributes", {})
        for attr in attrs:
            if attr.lower() in cls.SUSPICIOUS_ATTRIBUTES:
                return True, f"Elemento possui atributo de armadilha: {attr}"

        name = element_info.get("name", "")
        el_id = element_info.get("id", "")
        classes = " ".join(element_info.get("classes", []))
        combined_identifiers = f"{name} {el_id} {classes}"

        for pat in cls.SUSPICIOUS_NAMES_OR_IDS:
            if pat.search(combined_identifiers):
                return True, f"Identificador coincide com padrão de honeypot: {pat.pattern}"

        # 2. Checagem de Estilos CSS Ocultos
        styles = element_info.get("styles", {})
        display = styles.get("display", "").lower()
        visibility = styles.get("visibility", "").lower()
        opacity = styles.get("opacity", "1")
        left = styles.get("left", "")
        top = styles.get("top", "")

        if display == "none":
            return True, "Elemento oculto via display: none"
        if visibility == "hidden":
            return True, "Elemento oculto via visibility: hidden"

        try:
            op_val = float(opacity)
            if op_val <= 0.05:
                return True, f"Elemento transparente com opacidade {op_val}"
        except ValueError:
            pass

        # Posições clássicas fora da tela (-9999px, etc)
        for coord in [left, top]:
            if coord:
                num_match = re.search(r"-?\d+", coord)
                if num_match and int(num_match.group(0)) <= -500:
                    return True, f"Elemento posicionado fora da tela ({coord})"

        # 3. Dimensões mínimas (1px trap link ou 0px)
        bbox = element_info.get("bounding_box", {})
        width = bbox.get("width", 100)
        height = bbox.get("height", 20)
        x = bbox.get("x", 0)
        y = bbox.get("y", 0)

        if width <= 1 or height <= 1:
            return True, f"Elemento armadilha com dimensões mínimas ({width}x{height}px)"

        if x <= -100 or y <= -100:
            return True, f"Coordenadas de renderização negativas ({x}, {y})"

        # 4. Flags de Acessibilidade Fraudulentas
        # Bots costumam clicar em aria-hidden="true" se estiverem buscando seletores genéricos
        if attrs.get("aria-hidden") == "true" and attrs.get("tabindex") == "-1":
            # Se não há texto visível e está fora do foco de acessibilidade
            if element_info.get("tag") in ("a", "button", "input"):
                return True, "Elemento interativo marcado com aria-hidden=true e tabindex=-1"

        return False, ""

    @classmethod
    def filter_safe_elements(cls, elements: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filtra uma lista de elementos descartando armadilhas antifraude."""
        safe = []
        for el in elements:
            is_trap, _ = cls.is_honeypot(el)
            if not is_trap:
                safe.append(el)
        return safe


# ---------------------------------------------------------------------------
# 5. Simulador de Sensores Mobile (Giroscópio & Acelerômetro)
# ---------------------------------------------------------------------------

class SensorSimulator:
    """
    Gera fluxos sintéticos de sensores inerciais (IMU: Giroscópio e Acelerômetro).
    Projetado para superar verificações de anti-bot que exigem variância cumulativa > 0.01
    ao longo de janelas de 5 segundos (comprovando que o dispositivo está na mão de um humano).
    """

    @classmethod
    def generate_sensor_stream(
        cls,
        duration_seconds: float = 5.0,
        sample_rate_hz: int = 60,
    ) -> list[dict[str, float]]:
        """Gera amostras de orientação (alpha, beta, gamma) com tremor fisiológico humano."""
        total_samples = int(duration_seconds * sample_rate_hz)
        samples: list[dict[str, float]] = []

        # Posição de repouso típica de celular segurado em ângulo de ~45 graus
        alpha = random.uniform(150.0, 210.0)  # Azimute / Bússola
        beta = random.uniform(35.0, 55.0)     # Inclinação frente-trás (típica de leitura)
        gamma = random.uniform(-10.0, 10.0)   # Inclinação lateral

        for i in range(total_samples):
            # Random walk com restauração de mola para manter dentro de limites humanos
            d_alpha = random.gauss(0, 0.08) - (alpha - 180.0) * 0.002
            d_beta = random.gauss(0, 0.06) - (beta - 45.0) * 0.003
            d_gamma = random.gauss(0, 0.05) - gamma * 0.003

            alpha += d_alpha
            beta += d_beta
            gamma += d_gamma

            samples.append({
                "time_ms": round((i / sample_rate_hz) * 1000, 2),
                "alpha": round(alpha, 3),
                "beta": round(beta, 3),
                "gamma": round(gamma, 3),
                "accel_x": round(random.gauss(0, 0.04), 3),
                "accel_y": round(random.gauss(9.81 * math.sin(math.radians(beta)), 0.05), 3),
                "accel_z": round(random.gauss(9.81 * math.cos(math.radians(beta)), 0.05), 3),
            })

        return samples

    @classmethod
    def get_cumulative_variance(cls, stream: list[dict[str, float]]) -> float:
        """Calcula a variância cumulativa do giroscópio para atestar que é > 0.01."""
        if len(stream) < 2:
            return 0.0

        betas = [s["beta"] for s in stream]
        mean_beta = sum(betas) / len(betas)
        var_beta = sum((b - mean_beta) ** 2 for b in betas) / len(betas)

        gammas = [s["gamma"] for s in stream]
        mean_gamma = sum(gammas) / len(gammas)
        var_gamma = sum((g - mean_gamma) ** 2 for g in gammas) / len(gammas)

        return round(var_beta + var_gamma, 4)

    @classmethod
    def generate_js_sensor_mock(cls) -> str:
        """Gera código JavaScript para emular eventos contínuos de orientação no navegador."""
        return """
        (() => {
            let beta = 45.0 + (Math.random() * 5);
            let gamma = (Math.random() * 4) - 2;
            let alpha = 180.0;

            function dispatchSensorEvents() {
                beta += (Math.random() - 0.5) * 0.15;
                gamma += (Math.random() - 0.5) * 0.12;
                alpha += (Math.random() - 0.5) * 0.20;

                const orientEvt = new Event('deviceorientation');
                orientEvt.alpha = alpha;
                orientEvt.beta = beta;
                orientEvt.gamma = gamma;
                orientEvt.absolute = false;
                window.dispatchEvent(orientEvt);

                const motionEvt = new Event('devicemotion');
                motionEvt.acceleration = {
                    x: (Math.random() - 0.5) * 0.05,
                    y: (Math.random() - 0.5) * 0.05,
                    z: (Math.random() - 0.5) * 0.05
                };
                motionEvt.accelerationIncludingGravity = {
                    x: 0.1,
                    y: 9.8 * Math.sin(beta * Math.PI / 180),
                    z: 9.8 * Math.cos(beta * Math.PI / 180)
                };
                motionEvt.rotationRate = {
                    alpha: (Math.random() - 0.5) * 0.1,
                    beta: (Math.random() - 0.5) * 0.1,
                    gamma: (Math.random() - 0.5) * 0.1
                };
                motionEvt.interval = 16.6;
                window.dispatchEvent(motionEvt);
            }

            setInterval(dispatchSensorEvents, 16.6);
        })();
        """


# ---------------------------------------------------------------------------
# 6. Motor Geral de Evasão (StealthEngine) e Injeção Anti-Tamper
# ---------------------------------------------------------------------------

class StealthEngine:
    """
    Motor central que unifica perfis de hardware, injeção de scripts anti-tamper,
    movimento biométrico de cursor e proteção contra armadilhas.
    """

    def __init__(self, profile_name: str = "windows_desktop") -> None:
        self.profile = DEVICE_PROFILES.get(profile_name, DEVICE_PROFILES["windows_desktop"])
        self.mouse = BezierMouse()
        self.typing = HumanTyping()
        self.honeypot = HoneypotDetector()
        self.sensors = SensorSimulator()

    def generate_init_script(self) -> str:
        """
        Gera o script JavaScript que é injetado no navegador antes da execução de qualquer
        script da página (via context.add_init_script).
        
        Garante:
        - webdriver = undefined e ausência de automação
        - Function.prototype.toString retorna '[native code]' para funções sobrescritas
        - Plugins e mimetypes realistas
        - WebGL unmasked vendor e renderer condizentes com o perfil de hardware
        - Dimensões de tela e profundidade de cor corretas
        - Emulação de sensores se perfil mobile
        """
        import json
        p = self.profile
        sensor_js = self.sensors.generate_js_sensor_mock() if p.is_mobile else ""
        chrome_mock = (
            'window.chrome = { runtime: {}, app: {}, csi: makeNative(() => {}, "csi"), loadTimes: makeNative(() => {}, "loadTimes") };'
            if not p.is_mobile else ""
        )

        template = """
        (() => {
            // 1. Cloaking de Function.prototype.toString (Anti-Tamper Lock)
            const originalToString = Function.prototype.toString;
            const patchedFns = new WeakSet();

            function makeNative(fn, name) {
                patchedFns.add(fn);
                return fn;
            }

            Function.prototype.toString = function () {
                if (patchedFns.has(this)) {
                    const fnName = this.name || '';
                    return `function ${fnName}() { [native code] }`;
                }
                return originalToString.call(this);
            };
            makeNative(Function.prototype.toString, 'toString');

            // 2. Remoção / Mascaramento de navigator.webdriver
            try {
                delete Object.getPrototypeOf(navigator).webdriver;
            } catch (e) {}

            Object.defineProperty(navigator, 'webdriver', {
                get: makeNative(() => undefined, 'get webdriver'),
                configurable: true,
                enumerable: true
            });

            // 3. Propriedades de Plataforma e Hardware
            Object.defineProperty(navigator, 'platform', {
                get: makeNative(() => '__PLATFORM__', 'get platform'),
                configurable: true,
                enumerable: true
            });

            Object.defineProperty(navigator, 'hardwareConcurrency', {
                get: makeNative(() => __HW_CONCURRENCY__, 'get hardwareConcurrency'),
                configurable: true,
                enumerable: true
            });

            Object.defineProperty(navigator, 'deviceMemory', {
                get: makeNative(() => __DEVICE_MEMORY__, 'get deviceMemory'),
                configurable: true,
                enumerable: true
            });

            Object.defineProperty(navigator, 'languages', {
                get: makeNative(() => __LANGUAGES__, 'get languages'),
                configurable: true,
                enumerable: true
            });

            // 4. Spoofing de WebGL Vendor e Renderer
            const getParameterProxy = function (param) {
                // 0x9245 = UNMASKED_VENDOR_WEBGL
                if (param === 0x9245) return '__WEBGL_VENDOR__';
                // 0x9246 = UNMASKED_RENDERER_WEBGL
                if (param === 0x9246) return '__WEBGL_RENDERER__';
                return this.callOriginal ? this.callOriginal(param) : null;
            };
            makeNative(getParameterProxy, 'getParameter');

            function patchWebGL(proto) {
                if (!proto) return;
                const oldGetParam = proto.getParameter;
                proto.getParameter = function (param) {
                    if (param === 0x9245) return '__WEBGL_VENDOR__';
                    if (param === 0x9246) return '__WEBGL_RENDERER__';
                    return oldGetParam.call(this, param);
                };
                makeNative(proto.getParameter, 'getParameter');
            }

            if (window.WebGLRenderingContext) {
                patchWebGL(window.WebGLRenderingContext.prototype);
            }
            if (window.WebGL2RenderingContext) {
                patchWebGL(window.WebGL2RenderingContext.prototype);
            }

            // 5. Configuração de Tela (Screen Resolution)
            Object.defineProperty(window.screen, 'availWidth', {
                get: makeNative(() => __SCREEN_AVAIL_WIDTH__, 'get availWidth')
            });
            Object.defineProperty(window.screen, 'availHeight', {
                get: makeNative(() => __SCREEN_AVAIL_HEIGHT__, 'get availHeight')
            });
            Object.defineProperty(window.screen, 'colorDepth', {
                get: makeNative(() => __COLOR_DEPTH__, 'get colorDepth')
            });
            Object.defineProperty(window.screen, 'pixelDepth', {
                get: makeNative(() => __COLOR_DEPTH__, 'get pixelDepth')
            });

            // 6. Chrome Runtime Mock (no desktop Chromium)
            __CHROME_MOCK__

            // 7. Simulação de Sensores Inerciais Mobile
            __SENSOR_JS__
        })();
        """

        return (
            template
            .replace("__PLATFORM__", p.platform)
            .replace("__HW_CONCURRENCY__", str(p.hardware_concurrency))
            .replace("__DEVICE_MEMORY__", str(p.device_memory))
            .replace("__LANGUAGES__", json.dumps(p.languages))
            .replace("__WEBGL_VENDOR__", p.webgl_vendor)
            .replace("__WEBGL_RENDERER__", p.webgl_renderer)
            .replace("__SCREEN_AVAIL_WIDTH__", str(p.screen_avail["width"]))
            .replace("__SCREEN_AVAIL_HEIGHT__", str(p.screen_avail["height"]))
            .replace("__COLOR_DEPTH__", str(p.color_depth))
            .replace("__CHROME_MOCK__", chrome_mock)
            .replace("__SENSOR_JS__", sensor_js)
        )


    def get_playwright_context_options(self) -> dict[str, Any]:
        """Retorna os parâmetros de criação do contexto do Playwright."""
        return {
            "user_agent": self.profile.user_agent,
            "viewport": self.profile.viewport,
            "device_scale_factor": self.profile.device_scale_factor,
            "is_mobile": self.profile.is_mobile,
            "has_touch": self.profile.has_touch,
            "extra_http_headers": self.profile.extra_headers,
            "locale": self.profile.languages[0],
            "ignore_https_errors": True,
        }

    async def apply_to_context(self, context: Any) -> None:
        """Injeta o script anti-tamper e configurações no BrowserContext do Playwright."""
        script = self.generate_init_script()
        if hasattr(context, "add_init_script"):
            await context.add_init_script(script)
