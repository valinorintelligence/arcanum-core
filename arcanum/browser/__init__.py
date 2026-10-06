# Módulo de Agente de Navegador Headless Web (Estilo XBOW)
# Permite auditoria autônoma de aplicações web modernas (SPAs, formulários, fluxos complexos)
# detectando falhas de lógica de negócios, IDORs, bypass de autenticação e manipulação de estado.

from .models import BrowserFinding, BrowserAuditSession, BusinessLogicFlaw
from .agent import HeadlessBrowserAgent
from .stealth import (
    StealthEngine,
    DeviceProfile,
    DEVICE_PROFILES,
    BezierMouse,
    HumanTyping,
    HoneypotDetector,
    SensorSimulator,
)

__all__ = [
    "BrowserFinding",
    "BrowserAuditSession",
    "BusinessLogicFlaw",
    "HeadlessBrowserAgent",
    "StealthEngine",
    "DeviceProfile",
    "DEVICE_PROFILES",
    "BezierMouse",
    "HumanTyping",
    "HoneypotDetector",
    "SensorSimulator",
]

