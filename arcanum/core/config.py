"""Arcanum Core configuration using pydantic BaseSettings."""

from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings


class ArcanumConfig(BaseSettings):
    """Central configuration for the Arcanum platform."""

    model_config = {"env_prefix": "ARCANUM_"}

    # Ollama / LLM
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3:32b"

    # Sandbox
    sandbox_image: str = "arcanum-sandbox:latest"
    sandbox_timeout: int = 300

    # Data paths
    data_dir: Path = Path.home() / ".arcanum"

    # Web server
    web_port: int = 8000
    web_host: str = "0.0.0.0"

    # LLM context
    max_context_tokens: int = 32000

    # Logging
    log_level: str = "INFO"

    # ------------------------------------------------------------------
    # Derived paths (computed from data_dir)
    # ------------------------------------------------------------------

    @property
    def ops_dir(self) -> Path:
        return self.data_dir / "ops"

    @property
    def stash_db(self) -> Path:
        return self.data_dir / "stash.db"

    @property
    def cve_db(self) -> Path:
        return self.data_dir / "cve.db"

    # ------------------------------------------------------------------
    # Ensure required directories exist on first access
    # ------------------------------------------------------------------

    def model_post_init(self, __context) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.ops_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_config() -> ArcanumConfig:
    """Return the singleton ArcanumConfig instance."""
    return ArcanumConfig()
