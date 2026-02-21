"""Application settings."""
from __future__ import annotations

import os
from functools import lru_cache
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Typed runtime settings loaded from environment variables."""

    app_name: str = "Email Phishing Detector"
    app_version: str = "1.0.0"
    schema_version: str = "v1"

    # Compose models short syntax for `phishing-detect` injects these env vars.
    phishing_detect_url: str | None = Field(default=None, alias="PHISHING_DETECT_URL")
    phishing_detect_model: str | None = Field(default=None, alias="PHISHING_DETECT_MODEL")

    ollama_host: str = Field(default="http://host.docker.internal:11434", alias="OLLAMA_HOST")
    ollama_model: str = Field(default="ai/llama3.2", alias="OLLAMA_MODEL")
    ollama_api_key: str = Field(default="ollama", alias="OLLAMA_API_KEY")

    request_timeout_seconds: float = Field(default=20.0, alias="REQUEST_TIMEOUT_SECONDS")
    model_retries: int = Field(default=1, alias="MODEL_RETRIES")
    max_payload_bytes: int = Field(default=500_000, alias="MAX_PAYLOAD_BYTES")

    def model_endpoint(self) -> str:
        """Resolve model endpoint, prioritizing Compose model URL injection."""
        return (self.phishing_detect_url or self.ollama_host).strip()

    def model_name(self) -> str:
        """Resolve model name, prioritizing Compose model injection."""
        return (self.phishing_detect_model or self.ollama_model).strip()

    def openai_base_url(self) -> str:
        """
        Normalize endpoint for OpenAI-compatible clients.

        Compose-injected model URLs may already include `/v1` (or deeper paths ending in `/v1`).
        """
        endpoint = self.model_endpoint().rstrip("/")
        parsed = urlparse(endpoint)
        path = parsed.path.rstrip("/")
        if path.endswith("/v1"):
            return endpoint
        return f"{endpoint}/v1"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached process-level settings."""
    return Settings.model_validate(os.environ)
