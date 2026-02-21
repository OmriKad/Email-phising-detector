"""PydanticAI model adapter for Ollama-compatible model runners."""
from __future__ import annotations

import os
from typing import Any

from app.core.config import Settings


def build_ollama_model(settings: Settings) -> Any:
    """Build a PydanticAI model object configured for Ollama OpenAI-compatible endpoint."""
    base_url = settings.openai_base_url()
    model_name = settings.model_name()
    os.environ.setdefault("OPENAI_BASE_URL", base_url)
    os.environ.setdefault("OPENAI_API_KEY", settings.ollama_api_key)

    try:
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider

        provider = OpenAIProvider(base_url=base_url, api_key=settings.ollama_api_key)
        return OpenAIChatModel(model_name, provider=provider)
    except Exception:
        # Fall back to string model configuration if provider-specific import path changes.
        return f"openai:{model_name}"
