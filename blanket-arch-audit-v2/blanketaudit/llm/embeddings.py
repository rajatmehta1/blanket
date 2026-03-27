"""Embedding provider abstraction — ALL embedding access goes through here.

Use ``get_embeddings()`` everywhere.  Direct imports of provider SDKs outside
this package are forbidden (see CLAUDE.md).
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit.config import EmbeddingProvider, get_settings
from blanketaudit.exceptions import LLMError

logger = structlog.get_logger()

# Default embedding model names when settings.embedding.model is empty.
_DEFAULT_MODELS: dict[EmbeddingProvider, str] = {
    EmbeddingProvider.OPENAI: "text-embedding-3-small",
    EmbeddingProvider.OLLAMA: "nomic-embed-text",
    EmbeddingProvider.HUGGINGFACE: "all-MiniLM-L6-v2",
    EmbeddingProvider.VOYAGE: "voyage-3",
}


def _resolve_model(provider: EmbeddingProvider, model: str) -> str:
    if model:
        return model
    return _DEFAULT_MODELS.get(provider, "")


def get_embeddings(
    *,
    model_override: str | None = None,
    **kwargs: Any,
) -> Any:
    """Return a configured ``Embeddings`` instance, or *None* if provider is ``"none"``.

    Parameters
    ----------
    model_override:
        If provided, overrides ``settings.embedding.model`` and the provider default.
    **kwargs:
        Forwarded to the embedding model constructor.
    """
    settings = get_settings()
    cfg = settings.embedding

    if cfg.provider is EmbeddingProvider.NONE:
        logger.info("embeddings.provider_none", msg="Embedding provider is 'none'; returning None")
        return None

    model = model_override or _resolve_model(cfg.provider, cfg.model)

    logger.info(
        "embeddings.init",
        provider=cfg.provider.value,
        model=model,
    )

    try:
        if cfg.provider is EmbeddingProvider.OPENAI:
            from langchain_openai import OpenAIEmbeddings  # type: ignore[import-untyped]

            return OpenAIEmbeddings(model=model, **kwargs)

        if cfg.provider is EmbeddingProvider.OLLAMA:
            from langchain_community.embeddings import OllamaEmbeddings  # type: ignore[import-untyped]

            return OllamaEmbeddings(model=model, **kwargs)

        if cfg.provider is EmbeddingProvider.HUGGINGFACE:
            from langchain_community.embeddings import HuggingFaceEmbeddings  # type: ignore[import-untyped]

            return HuggingFaceEmbeddings(model_name=model, **kwargs)

        if cfg.provider is EmbeddingProvider.VOYAGE:
            from langchain_community.embeddings import VoyageAIEmbeddings  # type: ignore[import-untyped]

            return VoyageAIEmbeddings(model=model, **kwargs)

    except ImportError as exc:
        raise LLMError(
            f"Embedding package for '{cfg.provider.value}' is not installed. "
            f"Install the corresponding langchain-* package.",
            details={"provider": cfg.provider.value},
        ) from exc

    raise LLMError(
        f"Unsupported embedding provider: {cfg.provider.value}",
        details={"provider": cfg.provider.value},
    )
