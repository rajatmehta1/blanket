"""LLM provider abstraction — ALL LLM access goes through here.

Every module in the codebase must use ``get_llm()`` or ``get_llm_for_agent()``
to obtain a chat model.  Direct imports of provider SDKs outside this package
are forbidden (see CLAUDE.md).
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit.config import LLMProvider, get_settings
from blanketaudit.exceptions import LLMError

logger = structlog.get_logger()

# Default model names when settings.llm.model is empty.
_DEFAULT_MODELS: dict[LLMProvider, str] = {
    LLMProvider.ANTHROPIC: "claude-sonnet-4-20250514",
    LLMProvider.OPENAI: "gpt-4o-mini",
    LLMProvider.OLLAMA: "llama3.1",
    LLMProvider.GROQ: "llama-3.1-70b-versatile",
    LLMProvider.GOOGLE: "gemini-2.0-flash",
    LLMProvider.AZURE: "gpt-4o-mini",
}

# Higher-capability defaults for the compliance agent (design doc §9.3).
_DEFAULT_COMPLIANCE_MODELS: dict[LLMProvider, str] = {
    LLMProvider.ANTHROPIC: "claude-opus-4-20250514",
    LLMProvider.OPENAI: "gpt-4o",
    LLMProvider.GOOGLE: "gemini-2.5-pro",
}


def _resolve_model(provider: LLMProvider, model: str) -> str:
    """Return *model* if non-empty, otherwise the provider default."""
    if model:
        return model
    return _DEFAULT_MODELS.get(provider, "")


def _build_llm(
    provider: LLMProvider,
    model: str,
    temperature: float,
    max_retries: int,
    timeout: int,
    **extra: Any,
) -> Any:
    """Lazily import the right LangChain class and instantiate it."""
    try:
        if provider is LLMProvider.ANTHROPIC:
            from langchain_anthropic import ChatAnthropic  # type: ignore[import-untyped]

            return ChatAnthropic(
                model=model,
                temperature=temperature,
                max_retries=max_retries,
                timeout=float(timeout),
                **extra,
            )

        if provider is LLMProvider.OPENAI:
            from langchain_openai import ChatOpenAI  # type: ignore[import-untyped]

            return ChatOpenAI(
                model=model,
                temperature=temperature,
                max_retries=max_retries,
                timeout=float(timeout),
                **extra,
            )

        if provider is LLMProvider.OLLAMA:
            from langchain_community.chat_models import ChatOllama  # type: ignore[import-untyped]

            cfg = get_settings().llm
            ollama_kwargs: dict[str, Any] = {
                "model": model,
                "temperature": temperature,
            }
            if cfg.base_url:
                ollama_kwargs["base_url"] = cfg.base_url
            ollama_kwargs.update(extra)
            return ChatOllama(**ollama_kwargs)

        if provider is LLMProvider.GROQ:
            from langchain_groq import ChatGroq  # type: ignore[import-untyped]

            return ChatGroq(
                model=model,
                temperature=temperature,
                max_retries=max_retries,
                timeout=float(timeout),
                **extra,
            )

        if provider is LLMProvider.GOOGLE:
            from langchain_google_genai import ChatGoogleGenerativeAI  # type: ignore[import-untyped]

            return ChatGoogleGenerativeAI(
                model=model,
                temperature=temperature,
                max_retries=max_retries,
                timeout=float(timeout),
                **extra,
            )

        if provider is LLMProvider.AZURE:
            from langchain_openai import AzureChatOpenAI  # type: ignore[import-untyped]

            return AzureChatOpenAI(
                model=model,
                temperature=temperature,
                max_retries=max_retries,
                timeout=float(timeout),
                **extra,
            )

    except ImportError as exc:
        raise LLMError(
            f"Provider package for '{provider.value}' is not installed. "
            f"Install the corresponding langchain-* package.",
            details={"provider": provider.value},
        ) from exc

    raise LLMError(
        f"Unsupported LLM provider: {provider.value}",
        details={"provider": provider.value},
    )


# ── Public API ───────────────────────────────────────────────


def get_llm(
    *,
    model_override: str | None = None,
    **kwargs: Any,
) -> Any:
    """Return a configured ``BaseChatModel``, or *None* if provider is ``"none"``.

    Parameters
    ----------
    model_override:
        If provided, overrides both ``settings.llm.model`` and the provider
        default.  Used by ``get_llm_for_agent`` for per-agent routing.
    **kwargs:
        Forwarded to the LangChain chat model constructor.
    """
    settings = get_settings()
    cfg = settings.llm

    if cfg.provider is LLMProvider.NONE:
        logger.info("llm.provider_none", msg="LLM provider is 'none'; returning None")
        return None

    model = model_override or _resolve_model(cfg.provider, cfg.model)

    logger.info(
        "llm.init",
        provider=cfg.provider.value,
        model=model,
        temperature=cfg.temperature,
    )

    return _build_llm(
        provider=cfg.provider,
        model=model,
        temperature=cfg.temperature,
        max_retries=cfg.max_retries,
        timeout=cfg.timeout_seconds,
        **kwargs,
    )


def get_llm_for_agent(
    agent_name: str,
    **kwargs: Any,
) -> Any:
    """Return a model routed per design doc §9.3.

    Resolution order (first non-empty wins):
    1. ``settings.llm.agent_model_overrides[agent_name]``
    2. ``settings.llm.compliance_model`` (if *agent_name* is ``"compliance"``)
    3. Provider-specific compliance default (if *agent_name* is ``"compliance"``)
    4. ``get_llm()`` (standard model)
    """
    settings = get_settings()
    cfg = settings.llm

    if cfg.provider is LLMProvider.NONE:
        return None

    # 1. Explicit per-agent override
    override = cfg.agent_model_overrides.get(agent_name)
    if override:
        logger.info(
            "llm.agent_override",
            agent=agent_name,
            model=override,
        )
        return get_llm(model_override=override, **kwargs)

    # 2-3. Compliance agent gets a higher-capability model
    if agent_name == "compliance":
        compliance_model = cfg.compliance_model or _DEFAULT_COMPLIANCE_MODELS.get(
            cfg.provider, ""
        )
        if compliance_model:
            logger.info(
                "llm.compliance_model",
                agent=agent_name,
                model=compliance_model,
            )
            return get_llm(model_override=compliance_model, **kwargs)

    # 4. Standard model
    return get_llm(**kwargs)
