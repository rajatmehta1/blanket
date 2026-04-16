"""Tests for blanketaudit2.llm.provider — LLM provider abstraction."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blanketaudit2.config import LLMProvider, Settings, get_settings
from blanketaudit2.exceptions import LLMError
from blanketaudit2.llm.provider import (
    _DEFAULT_COMPLIANCE_MODELS,
    _DEFAULT_MODELS,
    get_llm,
    get_llm_for_agent,
)


# ── Helpers ──────────────────────────────────────────────────


def _make_settings(**llm_overrides) -> Settings:
    """Build a Settings with LLM config overrides."""
    get_settings.cache_clear()
    llm = {"provider": "none", "model": "", "compliance_model": "", **llm_overrides}
    return Settings(llm=llm)


# ── get_llm ──────────────────────────────────────────────────


class TestGetLlmNone:
    def test_returns_none_for_provider_none(self):
        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(provider="none")
            assert get_llm() is None


class TestGetLlmAnthropic:
    @patch("langchain_anthropic.ChatAnthropic", autospec=False)
    def test_instantiates_chat_anthropic(self, MockChatAnthropic):
        mock_instance = MagicMock()
        MockChatAnthropic.return_value = mock_instance

        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(
                provider="anthropic", model="claude-sonnet-4-20250514"
            )
            result = get_llm()

        MockChatAnthropic.assert_called_once()
        call_kwargs = MockChatAnthropic.call_args[1]
        assert call_kwargs["model"] == "claude-sonnet-4-20250514"
        assert call_kwargs["temperature"] == 0.0
        assert result is mock_instance


class TestGetLlmOpenAI:
    @patch("langchain_openai.ChatOpenAI", autospec=False)
    def test_instantiates_chat_openai(self, MockChatOpenAI):
        mock_instance = MagicMock()
        MockChatOpenAI.return_value = mock_instance

        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(provider="openai", model="gpt-4o")
            result = get_llm()

        MockChatOpenAI.assert_called_once()
        assert MockChatOpenAI.call_args[1]["model"] == "gpt-4o"
        assert result is mock_instance


class TestGetLlmOllama:
    def test_instantiates_chat_ollama(self):
        MockChatOllama = MagicMock()
        mock_instance = MagicMock()
        MockChatOllama.return_value = mock_instance

        mock_module = MagicMock()
        mock_module.ChatOllama = MockChatOllama

        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs, \
             patch.dict("sys.modules", {"langchain_community": MagicMock(), "langchain_community.chat_models": mock_module}):
            mock_gs.return_value = _make_settings(provider="ollama", model="llama3.1")
            result = get_llm()

        MockChatOllama.assert_called_once()
        assert MockChatOllama.call_args[1]["model"] == "llama3.1"
        assert result is mock_instance


class TestGetLlmGroq:
    def test_instantiates_chat_groq(self):
        MockChatGroq = MagicMock()
        mock_instance = MagicMock()
        MockChatGroq.return_value = mock_instance

        mock_module = MagicMock()
        mock_module.ChatGroq = MockChatGroq

        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs, \
             patch.dict("sys.modules", {"langchain_groq": mock_module}):
            mock_gs.return_value = _make_settings(
                provider="groq", model="llama-3.1-70b-versatile"
            )
            result = get_llm()

        MockChatGroq.assert_called_once()
        assert result is mock_instance


class TestGetLlmGoogle:
    @patch("langchain_google_genai.ChatGoogleGenerativeAI", autospec=False)
    def test_instantiates_google(self, MockGoogle):
        mock_instance = MagicMock()
        MockGoogle.return_value = mock_instance

        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(
                provider="google", model="gemini-2.0-flash"
            )
            result = get_llm()

        MockGoogle.assert_called_once()
        assert result is mock_instance


class TestGetLlmAzure:
    @patch("langchain_openai.AzureChatOpenAI", autospec=False)
    def test_instantiates_azure(self, MockAzure):
        mock_instance = MagicMock()
        MockAzure.return_value = mock_instance

        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(provider="azure", model="gpt-4o-mini")
            result = get_llm()

        MockAzure.assert_called_once()
        assert result is mock_instance


class TestGetLlmDefaults:
    @patch("langchain_anthropic.ChatAnthropic", autospec=False)
    def test_empty_model_uses_provider_default(self, MockChat):
        MockChat.return_value = MagicMock()
        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(provider="anthropic", model="")
            get_llm()

        assert MockChat.call_args[1]["model"] == _DEFAULT_MODELS[LLMProvider.ANTHROPIC]

    @patch("langchain_anthropic.ChatAnthropic", autospec=False)
    def test_model_override_takes_precedence(self, MockChat):
        MockChat.return_value = MagicMock()
        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(
                provider="anthropic", model="claude-sonnet-4-20250514"
            )
            get_llm(model_override="claude-opus-4-20250514")

        assert MockChat.call_args[1]["model"] == "claude-opus-4-20250514"


class TestGetLlmMissingPackage:
    def test_raises_llm_error_on_import_error(self):
        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(provider="anthropic")

            with patch.dict("sys.modules", {"langchain_anthropic": None}):
                with pytest.raises(LLMError, match="not installed"):
                    get_llm()


# ── get_llm_for_agent ────────────────────────────────────────


class TestGetLlmForAgent:
    @patch("langchain_anthropic.ChatAnthropic", autospec=False)
    def test_compliance_gets_higher_model(self, MockChat):
        MockChat.return_value = MagicMock()
        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(
                provider="anthropic",
                model="claude-sonnet-4-20250514",
                compliance_model="claude-opus-4-20250514",
            )
            get_llm_for_agent("compliance")

        assert MockChat.call_args[1]["model"] == "claude-opus-4-20250514"

    @patch("langchain_anthropic.ChatAnthropic", autospec=False)
    def test_security_gets_standard_model(self, MockChat):
        MockChat.return_value = MagicMock()
        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(
                provider="anthropic",
                model="claude-sonnet-4-20250514",
                compliance_model="claude-opus-4-20250514",
            )
            get_llm_for_agent("security")

        assert MockChat.call_args[1]["model"] == "claude-sonnet-4-20250514"

    @patch("langchain_anthropic.ChatAnthropic", autospec=False)
    def test_agent_model_overrides_takes_precedence(self, MockChat):
        MockChat.return_value = MagicMock()
        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(
                provider="anthropic",
                model="claude-sonnet-4-20250514",
                compliance_model="claude-opus-4-20250514",
                agent_model_overrides={"security": "claude-opus-4-20250514"},
            )
            get_llm_for_agent("security")

        assert MockChat.call_args[1]["model"] == "claude-opus-4-20250514"

    @patch("langchain_anthropic.ChatAnthropic", autospec=False)
    def test_compliance_default_when_compliance_model_empty(self, MockChat):
        MockChat.return_value = MagicMock()
        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(
                provider="anthropic",
                model="claude-sonnet-4-20250514",
                compliance_model="",
            )
            get_llm_for_agent("compliance")

        expected = _DEFAULT_COMPLIANCE_MODELS[LLMProvider.ANTHROPIC]
        assert MockChat.call_args[1]["model"] == expected

    def test_returns_none_for_provider_none(self):
        with patch("blanketaudit2.llm.provider.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(provider="none")
            assert get_llm_for_agent("compliance") is None
            assert get_llm_for_agent("security") is None
