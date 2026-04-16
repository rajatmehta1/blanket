"""Tests for blanketaudit2.llm.embeddings — Embedding provider abstraction."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blanketaudit2.config import EmbeddingProvider, Settings, get_settings
from blanketaudit2.exceptions import LLMError
from blanketaudit2.llm.embeddings import _DEFAULT_MODELS, get_embeddings


# ── Helpers ──────────────────────────────────────────────────


def _make_settings(**emb_overrides) -> Settings:
    get_settings.cache_clear()
    emb = {"provider": "none", "model": "", **emb_overrides}
    return Settings(embedding=emb, llm={"provider": "none"})


# ── Tests ────────────────────────────────────────────────────


class TestGetEmbeddingsNone:
    def test_returns_none_for_provider_none(self):
        with patch("blanketaudit2.llm.embeddings.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(provider="none")
            assert get_embeddings() is None


class TestGetEmbeddingsOpenAI:
    @patch("langchain_openai.OpenAIEmbeddings", autospec=False)
    def test_instantiates_openai_embeddings(self, MockEmb):
        mock_instance = MagicMock()
        MockEmb.return_value = mock_instance

        with patch("blanketaudit2.llm.embeddings.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(
                provider="openai", model="text-embedding-3-small"
            )
            result = get_embeddings()

        MockEmb.assert_called_once()
        assert MockEmb.call_args[1]["model"] == "text-embedding-3-small"
        assert result is mock_instance


class TestGetEmbeddingsOllama:
    def test_instantiates_ollama_embeddings(self):
        MockEmb = MagicMock()
        mock_instance = MagicMock()
        MockEmb.return_value = mock_instance

        mock_module = MagicMock()
        mock_module.OllamaEmbeddings = MockEmb

        with patch("blanketaudit2.llm.embeddings.get_settings") as mock_gs, \
             patch.dict("sys.modules", {"langchain_community": MagicMock(), "langchain_community.embeddings": mock_module}):
            mock_gs.return_value = _make_settings(
                provider="ollama", model="nomic-embed-text"
            )
            result = get_embeddings()

        MockEmb.assert_called_once()
        assert MockEmb.call_args[1]["model"] == "nomic-embed-text"
        assert result is mock_instance


class TestGetEmbeddingsHuggingFace:
    def test_instantiates_huggingface_embeddings(self):
        MockEmb = MagicMock()
        mock_instance = MagicMock()
        MockEmb.return_value = mock_instance

        mock_module = MagicMock()
        mock_module.HuggingFaceEmbeddings = MockEmb

        with patch("blanketaudit2.llm.embeddings.get_settings") as mock_gs, \
             patch.dict("sys.modules", {"langchain_community": MagicMock(), "langchain_community.embeddings": mock_module}):
            mock_gs.return_value = _make_settings(
                provider="huggingface", model="all-MiniLM-L6-v2"
            )
            result = get_embeddings()

        MockEmb.assert_called_once()
        assert MockEmb.call_args[1]["model_name"] == "all-MiniLM-L6-v2"
        assert result is mock_instance


class TestGetEmbeddingsDefaults:
    @patch("langchain_openai.OpenAIEmbeddings", autospec=False)
    def test_empty_model_uses_provider_default(self, MockEmb):
        MockEmb.return_value = MagicMock()
        with patch("blanketaudit2.llm.embeddings.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(provider="openai", model="")
            get_embeddings()

        assert MockEmb.call_args[1]["model"] == _DEFAULT_MODELS[EmbeddingProvider.OPENAI]

    @patch("langchain_openai.OpenAIEmbeddings", autospec=False)
    def test_model_override_takes_precedence(self, MockEmb):
        MockEmb.return_value = MagicMock()
        with patch("blanketaudit2.llm.embeddings.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(
                provider="openai", model="text-embedding-3-small"
            )
            get_embeddings(model_override="text-embedding-3-large")

        assert MockEmb.call_args[1]["model"] == "text-embedding-3-large"


class TestGetEmbeddingsMissingPackage:
    def test_raises_llm_error_on_import_error(self):
        with patch("blanketaudit2.llm.embeddings.get_settings") as mock_gs:
            mock_gs.return_value = _make_settings(provider="openai")

            with patch.dict("sys.modules", {"langchain_openai": None}):
                with pytest.raises(LLMError, match="not installed"):
                    get_embeddings()
