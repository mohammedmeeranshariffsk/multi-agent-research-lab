import pytest

from research_agent.config import Settings


def test_model_roles_and_timeout_are_loaded_from_environment(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "offline-test-key")
    monkeypatch.setenv("GEMINI_MODEL", "validation-model")
    monkeypatch.setenv("GEMINI_RESEARCH_MODEL", "research-model")
    monkeypatch.setenv("GEMINI_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("MAX_LLM_REQUESTS", "31")
    config = Settings()
    assert config.gemini_model == "validation-model"
    assert config.gemini_research_model == "research-model"
    assert config.gemini_timeout_seconds == 45 and config.max_llm_requests == 31


def test_request_budget_defaults_to_35(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "offline-test-key")
    monkeypatch.delenv("MAX_LLM_REQUESTS", raising=False)
    assert Settings().max_llm_requests == 35


def test_timeout_defaults_to_300_seconds(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "offline-test-key")
    monkeypatch.delenv("GEMINI_TIMEOUT_SECONDS", raising=False)
    assert Settings().gemini_timeout_seconds == 300


@pytest.mark.parametrize("name,value", [("MAX_LLM_REQUESTS", "0"), ("MAX_LLM_REQUESTS", "51"),
                                         ("GEMINI_TIMEOUT_SECONDS", "0"), ("GEMINI_TIMEOUT_SECONDS", "901")])
def test_runtime_bounds_reject_invalid_configuration(monkeypatch, name, value):
    monkeypatch.setenv("GEMINI_API_KEY", "offline-test-key")
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        Settings()
