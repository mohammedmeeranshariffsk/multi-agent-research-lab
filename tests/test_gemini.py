from types import SimpleNamespace as NS
from unittest.mock import Mock

import httpx
import pytest
from google import genai
from google.genai import interactions, types

from research_agent.config import settings
from research_agent.llm.gemini import GeminiClient, _parse_interaction
from research_agent.state import RequestBudget


def sdk_response():
    return interactions.Interaction(
        status="completed",
        steps=[
            {"type": "google_search_call", "id": "search-1", "arguments": {"queries": ["Android version", "Android version"]}},
            {"type": "google_search_result", "call_id": "search-1", "result": [{"search_suggestions": "<html>not a citation</html>"}]},
            {"type": "model_output", "content": [
                {"type": "text", "text": "Final answer.", "annotations": [
                    {"type": "url_citation", "url": "https://example.test/report", "title": None},
                    {"type": "url_citation", "url": "https://example.test/report", "title": "Report"},
                    {"type": "url_citation"}]}]},
        ],
    )


@pytest.mark.parametrize("dump", [False, True])
def test_installed_sdk_steps_and_annotations(dump):
    response = sdk_response()
    result = _parse_interaction(response.model_dump() if dump else response)
    assert result.text == "Final answer."
    assert result.sources == [{"title": "Report", "url": "https://example.test/report"}]
    assert result.search_queries == ["Android version"]


def test_output_text_preferred_over_step_text():
    response = sdk_response()
    response.output_text = "Preferred final answer."
    assert _parse_interaction(response).text == "Preferred final answer."


def test_missing_and_malformed_optional_metadata():
    response = NS(output_text="Answer", steps=[
        None, NS(type="google_search_call", arguments=None),
        NS(type="model_output", content=[None, NS(type="text", text=None, annotations=[None])]),
        NS(type="thought", content=[NS(type="text", text="Do not expose thoughts")])])
    result = _parse_interaction(response)
    assert result.text == "Answer" and result.sources == [] and result.search_queries == []


@pytest.mark.parametrize("status", [429, 500, 503, 504])
def test_actual_sdk_transport_has_one_http_attempt(monkeypatch, status):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(status, json={"error": {"code": status, "message": "Synthetic failure", "status": "INTERNAL"}})
    transport_client = httpx.Client(transport=httpx.MockTransport(handler))
    real_constructor = genai.Client
    def constructor(**kwargs):
        assert kwargs["http_options"].retry_options.attempts == 1
        return real_constructor(api_key="offline-test", http_options=types.HttpOptions(
            httpx_client=transport_client, retry_options=types.HttpRetryOptions(attempts=1)))
    monkeypatch.setattr("research_agent.llm.gemini.genai.Client", constructor)
    monkeypatch.setattr(settings, "gemini_research_model", "models/gemma-4-31b-it")
    client = GeminiClient()
    try:
        with pytest.raises(Exception, match="Synthetic failure"):
            client.generate_grounded("test")
        assert len(requests) == 1 and client.budget.used == 1
        assert requests[0].url.path.endswith("/interactions")
    finally:
        client.client.close()


def test_normal_generate_unchanged_and_budget_exhaustion_prevents_grounded_call(monkeypatch):
    monkeypatch.setattr(settings, "gemini_model", "gemini-3.1-flash-lite")
    client = GeminiClient.__new__(GeminiClient)
    client.budget = RequestBudget(1)
    client.client = NS(models=NS(generate_content=Mock(return_value=NS(text="OK"))),
                       interactions=NS(create=Mock()))
    assert client.generate("normal") == "OK"
    client.client.models.generate_content.assert_called_once_with(model="gemini-3.1-flash-lite", contents="normal")
    with pytest.raises(RuntimeError, match="budget exhausted"):
        client.generate_grounded("research")
    client.client.interactions.create.assert_not_called()
