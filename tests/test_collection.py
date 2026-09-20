import json
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

from research_agent.agents.evidence_validator import parse_validation, validate_evidence
from research_agent.agents.sample_discovery import candidate_priority, parse_candidates
from research_agent.collection_models import (
    Assessment,
    Candidate,
    Claim,
    Investigation,
    Source,
    Validation,
)
from research_agent.collection_orchestrator import run_collection
from research_agent.config import settings
from research_agent.llm.gemini import GeminiClient, GroundedResult
from research_agent.state import RequestBudget


def make_client(response=None, maximum=12):
    client = GeminiClient.__new__(GeminiClient)
    client.budget = RequestBudget(maximum)
    client.client = NS(interactions=NS(create=Mock(return_value=response)))
    return client

def test_grounding_metadata_and_model(monkeypatch):
    monkeypatch.setattr(settings, "gemini_research_model", "models/gemma-4-31b-it")
    citation = NS(type="url_citation", url="https://example.org/report", title=None)
    response = NS(output_text="ok", steps=[
        NS(type="google_search_call", arguments=NS(queries=["sms", "sms"])),
        NS(type="model_output", content=[NS(type="text", text="ok", annotations=[citation, citation, None])])])
    client = make_client(response)
    result = client.generate_grounded("test")
    assert result.sources == [{"title": "", "url": "https://example.org/report"}]
    assert result.search_queries == ["sms"]
    kwargs = client.client.interactions.create.call_args.kwargs
    assert kwargs == {"model": "gemma-4-31b-it", "input": "test", "tools": [{"type": "google_search"}]}
    assert result.text == "ok" and client.budget.used == 1

@pytest.mark.parametrize("response", [NS(output_text=None), NS(output_text="", steps=None), NS(steps=[NS(type="model_output", content=None)])])
def test_missing_metadata(response):
    result = make_client(response).generate_grounded("test")
    assert result.sources == [] and result.search_queries == [] and result.text == ""

@pytest.mark.parametrize("code, attempts", [(429, 1), (500, 1), (503, 1), (504, 1)])
def test_retry_bounded_and_budgeted(code, attempts):
    error = RuntimeError("external failure")
    error.code = code
    client = make_client()
    client.client.interactions.create.side_effect = error
    with pytest.raises(RuntimeError, match="external failure"):
        client.generate_grounded("test")
    assert client.budget.used == attempts
    assert client.client.interactions.create.call_count == attempts

def test_budget_blocks_retry():
    error = RuntimeError("external failure")
    error.code = 503
    client = make_client(maximum=1)
    client.client.interactions.create.side_effect = error
    with pytest.raises(RuntimeError, match="external failure"):
        client.generate_grounded("test")
    assert client.client.interactions.create.call_count == 1

def test_candidate_limit_and_null():
    result = GroundedResult(json.dumps({"candidates": [{"malware_family": str(i), "sha256": "UNKNOWN"} for i in range(9)]}), [], [])
    candidates = parse_candidates(result, 99)
    assert len(candidates) == 9 and candidates[0].sha256 is None
    with pytest.raises(ValueError):
        Candidate(sha256="invented")


def test_discovery_prioritizes_concrete_candidates_and_pool_exceeds_output_limit():
    result = GroundedResult(json.dumps({"candidates": [
        {"malware_family": "Family only", "evidence_scope": "FAMILY_LEVEL"},
        {"malware_family": "Concrete", "package_name": "com.example.app", "evidence_scope": "SAMPLE_LEVEL"},
        {"malware_family": "Hashed", "sha256": "a" * 64, "evidence_scope": "HASH_LEVEL"},
    ]}), [], [])
    candidates = parse_candidates(result, 10)
    assert [c.malware_family for c in candidates] == ["Hashed", "Concrete", "Family only"]
    assert candidate_priority(candidates[0]) < candidate_priority(candidates[1])

@pytest.mark.parametrize("text", [
    'not json',
    '{"dataset_decision":"MAYBE","assessments":[]}',
    '{"dataset_decision":"ACCEPT","assessments":"not-a-list"}',
    '{"unexpected":"field"}',
])
def test_bad_decisions(text):
    with pytest.raises(ValueError):
        parse_validation(text)

def test_decision():
    assert parse_validation('{"dataset_decision":"ACCEPT","assessments":[]}').dataset_decision == "ACCEPT"


def test_validation_json_does_not_need_legacy_decision_suffix():
    parsed = parse_validation('{"dataset_decision":"REJECT","assessments":[]}')
    assert parsed.dataset_decision == "REJECT"


def test_duplicate_validation_assessments_fail_closed():
    text = json.dumps({"dataset_decision": "ACCEPT", "assessments": [
        {"claim_id": "same", "status": "VERIFIED", "reason": "supported"},
        {"claim_id": "same", "status": "VERIFIED", "reason": "supported"},
    ]})
    with pytest.raises(ValueError, match="duplicate assessments"):
        parse_validation(text)

def test_validator_uses_non_grounded_analysis_with_collected_evidence():
    investigation, _ = fixture_evidence()
    candidate = Candidate(sha256="a" * 64)
    validation_text = '{"dataset_decision":"REJECT","assessments":[]}'
    class AnalysisOnly:
        def __init__(self): self.evidence = None
        def analyze_evidence(self, prompt, evidence):
            self.evidence = evidence
            return validation_text
        def generate_grounded(self, prompt):
            raise AssertionError("validator must not search")
    client = AnalysisOnly()
    result, _ = validate_evidence(candidate, "SMS interception", investigation, client)
    assert result.dataset_decision == "REJECT"
    assert "a" * 64 in client.evidence and "claims" in client.evidence

def fixture_evidence(scope="SAMPLE_LEVEL"):
    source = Source(url="https://example.org/report")
    claims = [Claim(claim_id="hash", kind="sha256", value="a"*64, evidence_scope=scope, sources=[source]), Claim(claim_id="behavior", kind="behavior", value="SMS interception", evidence_scope=scope, sources=[source])]
    validation = Validation(dataset_decision="ACCEPT", assessments=[Assessment(claim_id=c.claim_id, status="VERIFIED", reason="report supports claim", supporting_urls=[c.sources[0].url], source_excerpt="sample evidence") for c in claims])
    return Investigation(claims=claims), validation


def test_collection_saves_and_stops(tmp_path):
    investigation, validation = fixture_evidence()
    responses = iter([GroundedResult(json.dumps({"candidates": [{"sha256":"a"*64}]}), [], []), GroundedResult(investigation.model_dump_json(), [], []), GroundedResult(validation.model_dump_json(), [], [])])
    class Fake:
        def generate_grounded(self, prompt):
            self.budget.consume()
            return next(responses)
        def analyze_evidence(self, prompt, evidence):
            self.budget.consume()
            return next(responses).text
    job = run_collection("SMS interception", tmp_path, client=Fake())
    assert job["requests_used"] == 3 and not job["errors"]
    assert len(job["records"]) == 1
    assert (tmp_path / "android_malware_reference.md").exists()
    assert not (tmp_path / "candidates").exists()
    with pytest.raises(ValueError):
        run_collection("SMS", tmp_path, max_requests=101)

def test_collection_failure_audit(tmp_path):
    class Fake:
        def generate_grounded(self, prompt):
            self.budget.consume()
            raise RuntimeError("503 unavailable")
    job = run_collection("SMS", tmp_path, client=Fake())
    assert job["requests_used"] == 1 and "503" in job["errors"][0]["message"]
    report = tmp_path / "android_malware_reference.md"
    assert report.exists() and "503 unavailable" not in report.read_text(encoding="utf-8")


def test_gemini_validation_requests_json_without_provider_schema(monkeypatch):
    monkeypatch.setattr(settings, "gemini_model", "validation-model")
    client = GeminiClient.__new__(GeminiClient)
    client.budget = RequestBudget(2)
    client.client = NS(models=NS(generate_content=Mock(return_value=NS(
        text='{"dataset_decision":"REJECT","assessments":[]}'
    ))))

    text = client.analyze_evidence("validate", "collected evidence")

    kwargs = client.client.models.generate_content.call_args.kwargs
    assert kwargs["config"].response_mime_type == "application/json"
    assert kwargs["config"].response_schema is None
    assert json.loads(text)["dataset_decision"] == "REJECT"
    assert client.budget.used == 1
