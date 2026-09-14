import json
from types import SimpleNamespace as NS
from unittest.mock import Mock
import pytest
from research_agent.llm.gemini import GeminiClient, GroundedResult
from research_agent.config import settings
from research_agent.state import RequestBudget
from research_agent.collection_models import Candidate, Claim, Investigation, Validation, Assessment, Source, SampleSource
from research_agent.agents.sample_discovery import parse_candidates
from research_agent.agents.evidence_validator import parse_validation
from research_agent.agents.evidence_validator import validate_evidence
from research_agent.agents.dataset_synthesizer import synthesize_record
from research_agent.collection_orchestrator import run_collection

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
    assert len(candidates) == 5 and candidates[0].sha256 is None
    with pytest.raises(ValueError):
        Candidate(sha256="invented")

@pytest.mark.parametrize("text", ['{"dataset_decision":"ACCEPT"}', '{"dataset_decision":"ACCEPT"}\nDATASET_DECISION: REJECT', '{}\nDATASET_DECISION: MAYBE'])
def test_bad_decisions(text):
    with pytest.raises(ValueError):
        parse_validation(text)

def test_decision():
    assert parse_validation('{"dataset_decision":"ACCEPT"}\nDATASET_DECISION: ACCEPT').dataset_decision == "ACCEPT"

def test_validator_uses_non_grounded_analysis_with_collected_evidence():
    investigation, _ = fixture_evidence()
    candidate = Candidate(sha256="a" * 64)
    validation_text = '{"dataset_decision":"REJECT"}\nDATASET_DECISION: REJECT'
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
    assert "a" * 64 in client.evidence and "sample_sources" in client.evidence

def fixture_evidence(scope="SAMPLE_LEVEL"):
    source = Source(url="https://example.org/report")
    claims = [Claim(claim_id="hash", kind="sha256", value="a"*64, evidence_scope=scope, sources=[source]), Claim(claim_id="behavior", kind="behavior", value="SMS interception", evidence_scope=scope, sources=[source])]
    claims.append(Claim(claim_id="location", kind="sample_location", value="https://example.org/samples/one", evidence_scope=scope, sources=[Source(url="https://example.org/catalog")]))
    validation = Validation(dataset_decision="ACCEPT", assessments=[Assessment(claim_id=c.claim_id, status="VERIFIED", reason="report supports claim", supporting_urls=[c.sources[0].url], source_excerpt="sample evidence") for c in claims])
    return Investigation(claims=claims, sample_sources=[SampleSource(sample_page_url="https://example.org/samples/one", repository_name="Example catalog", sample_availability="AVAILABLE", matched_identifiers=["a" * 64], evidence_scope="HASH_LEVEL", useful_for_manual_acquisition=True)]), validation

def test_synthesis_serialization_and_manual_gate():
    investigation, validation = fixture_evidence()
    record = synthesize_record(Candidate(sha256="a"*64), "SMS interception", investigation, validation)
    result = json.loads(json.dumps(record))
    assert result["validation"]["dataset_decision"] == "ACCEPT"
    assert result["validation"]["analyst_verified"] is False
    assert result["sample"]["package_name"] is None
    assert len(result["sources"]) == 1
    assert result["sources"][0]["supports"] == ["hash", "behavior"]

@pytest.mark.parametrize("mode", ["family", "missing_source", "mismatch", "contradiction"])
def test_unproven_rejected(mode):
    investigation, validation = fixture_evidence("FAMILY_LEVEL" if mode == "family" else "SAMPLE_LEVEL")
    if mode == "missing_source":
        validation.assessments[1].supporting_urls = []
    if mode == "contradiction":
        validation.assessments[1].status = "CONTRADICTED"
    candidate = Candidate(sha256="b"*64 if mode == "mismatch" else "a"*64)
    record = synthesize_record(candidate, "SMS interception", investigation, validation)
    assert record["validation"]["dataset_decision"] == "REJECT"

def test_collection_saves_and_stops(tmp_path):
    investigation, validation = fixture_evidence()
    responses = iter([GroundedResult(json.dumps({"candidates": [{"sha256":"a"*64}]}), [], []), GroundedResult(investigation.model_dump_json(), [], []), GroundedResult('{"sample_sources": []}', [], []), GroundedResult(validation.model_dump_json()+"\nDATASET_DECISION: ACCEPT", [], [])])
    class Fake:
        def generate_grounded(self, prompt):
            self.budget.consume()
            return next(responses)
        def analyze_evidence(self, prompt, evidence):
            self.budget.consume()
            return next(responses).text
    job = run_collection("SMS interception", tmp_path, client=Fake())
    assert job["requests_used"] == 4 and not job["errors"]
    assert len(job["records"]) == 1
    assert not list((tmp_path / "validated").iterdir())
    with pytest.raises(ValueError):
        run_collection("SMS", tmp_path, max_requests=13)

def test_collection_failure_audit(tmp_path):
    class Fake:
        def generate_grounded(self, prompt):
            self.budget.consume()
            raise RuntimeError("503 unavailable")
    job = run_collection("SMS", tmp_path, client=Fake())
    assert job["requests_used"] == 1 and "503" in job["errors"][0]["message"]
    assert len(list((tmp_path / "candidates").glob("job-*.json"))) == 1


def test_hashless_obtainable_sample_accepted():
    investigation, validation = fixture_evidence()
    investigation.claims[0] = Claim(claim_id="hash", kind="package_name", value="ir.devixor.app", evidence_scope="SAMPLE_LEVEL", sources=[Source(url="https://example.org/report")])
    candidate = Candidate(package_name="ir.devixor.app", analysis_sources=[Source(url="https://example.org/report")])
    record = json.loads(json.dumps(synthesize_record(candidate, "SMS interception", investigation, validation)))
    assert record["sample"]["sha256"] is None
    assert record["sample"]["package_name"] == "ir.devixor.app"
    assert record["validation"]["dataset_decision"] == "ACCEPT"
    assert record["validation"]["analyst_verified"] is False
    assert record["sample_sources"][0]["sample_page_url"] == "https://example.org/samples/one"
    assert record["sample_sources"][0]["repository_name"] == "Example catalog"
    assert record["sample_sources"][0]["evidence_status"] == "VERIFIED"
    assert {s["url"] for s in record["analysis_sources"]} == {"https://example.org/report"}


@pytest.mark.parametrize("mode", ["absent", "unverified", "unrelated", "UNAVAILABLE", "UNKNOWN"])
def test_sample_location_required_even_with_hash(mode):
    investigation, validation = fixture_evidence()
    if mode == "absent":
        investigation.sample_sources = []
    elif mode == "unverified":
        validation.assessments[-1].status = "UNVERIFIED"
    elif mode == "unrelated":
        investigation.sample_sources[0].sample_page_url = "https://example.org/unrelated"
    else:
        investigation.sample_sources[0].sample_availability = mode
    record = synthesize_record(Candidate(sha256="a" * 64), "SMS interception", investigation, validation)
    assert record["validation"]["dataset_decision"] == "REJECT"


def test_sample_location_access_restrictions_and_unknown_fields():
    investigation, validation = fixture_evidence()
    investigation.sample_sources[0].sample_availability = "REQUIRES_ACCESS"
    record = synthesize_record(Candidate(), "SMS interception", investigation, validation)
    assert record["validation"]["dataset_decision"] == "ACCEPT"
    assert record["sample_sources"][0]["sample_availability"] == "REQUIRES_ACCESS"
    unknown = SampleSource(sample_page_url="UNKNOWN", repository_name="UNKNOWN")
    assert unknown.sample_page_url is None and unknown.repository_name is None
    assert unknown.sample_availability == "UNKNOWN"
    with pytest.raises(ValueError):
        SampleSource(download_page_url="file:///sample.apk")


def test_distinct_hashless_sample_pages_are_not_deduplicated():
    payload = {"candidates": [{"malware_family": "Example", "sample_sources": [{"sample_page_url": f"https://example.org/{i}"}]} for i in range(2)]}
    candidates = parse_candidates(GroundedResult(json.dumps(payload), [], []))
    assert len(candidates) == 2
    assert all(c.sha256 is None for c in candidates)
