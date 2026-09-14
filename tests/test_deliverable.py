"""Regression coverage for the user-facing table and its acceptance gates."""
import json
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from jsonschema import Draft202012Validator
from research_agent.collection_models import Candidate, SampleCandidate, SampleSource, Validation
from research_agent.agents.dataset_synthesizer import synthesize_record
from research_agent.agents.sample_discovery import parse_candidates
from research_agent.collection_orchestrator import run_collection
from research_agent.llm.gemini import GroundedResult, GeminiClient
from research_agent.sample_normalizer import candidate_to_sample_candidate, normalize_candidates
from research_agent.reporting import render_report
from tests.fixtures.example_banker import fixture, records, BEHAVIOR, HASH, STATIC, DEMO, SANDBOX, ACQUISITION


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline deliverable tests must not open network connections")
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def synth(parts):
    return synthesize_record(parts[0], BEHAVIOR, parts[1], parts[2])


def test_candidate_conversion_preserves_identifiers_and_sources():
    c, investigation, _ = fixture()
    converted = candidate_to_sample_candidate(c, investigation.sample_sources)
    assert converted.family == c.malware_family and converted.variant == c.campaign_or_variant
    assert converted.sha256 == HASH and converted.package_name == c.package_name
    assert converted.app_name == c.app_name and converted.sources == investigation.sample_sources
    assert converted.location_status == "UNVERIFIED"


def test_same_hash_merges_without_losing_partially_overlapping_sources():
    c, inv, _ = fixture()
    first = candidate_to_sample_candidate(c, inv.sample_sources)
    other = first.model_copy(deep=True)
    other.sources[0].repository_page_url = "https://example.test/repository/entry"
    other.sources.append(SampleSource(sample_page_url="https://example.test/tasks/another-provider"))
    result = normalize_candidates([first, other])
    urls = [url for s in result[0].sources for url in (s.sample_page_url, s.repository_page_url, s.download_page_url) if url]
    assert len(result) == 1
    assert set(urls) == {ACQUISITION, "https://example.test/repository/entry", "https://example.test/tasks/another-provider"}
    assert len(urls) == len(set(urls))
    assert first.sources[0].repository_page_url is None


@pytest.mark.parametrize("reverse", [False, True])
def test_conflicting_hashes_and_ambiguous_package_stay_separate(reverse):
    items = [SampleCandidate(sha256=HASH, package_name="com.example.banker"),
             SampleCandidate(package_name="com.example.banker"),
             SampleCandidate(sha256="f" * 64, package_name="com.example.banker")]
    result = normalize_candidates(items[::-1] if reverse else items)
    assert len(result) == 3
    assert {c.sha256 for c in result} == {HASH, None, "f" * 64}


def test_discovery_duplicate_hash_preserves_all_sources():
    c, inv, _ = fixture()
    a, b = c.model_dump(), c.model_dump()
    a["sample_sources"] = [inv.sample_sources[0].model_dump()]
    b["sample_sources"] = [{"sample_page_url": "https://example.test/tasks/another-provider"}]
    result = parse_candidates(GroundedResult(json.dumps({"candidates": [a, b]}), [], []))
    assert len(result) == 1 and len(result[0].sample_sources) == 2
    assert len(result[0].analysis_sources) == 3


def test_complete_synthetic_record_accepts_independently_of_model_vote():
    parts = fixture()
    parts[2].dataset_decision = "REJECT"
    record = synth(parts)
    assert record["benchmark_ready"] and record["validation"]["dataset_decision"] == "ACCEPT"
    assert record["validation"]["model_decision"] == "REJECT"
    assert record["validation"]["sample_location_status"] == "VERIFIED"
    assert record["validation"]["behavior_evidence_strength"] == "HIGH"
    assert record["validation"]["analyst_verified"] is False
    assert record["proof_of_concept"]["behavior_proven"]


def test_family_only_evidence_cannot_prove_behavior():
    parts = fixture()
    for a in parts[2].assessments:
        a.supported_scope = "FAMILY_LEVEL"
    record = synth(parts)
    assert not record["benchmark_ready"] and not record["proof_of_concept"]["behavior_proven"]
    assert all(c["evidence_scope"] == "FAMILY_LEVEL" for c in record["claims"])


def test_permission_alone_cannot_prove_behavior():
    parts = fixture()
    parts[1].claims = [c for c in parts[1].claims if c.kind in {"sha256", "package_name", "permission", "sample_location"}]
    record = synth(parts)
    assert record["validation"]["sample_location_status"] == "VERIFIED"
    assert not record["proof_of_concept"]["behavior_proven"] and not record["benchmark_ready"]


@pytest.mark.parametrize("missing", ["acquisition", "behavior"])
def test_acquisition_and_behavior_independently_required(missing):
    parts = fixture()
    if missing == "acquisition":
        parts[1].sample_sources = []
    else:
        parts[1].claims = [c for c in parts[1].claims if c.kind != "behavior"]
    record = synth(parts)
    assert not record["benchmark_ready"]
    if missing == "acquisition":
        assert record["proof_of_concept"]["behavior_proven"]
        assert record["validation"]["behavior_evidence_strength"] == "HIGH"
    else:
        assert record["validation"]["sample_location_status"] == "VERIFIED"


@pytest.mark.parametrize("claim_id", ["hash", "package", "behavior"])
def test_critical_contradictions_prevent_acceptance(claim_id):
    parts = fixture()
    next(a for a in parts[2].assessments if a.claim_id == claim_id).status = "CONTRADICTED"
    record = synth(parts)
    assert not record["benchmark_ready"] and record["validation"]["rejection_reasons"]


@pytest.mark.parametrize("availability", ["UNKNOWN", "REMOVED", "UNAVAILABLE"])
def test_unavailable_location_rejects(availability):
    parts = fixture()
    parts[1].sample_sources[0].sample_availability = availability
    record = synth(parts)
    assert not record["benchmark_ready"] and not record["sample_sources"]


def test_access_control_is_explicit_in_report():
    parts = fixture()
    parts[1].sample_sources[0].sample_availability = "LOGIN_REQUIRED"
    record = synth(parts)
    assert record["benchmark_ready"]
    assert "login/access required" in render_report([record], BEHAVIOR)


@pytest.mark.parametrize("failure", ["identity", "citation", "behavior_mismatch"])
def test_source_and_candidate_mismatches_do_not_prove_behavior(failure):
    parts = fixture()
    for a in parts[2].assessments:
        if a.claim_id in {"behavior", "runtime"}:
            if failure == "identity":
                a.identity_match = False
            elif failure == "citation":
                a.supporting_urls = ["https://example.test/unrelated-page"]
            else:
                a.behavior_match = False
    assert not synth(parts)["proof_of_concept"]["behavior_proven"]


def test_scope_cannot_be_upgraded_and_relationship_preserved():
    parts = fixture()
    relationship = next(c for c in parts[1].claims if c.kind == "relationship")
    relationship.evidence_scope = "PACKAGE_LEVEL"
    record = synth(parts)
    result = record["proof_of_concept"]["relationships"][0]
    assert result["value"] == relationship.value
    assert result["evidence_scope"] == "PACKAGE_LEVEL" and result["source_urls"] == [DEMO]


def test_unverified_technical_claims_do_not_satisfy_technical_requirement():
    parts = fixture()
    technical_ids = {c.claim_id for c in parts[1].claims if c.kind in {"permission", "component", "method", "api", "relationship"}}
    for a in parts[2].assessments:
        if a.claim_id in technical_ids:
            a.status = "UNVERIFIED"
    assert not synth(parts)["proof_of_concept"]["behavior_proven"]


def test_no_documented_technical_details_caps_strength_at_medium():
    parts = fixture()
    parts[1].claims = [c for c in parts[1].claims if c.kind not in {"permission", "component", "method", "api", "relationship"}]
    record = synth(parts)
    assert record["proof_of_concept"]["behavior_proven"]
    assert record["validation"]["behavior_evidence_strength"] == "MEDIUM"
    assert record["proof_of_concept"]["limitations"]


def test_markdown_includes_acquisition_evidence_types_scope_and_separate_leads():
    report = render_report(records(), BEHAVIOR, synthetic=True)
    table, leads = report.split("## Incomplete or unverified leads")
    assert "| Sample | APK acquisition link | Matching evidence and useful checks |" in table
    assert "SYNTHETIC" in report and "not real samples or research" in report
    for value in ("ExampleBanker", "com.example.banker", HASH, ACQUISITION, STATIC, DEMO, SANDBOX,
                  "Static analysis", "Researcher demonstration / runtime PoC", "Existing sandbox execution", "exact SHA256"):
        assert value in table
    assert "](" + ACQUISITION + ")" in table and "](" + STATIC + ")" in table
    assert "ExampleFamilyLead" not in table and "ExampleFamilyLead" in leads
    assert "Family-only evidence is context" in leads


def test_report_keeps_unknown_evidence_type_out_of_main_table():
    parts = fixture()
    for c in parts[1].claims:
        for source in c.sources:
            source.evidence_category = "UNSPECIFIED"
    report = render_report([synth(parts)], BEHAVIOR)
    assert "No complete, sufficiently supported rows." in report
    assert "No concrete matching evidence with a documented evidence type." in report


def test_report_escapes_untrusted_markdown_cells():
    generated = records()
    generated[0]["sample"]["malware_family"] = "<script>|malware"
    report = render_report(generated, BEHAVIOR, synthetic=True)
    assert "<script>" not in report and "&#124;" in report


class OfflineClient:
    def __init__(self, fail_at=None):
        self.calls = 0
        self.fail_at = fail_at

    def generate_grounded(self, prompt):
        self.budget.consume()
        self.calls += 1
        if self.calls == self.fail_at:
            raise RuntimeError("SYNTHETIC stage failure")
        candidate, investigation, validation = fixture()
        if self.calls == 1:
            second = candidate.model_copy(update={"sha256": "f" * 64})
            text = json.dumps({"candidates": [candidate.model_dump(), second.model_dump()]})
        elif self.calls in {2, 5}:
            text = investigation.model_dump_json()
        elif self.calls in {3, 6}:
            text = '{"sample_sources": []}'
        else:
            text = validation.model_dump_json() + "\nDATASET_DECISION: ACCEPT"
        return GroundedResult(text, [], [])

    def analyze_evidence(self, prompt, evidence):
        self.budget.consume()
        self.calls += 1
        if self.calls == self.fail_at:
            raise RuntimeError("SYNTHETIC stage failure")
        candidate, investigation, validation = fixture()
        return validation.model_dump_json() + "\nDATASET_DECISION: ACCEPT"


@pytest.mark.parametrize("stage,call", [("investigation", 2), ("sample_locator", 3), ("validation", 4)])
def test_stage_failures_preserve_every_rejected_record(tmp_path, stage, call):
    client = OfflineClient(fail_at=call)
    job = run_collection(BEHAVIOR, tmp_path, limit=2, client=client)
    assert len(job["records"]) == 2 and job["requests_used"] == call
    first = json.loads(Path(job["records"][0]).read_text())
    assert first["audit"]["error"]["stage"] == stage
    assert first["validation"]["dataset_decision"] == "REJECT"
    if stage != "investigation":
        assert first["claims"] and first["audit"]["investigation"]
    assert all(not json.loads(Path(p).read_text())["benchmark_ready"] for p in job["records"])


def test_exhausted_budget_preserves_all_candidates_without_more_requests(tmp_path):
    job = run_collection(BEHAVIOR, tmp_path, limit=2, max_requests=1, client=OfflineClient())
    assert job["requests_used"] == 1 and len(job["records"]) == 2
    assert job["rejected"] == 2 and job["accepted"] == 0


def test_offline_pipeline_saves_table_and_detailed_json(tmp_path):
    job = run_collection(BEHAVIOR, tmp_path, limit=1, client=OfflineClient())
    assert job["requests_used"] == 4 and job["accepted"] == 1
    report = Path(job["report"]).read_text(encoding="utf-8")
    assert ACQUISITION in report and STATIC in report
    saved = json.loads(Path(job["records"][0]).read_text())
    assert saved["sample_candidate"]["sha256"] == HASH and saved["proof_of_concept"]["behavior_proven"]


def test_invalid_stage_json_keeps_raw_audit_and_remaining_candidates(tmp_path):
    class InvalidClient(OfflineClient):
        def generate_grounded(self, prompt):
            response = super().generate_grounded(prompt)
            return GroundedResult("SYNTHETIC invalid JSON", [], []) if self.calls == 2 else response
    job = run_collection(BEHAVIOR, tmp_path, limit=2, client=InvalidClient())
    assert len(job["records"]) == 2 and job["requests_used"] == 2
    first = json.loads(Path(job["records"][0]).read_text())
    assert first["audit"]["failed_response"]["text"] == "SYNTHETIC invalid JSON"
    assert first["validation"]["dataset_decision"] == "REJECT"


def test_synthesis_is_deterministic_and_schema_valid():
    a, b = synth(fixture()), synth(fixture())
    assert a == b
    schema = json.loads((Path(__file__).parents[1] / "data/schemas/record.schema.json").read_text())
    validator = Draft202012Validator(schema)
    for record in records():
        validator.validate(json.loads(json.dumps(record)))


def test_sdk_has_one_attempt_and_search_has_no_function_loop(monkeypatch):
    constructor = Mock()
    monkeypatch.setattr("research_agent.llm.gemini.genai.Client", constructor)
    client = GeminiClient()
    assert constructor.call_args.kwargs["http_options"].retry_options.attempts == 1
    constructor.return_value.interactions.create.return_value = SimpleNamespace(output_text="", steps=[])
    client.generate_grounded("SYNTHETIC prompt")
    kwargs = constructor.return_value.interactions.create.call_args.kwargs
    assert kwargs["tools"] == [{"type": "google_search"}]
    assert kwargs["input"] == "SYNTHETIC prompt" and client.budget.used == 1
    constructor.return_value.models.generate_content.assert_not_called()
