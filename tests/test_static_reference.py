"""Level-1 static-reference policy; offline, metadata only."""
import pytest

from research_agent.agents.dataset_synthesizer import synthesize_static_record
from research_agent.collection_models import (
    Assessment,
    Candidate,
    Claim,
    Investigation,
    Source,
    Validation,
)
from research_agent.reporting import render_static_report

URL = "https://example.test/research/static-analysis"


def reference(kind="package_name", value="com.example.sample"):
    source = Source(url=URL, title="Technical analysis", evidence_category="STATIC_ANALYSIS")
    candidate = Candidate(malware_family="ExampleSpy", **{kind: value})
    claims = [Claim(claim_id=k, kind=k, value=v, evidence_scope="SAMPLE_LEVEL",
                    sources=[source], excerpt="Documented: " + v)
              for k, v in [("malware_family", "ExampleSpy"), (kind, value),
                           ("method", "SmsReceiver.onReceive parses the incoming SMS")]]
    validation = Validation(assessments=[Assessment(
        claim_id=c.claim_id, status="VERIFIED", reason="Supported", supporting_urls=[URL],
        source_excerpt=c.excerpt, identity_match=True) for c in claims])
    return candidate, Investigation(claims=claims), validation


def render(parts, grounded=URL):
    return synthesize_static_record(parts[0], "Android malware", parts[1], parts[2], [{"url": grounded}])


@pytest.mark.parametrize("kind,value", [("package_name", "com.example.sample"),
                                      ("sha256", "a" * 64), ("sha1", "b" * 40), ("md5", "c" * 32)])
def test_supported_identifier_and_static_article_accept_without_acquisition(kind, value):
    result = render(reference(kind, value))
    assert result["benchmark_ready"] and not result["validation"]["analyst_verified"]
    markdown = render_static_report([result], "Android malware")
    assert value in markdown and URL in markdown and "ExampleSpy" in markdown
    assert "acquisition" not in markdown.lower()


def test_completeness_is_deterministic_and_independent_of_model_vote():
    parts = reference()
    parts[2].dataset_decision = "REJECT"
    first, second = render(parts), render(parts)
    assert first == second and first["benchmark_ready"]
    assert first["validation"]["model_decision"] == "REJECT"
    assert "| COMPLETE |" in render_static_report([first], "Android malware")


@pytest.mark.parametrize("matching_source", [True, False])
def test_static_evidence_with_different_wording_requires_source_agreement(matching_source):
    parts = reference()
    claim = next(c for c in parts[1].claims if c.kind == "method")
    assessment = next(a for a in parts[2].assessments if a.claim_id == claim.claim_id)
    claim.excerpt = "The malware uses SmsReceiver.onReceive to parse incoming SMS messages."
    assessment.source_excerpt = "Incoming SMS messages are parsed by SmsReceiver.onReceive."
    assessment.supporting_urls = [URL if matching_source else "https://example.test/other-analysis"]
    assert assessment.source_excerpt not in claim.excerpt
    assert claim.excerpt not in assessment.source_excerpt

    result = render(parts)
    effective = next(c for c in result["claims"] if c["claim_id"] == claim.claim_id)
    assert result["benchmark_ready"] is matching_source
    if matching_source:
        assert effective["evidence_status"] == "VERIFIED"
        assert effective["verified_urls"] == [URL]
        assert result["articles"][0]["findings"] == [claim.value]
    else:
        assert effective["evidence_status"] == "UNVERIFIED"
        assert effective["verified_urls"] == []
        assert result["articles"] == []


@pytest.mark.parametrize("failure", ["news", "no_identifier", "unsupported", "ungrounded",
                                     "missing_excerpt", "missing_validator_excerpt", "contradiction"])
def test_missing_or_unsupported_static_evidence_rejects(failure):
    parts = reference()
    if failure == "news":
        parts[1].claims[-1].sources[0].evidence_category = "FAMILY_CONTEXT"
    elif failure == "no_identifier":
        parts[1].claims = [c for c in parts[1].claims if c.kind != "package_name"]
    elif failure == "unsupported":
        parts[2].assessments[1].status = "UNVERIFIED"
    elif failure == "missing_excerpt":
        parts[1].claims[1].excerpt = " "
    elif failure == "missing_validator_excerpt":
        parts[2].assessments[1].source_excerpt = " "
    elif failure == "contradiction":
        parts[2].assessments[0].status = "CONTRADICTED"
    result = render(parts, "https://example.test/unrelated" if failure == "ungrounded" else URL)
    assert not result["benchmark_ready"]


@pytest.mark.parametrize("kind,value", [("md5", "not-a-hash"), ("sha1", "a" * 32)])
def test_invalid_digest_rejected(kind, value):
    with pytest.raises(ValueError):
        Candidate(**{kind: value})


def test_redirect_cannot_be_a_static_reference():
    parts = reference()
    redirect = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/token"
    for c in parts[1].claims:
        c.sources[0].url = redirect
    for a in parts[2].assessments:
        a.supporting_urls = [redirect]
    result = render(parts, redirect)
    assert not result["benchmark_ready"]
    assert redirect not in render_static_report([result], "Android malware")


def test_actual_resolved_citation_preserves_grounding_for_canonical_article():
    parts = reference()
    redirect = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/token"
    for c in parts[1].claims:
        c.sources[0].url = redirect
    for a in parts[2].assessments:
        a.supporting_urls = [redirect]
    result = synthesize_static_record(parts[0], "Android malware", parts[1], parts[2],
                                      [{"url": URL, "original_url": redirect}])
    assert result["benchmark_ready"]
    report = render_static_report([result], "Android malware")
    assert URL in report and redirect not in report


@pytest.mark.parametrize("mode,status", [("complete", "COMPLETE"), ("partial", "PARTIAL"),
                                       ("discovered", "DISCOVERED")])
def test_report_retains_candidates_with_deterministic_completeness(mode, status):
    parts = reference()
    if mode != "complete":
        parts[2].assessments = []
    if mode == "discovered":
        parts[1].claims = []
    record = render(parts)
    # Visibility does not depend on the legacy compatibility flag.
    record["benchmark_ready"] = False
    report = render_static_report([record], "Android malware")
    assert "ExampleSpy" in report and "com.example.sample" in report
    assert f"| {status} |" in report
    if mode == "partial":
        assert "SmsReceiver.onReceive" in report
        assert all(c["evidence_status"] == "UNVERIFIED" for c in record["claims"])
    if mode == "discovered":
        assert "| — | com.example.sample | — | — | DISCOVERED |" in report


def test_missing_fields_and_internal_errors_are_not_invented_or_leaked():
    record = synthesize_static_record(Candidate(app_name="OnlyName"), "Android malware",
                                      Investigation(), Validation())
    record["audit"]["error"] = {"stage": "investigation", "message": "private stack trace"}
    report = render_static_report([record], "Android malware")
    assert "| OnlyName | — | — | — | — | — | DISCOVERED |" in report
    assert "private stack trace" not in report


@pytest.mark.parametrize("url", ["https://example.test/sample.apk", "https://example.test/sample.ZIP?download=1",
                               "https://example.test/sample%2Eapk",
                               "https://vertexaisearch.cloud.google.com/grounding-api-redirect/token"])
def test_partial_report_never_uses_binary_or_redirect_article(url):
    candidate = Candidate(malware_family="ExampleSpy", analysis_sources=[
        Source(url=url, evidence_category="STATIC_ANALYSIS")])
    record = synthesize_static_record(candidate, "Android malware", Investigation(), Validation())
    report = render_static_report([record], "Android malware")
    assert url not in report
    assert "| — | — | — | — | DISCOVERED |" in report


def test_partial_report_prefers_canonical_grounded_article_and_keeps_audit():
    parts = reference()
    parts[2].assessments = []
    redirect = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/token"
    for claim in parts[1].claims:
        claim.sources[0].url = redirect
    record = synthesize_static_record(parts[0], "Android malware", parts[1], parts[2],
                                      [{"url": URL, "original_url": redirect}])
    report = render_static_report([record], "Android malware")
    assert URL in report and redirect not in report and "| PARTIAL |" in report
    assert record["claims"][0]["sources"][0]["url"] == redirect
    assert record["grounded_sources"][0]["original_url"] == redirect


def test_static_report_escapes_untrusted_cells():
    record = synthesize_static_record(Candidate(app_name="<script>|[click](https://bad.test)"),
                                      "Android malware", Investigation(), Validation())
    report = render_static_report([record], "Android malware")
    assert "<script>" not in report and "&#124;" in report and "[click]" not in report


def test_collected_finding_without_citations_remains_partial():
    parts = reference()
    parts[1].claims[-1].sources = []
    record = render(parts)
    report = render_static_report([record], "Android malware")
    assert "SmsReceiver.onReceive" in report and "| PARTIAL |" in report
    assert record["claims"][-1]["evidence_status"] == "UNVERIFIED"


def test_discovery_article_is_visible_without_implying_investigation():
    candidate = Candidate(malware_family="ExampleSpy", analysis_sources=[
        Source(url=URL, evidence_category="STATIC_ANALYSIS")])
    record = synthesize_static_record(candidate, "Android malware", Investigation(), Validation())
    report = render_static_report([record], "Android malware")
    assert URL in report and "| DISCOVERED |" in report


@pytest.mark.parametrize("failure", ["claim_id", "identity", "scope", "contradiction"])
def test_incomplete_evidence_is_retained_without_upgrading_validation(failure):
    parts = reference()
    assessment = parts[2].assessments[-1]
    if failure == "claim_id":
        assessment.claim_id = "unrelated"
    elif failure == "identity":
        assessment.identity_match = False
    elif failure == "scope":
        assessment.supported_scope = "FAMILY_LEVEL"
    else:
        assessment.status = "CONTRADICTED"
    record = render(parts)
    assert not record["benchmark_ready"] and not record["articles"]
    assert "| PARTIAL |" in render_static_report([record], "Android malware")
