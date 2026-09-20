"""SYNTHETIC static-analysis evidence; no real sample or live research."""
from research_agent.collection_models import (
    Assessment,
    Candidate,
    Claim,
    Investigation,
    Source,
    Validation,
)

HASH = "0123456789abcdef" * 4
BEHAVIOR = "SMS / OTP interception"
STATIC = "https://example.test/research/example-banker-static"


def fixture():
    source = Source(title="SYNTHETIC static analysis", url=STATIC, evidence_category="STATIC_ANALYSIS")
    candidate = Candidate(sha256=HASH, package_name="com.example.banker", app_name="ExampleBanker",
                          malware_family="ExampleBanker", evidence_scope="HASH_LEVEL", analysis_sources=[source])
    claims = [Claim(claim_id=kind, kind=kind, value=value, evidence_scope="HASH_LEVEL",
                    sources=[source], excerpt="SYNTHETIC: " + value)
              for kind, value in [("sha256", HASH), ("package_name", "com.example.banker"),
                                  ("malware_family", "ExampleBanker"),
                                  ("method", "ExampleSmsReceiver.onReceive reads incoming message text")]]
    validation = Validation(dataset_decision="ACCEPT", assessments=[
        Assessment(claim_id=c.claim_id, status="VERIFIED", reason="SYNTHETIC fixture assertion",
                   supporting_urls=[STATIC], source_excerpt=c.excerpt, supported_scope="HASH_LEVEL",
                   identity_match=True, matched_identifiers=[HASH, "com.example.banker"]) for c in claims
    ])
    return candidate, Investigation(claims=claims), validation
