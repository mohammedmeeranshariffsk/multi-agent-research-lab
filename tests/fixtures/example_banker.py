"""Safe SYNTHETIC ExampleBanker fixture; no real APK or external research."""
import json
from pathlib import Path
from research_agent.collection_models import Candidate, Claim, Investigation, Validation, Assessment, Source, SampleSource
from research_agent.agents.dataset_synthesizer import synthesize_record
from research_agent.reporting import render_report

HASH = "0123456789abcdef" * 4
BEHAVIOR = "SMS / OTP interception"
STATIC = "https://example.test/research/example-banker-static"
DEMO = "https://example.test/demos/example-banker-runtime"
SANDBOX = "https://example.test/sandbox/reports/example-banker"
ACQUISITION = "https://example.test/samples/" + HASH


def fixture():
    report = Source(title="SYNTHETIC static analysis", url=STATIC, evidence_category="STATIC_ANALYSIS")
    demo = Source(title="SYNTHETIC researcher demonstration", url=DEMO, evidence_category="RESEARCHER_DEMONSTRATION")
    sandbox = Source(title="SYNTHETIC existing sandbox report", url=SANDBOX, evidence_category="SANDBOX_EXECUTION")
    location = SampleSource(sample_page_url=ACQUISITION, repository_name="SYNTHETIC sample catalog",
                            sample_availability="AVAILABLE", matched_identifiers=[HASH, "com.example.banker"],
                            evidence_scope="HASH_LEVEL", useful_for_manual_acquisition=True,
                            notes="SYNTHETIC exact-hash entry; no real sample exists.")
    candidate = Candidate(sha256=HASH, package_name="com.example.banker", app_name="ExampleBanker",
                          malware_family="ExampleBanker", campaign_or_variant="1.0",
                          evidence_scope="HASH_LEVEL", analysis_sources=[report, demo, sandbox])
    specs = [
        ("hash", "sha256", HASH, report),
        ("package", "package_name", "com.example.banker", report),
        ("family", "malware_family", "ExampleBanker", report),
        ("app", "app_name", "ExampleBanker", report),
        ("variant", "campaign_or_variant", "1.0", report),
        ("behavior", "behavior", "SMS / OTP interception: incoming messages are read", report),
        ("permission", "permission", "android.permission.RECEIVE_SMS", report),
        ("receiver", "component", "ExampleSmsReceiver handles SMS_RECEIVED", report),
        ("method", "method", "ExampleSmsReceiver.onReceive reads incoming message text", report),
        ("api", "api", "SmsMessage.getMessageBody", report),
        ("relationship", "relationship", "ExampleSmsReceiver.onReceive reads message text via SmsMessage.getMessageBody", demo),
        ("runtime", "behavior", "SMS / OTP interception observed in an existing sandbox report", sandbox),
        ("location", "sample_location", ACQUISITION, Source(url=ACQUISITION, title="SYNTHETIC catalog entry")),
    ]
    claims = [Claim(claim_id=id_, kind=kind, value=value, evidence_scope="HASH_LEVEL",
                    sources=[source], excerpt="SYNTHETIC: " + value) for id_, kind, value, source in specs]
    claims[8].class_name = "ExampleSmsReceiver"
    claims[8].method_name = "onReceive"
    validation = Validation(dataset_decision="ACCEPT", assessments=[
        Assessment(claim_id=c.claim_id, status="VERIFIED", reason="SYNTHETIC offline fixture assertion; not live verification.",
                   supporting_urls=[c.sources[0].url], source_excerpt=c.excerpt, supported_scope="HASH_LEVEL",
                   identity_match=True, matched_identifiers=[HASH, "com.example.banker"],
                   behavior_match=True if c.kind == "behavior" else None) for c in claims
    ])
    return candidate, Investigation(claims=claims, sample_sources=[location]), validation


def records():
    candidate, investigation, validation = fixture()
    accepted = synthesize_record(candidate, BEHAVIOR, investigation, validation)
    accepted["audit"]["synthetic"] = True
    accepted["audit"]["notice"] = "SYNTHETIC example.test metadata. Not a real malware sample or live research."
    weak_candidate = Candidate(malware_family="ExampleFamilyLead")
    context = Source(url="https://example.test/research/family-context",
                     title="SYNTHETIC family context", evidence_category="FAMILY_CONTEXT")
    weak = Investigation(claims=[Claim(claim_id="family_context", kind="behavior",
                                      value=BEHAVIOR, evidence_scope="FAMILY_LEVEL", sources=[context])])
    assessment = Validation(assessments=[Assessment(claim_id="family_context", status="VERIFIED",
                              reason="Family context only.", source_excerpt="SYNTHETIC family claim",
                              supported_scope="FAMILY_LEVEL", supporting_urls=[context.url])])
    rejected = synthesize_record(weak_candidate, BEHAVIOR, weak, assessment)
    rejected["audit"]["synthetic"] = True
    return [accepted, rejected]


def main():
    output = Path("examples/synthetic")
    output.mkdir(parents=True, exist_ok=True)
    generated = records()
    for record in generated:
        name = "example-banker.json" if record["benchmark_ready"] else "incomplete-lead.json"
        (output / name).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (output / "report.md").write_text(render_report(generated, BEHAVIOR, synthetic=True), encoding="utf-8")
    print("Generated SYNTHETIC report: " + str(output / "report.md"))


if __name__ == "__main__":
    main()
