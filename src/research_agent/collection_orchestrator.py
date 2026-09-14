"""Bounded metadata-only collection with a simple Markdown result."""
import argparse
import json
from hashlib import sha256
from pathlib import Path
from uuid import uuid4
from research_agent.agents.sample_discovery import discover_samples, parse_candidates
from research_agent.agents.evidence_investigator import investigate_candidate
from research_agent.agents.evidence_validator import validate_evidence
from research_agent.agents.sample_locator import locate_sample
from research_agent.agents.dataset_synthesizer import synthesize_record
from research_agent.collection_models import Claim, Source, Investigation, Validation, grounded_payload
from research_agent.sample_normalizer import candidate_to_sample_candidate, normalize_candidates
from research_agent.reporting import render_report
from research_agent.llm.gemini import GeminiClient
from research_agent.state import RequestBudget

MAX_RESEARCH_REQUESTS = 12


def run_collection(behavior, output_dir="data", limit=5, max_requests=12, client=None):
    if not behavior.strip():
        raise ValueError("behavior must not be empty")
    if not 1 <= max_requests <= MAX_RESEARCH_REQUESTS:
        raise ValueError("max_requests must be between 1 and 12")
    budget = RequestBudget(maximum=max_requests)
    client = client or GeminiClient(budget)
    client.budget = budget
    root = Path(output_dir)
    for folder in ("schemas", "candidates", "validated", "rejected"):
        (root / folder).mkdir(parents=True, exist_ok=True)
    job = {"behavior": behavior, "records": [], "errors": [], "requests_used": 0,
           "requests_maximum": max_requests, "candidates_discovered": 0}
    audit_path = root / "candidates" / f"job-{uuid4().hex}.json"
    records = []
    stage = "discovery"
    halted = False
    try:
        discovery = discover_samples(behavior, client, limit)
        job["discovery"] = grounded_payload(discovery)
        candidates = parse_candidates(discovery, limit)
        job["candidates_discovered"] = len(candidates)
        for candidate in candidates:
            investigation, validation = Investigation(), Validation()
            audit = {}
            try:
                stage = "budget"
                if halted or budget.remaining < 3:
                    raise RuntimeError("Research stopped or insufficient budget for investigation, locator, and validation")
                stage = "investigation"
                investigation, result = investigate_candidate(candidate, behavior, client)
                audit[stage] = grounded_payload(result)
                stage = "sample_locator"
                locations, result = locate_sample(candidate, investigation, client)
                audit[stage] = grounded_payload(result)
                normalized = normalize_candidates([candidate_to_sample_candidate(
                    candidate, candidate.sample_sources + investigation.sample_sources + locations)])
                investigation.sample_sources = normalized[0].sources
                audit["sample_candidate"] = normalized[0].model_dump()
                # These are hypotheses for the independent validator, never verified facts.
                known = {c.value for c in investigation.claims if c.kind == "sample_location"}
                known_ids = {c.claim_id for c in investigation.claims}
                for location in locations:
                    for url in (location.sample_page_url, location.repository_page_url, location.download_page_url):
                        if not url or url in known:
                            continue
                        claim_id = "locator_" + sha256(url.encode()).hexdigest()[:16]
                        while claim_id in known_ids:
                            claim_id += "_"
                        investigation.claims.append(Claim(
                            claim_id=claim_id, kind="sample_location", value=url,
                            evidence_scope=location.evidence_scope,
                            sources=[Source(url=url)], excerpt=location.notes or None))
                        known.add(url)
                        known_ids.add(claim_id)
                stage = "validation"
                validation, result = validate_evidence(candidate, behavior, investigation, client)
                audit["validator"] = grounded_payload(result)
            except Exception as exc:
                error = {"stage": stage, "type": type(exc).__name__, "message": str(exc)}
                job["errors"].append(error)
                audit["error"] = error
                if getattr(exc, "grounded_result", None):
                    audit["failed_response"] = grounded_payload(exc.grounded_result)
                halted = True  # Still serialize every remaining candidate without more calls.
            record = synthesize_record(candidate, behavior, investigation, validation)
            if "error" in audit:
                reason = audit["error"]["stage"] + ": " + audit["error"]["message"]
                record["validation"]["rejection_reasons"].append(reason)
                record["validation"].update(dataset_decision="REJECT", benchmark_ready=False)
                record["benchmark_ready"] = False
            record["audit"] = audit
            folder = "candidates" if record["benchmark_ready"] else "rejected"
            path = root / folder / (record["record_id"] + ".json")
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            job["records"].append(str(path))
            records.append(record)
    except Exception as exc:
        job["errors"].append({"stage": stage, "type": type(exc).__name__, "message": str(exc)})
    finally:
        job["requests_used"] = budget.used
        job["accepted"] = sum(r["benchmark_ready"] for r in records)
        job["rejected"] = len(records) - job["accepted"]
        job["benchmark_ready"] = job["accepted"]
        report = audit_path.with_suffix(".md")
        job["report"] = str(report)
        report.write_text(render_report(records, behavior), encoding="utf-8")
        audit_path.write_text(json.dumps(job, indent=2), encoding="utf-8")
    return job


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--behavior", default="SMS / OTP / Notification Interception")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--max-requests", type=int, default=12)
    parser.add_argument("--output-dir", default="data")
    args = parser.parse_args()
    result = run_collection(args.behavior, args.output_dir, args.limit, args.max_requests)
    print(f"Behavior: {result['behavior']}\nRequests: {result['requests_used']}/{result['requests_maximum']}\n"
          f"Discovered: {result['candidates_discovered']}; accepted: {result['accepted']}; "
          f"rejected: {result['rejected']}; benchmark-ready: {result['benchmark_ready']}\nReport: {result['report']}")
    for error in result["errors"]:
        print(f"{error['stage']}: {error['type']}: {error['message']}")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
