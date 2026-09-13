"""Bounded metadata-only collection, separate from architecture review."""
import argparse
import json
from pathlib import Path
from uuid import uuid4
from research_agent.agents.sample_discovery import discover_samples, parse_candidates
from research_agent.agents.evidence_investigator import investigate_candidate
from research_agent.agents.evidence_validator import validate_evidence
from research_agent.agents.sample_locator import locate_sample
from research_agent.agents.dataset_synthesizer import synthesize_record
from research_agent.collection_models import Investigation, Validation, grounded_payload
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
    job = {"behavior": behavior, "records": [], "errors": [], "requests_used": 0, "requests_maximum": max_requests}
    audit_path = root / "candidates" / f"job-{uuid4().hex}.json"
    try:
        discovery = discover_samples(behavior, client, limit)
        job["discovery"] = grounded_payload(discovery)
        candidates = parse_candidates(discovery, limit)
        for candidate in candidates:
            investigation, validation = Investigation(), Validation()
            audit = {}
            try:
                if budget.remaining < 3:
                    raise RuntimeError("Insufficient remaining budget for investigation, locator, and validation")
                investigation, result = investigate_candidate(candidate, behavior, client)
                audit["investigation"] = grounded_payload(result)
                locations, result = locate_sample(candidate, investigation, client)
                investigation.sample_sources.extend(locations)
                audit["sample_locator"] = grounded_payload(result)
                validation, result = validate_evidence(candidate, behavior, investigation, client)
                audit["validator"] = grounded_payload(result)
                record = synthesize_record(candidate, behavior, investigation, validation)
            except Exception as exc:
                job["errors"].append({"type": type(exc).__name__, "message": str(exc)})
                record = synthesize_record(candidate, behavior, investigation, Validation())
                audit["error"] = job["errors"][-1]
            record["audit"] = audit
            folder = "candidates" if record["validation"]["dataset_decision"] == "ACCEPT" else "rejected"
            path = root / folder / (record["record_id"] + ".json")
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            job["records"].append(str(path))
            if job["errors"]:
                break  # Preserve external failures; never keep retrying across candidates.
    except Exception as exc:
        job["errors"].append({"type": type(exc).__name__, "message": str(exc)})
    finally:
        job["requests_used"] = budget.used
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
    print(json.dumps(result, indent=2))
    return 1 if result["errors"] else 0

if __name__ == "__main__":
    raise SystemExit(main())
