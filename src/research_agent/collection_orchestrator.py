"""Bounded metadata-only collection with a simple Markdown result."""
import argparse
import time
from pathlib import Path

from research_agent.agents.dataset_synthesizer import synthesize_static_record
from research_agent.agents.evidence_investigator import investigate_candidate
from research_agent.agents.evidence_validator import validate_evidence
from research_agent.agents.sample_discovery import (
    discover_samples,
    has_concrete_identity,
    parse_candidates,
)
from research_agent.collection_models import (
    Investigation,
    Validation,
    grounded_payload,
)
from research_agent.config import settings
from research_agent.llm.gemini import GeminiClient
from research_agent.progress import ProgressClient, ProgressReporter
from research_agent.reporting import render_static_report, static_record_status
from research_agent.state import RequestBudget

MAX_RESEARCH_REQUESTS = 100


def run_collection(behavior, output_dir="data", limit=5, max_requests=None, client=None):
    if not behavior.strip():
        raise ValueError("behavior must not be empty")
    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    max_requests = settings.max_llm_requests if max_requests is None else max_requests
    if not 1 <= max_requests <= MAX_RESEARCH_REQUESTS:
        raise ValueError("max_requests must be between 1 and 100")
    total_started = time.monotonic()
    budget = RequestBudget(maximum=max_requests)
    base_client = client or GeminiClient(budget)
    base_client.budget = budget
    progress = ProgressReporter(budget, total_stages=3)
    client = ProgressClient(base_client, progress)
    progress.write("[JOB] Starting collection")
    progress.write(f"[JOB] Behavior: {behavior}")
    progress.write(f"[JOB] Candidate limit: {limit}")
    progress.write(f"[JOB] Request budget: 0/{max_requests}")
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    job = {"behavior": behavior, "records": [], "errors": [], "requests_used": 0,
           "requests_maximum": max_requests, "candidates_discovered": 0,
           "enrichment_attempts": 0, "useful_enrichments": 0}
    records = []
    stage = "discovery"
    try:
        with progress.stage(1, "DISCOVERY"):
            pool_limit = min(50, max(limit * 4, limit + 2))
            progress.write(f"  Discovery pool requested: {pool_limit}")
            discovery = discover_samples(behavior, client, pool_limit)
            job["discovery"] = grounded_payload(discovery)
            candidates = parse_candidates(discovery, pool_limit)
        job["candidates_discovered"] = len(candidates)
        progress.write(f"  Candidates found: {len(candidates)}")
        progress.write(f"  Concrete candidates: {sum(has_concrete_identity(c) for c in candidates)}")
        enrichment_attempts = 0
        useful_enrichments = 0
        max_enrichment_attempts = min(len(candidates), limit + 1)
        for candidate in candidates:
            progress.write(f"[SAMPLE] name={candidate.app_name} sha256={candidate.sha256} package={candidate.package_name} scope={candidate.evidence_scope}")
            investigation, validation = Investigation(), Validation()
            audit = {}
            grounded_sources = list(discovery.sources)
            should_enrich = (useful_enrichments < limit
                             and enrichment_attempts < max_enrichment_attempts)
            if should_enrich:
                enrichment_attempts += 1
                try:
                    stage = "budget"
                    if budget.remaining < 2:
                        raise RuntimeError(
                            "Insufficient request budget for investigation and validation"
                        )
                    stage = "investigation"
                    with progress.stage(2, "INVESTIGATION"):
                        investigation, result = investigate_candidate(candidate, behavior, client)
                    audit[stage] = grounded_payload(result)
                    progress.write(f"  Evidence sources: {len(result.sources)}")
                    grounded_sources.extend(result.sources)
                    progress.write(f"  Resolved citations: {sum(bool(s.get('original_url')) for s in grounded_sources)}")
                    stage = "validation"
                    with progress.stage(3, "VALIDATION"):
                        validation, result = validate_evidence(candidate, behavior, investigation, client)
                    audit["validator"] = grounded_payload(result)
                except Exception as exc:  # noqa: BLE001 - Preserve candidate and continue bounded processing.
                    error = {
                        "stage": stage,
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                    job["errors"].append(error)
                    audit["error"] = error

                    if getattr(exc, "grounded_result", None):
                        audit["failed_response"] = grounded_payload(exc.grounded_result)
            else:
                audit["enrichment_skipped"] = "bounded candidate selection"
            progress.write("[REPORT] Checking evidence completeness...")
            record = synthesize_static_record(candidate, behavior, investigation, validation, grounded_sources)
            if "error" in audit:
                reason = audit["error"]["stage"] + ": " + audit["error"]["message"]
                record["validation"]["rejection_reasons"].append(reason)
                record["validation"].update(dataset_decision="REJECT", benchmark_ready=False)
                record["benchmark_ready"] = False
            record["audit"] = audit
            if "error" not in audit and static_record_status(record) != "DISCOVERED":
                useful_enrichments += 1
            progress.write(f"[PROOF] benchmark_ready={record['benchmark_ready']}")
            for reason in record["validation"]["rejection_reasons"]:
                progress.write(f"  Incomplete evidence: {reason}")
            records.append(record)
            job["records"].append(record)
        job["enrichment_attempts"] = enrichment_attempts
        job["useful_enrichments"] = useful_enrichments
    except Exception as exc:  # noqa: BLE001 - Always emit a report when collection fails.
        job["errors"].append({"stage": stage, "type": type(exc).__name__, "message": str(exc)})
    finally:
        job["requests_used"] = budget.used
        job["accepted"] = sum(r["benchmark_ready"] for r in records)
        job["rejected"] = len(records) - job["accepted"]
        job["benchmark_ready"] = job["accepted"]
        report = root / "android_malware_reference.md"
        job["report"] = str(report)
        progress.write(f"[REPORT] Writing: {report}")
        report.write_text(render_static_report(records, behavior, requested_count=limit), encoding="utf-8")
        for error in job["errors"]:
            progress.write(f"[ERROR] {error['stage']}: {error['type']}: {error['message']}")
        progress.write("[DONE]")
        progress.write(f"Requests: {budget.used}/{max_requests}")
        progress.write(f"Total time: {time.monotonic() - total_started:.1f}s")
        progress.write(f"Discovered: {job['candidates_discovered']}")
        progress.write(f"Complete: {job['accepted']}")
        progress.write(f"Incomplete: {job['rejected']}")
        progress.write(f"Benchmark-ready: {job['benchmark_ready']}")
        progress.write(f"Report: {report}")
    return job


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--behavior", default="SMS / OTP / Notification Interception")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--max-requests", type=int, default=settings.max_llm_requests)
    parser.add_argument("--output-dir", default="data")
    args = parser.parse_args()
    result = run_collection(args.behavior, args.output_dir, args.limit, args.max_requests)
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
