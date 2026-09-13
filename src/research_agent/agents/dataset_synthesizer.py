"""Deterministic synthesis: never generates new facts or makes API calls."""
from hashlib import sha256
import json
from research_agent.collection_models import Candidate

def synthesize_record(candidate, behavior, investigation, validation):
    assessments = {a.claim_id: a for a in validation.assessments}
    evidence = []
    sources = {}
    for claim in investigation.claims:
        a = assessments.get(claim.claim_id)
        urls = {s.url for s in claim.sources}
        supported = bool(a and a.status == "VERIFIED" and claim.value.strip().upper() not in {"", "UNKNOWN", "NULL", "N/A"} and a.source_excerpt and urls.intersection(a.supporting_urls))
        status = a.status if a else "UNVERIFIED"
        if status == "VERIFIED" and not supported:
            status = "UNVERIFIED"
        item = claim.model_dump()
        item["evidence_status"] = status
        evidence.append(item)
        for source in (claim.sources if claim.kind != "sample_location" else []):
            entry = sources.setdefault(source.url, {**source.model_dump(), "supports": []})
            entry["supports"].append(claim.claim_id)
    sample = {k: None for k in ("sha256", "package_name", "app_name", "malware_family", "campaign_or_variant")}
    for key in sample:
        values = {e["value"] for e in evidence if e["kind"] == key and e["evidence_status"] == "VERIFIED" and e["evidence_scope"] == "SAMPLE_LEVEL"}
        if len(values) == 1:
            sample[key] = values.pop()
    sample = {k: v for k, v in Candidate(**sample).model_dump().items() if k in sample}
    proven_behavior = any(e["kind"] == "behavior" and e["evidence_scope"] == "SAMPLE_LEVEL" and e["evidence_status"] == "VERIFIED" for e in evidence)
    sample_sources = []
    seen_locations = set()
    for location in candidate.sample_sources + investigation.sample_sources:
        item = location.model_dump()
        key = json.dumps(item, sort_keys=True)
        if key in seen_locations:
            continue
        seen_locations.add(key)
        location_urls = {item[k] for k in ("sample_page_url", "repository_page_url", "download_page_url") if item[k]}
        matching = [e for e in evidence if e["kind"] == "sample_location" and e["value"] in location_urls and e["evidence_scope"] == "SAMPLE_LEVEL" and e["evidence_status"] == "VERIFIED"]
        item["evidence_status"] = "VERIFIED" if matching else "UNVERIFIED"
        item["supports"] = [e["claim_id"] for e in matching]
        sample_sources.append(item)
    for item in sample_sources:
        item["useful_for_manual_acquisition"] = bool(item["useful_for_manual_acquisition"] and item["evidence_status"] == "VERIFIED" and item["evidence_scope"] in {"HASH_LEVEL", "PACKAGE_LEVEL", "SAMPLE_LEVEL"} and item["sample_availability"] in {"AVAILABLE", "REQUIRES_ACCESS", "LOGIN_REQUIRED"})
    useful = [s for s in sample_sources if s["useful_for_manual_acquisition"]]
    location_status = "VERIFIED" if useful else ("PARTIAL" if sample_sources else "UNVERIFIED")
    sample_sources = useful
    obtainable = bool(useful)
    accepted = validation.dataset_decision == "ACCEPT" and obtainable and proven_behavior
    accepted = accepted and (candidate.sha256 is None or sample["sha256"] is None or candidate.sha256 == sample["sha256"])
    accepted = accepted and not any(e["evidence_status"] == "CONTRADICTED" for e in evidence)
    identity = candidate.sha256 or json.dumps(candidate.model_dump(), sort_keys=True)
    record_id = sha256((identity + "\n" + behavior).encode()).hexdigest()[:24]
    return {
        "record_id": record_id, "schema_version": "1.0", "behavior": behavior,
        "sample": sample, "discovered_candidate": candidate.model_dump(),
        "manifest_evidence": {"permissions": [e for e in evidence if e["kind"] == "permission"], "components": [e for e in evidence if e["kind"] == "component"]},
        "code_evidence": [e for e in evidence if e["kind"] in {"class", "method", "api", "string"}],
        "behavior_relationships": [e for e in evidence if e["kind"] == "relationship"],
        "claims": evidence, "sources": list(sources.values()),
        "analysis_sources": list(sources.values()), "sample_sources": sample_sources,
        "validation": {"dataset_decision": "ACCEPT" if accepted else "REJECT", "evidence_strength": "MEDIUM" if accepted else "LOW", "behavior_evidence_strength": "HIGH" if proven_behavior else "LOW", "sample_location_status": location_status, "analyst_verified": False, "assessments": validation.model_dump()["assessments"], "model_decision": validation.dataset_decision},
    }
