"""Deterministic metadata synthesis; acceptance never comes from a model vote."""
from hashlib import sha256
import json
from urllib.parse import urlsplit
from research_agent.collection_models import Candidate, SampleSource
from research_agent.poc_builder import build_poc, effective_claims, verified_identity, IDENTITY_KINDS, SCOPE_RANK
from research_agent.sample_normalizer import candidate_to_sample_candidate, normalize_candidates


def synthesize_record(candidate, behavior, investigation, validation):
    evidence = effective_claims(investigation, validation)
    sample = verified_identity(candidate, evidence)
    proof = build_poc(candidate, investigation, validation, behavior)
    sources = {}
    for source in candidate.sources + candidate.analysis_sources:
        sources.setdefault(source.url, {**source.model_dump(), "supports": []})
    for claim in evidence:
        if claim["kind"] == "sample_location":
            continue
        for source in claim["sources"]:
            entry = sources.setdefault(source["url"], {**source, "supports": []})
            if claim["claim_id"] not in entry["supports"]:
                entry["supports"].append(claim["claim_id"])

    sample_sources = []
    seen = set()
    concrete_identity = bool(sample["sha256"] or sample["package_name"]
                             or (sample["campaign_or_variant"] and (sample["app_name"] or sample["malware_family"])))
    for location in candidate.sample_sources + investigation.sample_sources:
        item = location.model_dump()
        urls = {item[k] for k in ("sample_page_url", "repository_page_url", "download_page_url") if item[k]}
        # No redirect, generic homepage, or binary URL is an acquisition page.
        safe_urls = {u for u in urls if urlsplit(u).path.strip("/")
                     and "grounding-api-redirect" not in u and not urlsplit(u).path.lower().endswith((".apk", ".zip"))}
        matching = [c for c in evidence if c["kind"] == "sample_location"
                    and c["value"] in safe_urls and c["evidence_scope"] != "FAMILY_LEVEL"
                    and c["evidence_status"] == "VERIFIED"]
        # A validated SAMPLE_LEVEL location assertion is scoped to this investigation.
        # Explicit contrary identifiers or an independent negative assessment override it.
        ids = {v.casefold() for v in item["matched_identifiers"]}
        wrong_hash = bool(sample["sha256"] and any(len(v) == 64 and v != sample["sha256"] for v in ids))
        usable = (concrete_identity and not wrong_hash and bool(matching)
                  and item["useful_for_manual_acquisition"] and item["evidence_scope"] != "FAMILY_LEVEL"
                  and item["sample_availability"] in {"AVAILABLE", "LOGIN_REQUIRED", "REQUIRES_ACCESS"})
        for claim in matching:
            a = claim["assessment"]
            if a.get("matched_identifiers"):
                known = {v.casefold() for v in sample.values() if v}
                usable = usable and bool(known.intersection(v.casefold() for v in a["matched_identifiers"]))
        if not usable:
            continue
        item["evidence_scope"] = min([item["evidence_scope"]] + [c["evidence_scope"] for c in matching], key=SCOPE_RANK.get)
        # Never label package-only identity as an exact hash match.
        if not sample["sha256"] and item["evidence_scope"] == "HASH_LEVEL":
            item["evidence_scope"] = "PACKAGE_LEVEL" if sample["package_name"] else "SAMPLE_LEVEL"
        for key in ("sample_page_url", "repository_page_url", "download_page_url"):
            if item[key] not in safe_urls or item[key] in seen:
                item[key] = None
        remaining = {item[k] for k in ("sample_page_url", "repository_page_url", "download_page_url") if item[k]}
        if not remaining:
            continue
        seen.update(remaining)
        item.update(evidence_status="VERIFIED", supports=[c["claim_id"] for c in matching])
        sample_sources.append(item)
    reasons = []
    if not concrete_identity:
        reasons.append("No independently verified concrete sample identity.")
    if not sample_sources:
        reasons.append("No independently verified, manually usable sample acquisition page.")
    if not proof.behavior_proven:
        reasons.extend(proof.limitations or ["Requested behavior is not proven for this sample."])
    for key in ("sha256", "package_name"):
        proposed, verified = getattr(candidate, key), sample[key]
        if proposed and verified and proposed.casefold() != verified.casefold():
            reasons.append("Discovered and verified " + key + " conflict.")
    if any(c["evidence_status"] == "CONTRADICTED" and c["kind"] in IDENTITY_KINDS | {"behavior"}
           for c in evidence):
        reasons.append("Critical identity or behavior contradiction.")
    accepted = not reasons
    identity = candidate.sha256 or json.dumps({k: getattr(candidate, k) for k in sorted(IDENTITY_KINDS)}, sort_keys=True)
    record_id = sha256((identity + "\n" + behavior).encode()).hexdigest()[:24]
    normalized = normalize_candidates([candidate_to_sample_candidate(
        Candidate(**sample), [SampleSource.model_validate({k: v for k, v in s.items() if k in SampleSource.model_fields})
                              for s in sample_sources])])[0]
    normalized.location_status = "VERIFIED" if sample_sources else "UNVERIFIED"
    return {
        "record_id": record_id, "schema_version": "1.0", "behavior": behavior,
        "sample": sample, "sample_candidate": normalized.model_dump(), "discovered_candidate": candidate.model_dump(),
        "manifest_evidence": {"permissions": [e for e in evidence if e["kind"] == "permission"],
                              "components": [e for e in evidence if e["kind"] == "component"]},
        "code_evidence": [e for e in evidence if e["kind"] in {"class", "method", "api", "string", "network"}],
        "behavior_relationships": [e for e in evidence if e["kind"] == "relationship"],
        "claims": evidence, "sources": list(sources.values()), "analysis_sources": list(sources.values()),
        "sample_sources": sample_sources, "proof_of_concept": proof.model_dump(), "benchmark_ready": accepted,
        "validation": {"dataset_decision": "ACCEPT" if accepted else "REJECT",
                       "evidence_strength": proof.evidence_strength, "behavior_evidence_strength": proof.evidence_strength,
                       "sample_location_status": normalized.location_status, "benchmark_ready": accepted,
                       "analyst_verified": False, "rejection_reasons": list(dict.fromkeys(reasons)),
                       "assessments": validation.model_dump()["assessments"], "model_decision": validation.dataset_decision},
        "audit": {},
    }
