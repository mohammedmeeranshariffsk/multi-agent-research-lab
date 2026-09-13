"""Locate public sample pages; never downloads or analyzes samples."""
import json
from urllib.parse import urlparse
from research_agent.collection_models import Candidate, Investigation, SampleSource, parse_json, prompt

def _queries(candidate: Candidate) -> list[str]:
    ids = [candidate.package_name, candidate.malware_family, candidate.app_name, candidate.campaign_or_variant, candidate.sha256]
    ids = [x for x in ids if x]
    queries = [f'"{value}" {suffix}' for value in ids for suffix in ("MalwareBazaar", "ANY.RUN", "Hybrid Analysis", "Joe Sandbox", "APK sample")]
    return queries + [f'site:{domain} "{value}"' for value in ids for domain in ("bazaar.abuse.ch", "any.run", "hybrid-analysis.com", "joesandbox.com")]

def locate_sample(candidate: Candidate, investigation: Investigation, client):
    payload = {"candidate": candidate.model_dump(), "investigation": investigation.model_dump(), "targeted_queries": _queries(candidate), "output_schema": {"sample_sources": [{"sample_page_url": None, "repository_page_url": None, "download_page_url": None, "repository_name": None, "sample_availability": "UNKNOWN", "matched_identifiers": [], "evidence_scope": "SAMPLE_LEVEL", "notes": ""}]}}
    result = client.generate_grounded(prompt("sample_locator", payload))
    data = parse_json(result.text)
    grounded = {s["url"] for s in result.sources if s.get("url")}
    locations = []
    seen = set()
    for raw in data.get("sample_sources", []):
        source = SampleSource.model_validate(raw)
        urls = {u for u in (source.sample_page_url, source.repository_page_url, source.download_page_url) if u}
        urls = {u for u in urls if "vertexaisearch.cloud.google.com/grounding-api-redirect" not in u}
        identifiers = {x.lower() for x in source.matched_identifiers}
        candidate_ids = {x.lower() for x in _queries(candidate) for x in []} | {x.lower() for x in (candidate.sha256, candidate.package_name, candidate.app_name, candidate.campaign_or_variant, candidate.malware_family) if x}
        concrete = identifiers & candidate_ids
        if not concrete or source.evidence_scope == "FAMILY_LEVEL" or not source.useful_for_manual_acquisition:
            continue
        # LLM URLs are usable only when a grounding chunk corroborates the URL/domain.
        if not any(any(u == g or urlparse(u).netloc == urlparse(g).netloc for g in grounded) for u in urls):
            continue
        key = tuple(sorted(urls))
        if key and key not in seen:
            locations.append(source)
            seen.add(key)
    return locations, result
