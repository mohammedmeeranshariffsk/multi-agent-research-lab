"""Locate public sample pages; never downloads or analyzes samples."""
from urllib.parse import urlparse
from research_agent.collection_models import Candidate, Investigation, SampleSource, parse_json, prompt, Model

class LocatorOutput(Model):
    sample_sources: list[SampleSource]

def _queries(candidate: Candidate) -> list[str]:
    ids = [candidate.package_name, candidate.malware_family, candidate.app_name, candidate.campaign_or_variant, candidate.sha256]
    ids = [x for x in ids if x]
    queries = [f'"{value}" {suffix}' for value in ids for suffix in ("MalwareBazaar", "ANY.RUN", "Hybrid Analysis", "Joe Sandbox", "APK sample")]
    return queries + [f'site:{domain} "{value}"' for value in ids for domain in ("bazaar.abuse.ch", "any.run", "hybrid-analysis.com", "joesandbox.com")]

def locate_sample(candidate: Candidate, investigation: Investigation, client):
    payload = {"candidate": candidate.model_dump(), "investigation": investigation.model_dump(), "targeted_queries": _queries(candidate), "output_schema": LocatorOutput.model_json_schema()}
    result = client.generate_grounded(prompt("sample_locator", payload))
    try:
        data = LocatorOutput.model_validate(parse_json(result.text))
    except ValueError as exc:
        exc.grounded_result = result
        raise
    grounded = {s["url"] for s in result.sources if s.get("url")}
    locations = []
    seen = set()
    for source in data.sample_sources:
        urls = {u for u in (source.sample_page_url, source.repository_page_url, source.download_page_url) if u}
        urls = {u for u in urls if "vertexaisearch.cloud.google.com/grounding-api-redirect" not in u}
        identifiers = {x.lower() for x in source.matched_identifiers}
        candidate_ids = {x.lower() for x in (candidate.sha256, candidate.package_name) if x}
        if candidate.campaign_or_variant and candidate.campaign_or_variant.lower() in identifiers:
            candidate_ids.update(x.lower() for x in (candidate.app_name, candidate.malware_family) if x)
        concrete = identifiers & candidate_ids
        if not concrete or source.evidence_scope == "FAMILY_LEVEL" or not source.useful_for_manual_acquisition:
            continue
        # LLM URLs are usable only when a grounding chunk corroborates the URL/domain.
        corroborated = {u for u in urls if any(u == g or urlparse(u).hostname == urlparse(g).hostname for g in grounded)
                       and urlparse(u).path.strip("/") and not urlparse(u).path.lower().endswith((".apk", ".zip"))}
        for field in ("sample_page_url", "repository_page_url", "download_page_url"):
            if getattr(source, field) not in corroborated:
                setattr(source, field, None)
        key = tuple(sorted(corroborated))
        if key and key not in seen:
            locations.append(source)
            seen.add(key)
    return locations, result
