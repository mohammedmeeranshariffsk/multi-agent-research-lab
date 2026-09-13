from research_agent.collection_models import Candidate, parse_json, prompt

def discover_samples(behavior, client, limit=5):
    return client.generate_grounded(prompt("sample_discovery", {"behavior": behavior, "limit": max(1, min(limit, 5))}))

def parse_candidates(result, limit=5):
    data = parse_json(result.text)
    candidates = []
    seen = set()
    for item in data.get("candidates", [])[:max(1, min(limit, 5))]:
        candidate = Candidate.model_validate(item)
        key = candidate.sha256 or (candidate.package_name, candidate.app_name, candidate.malware_family, candidate.campaign_or_variant, tuple((s.sample_page_url, s.repository_page_url, s.download_page_url) for s in candidate.sample_sources))
        if key not in seen:
            candidates.append(candidate)
            seen.add(key)
    return candidates
