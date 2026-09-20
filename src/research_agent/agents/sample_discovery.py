from research_agent.collection_models import Candidate, Model, parse_json, prompt


class DiscoveryOutput(Model):
    candidates: list[Candidate]


def has_concrete_identity(candidate: Candidate) -> bool:
    return bool(candidate.sha256 or candidate.sha1 or candidate.md5 or candidate.package_name)


def candidate_priority(candidate: Candidate) -> tuple:
    return (
        0 if candidate.sha256 else 1,
        0 if candidate.evidence_scope == "HASH_LEVEL" else 1 if candidate.evidence_scope in {"SAMPLE_LEVEL", "PACKAGE_LEVEL"} else 2,
        0 if candidate.package_name else 1,
        0 if candidate.app_name else 1,
        0 if candidate.campaign_or_variant else 1,
        0 if candidate.analysis_sources else 1,
        (candidate.sha256 or candidate.package_name or candidate.malware_family or "").lower(),
    )

def discover_samples(behavior, client, limit=5):
    return client.generate_grounded(prompt("sample_discovery", {
        "behavior": behavior, "limit": max(1, min(limit, 50)),
        "output_schema": DiscoveryOutput.model_json_schema(),
    }))

def parse_candidates(result, limit=5):
    data = parse_json(result.text)
    if not isinstance(data, dict) or not isinstance(data.get("candidates"), list):
        raise ValueError("discovery must contain a candidates list")  # noqa: TRY004
    candidates = []
    seen = {}
    for item in data.get("candidates", [])[:max(1, min(limit, 50))]:
        try:
            candidate = Candidate.model_validate(item)
        except ValueError:
            continue  # One malformed discovery object must not erase usable candidates.
        key = candidate.sha256 or candidate.sha1 or candidate.md5 or (candidate.package_name, candidate.app_name, candidate.malware_family, candidate.campaign_or_variant)
        if key not in seen:
            candidates.append(candidate)
            seen[key] = candidate
        else:
            existing = seen[key]
            for field in ("sources", "analysis_sources"):
                values = getattr(existing, field)
                for value in getattr(candidate, field):
                    if value not in values:
                        values.append(value)
    return sorted(candidates, key=lambda c: (not has_concrete_identity(c), candidate_priority(c)))
