"""Deterministic normalization and conservative merging of sample references."""
from urllib.parse import urlsplit, urlunsplit
from .collection_models import Candidate, SampleCandidate, SampleSource

_STATUS = {"UNVERIFIED": 0, "PARTIAL": 1, "VERIFIED": 2}

def _url(url: str | None) -> str | None:
    if not url:
        return None
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), parts.query, parts.fragment))

def candidate_key(candidate: SampleCandidate):
    if candidate.sha256:
        return ("sha256", candidate.sha256.lower())
    if candidate.package_name:
        return ("package", candidate.package_name.lower())
    if candidate.app_name and candidate.variant:
        return ("app_variant", candidate.app_name.lower(), candidate.variant.lower())
    if candidate.family and candidate.variant:
        return ("family_variant", candidate.family.lower(), candidate.variant.lower())
    return None

def _conflicts(a: SampleCandidate, b: SampleCandidate) -> bool:
    return any(getattr(a, key) and getattr(b, key)
               and getattr(a, key).casefold() != getattr(b, key).casefold()
               for key in ("sha256", "package_name", "variant"))

def _same_sample(a: SampleCandidate, b: SampleCandidate) -> bool:
    if _conflicts(a, b):
        return False
    if a.sha256 and b.sha256:
        return a.sha256.lower() == b.sha256.lower()
    if a.package_name and b.package_name:
        return a.package_name.lower() == b.package_name.lower()
    ka, kb = candidate_key(a), candidate_key(b)
    return ka is not None and ka == kb

def _merge(a: SampleCandidate, b: SampleCandidate) -> SampleCandidate:
    values = {field: getattr(a, field) or getattr(b, field) for field in ("family", "sha256", "package_name", "app_name", "variant")}
    sources = []
    seen = set()
    for source in a.sources + b.sources:
        item = source.model_copy(deep=True)
        for key in ("sample_page_url", "repository_page_url", "download_page_url"):
            url = _url(getattr(item, key))
            setattr(item, key, url if url not in seen else None)
            if url:
                seen.add(url)
        if any(getattr(item, key) for key in ("sample_page_url", "repository_page_url", "download_page_url")):
            sources.append(item)
    status = max((a.location_status, b.location_status), key=lambda x: _STATUS[x])
    merged = SampleCandidate(**values, location_status=status, sources=sources)
    return merged.model_copy(update={"identifier_strength": identifier_strength(merged)})

def identifier_strength(candidate: SampleCandidate) -> str:
    if candidate.sha256: return "SHA256"
    if candidate.package_name: return "PACKAGE_NAME"
    if candidate.app_name and candidate.variant: return "APP_PLUS_VARIANT"
    if candidate.family and candidate.variant: return "FAMILY_PLUS_VARIANT"
    return "FAMILY_ONLY"

def normalize_candidates(candidates: list[SampleCandidate | dict]) -> list[SampleCandidate]:
    inputs = [c if isinstance(c, SampleCandidate) else SampleCandidate.model_validate(c) for c in candidates]
    package_hashes = {}
    for c in inputs:
        if c.package_name and c.sha256:
            package_hashes.setdefault(c.package_name.casefold(), set()).add(c.sha256.lower())
    result: list[SampleCandidate] = []
    for raw in inputs:
        item = raw if isinstance(raw, SampleCandidate) else SampleCandidate.model_validate(raw)
        item = _merge(item.model_copy(update={"sources": []}), item)
        key = candidate_key(item)
        if key is None:
            result.append(item)
            continue
        def matches(existing):
            ambiguous = item.package_name and len(package_hashes.get(item.package_name.casefold(), set())) > 1
            if ambiguous and bool(existing.sha256) != bool(item.sha256):
                return False
            return _same_sample(existing, item)
        match = next((i for i, existing in enumerate(result) if matches(existing)), None)
        if match is None:
            result.append(item)
        else:
            result[match] = _merge(result[match], item)
    return result


def candidate_to_sample_candidate(candidate: Candidate, sources: list[SampleSource]) -> SampleCandidate:
    """Convert collected hypotheses, without promoting location validation."""
    item = SampleCandidate(family=candidate.malware_family, sha256=candidate.sha256,
                           package_name=candidate.package_name, app_name=candidate.app_name,
                           variant=candidate.campaign_or_variant, sources=sources)
    item.identifier_strength = identifier_strength(item)
    return item
