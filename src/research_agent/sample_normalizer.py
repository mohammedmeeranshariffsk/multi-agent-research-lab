"""Deterministic normalization and conservative merging of sample references."""
from urllib.parse import urlsplit, urlunsplit
from .collection_models import SampleCandidate, SampleSource

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
    return bool(a.sha256 and b.sha256 and a.sha256.lower() != b.sha256.lower())

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
    sources = list(a.sources)
    seen = {_url(u) for s in sources for u in (s.sample_page_url, s.repository_page_url, s.download_page_url) if u}
    for source in b.sources:
        urls = {_url(u) for u in (source.sample_page_url, source.repository_page_url, source.download_page_url) if u}
        if not urls or not urls & seen:
            sources.append(source)
            seen.update(urls)
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
    result: list[SampleCandidate] = []
    for raw in candidates:
        item = raw if isinstance(raw, SampleCandidate) else SampleCandidate.model_validate(raw)
        item = item.model_copy(update={"identifier_strength": identifier_strength(item)})
        key = candidate_key(item)
        if key is None:
            result.append(item)
            continue
        match = next((i for i, existing in enumerate(result) if _same_sample(existing, item)), None)
        if match is None:
            result.append(item)
        else:
            result[match] = _merge(result[match], item)
    return result
