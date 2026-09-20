"""Deterministic source agreement and scope checks for collected claims."""
from .collection_models import Investigation, Validation

SCOPE_RANK = {"FAMILY_LEVEL": 0, "PACKAGE_LEVEL": 1, "SAMPLE_LEVEL": 2, "HASH_LEVEL": 3}


def effective_claims(investigation: Investigation, validation: Validation) -> list[dict]:
    """A verifier can downgrade scope; neither a URL domain nor a label is proof."""
    assessments = {a.claim_id: a for a in validation.assessments}
    result = []
    for claim in investigation.claims:
        a = assessments.get(claim.claim_id)
        scope = min((claim.evidence_scope, a.supported_scope or claim.evidence_scope),
                    key=SCOPE_RANK.get) if a else claim.evidence_scope
        urls = sorted({s.url for s in claim.sources} & set(a.supporting_urls if a else []))
        status = a.status if a else "UNVERIFIED"
        if status == "VERIFIED" and (
            not urls or not a.source_excerpt or not a.source_excerpt.strip()
            or claim.value.strip().upper() in {"", "UNKNOWN", "NULL", "N/A"}
            or a.identity_match is False
        ):
            status = "UNVERIFIED"
        result.append({**claim.model_dump(), "evidence_scope": scope,
                       "original_scope": claim.evidence_scope, "evidence_status": status,
                       "verified_urls": urls, "assessment": a.model_dump() if a else {}})
    return result

