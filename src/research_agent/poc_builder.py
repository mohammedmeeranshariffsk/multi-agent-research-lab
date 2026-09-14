"""Deterministic proof checks over collected claims and independent assessments."""
import re
from .collection_models import Candidate, Investigation, Validation, PocEvidence, ProofOfConcept

SCOPE_RANK = {"FAMILY_LEVEL": 0, "PACKAGE_LEVEL": 1, "SAMPLE_LEVEL": 2, "HASH_LEVEL": 3}
IDENTITY_KINDS = {"sha256", "package_name", "app_name", "malware_family", "campaign_or_variant"}
GROUPS = {"permission": "permissions", "component": "components", "class": "classes",
          "api": "api_calls", "method": "methods", "string": "strings",
          "network": "network", "relationship": "relationships", "behavior": "behavior_descriptions"}


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


def verified_identity(candidate: Candidate, claims: list[dict]) -> dict:
    sample = {}
    for kind in sorted(IDENTITY_KINDS):
        values = {c["value"].strip() for c in claims if c["kind"] == kind
                  and c["evidence_status"] == "VERIFIED" and c["evidence_scope"] != "FAMILY_LEVEL"}
        sample[kind] = next(iter(values)) if len(values) == 1 else None
    # Apply the existing hash and unknown-value validation without filling hypotheses.
    try:
        checked = Candidate(**sample)
    except ValueError:
        sample["sha256"] = None
        checked = Candidate(**sample)
    return {key: getattr(checked, key) for key in sorted(IDENTITY_KINDS)}


def identity_linked(claim: dict, candidate: Candidate, claims: list[dict]) -> bool:
    a = claim["assessment"]
    if a.get("identity_match") is False or claim["evidence_scope"] == "FAMILY_LEVEL":
        return False
    identifiers = verified_identity(candidate, claims)
    expected = {str(v).casefold() for v in identifiers.values() if v}
    matched = {v.casefold() for v in a.get("matched_identifiers", [])}
    if matched:
        # An explicit different hash/package must not be rescued by a family match.
        if candidate.sha256 and any(re.fullmatch(r"[a-fA-F0-9]{64}", m)
                                   and m != candidate.sha256.lower() for m in matched):
            return False
        concrete = {str(identifiers[k]).casefold() for k in ("sha256", "package_name")
                    if identifiers[k]}
        if matched & concrete:
            return True
        return bool(identifiers["campaign_or_variant"]
                    and identifiers["campaign_or_variant"].casefold() in matched
                    and matched & {str(identifiers[k]).casefold()
                                   for k in ("app_name", "malware_family") if identifiers[k]})
    # Backward compatibility: an exact cited page verifies both identity and claim.
    identity_urls = {url for c in claims if c["kind"] in {"sha256", "package_name"}
                     and c["evidence_status"] == "VERIFIED" and c["evidence_scope"] != "FAMILY_LEVEL"
                     for url in c["verified_urls"]}
    return bool(expected and identity_urls.intersection(claim["verified_urls"]))


def behavior_matches(value: str, behavior: str) -> bool:
    """Conservative text fallback for old assessments without behavior_match."""
    tokens = lambda text: set(re.findall(r"[a-z0-9]+", text.casefold()))
    requested, documented = tokens(behavior), tokens(value)
    return bool(requested) and requested <= documented


def build_poc(candidate: Candidate, investigation: Investigation, validation: Validation,
              behavior: str) -> ProofOfConcept:
    claims = effective_claims(investigation, validation)
    groups = {name: [] for name in GROUPS.values()}
    proven_claims = []
    verified_technical = []
    supplied_technical = False
    for claim in claims:
        kind = claim["kind"]
        if kind not in GROUPS:
            continue
        linked = identity_linked(claim, candidate, claims)
        status = claim["evidence_status"]
        if status == "VERIFIED" and claim["evidence_scope"] != "FAMILY_LEVEL" and not linked:
            status = "UNVERIFIED"
        urls = claim["verified_urls"] if status == "VERIFIED" else [s["url"] for s in claim["sources"]]
        entry = PocEvidence(
            claim_id=claim["claim_id"], evidence_type="behavior_description" if kind == "behavior" else kind,
            value=claim["value"], class_name=claim["class_name"], method_name=claim["method_name"],
            source_urls=urls, evidence_scope=claim["evidence_scope"], validation_status=status,
            rationale=claim["assessment"].get("reason", "No independent assessment"),
            evidence_categories=sorted({s["evidence_category"] for s in claim["sources"] if s["url"] in urls}),
        )
        groups[GROUPS[kind]].append(entry)
        if kind != "behavior":
            supplied_technical = True
            if status == "VERIFIED" and linked:
                verified_technical.append(entry)
        else:
            matched = claim["assessment"].get("behavior_match")
            matched = behavior_matches(claim["value"], behavior) if matched is None else matched
            if matched and status == "VERIFIED" and linked:
                proven_claims.append(entry)
    critical = any(c["evidence_status"] == "CONTRADICTED"
                   and c["kind"] in IDENTITY_KINDS | {"behavior"} for c in claims)
    proven = bool(proven_claims) and not critical and (not supplied_technical or bool(verified_technical))
    limitations = []
    if not proven_claims:
        limitations.append("No verified requested behavior linked to concrete sample identity.")
    if critical:
        limitations.append("Critical identity or behavior contradiction.")
    if supplied_technical and not verified_technical:
        limitations.append("Supplied technical claims lack verified, sample-linked support.")
    elif not supplied_technical and proven_claims:
        limitations.append("No technical implementation details documented; strength capped at MEDIUM.")
    supporting = sorted({url for e in proven_claims + verified_technical for url in e.source_urls})
    # Two distinct cited pages are a corroboration heuristic, not independent confirmation.
    strength = "HIGH" if proven and verified_technical and len(supporting) >= 2 else ("MEDIUM" if proven else "LOW")
    summary = "; ".join(dict.fromkeys(e.value for e in proven_claims)) if proven else "Behavior not proven for this sample."
    return ProofOfConcept(behavior=behavior, summary=summary, **groups, supporting_sources=supporting,
                          behavior_proven=proven, evidence_strength=strength, limitations=limitations)
