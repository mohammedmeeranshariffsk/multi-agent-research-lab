"""Deterministic metadata synthesis; acceptance never comes from a model vote."""
import re
from urllib.parse import urlsplit

from research_agent.collection_models import Candidate
from research_agent.poc_builder import effective_claims


def synthesize_static_record(candidate, behavior, investigation, validation, grounded_sources=()):
    """Level 1: one grounded article must link family, identifier and static findings."""
    evidence = effective_claims(investigation, validation)
    identifiers = {"sha256", "sha1", "md5", "package_name"}
    technical = {"permission", "component", "class", "method", "api", "string", "network", "relationship"}
    grounded = {s["url"] for s in grounded_sources if s.get("url")}
    aliases = {s["original_url"]: s["url"] for s in grounded_sources if s.get("original_url")}
    articles = {}
    for claim in evidence:
        excerpt = " ".join((claim.get("excerpt") or "").split())
        checked_excerpt = " ".join((claim["assessment"].get("source_excerpt") or "").split())
        if claim["evidence_status"] != "VERIFIED" or not excerpt or not checked_excerpt:
            continue
        for source in claim["sources"]:
            url = aliases.get(source["url"], source["url"])
            if (url not in grounded or source["url"] not in claim["verified_urls"]
                    or "grounding-api-redirect" in url
                    or urlsplit(url).path.lower().endswith((".apk", ".zip"))):
                continue
            article = articles.setdefault(url, {"url": url, "title": source["title"] or url,
                                               "families": set(), "identifiers": {}, "findings": []})
            kind, value = claim["kind"], claim["value"].strip()
            if kind == "malware_family":
                article["families"].add(value)
            if claim["evidence_scope"] == "FAMILY_LEVEL":
                continue
            if kind in identifiers:
                try:
                    normalized = getattr(Candidate(**{kind: value}), kind)
                except ValueError:
                    continue
                if kind == "package_name" and not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", value):
                    continue
                article["identifiers"].setdefault(kind, set()).add(normalized)
            # A bare permission name without technical discussion is insufficient.
            if (kind in technical and source["evidence_category"] == "STATIC_ANALYSIS"
                    and (kind != "permission" or len(excerpt) > len(value) + 20)):
                article["findings"].append(value)
    rows = []
    for article in articles.values():
        if (len(article["families"]) != 1 or not article["identifiers"] or not article["findings"]
                or any(len(values) != 1 for values in article["identifiers"].values())):
            continue
        identity = {key: next(iter(values)) for key, values in article["identifiers"].items()}
        if any(getattr(candidate, key) and getattr(candidate, key).casefold() != value.casefold()
               for key, value in identity.items()):
            continue
        rows.append({"family": next(iter(article["families"])), "url": article["url"],
                     "title": article["title"], "identifiers": identity,
                     "findings": list(dict.fromkeys(article["findings"]))})
    critical = any(c["evidence_status"] == "CONTRADICTED"
                   and c["kind"] in identifiers | technical | {"malware_family"} for c in evidence)
    if critical:
        rows = []
    reasons = [] if rows else ["No grounded static-analysis article verifies family, a package/hash and code-level findings together."]
    if not articles:
        reasons.append("No canonical grounded citation matches the locally validated source excerpts.")
    elif not rows:
        if not any(a["families"] for a in articles.values()):
            reasons.append("Family attribution is not supported by the article evidence.")
        if not any(a["identifiers"] for a in articles.values()):
            reasons.append("No article-supported package or valid digest.")
        if not any(a["findings"] for a in articles.values()):
            reasons.append("No supported static/code-level findings.")
    if critical:
        reasons.append("Critical contradiction in supplied evidence.")
    return {"sample": {"malware_family": rows[0]["family"] if rows else None},
            "discovered_candidate": candidate.model_dump(), "claims": evidence,
            "articles": rows, "grounded_sources": list(grounded_sources),
            "benchmark_ready": bool(rows), "audit": {},
            "validation": {"dataset_decision": "ACCEPT" if rows else "REJECT",
                           "model_decision": validation.dataset_decision,
                           "analyst_verified": False, "rejection_reasons": reasons}}
