"""Small user-facing reports; detailed evidence stays in the returned records."""
import html
import re
from urllib.parse import quote, unquote, urlsplit


def cell(value: str) -> str:
    return html.escape(str(value), quote=False).replace("|", "&#124;").replace("\r", " ").replace("\n", " ").replace("[", "&#91;").replace("]", "&#93;")


def metadata_value(articles, claims, candidate, kind):
    if articles:
        value = articles[0].get("identifiers", {}).get(kind)
        if kind == "malware_family":
            value = articles[0]["family"]
        if value:
            return value
    values = [c["value"] for c in claims if c["kind"] == kind
              and c["evidence_status"] != "CONTRADICTED"
              and c["value"].strip().upper() not in {"", "UNKNOWN", "NULL", "N/A"}]
    if kind in {"sha256", "sha1", "md5"}:
        length = {"sha256": 64, "sha1": 40, "md5": 32}[kind]
        values = [v for v in values if re.fullmatch(r"[a-fA-F0-9]{" + str(length) + "}", v)]
    value = candidate.get(kind)
    if values:
        return values[0]
    return value


def static_record_status(record):
    claims = record.get("claims", [])
    grounded = record.get("grounded_sources", [])
    aliases = {s["original_url"]: s["url"] for s in grounded if s.get("original_url")}
    articles = [a for a in record.get("articles", []) if static_article_url(a["url"])]
    findings = [c for c in claims
                if c["kind"] in {"permission", "component", "class", "method", "api", "string", "network", "relationship"}
                and c["value"].strip().upper() not in {"", "UNKNOWN", "NULL", "N/A"}
                and c["evidence_status"] != "CONTRADICTED"]
    investigated_article = any(s.get("evidence_category") == "STATIC_ANALYSIS"
                               and static_article_url(aliases.get(s["url"], s["url"]))
                               for c in claims for s in c["sources"])
    if articles and not record.get("audit", {}).get("error"):
        return "COMPLETE"
    return "PARTIAL" if investigated_article or findings else "DISCOVERED"


def render_static_report(records, behavior, *, requested_count=None):
    status_description = "COMPLETE: supported family, article, identifier and code findings. PARTIAL: collected technical evidence needs further validation or details. DISCOVERED: discovery metadata only; no useful technical evidence established."
    lines = ["# Android Malware Static Analysis Reference", "",
             status_description, "",
             "Incomplete rows may contain unverified collected metadata. Analyst verification remains manual.", "",
             "| Malware / sample | Malware family | Static-analysis article | Package name | Digest/hash | Static/code findings | Status |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for record in records:
        candidate = record.get("discovered_candidate", {})
        claims = sorted(record.get("claims", []), key=lambda c: c["evidence_status"] != "VERIFIED")
        grounded = record.get("grounded_sources", [])
        aliases = {s["original_url"]: s["url"] for s in grounded if s.get("original_url")}
        grounded_urls = {s["url"] for s in grounded}
        articles = [a for a in record.get("articles", []) if static_article_url(a["url"])]
        article = articles[0] if articles else None
        sources = [s for c in claims for s in c["sources"]]
        sources += candidate.get("analysis_sources", []) + candidate.get("sources", [])
        if article is None:
            suitable = [dict(s, url=aliases.get(s["url"], s["url"])) for s in sources
                        if s.get("evidence_category") == "STATIC_ANALYSIS"
                        and static_article_url(aliases.get(s["url"], s["url"]))]
            suitable.sort(key=lambda s: s["url"] not in grounded_urls)
            article = suitable[0] if suitable else None
        findings = [c["value"] for c in claims
                    if c["kind"] in {"permission", "component", "class", "method", "api", "string", "network", "relationship"}
                    and c["value"].strip().upper() not in {"", "UNKNOWN", "NULL", "N/A"}
                    and c["evidence_status"] != "CONTRADICTED"]
        if articles:
            findings = articles[0]["findings"]

        status = static_record_status(record)
        metadata = {kind: metadata_value(articles, claims, candidate, kind) for kind in (
            "app_name", "campaign_or_variant", "malware_family", "package_name", "sha256", "sha1", "md5",
        )}
        name = metadata["app_name"] or metadata["campaign_or_variant"] or metadata["malware_family"]
        hashes = [key.upper() + ": " + metadata[key]
                  for key in ("sha256", "sha1", "md5") if metadata[key]]
        values = [cell(name or "—"), cell(metadata["malware_family"] or "—"),
                  link(article.get("title") or "Static analysis", article["url"]) if article else "—",
                  cell(metadata["package_name"] or "—"), "<br>".join(cell(v) for v in hashes) or "—",
                  "<br>".join(cell(v[:300]) for v in list(dict.fromkeys(findings))[:4]) or "—", status]
        lines.append("| " + " | ".join(values) + " |")
    if not records:
        lines.extend(["", "No candidates discovered."])
    return "\n".join(lines) + "\n"


def static_article_url(url: str) -> bool:
    parsed = urlsplit(url)
    return (parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)
            and "grounding-api-redirect" not in url
            and not unquote(parsed.path).lower().endswith((".apk", ".zip")))


def link(label: str, url: str) -> str:
    if urlsplit(url).scheme.lower() not in {"http", "https"}:
        return cell(label) + " (invalid URL)"
    return "[" + cell(label) + "](" + quote(url, safe=":/?=&%#@+~.-_") + ")"
