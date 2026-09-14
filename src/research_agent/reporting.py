"""Small user-facing report; all detailed evidence stays in the JSON."""
import html
from urllib.parse import quote, urlsplit

CATEGORIES = {
    "STATIC_ANALYSIS": "Static analysis",
    "RESEARCHER_DEMONSTRATION": "Researcher demonstration / runtime PoC",
    "SANDBOX_EXECUTION": "Existing sandbox execution",
    "FAMILY_CONTEXT": "Family-level context only",
    "UNSPECIFIED": "Evidence type not documented",
}
SCOPES = {"HASH_LEVEL": "exact SHA256", "SAMPLE_LEVEL": "package/variant",
          "PACKAGE_LEVEL": "package/variant", "FAMILY_LEVEL": "family only"}


def cell(value: str) -> str:
    return html.escape(str(value), quote=False).replace("|", "&#124;").replace("\n", " ")


def link(label: str, url: str) -> str:
    if urlsplit(url).scheme.lower() not in {"http", "https"}:
        return cell(label) + " (invalid URL)"
    return "[" + cell(label).replace("[", "&#91;").replace("]", "&#93;") + "](" + quote(url, safe=":/?=&%#@+~.-_") + ")"


def evidence_checks(record: dict) -> list[str]:
    proof = record.get("proof_of_concept", {})
    result = []
    for group in ("behavior_descriptions", "relationships", "methods", "api_calls", "components", "permissions"):
        for e in proof.get(group, []):
            if e["validation_status"] != "VERIFIED" or e["evidence_scope"] == "FAMILY_LEVEL":
                continue
            categories = [c for c in e.get("evidence_categories", []) if c not in {"UNSPECIFIED", "FAMILY_CONTEXT"}]
            if not categories or not e["source_urls"]:
                continue
            scope = SCOPES[e["evidence_scope"]]
            if scope == "exact SHA256" and not record["sample"].get("sha256"):
                scope = "package/variant"
            citations = ", ".join(link("evidence", u) for u in e["source_urls"])
            result.append(cell(e["value"]) + " — " + " / ".join(CATEGORIES[c] for c in categories)
                          + "; match: " + scope + "; " + citations)
    return result


def render_report(records: list[dict], behavior: str, *, synthetic: bool = False) -> str:
    lines = ["# " + ("SYNTHETIC — " if synthetic else "") + "Android sample references", ""]
    if synthetic:
        lines.extend(["**SYNTHETIC offline fixture. All example.test links and evidence are invented test data, not real samples or research.**", ""])
    lines.extend(["Behavior: " + cell(behavior), "",
                  "Automated evidence checks only; analyst verification remains a manual step.", "",
                  "| Sample | APK acquisition link | Matching evidence and useful checks |",
                  "| --- | --- | --- |"])
    leads = []
    for record in records:
        sample = record["sample"]
        hypothesis = record.get("discovered_candidate", {})
        family = sample.get("malware_family") or hypothesis.get("malware_family") or "Unknown family"
        package = sample.get("package_name") or sample.get("app_name") or "identifier not verified"
        label = cell(family + " — " + package)
        if sample.get("sha256"):
            label += "<br>SHA256: " + cell(sample["sha256"])
        acquisition = []
        for s in record.get("sample_sources", []):
            for key in ("sample_page_url", "repository_page_url", "download_page_url"):
                if s.get(key):
                    access = " (login/access required)" if s["sample_availability"] in {"LOGIN_REQUIRED", "REQUIRES_ACCESS"} else ""
                    acquisition.append(link(s.get("repository_name") or "Sample page", s[key]) + access)
        checks = evidence_checks(record)
        if record.get("benchmark_ready") and record.get("proof_of_concept", {}).get("behavior_proven") and acquisition and checks:
            lines.append("| " + label + " | " + "<br>".join(acquisition) + " | " + "<br>".join(checks[:6]) + " |")
        else:
            reasons = list(record.get("validation", {}).get("rejection_reasons", []))
            if not acquisition:
                reasons.append("No verified acquisition page.")
            if not checks:
                reasons.append("No concrete matching evidence with a documented evidence type.")
            context = ", ".join(link(s.get("title") or "Context", s["url"]) for s in record.get("analysis_sources", [])[:3])
            scope_note = "Family-only evidence is context, not proof for an exact APK. " if any(
                c["evidence_scope"] == "FAMILY_LEVEL" for c in record.get("claims", [])) else ""
            leads.append("- " + cell(family) + ": " + scope_note + cell(" ".join(dict.fromkeys(reasons)))
                         + (" Context: " + context if context else "") + " Record: " + cell(record["record_id"]))
    if not any(line.startswith("| ") and not line.startswith(("| Sample", "| ---")) for line in lines):
        lines.extend(["", "No complete, sufficiently supported rows."])
    lines.extend(["", "## Incomplete or unverified leads", ""])
    lines.extend(leads or ["None."])
    return "\n".join(lines) + "\n"
