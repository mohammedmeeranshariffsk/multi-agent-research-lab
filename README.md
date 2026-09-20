# Android Malware Intelligence Reference

Level 1 collects public metadata into `data/android_malware_reference.md`:

| Malware / sample | Malware family | Static-analysis article | Package name | Digest/hash | Static/code findings | Status |
| --- | --- | --- | --- | --- | --- | --- |

## Flow

Discovery → Investigation → Validation → Report.

Discovery requests a bounded candidate pool (up to four candidates for `--limit 1`). Investigation collects available article excerpts, identifiers and static/code findings, including for candidates that initially lack identifiers. Both stages use `GEMINI_RESEARCH_MODEL` with Google Search. Validation uses `GEMINI_MODEL` without browsing. Every usable discovered candidate is retained in the report, including candidates whose investigation or validation failed. One candidate failure does not stop later candidates.

COMPLETE requires a grounded canonical static-analysis article linking a supported family, package or valid SHA256/SHA1/MD5, and meaningful code findings. Existing claim-ID, source-agreement, scope, identity and contradiction checks remain authoritative; different excerpt wording alone does not invalidate evidence. PARTIAL means investigation collected technical sources or findings but completeness checks are not satisfied. DISCOVERED means discovery metadata is available, without useful technical evidence from investigation. Missing fields render as `—`. Metadata outside a complete article is labeled collected or discovered; detailed claims, assessments, source URLs and errors stay in memory. Analyst verification remains manual.

No acquisition link or downloadable APK is required. Sample Locator and the obsolete acquisition/proof pipeline have been removed. No malware is downloaded, installed, executed or decompiled. Article cells exclude grounding redirects and APK/ZIP URLs, preferring resolved canonical citations.

## Run

Install with `pip install -e ".[dev]"`. Configure model names and credentials locally using `.env.example`; never commit credentials.

```powershell
python -m research_agent.collection_orchestrator --behavior "Android malware" --limit 1
```

Run from the repository directory: the output path is relative to the current working directory. `--limit` sizes the discovery pool; it no longer stops processing after a target number of complete rows. Discovery costs one model request, then investigation and validation normally cost two per candidate while budget remains. Candidates that cannot be investigated within the budget still appear with their available metadata. Every API attempt consumes budget. Validation alone has one bounded retry for HTTP 500/502/503/504.

Normal runtime writes only the Markdown report. No candidate/job/audit/proof JSON files are generated. Internal exception details remain in console output and returned records, outside the report. Compatibility counters (`accepted`, `rejected`, `benchmark_ready`) describe completeness checks and do not control report visibility.

## Offline checks

```powershell
python -m pytest -q
python -m ruff check src tests
```

Synthetic fixtures use example.test and are not real malware research.
