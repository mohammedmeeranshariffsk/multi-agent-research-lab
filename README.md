# Android sample references and matching evidence

The primary result is a short Markdown table:

| Sample | APK acquisition link | Matching evidence and useful checks |
| --- | --- | --- |
| Family — package, plus SHA256 when documented | Concrete sample page, including access requirements | Clickable evidence, concise documented behavior, evidence type and match scope |

Only complete supported rows appear in the table. Family-only and incomplete leads appear below it with missing-evidence reasons. Detailed JSON preserves hypotheses, citations, independent assessments, effective scope, proof evidence and audit responses.

See the [SYNTHETIC example report](examples/synthetic/report.md) and [example JSON](examples/synthetic/example-banker.json). These are offline fixtures using example.test, not real malware research.

## Run

Install the project and test dependencies with `pip install -e ".[dev]"`. Configure `GEMINI_API_KEY`, `GEMINI_MODEL` and `GEMINI_RESEARCH_MODEL` in your local `.env`. Grounded research uses only Google Search. A job is capped at 12 requests, SDK retries and automatic function loops are disabled, and external failures stop further research while preserving remaining leads.

```powershell
$env:PYTHONPATH = "src"
..\venv\Scripts\python.exe -m research_agent.collection_orchestrator --behavior "SMS / OTP / Notification Interception" --limit 1
```

Pipeline: discovery → candidate parsing/source preservation → investigation → sample location → SampleCandidate conversion/normalization → independent validation → deterministic proof construction → record synthesis → JSON and Markdown.

The normalizer merges compatible hash/package/variant references and retains unique acquisition URLs. Conflicting hashes and ambiguous package-to-multiple-hash references remain separate. Family-only references never serve as an identity merge key. Analysis sources are not acquisition sources.

## Acceptance and evidence

ACCEPT / benchmark-ready requires verified concrete identity, a separately verified usable acquisition page, verified requested behavior linked to the identity, and no critical identity or behavior contradiction. Missing, removed and unavailable acquisition locations reject. Access-controlled locations retain their explicit access status. A model recommendation cannot override these checks.

Scope is HASH_LEVEL > SAMPLE_LEVEL > PACKAGE_LEVEL > FAMILY_LEVEL. Validation may downgrade it, never upgrade it. Proof construction uses exact claim/assessment citation intersections. Explicit mismatches reject support; for legacy assessments without matched identifiers, behavior linkage requires a verified identity claim on the same cited page. Legacy independently verified SAMPLE_LEVEL acquisition claims remain supported; mere locator assertions do not count.

A permission alone never proves behavior. When technical claims are supplied, at least one must be independently verified and linked. If no technical details are documented, concrete verified behavior can be MEDIUM, with an explicit limitation. HIGH additionally requires verified technical evidence and at least two distinct supporting page URLs. This is a corroboration heuristic, not a guarantee of independent confirmation. Otherwise evidence strength is LOW.

The report distinguishes static analysis, researcher demonstration/runtime PoC and existing sandbox execution. It does not guess an evidence type. Unclassified evidence stays in JSON/leads. Family context never becomes proof for an exact APK. Package/variant matching is weaker than exact SHA256 matching.

`analyst_verified` always starts false. Benchmark-ready means eligible for manual benchmark review, not independently reproduced execution.

## Outputs and offline verification

- `data/candidates/`: accepted records awaiting analyst review, job audit JSON and Markdown reports.
- `data/rejected/`: partial/rejected records with reasons and available evidence.
- `data/validated/`: reserved for explicit manual analyst review.
- `data/schemas/record.schema.json`: output schema.

Generate the safe fixture and run the complete tests:

```powershell
$env:PYTHONPATH = "src"
..\venv\Scripts\python.exe -m tests.fixtures.example_banker
..\venv\Scripts\python.exe -m pytest -q
```

The fixture generator makes no model or network calls. Tests mock the research calls; synthetic data must never be represented as live collection.

## Boundaries and limitations

This project records metadata only: it never downloads, opens, executes, decompiles or analyzes APKs. It is not a detector, downloader, emulator or sandbox integration. Existing sandbox reports and public demonstrations are citations only.

Public searches are incomplete. Grounding metadata and independent model assessments do not replace human source review, and provider redirects may prevent canonical URL corroboration. Availability and package-level attribution can change; exact hash links are preferable. A failed discovery response is retained in the job audit. Stage failures after discovery preserve rejected candidates without retry loops.
