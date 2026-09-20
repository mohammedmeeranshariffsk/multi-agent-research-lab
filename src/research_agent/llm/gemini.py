import logging
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from google import genai
from google.genai import types

from research_agent.config import settings
from research_agent.state import RequestBudget

logger = logging.getLogger(__name__)


@dataclass
class GroundedResult:
    text: str
    sources: list[dict[str, str]]
    search_queries: list[str]


class GeminiClient:
    """
    Small wrapper around the Google Gemini / Gemma API.

    Supports:
    - Normal model generation
    - Google Search-grounded generation
    - Request-budget tracking
    - Grounding metadata extraction
    - Source de-duplication
    """

    def __init__(
        self,
        budget: RequestBudget | None = None,
    ) -> None:
        self.client = genai.Client(
            api_key=settings.gemini_api_key,
            http_options=types.HttpOptions(
                timeout=settings.gemini_timeout_seconds * 1000,
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )

        # SDK 2.22's Interactions adapter translates attempts=1 into one
        # additional retry. Disable it before any request is issued.
        self.client.interactions.sdk_configuration.retry_config.strategy = "none"

        self.budget = budget or RequestBudget(
            maximum=settings.max_llm_requests
        )

    def generate(
        self,
        prompt: str,
    ) -> str:
        """
        Normal LLM generation without web grounding.
        """

        if not settings.gemini_model:
            raise RuntimeError(
                "GEMINI_MODEL is not configured in .env"
            )

        self.budget.consume()

        response = self.client.models.generate_content(
            model=settings.gemini_model,
            contents=prompt,
        )

        return response.text or ""

    def generate_grounded(
        self,
        prompt: str,
    ) -> GroundedResult:
        """
        Generate a response using Google Search grounding.

        Important:
        Gemma 4 supports Google Search in our current setup,
        but URL Context is not enabled for this model.

        Therefore this method intentionally uses Google Search only.
        """

        if not settings.gemini_research_model:
            raise RuntimeError("GEMINI_RESEARCH_MODEL is not configured")

        self.budget.consume()
        research_model = settings.gemini_research_model.removeprefix("models/")
        logger.info("[grounded] model=%s", research_model)
        logger.info("[grounded] google_search=true")
        response = self.client.interactions.create(
            model=research_model,
            input=prompt,
            tools=[{"type": "google_search"}],
        )

        result = _parse_interaction(response)
        result.sources = _canonical_sources(result.sources)
        logger.info("[grounded] sources=%d", len(result.sources))
        return result

    def analyze_evidence(
        self,
        prompt: str,
        evidence: str,
    ) -> str:
        """
        Analyze evidence that has already been collected.

        This method does NOT perform web search.

        Useful for:
        - Evidence Investigator
        - Evidence Validator
        - Dataset Synthesizer
        """

        if not settings.gemini_model:
            raise RuntimeError(
                "GEMINI_MODEL is not configured in .env"
            )

        self.budget.consume()
        logger.info("[analysis] model=%s grounded=false", settings.gemini_model)

        full_prompt = f"""
{prompt}

==============================
COLLECTED PUBLIC EVIDENCE
==============================

{evidence}

==============================
END OF EVIDENCE
==============================

Only make claims supported by the supplied evidence.

If information is unavailable, return UNKNOWN or null.

Do not invent:
- malware hashes
- package names
- class names
- method names
- API calls
- permissions
- URLs
- data-flow relationships
"""

        response = self.client.models.generate_content(
            model=settings.gemini_model,
            contents=full_prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
            ),
        )

        return response.text or ""


def _field(value, name, default=None):
    """Support SDK objects as well as model_dump dictionaries."""
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _canonical_sources(sources):
    """Resolve only Google's citation headers; never request the destination page/binary."""
    resolved = {}
    attempts = 0
    opener = build_opener(_NoRedirect())
    for source in sources:
        url = source["url"]
        parsed = urlsplit(url)
        item = dict(source)
        if (parsed.scheme == "https" and parsed.hostname == "vertexaisearch.cloud.google.com"
                and parsed.path.startswith("/grounding-api-redirect/") and not parsed.username
                and attempts < 8):
            attempts += 1
            try:
                response = opener.open(Request(url, method="HEAD"), timeout=3)
                response.close()
            except HTTPError as exc:
                target = exc.headers.get("Location", "")
                exc.close()
                destination = urlsplit(target)
                if (exc.code in {301, 302, 303, 307, 308} and destination.scheme in {"https", "http"}
                        and destination.hostname and not destination.username
                        and destination.hostname != "vertexaisearch.cloud.google.com"
                        and not destination.path.lower().endswith((".apk", ".zip"))):
                    item = {**source, "url": target, "original_url": url}
            except (URLError, TimeoutError, ValueError):
                pass  # An unresolved citation remains unusable for final article proof.
        resolved.setdefault(item["url"], item)
    return list(resolved.values())


def _items(value):
    return value if isinstance(value, (list, tuple)) else []


def _parse_interaction(response) -> GroundedResult:
    # google-genai 2.22: Interaction.steps -> ModelOutputStep.content ->
    # TextContent.annotations -> URLCitation; search queries live in call steps.
    sources: dict[str, dict[str, str]] = {}
    queries: list[str] = []
    text_parts: list[str] = []
    for step in _items(_field(response, "steps")):
        if _field(step, "type") == "google_search_call":
            for query in _items(_field(_field(step, "arguments"), "queries")):
                if isinstance(query, str) and query and query not in queries:
                    queries.append(query)
        if _field(step, "type") != "model_output":
            if _field(step, "type") == "google_search_result":
                _collect_search_sources(_field(step, "result"), sources)
            continue
        for content in _items(_field(step, "content")):
            if _field(content, "type") != "text":
                continue
            text = _field(content, "text")
            if isinstance(text, str) and text:
                text_parts.append(text)
            for annotation in _items(_field(content, "annotations")):
                if _field(annotation, "type") != "url_citation":
                    continue
                url = _field(annotation, "url")
                title = _field(annotation, "title")
                if not isinstance(url, str) or not url.strip():
                    continue
                url = url.strip()
                title = title if isinstance(title, str) else ""
                if url not in sources:
                    sources[url] = {"title": title, "url": url}
                elif not sources[url]["title"] and title:
                    sources[url]["title"] = title
    answer = _field(response, "output_text")
    return GroundedResult(
        text=answer if isinstance(answer, str) and answer else "\n".join(text_parts),
        sources=list(sources.values()),
        search_queries=queries,
    )


def _collect_search_sources(value, sources):
    """Collect URLs only from structured Google Search result records."""
    if not isinstance(value, (dict, list, tuple)) and hasattr(value, "model_dump"):
        value = value.model_dump()
    if isinstance(value, (list, tuple)):
        for item in value:
            _collect_search_sources(item, sources)
        return
    if not isinstance(value, dict):
        return
    url = value.get("url")
    if isinstance(url, str) and url.strip() and "grounding-api-redirect" not in url:
        title = value.get("title")
        entry = {"title": title if isinstance(title, str) else "", "url": url.strip()}
        existing = sources.get(entry["url"])
        if existing is None or (not existing["title"] and entry["title"]):
            sources[entry["url"]] = entry
    for key in ("search_results", "results"):
        _collect_search_sources(value.get(key), sources)
