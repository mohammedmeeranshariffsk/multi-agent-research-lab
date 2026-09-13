from dataclasses import dataclass
import logging

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
        )

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
        response = self.client.models.generate_content(
            model=research_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                tools=[types.Tool(google_search=types.GoogleSearch())],
            ),
        )

        sources: list[dict[str, str]] = []
        search_queries: list[str] = []

        seen_urls: set[str] = set()

        candidates = getattr(
            response,
            "candidates",
            None,
        )

        if candidates:
            candidate = candidates[0]

            metadata = getattr(
                candidate,
                "grounding_metadata",
                None,
            )

            if metadata:
                queries = getattr(
                    metadata,
                    "web_search_queries",
                    None,
                )

                if queries:
                    for query in queries:
                        if query not in search_queries:
                            search_queries.append(query)

                chunks = getattr(
                    metadata,
                    "grounding_chunks",
                    None,
                )

                if chunks:
                    for chunk in chunks:
                        web = getattr(
                            chunk,
                            "web",
                            None,
                        )

                        if not web:
                            continue

                        title = (
                            getattr(
                                web,
                                "title",
                                "",
                            )
                            or ""
                        )

                        url = (
                            getattr(
                                web,
                                "uri",
                                "",
                            )
                            or ""
                        )

                        if not url:
                            continue

                        if url in seen_urls:
                            continue

                        seen_urls.add(url)

                        sources.append(
                            {
                                "title": title,
                                "url": url,
                            }
                        )

        logger.info("[grounded] sources=%d", len(sources))
        return GroundedResult(
            text=response.text or "",
            sources=sources,
            search_queries=search_queries,
        )

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
        )

        return response.text or ""
