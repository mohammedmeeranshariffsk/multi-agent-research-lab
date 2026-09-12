from google import genai

from research_agent.config import settings
from research_agent.state import RequestBudget


class GeminiClient:
    """Small wrapper around the Google Gemini API."""

    def __init__(
        self,
        budget: RequestBudget | None = None,
    ) -> None:
        self.client = genai.Client(
            api_key=settings.gemini_api_key
        )

        self.budget = budget or RequestBudget(
            maximum=settings.max_llm_requests
        )

    def generate(self, prompt: str) -> str:
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