import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    def __init__(self) -> None:
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        self.gemini_model = os.getenv("GEMINI_MODEL", "")
        self.gemini_research_model = os.getenv("GEMINI_RESEARCH_MODEL", "gemma-4-31b-it")
        self.max_llm_requests = int(os.getenv("MAX_LLM_REQUESTS", "35"))
        self.gemini_timeout_seconds = int(os.getenv("GEMINI_TIMEOUT_SECONDS", "300"))

        if not 1 <= self.max_llm_requests <= 50:
            raise ValueError("MAX_LLM_REQUESTS must be between 1 and 50")
        if not 1 <= self.gemini_timeout_seconds <= 900:
            raise ValueError("GEMINI_TIMEOUT_SECONDS must be between 1 and 900")

        if not self.gemini_api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is missing. Add it to your .env file."
            )


settings = Settings()
