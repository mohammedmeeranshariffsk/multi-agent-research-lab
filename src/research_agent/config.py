import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    def __init__(self) -> None:
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        self.gemini_model = os.getenv("GEMINI_MODEL", "")
        self.max_llm_requests = int(os.getenv("MAX_LLM_REQUESTS", "20"))

        if not self.gemini_api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is missing. Add it to your .env file."
            )


settings = Settings()