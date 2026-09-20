"""Allow the fully mocked test suite to collect without a real API credential."""
import os

os.environ.setdefault("GEMINI_API_KEY", "offline-unit-tests-not-a-real-key")
