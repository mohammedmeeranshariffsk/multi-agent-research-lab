import json
from research_agent.llm.gemini import GroundedResult, GeminiClient
from research_agent.config import settings
from research_agent.state import RequestBudget
from groq import Groq
import logging

logger = logging.getLogger(__name__)

class ResearchClient:
    """Groq browser research plus Gemini's evidence-only validator."""
    def __init__(self, budget=None):
        if not settings.groq_api_key:
            raise RuntimeError("GROQ_API_KEY is not configured")
        self.budget = budget or RequestBudget(settings.max_llm_requests)
        self.client = Groq(api_key=settings.groq_api_key)
        self.validator = GeminiClient(self.budget)

    def generate_grounded(self, prompt: str) -> GroundedResult:
        self.budget.consume()
        logger.info("[grounded] provider=groq model=%s browser_search=true", settings.groq_model)
        response = self.client.chat.completions.create(
            model=settings.groq_model, messages=[{"role": "user", "content": prompt}],
            tools=[{"type": "browser_search"}], max_tokens=8192,
        )
        return _parse_response(response)

    def analyze_evidence(self, prompt: str, evidence: str) -> str:
        return self.validator.analyze_evidence(prompt, evidence)

    def close(self):
        self.client.close()
        self.validator.client.close()

def _dump(value):
    if isinstance(value, dict): return value
    fn = getattr(value, "model_dump", None)
    return fn() if callable(fn) else {}

def _parse_response(response):
    data = _dump(response)
    choices = data.get("choices", [])
    message = choices[0].get("message", {}) if choices else {}
    text = message.get("content") or ""
    sources, queries = [], []
    structured = (message.get("annotations") or []) + (message.get("citations") or [])
    for item in structured:
        item = _dump(item)
        url = item.get("url") or item.get("source_url")
        if isinstance(url, str) and url and url not in {s["url"] for s in sources}:
            sources.append({"title": str(item.get("title") or ""), "url": url})
    tools = data.get("executed_tools", []) + data.get("tool_results", []) + message.get("executed_tools", [])
    for tool in tools:
        tool = _dump(tool)
        result = tool.get("result", tool)
        sr = result.get("search_results", {}) if isinstance(result, dict) else {}
        items = result.get("sources", []) if isinstance(result, dict) else []
        items += sr.get("results", []) if isinstance(sr, dict) else []
        for item in items:
            item = _dump(item); url = item.get("url")
            if isinstance(url, str) and url and url not in {s["url"] for s in sources}:
                sources.append({"title": str(item.get("title") or ""), "url": url})
        args = tool.get("arguments", {})
        if isinstance(args, str):
            try: args = json.loads(args)
            except (TypeError, ValueError): args = {}
        found_queries = (result.get("queries", []) if isinstance(result, dict) else [])
        if isinstance(args, dict) and isinstance(args.get("query"), str): found_queries.append(args["query"])
        for q in found_queries:
            if isinstance(q, str) and q not in queries: queries.append(q)
    return GroundedResult(text, sources, queries)
