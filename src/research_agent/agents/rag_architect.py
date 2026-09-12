from pathlib import Path

from research_agent.llm.gemini import GeminiClient


PROMPT_PATH = (
    Path(__file__).resolve().parent.parent
    / "prompts"
    / "rag_architect.md"
)


def load_rag_prompt() -> str:
    return PROMPT_PATH.read_text(
        encoding="utf-8"
    )


def run_rag_review(
    proposal: str,
    client: GeminiClient,
) -> str:
    system_prompt = load_rag_prompt()

    prompt = f"""
{system_prompt}

---

# Proposal To Review

{proposal}
"""

    return client.generate(prompt)

def run_rag_consensus_review(
    original_proposal: str,
    candidate_plan: str,
    client: GeminiClient,
) -> str:
    prompt = f"""
You are the RAG / AI Architect.

You must determine whether the current candidate architecture is
technically acceptable from the perspective of retrieval systems,
LLM architecture, embeddings, indexing, evaluation, and scalability.

A blocking objection is something that materially damages:

- retrieval quality
- scalability
- context efficiency
- reliability
- evaluation validity
- system architecture

Minor optimizations are NOT blocking objections.

Evaluate specifically:

- chunking
- indexing
- vector retrieval
- metadata
- hybrid retrieval
- query routing
- deterministic tools versus LLM usage
- summarization
- retrieval precision and recall
- context-window usage
- evaluation methodology
- scalability

You MUST end with exactly one of:

CONSENSUS: AGREE

or

CONSENSUS: DISAGREE

If you disagree, list only the blocking changes required for agreement.

Do not create unnecessary new architecture requirements simply to
continue the debate.

# Original Proposal

{original_proposal}

# Current Candidate Architecture

{candidate_plan}
"""

    return client.generate(prompt)