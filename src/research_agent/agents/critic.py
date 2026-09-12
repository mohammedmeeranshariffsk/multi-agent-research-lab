from pathlib import Path

from research_agent.llm.gemini import GeminiClient


PROMPT_PATH = (
    Path(__file__).resolve().parent.parent
    / "prompts"
    / "critic.md"
)


def load_critic_prompt() -> str:
    return PROMPT_PATH.read_text(
        encoding="utf-8"
    )


def run_critic_review(
    proposal: str,
    client: GeminiClient,
) -> str:
    system_prompt = load_critic_prompt()

    prompt = f"""
{system_prompt}

---

# Proposal To Review

{proposal}
"""

    return client.generate(prompt)

def run_critic_consensus_review(
    original_proposal: str,
    candidate_plan: str,
    client: GeminiClient,
) -> str:
    prompt = f"""
You are the Cost / Complexity Critic.

Review the current candidate architecture and determine whether its
remaining complexity, cost, operational risk, and LLM usage are
acceptable.

You are intentionally skeptical, but you must not block consensus over
minor preferences.

A blocking objection must represent a meaningful engineering problem,
such as:

- unnecessary major infrastructure
- uncontrolled LLM cost
- unacceptable scalability problems
- lack of deterministic fallback
- duplicated architecture
- serious reliability problems
- inability to evaluate the system objectively

Minor optimizations or potential future simplifications are NOT
blocking objections.

You MUST end with exactly one of:

CONSENSUS: AGREE

or

CONSENSUS: DISAGREE

If you disagree, identify only the blocking issues that must be fixed.

Do not disagree merely because an even simpler architecture could
theoretically exist.

# Original Proposal

{original_proposal}

# Current Candidate Architecture

{candidate_plan}
"""

    return client.generate(prompt)