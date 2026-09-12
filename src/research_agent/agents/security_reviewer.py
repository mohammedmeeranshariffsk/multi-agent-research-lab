from pathlib import Path

from research_agent.llm.gemini import GeminiClient


PROMPT_PATH = (
    Path(__file__).resolve().parent.parent
    / "prompts"
    / "security_reviewer.md"
)


def load_security_prompt() -> str:
    return PROMPT_PATH.read_text(
        encoding="utf-8"
    )


def run_security_review(
    proposal: str,
    client: GeminiClient,
) -> str:
    system_prompt = load_security_prompt()

    prompt = f"""
{system_prompt}

---

# Proposal To Review

{proposal}
"""

    return client.generate(prompt)
def run_security_consensus_review(
    original_proposal: str,
    candidate_plan: str,
    client: GeminiClient,
) -> str:
    prompt = f"""
You are the Android Security Reviewer.

You previously participated in reviewing this architecture.

You must now determine whether the current candidate architecture is
acceptable from an Android malware analysis and security-engineering
perspective.

A blocking objection is an issue that would make the proposed
architecture unsafe, misleading, technically unsound, or likely to
produce unacceptable false positives or false negatives.

Minor improvements and future enhancements are NOT blocking objections.

Evaluate specifically:

- deterministic evidence collection
- permissions
- API calls
- strings
- Android components
- call relationships
- source-to-sink relationships
- obfuscation handling
- library filtering
- false positives
- evidence strength
- malware-family attribution
- explainability
- whether the LLM is being used appropriately

You MUST end with exactly one of:

CONSENSUS: AGREE

or

CONSENSUS: DISAGREE

If you disagree, clearly identify only the blocking issues that must be
changed before you can agree.

If you agree, you may provide non-blocking observations, but do not
invent new requirements merely to continue the discussion.

# Original Proposal

{original_proposal}

# Current Candidate Architecture

{candidate_plan}
"""

    return client.generate(prompt)