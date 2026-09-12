from pathlib import Path

from research_agent.llm.gemini import GeminiClient


PROMPT_PATH = (
    Path(__file__).resolve().parent.parent
    / "prompts"
    / "synthesizer.md"
)


def load_synthesizer_prompt() -> str:
    return PROMPT_PATH.read_text(
        encoding="utf-8"
    )


def run_synthesis(
    proposal: str,
    security_review: str,
    rag_review: str,
    critic_review: str,
    client: GeminiClient,
) -> str:
    system_prompt = load_synthesizer_prompt()

    prompt = f"""
{system_prompt}

---

# Original Proposal

{proposal}

---

# Android Security Reviewer

{security_review}

---

# RAG / AI Architect

{rag_review}

---

# Cost / Complexity Critic

{critic_review}
"""

    return client.generate(prompt)

def revise_for_consensus(
    original_proposal: str,
    current_plan: str,
    security_feedback: str,
    rag_feedback: str,
    critic_feedback: str,
    client: GeminiClient,
) -> str:
    prompt = f"""
You are the Technical Lead responsible for reaching engineering
consensus.

You have:

1. the original proposal
2. the current candidate architecture
3. Android Security Reviewer feedback
4. RAG / AI Architect feedback
5. Cost / Complexity Critic feedback

Your job is to revise the candidate architecture so that all legitimate
blocking objections are resolved.

IMPORTANT:

Do NOT blindly add every suggestion.

Distinguish between:

BLOCKING:
must be resolved for architectural correctness

NON-BLOCKING:
useful suggestion, optimization, or future improvement

Only modify the architecture when there is a legitimate reason.

Preserve good decisions already made.

Do not reintroduce ideas already rejected unless new evidence clearly
justifies them.

Return a complete revised architecture, not merely a list of changes.

Use this structure:

# Revised Architecture Decision

## Executive Summary

## Changes From Previous Version

## Blocking Issues Resolved

## Must Build

## Should Build

## Experiments

## Defer

## Reject

## Final Architecture

## Implementation Order

## Evaluation Plan

## Remaining Risks

## Open Questions

# Original Proposal

{original_proposal}

# Current Candidate Architecture

{current_plan}

# Security Reviewer Feedback

{security_feedback}

# RAG Architect Feedback

{rag_feedback}

# Cost Critic Feedback

{critic_feedback}
"""

    return client.generate(prompt)