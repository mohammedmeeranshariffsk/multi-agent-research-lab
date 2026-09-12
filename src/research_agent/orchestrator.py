from dataclasses import dataclass

from research_agent.agents.critic import (
    run_critic_consensus_review,
    run_critic_review,
)
from research_agent.agents.rag_architect import (
    run_rag_consensus_review,
    run_rag_review,
)
from research_agent.agents.security_reviewer import (
    run_security_consensus_review,
    run_security_review,
)
from research_agent.agents.synthesizer import (
    revise_for_consensus,
    run_synthesis,
)
from research_agent.config import settings
from research_agent.llm.gemini import GeminiClient
from research_agent.state import RequestBudget


@dataclass
class ConsensusResult:
    final_plan: str
    consensus_reached: bool
    rounds: int
    requests_used: int
    requests_maximum: int
    transcript: list[str]


def has_agreed(review: str) -> bool:
    return "CONSENSUS: AGREE" in review.upper()


def run_research_review(
    proposal: str,
) -> ConsensusResult:

    budget = RequestBudget(
        maximum=settings.max_llm_requests
    )

    client = GeminiClient(budget)

    transcript: list[str] = []

    # ---------------------------------------------------------
    # ROUND 1
    # Independent specialist reviews
    # ---------------------------------------------------------

    security_review = run_security_review(
        proposal,
        client,
    )

    rag_review = run_rag_review(
        proposal,
        client,
    )

    critic_review = run_critic_review(
        proposal,
        client,
    )

    transcript.append(
        "# Initial Security Review\n\n"
        + security_review
    )

    transcript.append(
        "# Initial RAG Review\n\n"
        + rag_review
    )

    transcript.append(
        "# Initial Critic Review\n\n"
        + critic_review
    )

    candidate_plan = run_synthesis(
        proposal,
        security_review,
        rag_review,
        critic_review,
        client,
    )

    transcript.append(
        "# Candidate Architecture - Round 1\n\n"
        + candidate_plan
    )

    round_number = 1

    # ---------------------------------------------------------
    # CONSENSUS LOOP
    # ---------------------------------------------------------

    while True:

        # We need three requests to check consensus.
        if budget.remaining < 3:
            break

        security_consensus = (
            run_security_consensus_review(
                proposal,
                candidate_plan,
                client,
            )
        )

        rag_consensus = (
            run_rag_consensus_review(
                proposal,
                candidate_plan,
                client,
            )
        )

        critic_consensus = (
            run_critic_consensus_review(
                proposal,
                candidate_plan,
                client,
            )
        )

        transcript.append(
            f"# Consensus Review - Round {round_number}\n\n"
            "## Security Reviewer\n\n"
            f"{security_consensus}\n\n"
            "## RAG Architect\n\n"
            f"{rag_consensus}\n\n"
            "## Cost Critic\n\n"
            f"{critic_consensus}"
        )

        security_agrees = has_agreed(
            security_consensus
        )

        rag_agrees = has_agreed(
            rag_consensus
        )

        critic_agrees = has_agreed(
            critic_consensus
        )

        if (
            security_agrees
            and rag_agrees
            and critic_agrees
        ):
            return ConsensusResult(
                final_plan=candidate_plan,
                consensus_reached=True,
                rounds=round_number,
                requests_used=budget.used,
                requests_maximum=budget.maximum,
                transcript=transcript,
            )

        # We need one more request for revision.
        if budget.remaining < 1:
            break

        candidate_plan = revise_for_consensus(
            proposal,
            candidate_plan,
            security_consensus,
            rag_consensus,
            critic_consensus,
            client,
        )

        round_number += 1

        transcript.append(
            f"# Candidate Architecture - Round "
            f"{round_number}\n\n"
            + candidate_plan
        )

    # ---------------------------------------------------------
    # No unanimous agreement within budget.
    # ---------------------------------------------------------

    return ConsensusResult(
        final_plan=candidate_plan,
        consensus_reached=False,
        rounds=round_number,
        requests_used=budget.used,
        requests_maximum=budget.maximum,
        transcript=transcript,
    )