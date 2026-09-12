from pathlib import Path

from research_agent.orchestrator import (
    run_research_review,
)


INPUT_PATH = Path(
    "examples/android_rag_proposal.md"
)

OUTPUT_PATH = Path(
    "outputs/android_rag_proposal_review.md"
)


def main() -> None:
    proposal = INPUT_PATH.read_text(
        encoding="utf-8"
    )

    result = run_research_review(
        proposal
    )

    report_parts = [
        "# Multi-Agent Architecture Review",
        "",
        f"Consensus Reached: "
        f"{result.consensus_reached}",
        f"Rounds: {result.rounds}",
        f"LLM Requests: "
        f"{result.requests_used} / "
        f"{result.requests_maximum}",
        "",
        "---",
        "",
    ]

    report_parts.extend(
        result.transcript
    )

    report_parts.extend(
        [
            "",
            "---",
            "",
            "# Final Consensus Architecture",
            "",
            result.final_plan,
        ]
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_PATH.write_text(
        "\n\n".join(report_parts),
        encoding="utf-8",
    )

    print()
    print("Multi-Agent Review Complete")
    print("---------------------------")
    print(
        "Consensus reached:",
        result.consensus_reached,
    )
    print(
        "Rounds:",
        result.rounds,
    )
    print(
        "Requests:",
        f"{result.requests_used} / "
        f"{result.requests_maximum}",
    )
    print(
        "Report:",
        OUTPUT_PATH,
    )


if __name__ == "__main__":
    main()