class RequestBudget:
    """Tracks and enforces the maximum number of LLM requests per run."""

    def __init__(self, maximum: int = 20) -> None:
        if maximum <= 0:
            raise ValueError("maximum must be greater than 0")

        self.maximum = maximum
        self.used = 0

    @property
    def remaining(self) -> int:
        return self.maximum - self.used

    def consume(self) -> None:
        if self.used >= self.maximum:
            raise RuntimeError(
                f"LLM request budget exhausted "
                f"({self.used}/{self.maximum})"
            )

        self.used += 1

    def __repr__(self) -> str:
        return (
            f"RequestBudget("
            f"used={self.used}, "
            f"maximum={self.maximum}, "
            f"remaining={self.remaining}"
            f")"
        )