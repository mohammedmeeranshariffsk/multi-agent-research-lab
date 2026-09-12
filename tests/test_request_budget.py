import pytest

from research_agent.state import RequestBudget


def test_initial_state():
    budget = RequestBudget(maximum=20)

    assert budget.maximum == 20
    assert budget.used == 0
    assert budget.remaining == 20


def test_consume_request():
    budget = RequestBudget(maximum=3)

    budget.consume()

    assert budget.used == 1
    assert budget.remaining == 2


def test_exhausted_budget_raises():
    budget = RequestBudget(maximum=2)

    budget.consume()
    budget.consume()

    with pytest.raises(RuntimeError):
        budget.consume()


def test_invalid_budget():
    with pytest.raises(ValueError):
        RequestBudget(maximum=0)