import io
import threading
import time
from unittest.mock import Mock

import pytest

from research_agent.agents.evidence_validator import parse_validation
from research_agent.config import settings
from research_agent.progress import ProgressClient, ProgressReporter
from research_agent.state import RequestBudget


def test_api_progress_heartbeat_is_local_and_joins_on_failure():
    output = io.StringIO()
    budget = RequestBudget(maximum=3)
    reporter = ProgressReporter(budget, stream=output, heartbeat_seconds=0.01)
    with pytest.raises(RuntimeError, match="synthetic"), reporter.api_call("test-model", google_search=True):
        time.sleep(0.025)
        raise RuntimeError("synthetic")
    assert budget.used == 0
    assert "Model: test-model" in output.getvalue()
    assert "Google Search: enabled" in output.getvalue()
    assert "Request: 1/3" in output.getvalue()
    assert "Elapsed: 1s..." in output.getvalue()
    assert not any(t.name == "collection-progress-heartbeat" and t.is_alive()
                   for t in threading.enumerate())


def test_stage_reports_success_and_failure_duration():
    output = io.StringIO()
    reporter = ProgressReporter(RequestBudget(1), stream=output)
    with reporter.stage(1, "DISCOVERY"):
        pass
    with pytest.raises(ValueError), reporter.stage(2, "INVESTIGATION"):
        raise ValueError("bad response")
    text = output.getvalue()
    assert "[1/4] DISCOVERY" in text and "✓ Completed in" in text
    assert "[2/4] INVESTIGATION" in text and "✗ FAILED after" in text
    assert "ValueError: bad response" in text


def _transient_error(code):
    error = RuntimeError(f"HTTP {code}")
    error.code = code
    return error


def _retry_client(outcomes, maximum=5):
    budget = RequestBudget(maximum)

    class FakeClient:
        def __init__(self):
            self.budget = budget
            self.call = Mock(side_effect=outcomes)

        def analyze_evidence(self, prompt, evidence):
            self.budget.consume()
            return self.call(prompt, evidence)

    base = FakeClient()
    output = io.StringIO()
    progress = ProgressReporter(budget, stream=output)
    return ProgressClient(base, progress), base, budget, output


def test_validation_retries_503_once_and_returns_second_response(monkeypatch):
    monkeypatch.setattr(settings, "gemini_model", "validation-model")
    monkeypatch.setattr("research_agent.progress.time.sleep", Mock())
    valid_json = '{"dataset_decision":"REJECT","assessments":[]}'
    client, base, budget, output = _retry_client([_transient_error(503), valid_json])

    result = client.analyze_evidence("prompt", "evidence")

    assert result == valid_json
    assert parse_validation(result).dataset_decision == "REJECT"
    assert base.call.call_count == 2
    assert budget.used == 2
    assert "Request: 1/5" in output.getvalue()
    assert "Request: 2/5" in output.getvalue()
    assert "retrying validation once" in output.getvalue()


def test_validation_two_503_responses_fail_after_two_attempts(monkeypatch):
    monkeypatch.setattr(settings, "gemini_model", "validation-model")
    monkeypatch.setattr("research_agent.progress.time.sleep", Mock())
    client, base, budget, _ = _retry_client([_transient_error(503), _transient_error(503)])

    with pytest.raises(RuntimeError, match="HTTP 503"):
        client.analyze_evidence("prompt", "evidence")

    assert base.call.call_count == 2
    assert budget.used == 2


def test_validation_400_is_not_retried(monkeypatch):
    monkeypatch.setattr(settings, "gemini_model", "validation-model")
    client, base, budget, _ = _retry_client([_transient_error(400)])

    with pytest.raises(RuntimeError, match="HTTP 400"):
        client.analyze_evidence("prompt", "evidence")

    assert base.call.call_count == 1
    assert budget.used == 1


def test_malformed_validation_json_is_not_retried(monkeypatch):
    monkeypatch.setattr(settings, "gemini_model", "validation-model")
    client, base, budget, _ = _retry_client(["not json"])
    result = client.analyze_evidence("prompt", "evidence")

    with pytest.raises(ValueError):
        parse_validation(result)

    assert base.call.call_count == 1
    assert budget.used == 1
