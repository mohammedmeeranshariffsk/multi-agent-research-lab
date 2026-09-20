"""Small stdout progress helpers for CLI collection runs."""
import sys
import threading
import time
from contextlib import contextmanager


class ProgressReporter:
    def __init__(self, budget, stream=None, heartbeat_seconds=10, total_stages=4):
        self.budget = budget
        self.stream = stream or sys.stdout
        self.heartbeat_seconds = heartbeat_seconds
        self.total_stages = total_stages
        self._write_lock = threading.Lock()

    def write(self, line):
        with self._write_lock:
            print(line, file=self.stream, flush=True)

    @contextmanager
    def stage(self, number, name):
        started = time.monotonic()
        self.write(f"[{number}/{self.total_stages}] {name}")
        try:
            yield
        except Exception as exc:
            self.write(f"✗ FAILED after {time.monotonic() - started:.1f}s")
            self.write(f"Error: {type(exc).__name__}: {exc}")
            raise
        else:
            self.write(f"✓ Completed in {time.monotonic() - started:.1f}s")

    @contextmanager
    def api_call(self, model, google_search):
        started = time.monotonic()
        maximum = self.budget.maximum
        self.write(f"  Model: {model}")
        self.write(f"  Google Search: {'enabled' if google_search else 'disabled'}")
        self.write(f"  Request: {self.budget.used + 1}/{maximum}")
        self.write("  Status: waiting for model...")
        stopped = threading.Event()

        def heartbeat():
            while not stopped.wait(self.heartbeat_seconds):
                if stopped.is_set():
                    break
                elapsed = max(1, round(time.monotonic() - started))
                with self._write_lock:
                    if stopped.is_set():
                        break
                    print(f"  Elapsed: {elapsed}s...", file=self.stream, flush=True)

        thread = threading.Thread(target=heartbeat, name="collection-progress-heartbeat", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stopped.set()
            thread.join()


class ProgressClient:
    """Observability-only proxy; delegates calls and budget unchanged."""
    def __init__(self, client, progress):
        self._client = client
        self.progress = progress

    def __getattr__(self, name):
        return getattr(self._client, name)

    def generate_grounded(self, prompt):
        from research_agent.config import settings
        with self.progress.api_call(settings.gemini_research_model, google_search=True):
            return self._client.generate_grounded(prompt)

    def analyze_evidence(self, prompt, evidence):
        from research_agent.config import settings
        transient_statuses = {500, 502, 503, 504}
        for attempt in range(2):
            try:
                with self.progress.api_call(settings.gemini_model, google_search=False):
                    return self._client.analyze_evidence(prompt, evidence)
            except Exception as exc:
                try:
                    status = int(getattr(exc, "code", None))
                except (TypeError, ValueError):
                    status = None
                if attempt != 0 or status not in transient_statuses:
                    raise
                self.progress.write(
                    f"  Transient HTTP {status}; retrying validation once after 1s"
                )
                time.sleep(1)

    def generate(self, prompt):
        from research_agent.config import settings
        with self.progress.api_call(settings.gemini_model, google_search=False):
            return self._client.generate(prompt)
