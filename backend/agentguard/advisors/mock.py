"""
Test/demo advisors — no network required.

* ``MockRelevanceAdvisor`` returns a fixed or callable-provided assessment. Used
  to simulate "the LLM says X" in tests without a real API call.
* ``RecordingAdvisor`` wraps another advisor and records every ``AdvisorRequest``
  it received, so tests can assert exactly what data reached the advisor (e.g.
  proving a secret is never sent).
"""

from __future__ import annotations

from typing import Callable

from ..goal import AdvisorRequest, RelevanceAssessment


class MockRelevanceAdvisor:
    """Return a canned assessment, or raise to simulate an unavailable LLM."""

    def __init__(
        self,
        assessment: RelevanceAssessment | Callable[[AdvisorRequest], RelevanceAssessment] | None = None,
        *,
        raises: BaseException | None = None,
    ) -> None:
        self._assessment = assessment
        self._raises = raises
        self.calls = 0

    def evaluate(self, request: AdvisorRequest) -> RelevanceAssessment:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        if callable(self._assessment):
            return self._assessment(request)
        assert self._assessment is not None, "MockRelevanceAdvisor needs an assessment or raises"
        return self._assessment


class RecordingAdvisor:
    """Wrap an advisor and record the requests it received (for data-flow tests)."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.requests: list[AdvisorRequest] = []

    def evaluate(self, request: AdvisorRequest) -> RelevanceAssessment:
        self.requests.append(request)
        return self._inner.evaluate(request)
