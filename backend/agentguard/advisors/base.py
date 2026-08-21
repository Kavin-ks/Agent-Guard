"""
Advisor interface + the data-minimization boundary.

`build_advisor_request` is the single chokepoint that decides what an advisor
(including any LLM) is allowed to see. It sends action metadata and goal text
only — never the raw payload, never a secret value. The presence of a secret is
communicated as a boolean, computed locally by the deterministic detector.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..detectors.scan import categories, scan_text
from ..detectors.secrets import detect_secrets
from ..goal import AdvisorRequest, RelevanceAssessment
from ..models import Action, Policy


@runtime_checkable
class RelevanceAdvisor(Protocol):
    """A relevance advisor evaluates goal↔action fit. Advisory only."""

    def evaluate(self, request: AdvisorRequest) -> RelevanceAssessment:  # pragma: no cover
        ...


def build_advisor_request(action: Action, policy: Policy) -> AdvisorRequest:
    """Construct the minimal, redacted request an advisor may receive.

    IMPORTANT: this is the ONLY place action data crosses to an advisor. It must
    never include ``action.payload`` text or any secret value.
    """
    payload_secrets = detect_secrets(action.payload)
    findings = scan_text(action.payload, "payload")
    return AdvisorRequest(
        goal=policy.goal_text,
        operation=action.operation.value,
        resource_kind=action.resource.kind.value,
        resource=action.resource.value,   # path/URL — not a secret value
        tool=action.tool,
        destination=action.destination,
        payload_present=action.payload is not None,
        payload_contains_secret=bool(payload_secrets),
        payload_contains_sensitive_data=bool(findings),
        sensitive_categories=categories(findings),  # category labels only, never values
        context_keys=sorted(action.context.keys()) if action.context else [],
    )
