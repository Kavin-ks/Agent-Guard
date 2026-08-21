"""
Claude-backed relevance advisor (real, callable Anthropic integration).

This is a genuine LLM call — not a hardcoded response. It:

  * receives ONLY the minimized `AdvisorRequest` (no payload, no secrets),
  * asks Claude for a structured relevance judgement (JSON),
  * parses defensively, and
  * on ANY failure (SDK missing, no key, timeout, HTTP error, malformed JSON)
    falls back to the deterministic heuristic advisor.

Failure is never fail-open: the fallback still produces a real assessment, and
the advisory can never override a deterministic DENY (enforced in the pipeline).
The default model is ``claude-opus-5`` (configurable); the operator may point it
at a faster/cheaper model via configuration.
"""

from __future__ import annotations

import json
import logging
import re

from ..goal import AdvisorRequest, RelevanceAssessment, RelevanceLevel
from ..models import Decision
from .heuristic import HeuristicRelevanceAdvisor

logger = logging.getLogger("agentguard.advisor.claude")

_SYSTEM = (
    "You are a security relevance advisor for an autonomous-agent authorization "
    "firewall. You do NOT make the security decision — deterministic controls do. "
    "Given the user's goal and a proposed agent action (metadata only), judge how "
    "well the action serves the goal, and whether it looks like goal drift "
    "(an action unrelated to or beyond the stated objective). "
    "You are never given secret values or file contents. "
    "Respond with ONLY a single JSON object, no prose, with keys: "
    'relevance ("HIGH"|"MEDIUM"|"LOW"), confidence (0..1), goal_drift (boolean), '
    'recommended_action ("ALLOW"|"ASK"|"DENY"), reason (short string).'
)

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


class ClaudeRelevanceAdvisor:
    def __init__(
        self,
        client=None,
        model: str = "claude-opus-5",
        timeout_s: float = 8.0,
        fallback=None,
    ) -> None:
        self._model = model
        self._timeout_s = timeout_s
        self._fallback = fallback or HeuristicRelevanceAdvisor()
        self._client = client
        self.source = f"llm:{model}"

        if self._client is None:
            try:  # lazy: absence of the SDK/key must not break the engine
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic()
            except Exception as exc:  # pragma: no cover - env dependent
                logger.warning("Anthropic client unavailable (%s); using heuristic fallback.", exc)
                self._client = None

    def _fallback_assessment(self, request: AdvisorRequest, why: str) -> RelevanceAssessment:
        a = self._fallback.evaluate(request)
        return a.model_copy(update={
            "available": False,
            "source": f"{a.source} (llm-unavailable: {why})",
        })

    def evaluate(self, request: AdvisorRequest) -> RelevanceAssessment:
        if self._client is None:
            return self._fallback_assessment(request, "no-client")

        user = json.dumps({
            "goal": request.goal,
            "action": {
                "operation": request.operation,
                "resource_kind": request.resource_kind,
                "resource": request.resource,
                "tool": request.tool,
                "destination": request.destination,
                "payload_present": request.payload_present,
                "payload_contains_secret": request.payload_contains_secret,
                "payload_contains_sensitive_data": request.payload_contains_sensitive_data,
                "sensitive_categories": request.sensitive_categories,
                "context_keys": request.context_keys,
            },
        })

        try:
            resp = self._client.with_options(timeout=self._timeout_s).messages.create(
                model=self._model,
                max_tokens=400,
                system=_SYSTEM,
                messages=[{"role": "user", "content": user}],
            )
            text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
            return self._parse(text)
        except Exception as exc:
            logger.warning("Claude advisor call failed (%s); using heuristic fallback.", exc)
            return self._fallback_assessment(request, type(exc).__name__)

    def _parse(self, text: str) -> RelevanceAssessment:
        match = _JSON_RE.search(text or "")
        if not match:
            raise ValueError("no JSON object in advisor response")
        data = json.loads(match.group(0))

        relevance = RelevanceLevel(str(data["relevance"]).upper())
        recommended = Decision(str(data["recommended_action"]).upper())
        confidence = float(data.get("confidence", 0.5))
        confidence = min(1.0, max(0.0, confidence))

        return RelevanceAssessment(
            relevance=relevance,
            confidence=confidence,
            reason=str(data.get("reason", ""))[:500],
            recommended_action=recommended,
            goal_drift=bool(data.get("goal_drift", relevance == RelevanceLevel.LOW)),
            available=True,
            source=self.source,
        )
