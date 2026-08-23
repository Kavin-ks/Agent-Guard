"""
Deterministic heuristic relevance advisor.

Estimates goal↔action relevance WITHOUT any network/LLM call, by comparing the
action's target against the goal's compiled scopes and topic vocabulary. It is:

  * the default advisor when no LLM API key is configured, and
  * the fallback the Claude advisor degrades to when the LLM is unavailable.

Because it is deterministic and offline, goal-drift detection keeps working even
with no LLM — which is exactly what the "LLM unavailable" failure mode requires.
"""

from __future__ import annotations

import re

from ..goal import AdvisorRequest, RelevanceAssessment, RelevanceLevel
from ..goal_compiler import compile_goal_representation
from ..models import Decision
from ..paths import matches_any

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "and", "or", "to", "of", "for", "src", "http", "https",
         "www", "com", "org", "net", "file", "files", "index", "main"}

# Extra vocabulary implied by common frontend topics, to reduce false drift.
_TOPIC_VOCAB = {
    "frontend": {"react", "jsx", "tsx", "css", "scss", "html", "component",
                 "components", "app", "navbar", "public", "assets", "style",
                 "styles", "page", "ui", "vite", "webpack", "npm", "yarn",
                 "test", "build", "portfolio", "website", "js", "ts", "json"},
    "backend": {"backend", "server", "api", "route", "controller"},
    "database": {"database", "db", "sql", "schema", "migration", "table"},
}


def _tokens(*parts: str) -> set[str]:
    out: set[str] = set()
    for p in parts:
        if not p:
            continue
        for t in _TOKEN_RE.findall(p.lower()):
            if len(t) > 1 and t not in _STOP:
                out.add(t)
    return out


class HeuristicRelevanceAdvisor:
    source = "heuristic"

    def evaluate(self, request: AdvisorRequest) -> RelevanceAssessment:
        rep = compile_goal_representation(request.goal)
        resource = request.resource

        # 0. Unscoped goal: no topics and no allowed/restricted scopes means there
        #    is no basis to call anything "goal drift" — drift is relative to a
        #    goal. Return MEDIUM (ambiguous, not a hard block) so the deterministic
        #    gates stay authoritative (secrets/destructive/exfil still blocked)
        #    without the advisory layer turning ordinary reads into ASK. Outbound
        #    actions still lean cautious below.
        unscoped = not rep.topics and not rep.allowed_resources and not rep.restricted_resources
        if unscoped and request.operation not in ("network", "transmit"):
            return RelevanceAssessment(
                relevance=RelevanceLevel.MEDIUM,
                confidence=0.5,
                reason="No scoped goal constraints provided; deterministic controls apply.",
                recommended_action=Decision.ALLOW,
                goal_drift=False,
                source=self.source,
            )

        # 1. Resource in a restricted scope -> clearly off-goal.
        if rep.restricted_resources and matches_any(rep.restricted_resources, resource):
            return RelevanceAssessment(
                relevance=RelevanceLevel.LOW,
                confidence=0.8,
                reason=(
                    "Target is in a restricted area of the goal (backend/database); "
                    "this action does not serve the requested objective."
                ),
                recommended_action=Decision.ASK,
                goal_drift=True,
                source=self.source,
            )

        # 2. Resource within an allowed scope -> clearly on-goal.
        if rep.allowed_resources and matches_any(rep.allowed_resources, resource):
            return RelevanceAssessment(
                relevance=RelevanceLevel.HIGH,
                confidence=0.75,
                reason="Target is within the goal's allowed working set.",
                recommended_action=Decision.ALLOW,
                goal_drift=False,
                source=self.source,
            )

        # 3. Otherwise, score topical overlap.
        goal_vocab: set[str] = _tokens(rep.objective)
        for topic in rep.topics:
            goal_vocab |= _TOPIC_VOCAB.get(topic, {topic})
        action_tokens = _tokens(resource, request.destination or "", request.tool)
        overlap = goal_vocab & action_tokens

        outbound = request.operation in ("network", "transmit")

        if overlap:
            return RelevanceAssessment(
                relevance=RelevanceLevel.MEDIUM,
                confidence=0.55,
                reason=(
                    f"Partial topical overlap with the goal ({', '.join(sorted(overlap))}); "
                    f"relevance is plausible but not certain."
                ),
                recommended_action=Decision.ALLOW,
                goal_drift=False,
                source=self.source,
            )

        # No overlap at all -> likely goal drift (stronger signal if outbound).
        return RelevanceAssessment(
            relevance=RelevanceLevel.LOW,
            confidence=0.6 if outbound else 0.5,
            reason=(
                "No topical connection between this action and the stated goal — "
                "likely goal drift."
                + (" Outbound communication to an unrelated destination." if outbound else "")
            ),
            recommended_action=Decision.ASK,
            goal_drift=True,
            source=self.source,
        )
