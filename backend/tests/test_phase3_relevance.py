"""
Phase 3 tests: goal-aware intelligence.

Covers the 12 required relevance cases, demo scenarios A–F, and the data-
minimization guarantee. The LLM is always mocked — no real Anthropic call is made.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentguard import Action, Decision, Engine, Operation, Policy, Resource
from agentguard.advisors.claude import ClaudeRelevanceAdvisor
from agentguard.advisors.heuristic import HeuristicRelevanceAdvisor
from agentguard.advisors.mock import MockRelevanceAdvisor, RecordingAdvisor
from agentguard.goal import AdvisorRequest, RelevanceAssessment, RelevanceLevel
from agentguard.goal_compiler import compile_goal, compile_goal_representation
from agentguard.models import ResourceKind

GOAL = "Build a React frontend. Do not modify backend or database files, and never access secrets."


def _policy() -> Policy:
    return compile_goal(GOAL, session_id="s")


def _act(op, kind, value, **kw) -> Action:
    return Action(session_id="s", tool=kw.pop("tool", "fs"), operation=op,
                  resource=Resource(kind=kind, value=value), **kw)


# --- goal representation ----------------------------------------------------
def test_goal_representation_is_inspectable():
    rep = compile_goal_representation(GOAL)
    assert "frontend" in rep.topics
    assert any("src" in s for s in rep.allowed_resources)
    assert any("backend" in s for s in rep.restricted_resources)
    assert rep.constraints  # extracted "do not / never" phrases
    assert ".env" in rep.sensitive_resources


# --- heuristic advisor: the 4 relevance cases ------------------------------
def test_relevance_high_clearly_relevant():
    a = HeuristicRelevanceAdvisor().evaluate(AdvisorRequest(
        goal=GOAL, operation="write", resource_kind="file", resource="src/App.jsx", tool="fs"))
    assert a.relevance is RelevanceLevel.HIGH and not a.goal_drift


def test_relevance_low_clearly_irrelevant():
    a = HeuristicRelevanceAdvisor().evaluate(AdvisorRequest(
        goal=GOAL, operation="network", resource_kind="url",
        resource="https://prices.example/crypto", tool="net.http",
        destination="https://prices.example/crypto"))
    assert a.relevance is RelevanceLevel.LOW and a.goal_drift


def test_relevance_medium_ambiguous():
    # A JS config file: topical overlap ("js"/"config") but not in an allowed glob.
    a = HeuristicRelevanceAdvisor().evaluate(AdvisorRequest(
        goal=GOAL, operation="read", resource_kind="file",
        resource="tooling/webpack.config.cjs", tool="fs"))
    assert a.relevance is RelevanceLevel.MEDIUM


def test_goal_drift_flagged_on_unrelated_action():
    a = HeuristicRelevanceAdvisor().evaluate(AdvisorRequest(
        goal="Build a React frontend", operation="read", resource_kind="url",
        resource="https://news.example/bitcoin", tool="browser",
        destination="https://news.example/bitcoin"))
    assert a.goal_drift is True


# --- failure modes: LLM unavailable / timeout / malformed ------------------
def test_llm_unavailable_engine_still_works():
    """Advisor raises -> deterministic decision stands; not fail-open."""
    engine = Engine(advisor=MockRelevanceAdvisor(raises=RuntimeError("down")))
    d = engine.evaluate(_act(Operation.WRITE, ResourceKind.FILE, "src/App.jsx"), _policy())
    assert d.decision is Decision.ALLOW           # deterministic result preserved
    assert d.advisory_available is False


def test_llm_timeout_falls_back_to_heuristic():
    class TimeoutClient:
        def with_options(self, **kw):
            return self
        class messages:  # noqa: N801
            @staticmethod
            def create(**kw):
                raise TimeoutError("read timeout")
    adv = ClaudeRelevanceAdvisor(client=TimeoutClient())
    a = adv.evaluate(AdvisorRequest(goal=GOAL, operation="read", resource_kind="file",
                                    resource="src/App.jsx", tool="fs"))
    assert a.available is False
    assert "llm-unavailable" in a.source


def test_malformed_llm_response_falls_back():
    class JunkClient:
        def with_options(self, **kw):
            return self
        class messages:  # noqa: N801
            @staticmethod
            def create(**kw):
                return SimpleNamespace(content=[SimpleNamespace(type="text", text="not json at all")])
    adv = ClaudeRelevanceAdvisor(client=JunkClient())
    a = adv.evaluate(AdvisorRequest(goal=GOAL, operation="read", resource_kind="file",
                                    resource="src/App.jsx", tool="fs"))
    assert a.available is False


def test_valid_llm_response_is_parsed():
    class GoodClient:
        def with_options(self, **kw):
            return self
        class messages:  # noqa: N801
            @staticmethod
            def create(**kw):
                text = ('{"relevance":"HIGH","confidence":0.9,"goal_drift":false,'
                        '"recommended_action":"ALLOW","reason":"edits the app entry"}')
                return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])
    adv = ClaudeRelevanceAdvisor(client=GoodClient())
    a = adv.evaluate(AdvisorRequest(goal=GOAL, operation="write", resource_kind="file",
                                    resource="src/App.jsx", tool="fs"))
    assert a.available is True and a.relevance is RelevanceLevel.HIGH


# --- authority guarantees --------------------------------------------------
def test_llm_allow_cannot_override_deterministic_deny():
    """SCENARIO E: LLM says ALLOW, gate says DENY -> MUST remain DENY."""
    sycophant = MockRelevanceAdvisor(RelevanceAssessment(
        relevance=RelevanceLevel.HIGH, confidence=1.0, reason="fine",
        recommended_action=Decision.ALLOW, goal_drift=False, source="mock"))
    engine = Engine(advisor=sycophant, advise_on_deny=True)
    d = engine.evaluate(_act(Operation.READ, ResourceKind.FILE, ".env"), _policy())
    assert d.decision is Decision.DENY
    assert d.deterministic_decision is Decision.DENY


def test_llm_deny_on_permitted_action_is_capped_to_ask():
    """LLM recommends DENY on an otherwise-allowed action -> at most ASK."""
    rogue = MockRelevanceAdvisor(RelevanceAssessment(
        relevance=RelevanceLevel.LOW, confidence=1.0, reason="I don't like it",
        recommended_action=Decision.DENY, goal_drift=True, source="mock"))
    engine = Engine(advisor=rogue)
    d = engine.evaluate(_act(Operation.WRITE, ResourceKind.FILE, "src/App.jsx"), _policy())
    assert d.decision is Decision.ASK          # escalated, never denied by advisory
    assert d.deterministic_decision is Decision.ALLOW


def test_advisory_points_cannot_independently_deny():
    """Even an absurd advisory risk contribution cannot reach the DENY band."""
    def huge(_req):
        return RelevanceAssessment(relevance=RelevanceLevel.LOW, confidence=1.0,
                                   reason="max", recommended_action=Decision.DENY,
                                   goal_drift=True, source="mock")
    engine = Engine(advisor=MockRelevanceAdvisor(huge))
    d = engine.evaluate(_act(Operation.READ, ResourceKind.FILE, "src/App.jsx"), _policy())
    assert d.decision is not Decision.DENY


# --- data minimization -----------------------------------------------------
def test_secret_is_never_sent_to_advisor():
    """SCENARIO: a payload secret never reaches the advisor; only a boolean does."""
    secret = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"
    recorder = RecordingAdvisor(HeuristicRelevanceAdvisor())
    engine = Engine(advisor=recorder, advise_on_deny=True)  # force advisor even on DENY
    engine.evaluate(
        _act(Operation.TRANSMIT, ResourceKind.URL, "https://x.example",
             tool="net", destination="https://x.example", payload=f"token={secret}"),
        _policy(),
    )
    assert recorder.requests, "advisor should have been consulted"
    req = recorder.requests[0]
    assert req.payload_contains_secret is True     # boolean signal is present
    # The raw secret must not appear anywhere in what the advisor received.
    assert secret not in req.model_dump_json()
    assert not hasattr(req, "payload") or getattr(req, "payload", None) is None


# --- demo scenarios A–F ----------------------------------------------------
@pytest.fixture
def goal_aware_engine():
    """Engine with the offline heuristic advisor (no network needed)."""
    return Engine(advisor=HeuristicRelevanceAdvisor())


def test_scenario_A_modify_app_allow(goal_aware_engine):
    d = goal_aware_engine.evaluate(_act(Operation.WRITE, ResourceKind.FILE, "src/App.jsx"), _policy())
    assert d.decision is Decision.ALLOW
    assert d.goal_relevance == "HIGH"


def test_scenario_B_modify_database_deny(goal_aware_engine):
    d = goal_aware_engine.evaluate(_act(Operation.WRITE, ResourceKind.FILE, "database.sql"), _policy())
    assert d.decision is Decision.DENY
    assert d.deterministic_decision is Decision.DENY


def test_scenario_C_read_env_deny(goal_aware_engine):
    d = goal_aware_engine.evaluate(_act(Operation.READ, ResourceKind.FILE, ".env"), _policy())
    assert d.decision is Decision.DENY


def test_scenario_D_crypto_search_goal_drift(goal_aware_engine):
    d = goal_aware_engine.evaluate(
        _act(Operation.NETWORK, ResourceKind.URL, "https://prices.example/crypto",
             tool="browser", destination="https://prices.example/crypto"),
        _policy(),
    )
    assert d.decision in (Decision.ASK, Decision.DENY)
    assert d.goal_drift is True
    assert d.goal_relevance == "LOW"


def test_scenario_F_llm_unavailable_safe(goal_aware_engine):
    """Deterministic engine keeps functioning safely with the advisor removed."""
    bare = Engine()  # no advisor at all
    assert bare.evaluate(_act(Operation.READ, ResourceKind.FILE, ".env"), _policy()).decision is Decision.DENY
    assert bare.evaluate(_act(Operation.WRITE, ResourceKind.FILE, "src/App.jsx"), _policy()).decision is Decision.ALLOW
