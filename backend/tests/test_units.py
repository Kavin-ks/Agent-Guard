"""
Component-level unit tests: secret detector, path/glob utilities, individual
gates, risk aggregation, the LLM-advisory guardrail, and malformed input.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard import Action, Decision, Engine, Operation, Policy, Resource
from agentguard.detectors.secrets import contains_secret, detect_secrets
from agentguard.gates.base import GateContext
from agentguard.gates.destructive import DestructiveGate
from agentguard.models import ResourceKind, Severity, Signal
from agentguard.paths import glob_match, matches_any, normalize_path
from agentguard.risk import aggregate


# --- secret detector -------------------------------------------------------
def test_detects_anthropic_key_and_redacts():
    findings = detect_secrets("token=sk-ant-api03-AbCdEf0123456789AbCdEf0123456789ZzZz")
    assert findings
    for f in findings:
        # fingerprint must not equal or contain the full secret body
        assert "0123456789AbCdEf0123456789" not in f.fingerprint
        assert "…" in f.fingerprint


def test_detects_private_key_block():
    assert contains_secret("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")


def test_no_false_positive_on_plain_prose():
    assert not contains_secret("This is a normal sentence about a React component.")


# --- path / glob -----------------------------------------------------------
def test_normalize_collapses_traversal():
    assert normalize_path("src/../.env") == ".env"
    assert normalize_path("../../.env") == "../../.env"


def test_glob_double_star():
    assert glob_match("backend/**", "backend/db/models.py")
    assert glob_match("**/.env*", "config/.env.production")
    assert not glob_match("src/**", "backend/server.py")


def test_matches_any_returns_pattern():
    assert matches_any(["src/**", "public/**"], "public/index.html") == "public/**"
    assert matches_any(["src/**"], "backend/x") is None


# --- individual gate -------------------------------------------------------
def test_destructive_gate_emits_ask():
    policy = Policy(session_id="s", destructive_requires_approval=True)
    action = Action(
        session_id="s", tool="fs", operation=Operation.DELETE,
        resource=Resource(kind=ResourceKind.FILE, value="notes.txt"),
    )
    signals = DestructiveGate().evaluate(GateContext(action=action, policy=policy))
    assert signals and signals[0].severity is Severity.ASK


def test_destructive_gate_respects_policy_toggle():
    policy = Policy(session_id="s", destructive_requires_approval=False)
    action = Action(
        session_id="s", tool="fs", operation=Operation.DELETE,
        resource=Resource(kind=ResourceKind.FILE, value="notes.txt"),
    )
    assert DestructiveGate().evaluate(GateContext(action=action, policy=policy)) == []


# --- risk aggregation & LLM guardrail -------------------------------------
def test_no_signals_is_allow_low_risk():
    policy = Policy(session_id="s")
    action = Action(
        session_id="s", tool="fs", operation=Operation.READ,
        resource=Resource(kind=ResourceKind.FILE, value="src/App.jsx"),
    )
    result = aggregate(action, policy, signals=[])
    assert result.decision is Decision.ALLOW
    assert result.risk_score < 40


def test_hard_deny_beats_low_score():
    policy = Policy(session_id="s")
    action = Action(
        session_id="s", tool="fs", operation=Operation.READ,
        resource=Resource(kind=ResourceKind.FILE, value="x"),
    )
    signals = [Signal(gate="g", severity=Severity.DENY, risk_points=0, reason="hard")]
    assert aggregate(action, policy, signals).decision is Decision.DENY


def test_llm_advisory_cannot_force_deny():
    """A malicious/wrong advisor emitting DENY is downgraded to ASK."""

    class RogueAdvisor:
        def assess(self, action, policy):
            return [Signal(gate="llm", severity=Severity.DENY, risk_points=100, reason="x")]

    engine = Engine(advisor=RogueAdvisor())
    policy = Policy(session_id="s")
    action = Action(
        session_id="s", tool="fs", operation=Operation.READ,
        resource=Resource(kind=ResourceKind.FILE, value="src/App.jsx"),
    )
    d = engine.evaluate(action, policy)
    # Advisory can escalate to ASK, never DENY.
    assert d.decision is Decision.ASK
    assert all(s.advisory for s in d.signals if s.gate.startswith("advisory:"))


def test_llm_advisory_cannot_override_hard_deny():
    """An advisor cannot rescue an action the hard gates denied."""

    class SycophantAdvisor:
        def assess(self, action, policy):
            return [Signal(gate="llm", severity=Severity.INFO, risk_points=0, reason="looks fine")]

    engine = Engine(advisor=SycophantAdvisor())
    policy = Policy(session_id="s", allowed_scopes=["**"])
    action = Action(
        session_id="s", tool="fs", operation=Operation.READ,
        resource=Resource(kind=ResourceKind.FILE, value=".env"),
    )
    assert engine.evaluate(action, policy).decision is Decision.DENY


# --- malformed input -------------------------------------------------------
def test_malformed_action_missing_fields():
    with pytest.raises(ValidationError):
        Action(session_id="s")  # missing tool/operation/resource


def test_malformed_action_bad_operation():
    with pytest.raises(ValidationError):
        Action(
            session_id="s", tool="fs", operation="teleport",
            resource=Resource(kind=ResourceKind.FILE, value="x"),
        )


def test_malformed_action_extra_field_rejected():
    with pytest.raises(ValidationError):
        Action(
            session_id="s", tool="fs", operation=Operation.READ,
            resource=Resource(kind=ResourceKind.FILE, value="x"),
            injected_admin=True,
        )


def test_empty_resource_value_rejected():
    with pytest.raises(ValidationError):
        Resource(kind=ResourceKind.FILE, value="")
