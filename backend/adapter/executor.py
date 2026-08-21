"""
GuardedExecutor — the enforcement point.

Guarantee: the wrapped tool function is invoked ONLY in two paths, and never
otherwise:
  * decision == ALLOW, or
  * decision == ASK -> human APPROVE -> fingerprint-verified consume authorizes.

Every other outcome (DENY, reject, expired, fingerprint mismatch, API error,
timeout, malformed response, auth failure) leaves the tool uncalled — fail-closed.

The same request dict used for evaluate is reused for consume, so the approved
fingerprint matches exactly; a different action presented to consume mismatches
and is refused (reuse attack). Agent Guard does not execute tools — this adapter
does, on the agent's behalf, only after authorization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .approval import ApprovalHandler, AutoReject
from .client import AgentGuardClient
from .errors import GuardError
from .registry import ToolRegistry

logger = logging.getLogger("agentguard.sdk.executor")


@dataclass
class ExecutionResult:
    decision: str                 # ALLOW | ASK | DENY | ERROR
    executed: bool                # was the wrapped tool actually invoked?
    authorized: bool              # did Agent Guard authorize execution?
    execution_status: str         # SUCCESS | BLOCKED | FAILED | NOT_EXECUTED
    reason: str = ""
    event_id: str | None = None
    approval_id: str | None = None
    risk_score: int | None = None
    output: Any = None            # tool return value, if executed
    details: dict = field(default_factory=dict)


class GuardedExecutor:
    def __init__(
        self,
        client: AgentGuardClient,
        registry: ToolRegistry,
        approval_handler: ApprovalHandler | None = None,
        *,
        session_id: str = "sim-agent",
        agent_id: str = "sim-agent",
        approver: str = "human",
    ) -> None:
        self._client = client
        self._registry = registry
        self._approval = approval_handler or AutoReject()
        self._session_id = session_id
        self._agent_id = agent_id
        self._approver = approver

    # -- request construction ---------------------------------------------
    def _build_request(self, tool_name, resource, goal, payload, destination, context) -> dict:
        tool = self._registry.get(tool_name)
        req = {
            "goal": goal,
            "action": tool.operation,
            "resource": resource,
            "resource_kind": tool.resource_kind,
            "tool": tool.name,
            "session_id": self._session_id,
            "agent_id": self._agent_id,
        }
        if payload is not None:
            req["payload"] = payload
        if destination is not None:
            req["destination"] = destination
        if context is not None:
            req["context"] = context
        return req

    # -- tool invocation (the ONLY place a tool is called) ----------------
    def _run_tool(self, tool_name, req, decision_label, event_id, risk) -> ExecutionResult:
        tool = self._registry.get(tool_name)
        call_kwargs = {
            "resource": req["resource"],
            "payload": req.get("payload"),
            "destination": req.get("destination"),
        }
        try:
            output = tool.fn(**call_kwargs)
        except Exception as exc:  # tool failed — record, do not crash the agent loop
            logger.info("tool '%s' failed on %s: %s", tool_name, req["resource"], type(exc).__name__)
            self._safe_record(event_id, "REPORTED_FAILED")
            return ExecutionResult(
                decision=decision_label, executed=True, authorized=True,
                execution_status="FAILED", reason=f"tool raised {type(exc).__name__}",
                event_id=event_id, risk_score=risk,
            )
        self._safe_record(event_id, "REPORTED_EXECUTED")
        return ExecutionResult(
            decision=decision_label, executed=True, authorized=True,
            execution_status="SUCCESS", reason="executed after authorization",
            event_id=event_id, risk_score=risk, output=output,
        )

    def _safe_record(self, event_id, status) -> None:
        if not event_id:
            return
        try:
            self._client.record_execution(event_id, status)
        except GuardError:
            pass  # best-effort; failure to record must not change enforcement

    # -- the guarded entry point ------------------------------------------
    def execute(
        self,
        tool_name: str,
        resource: str,
        *,
        goal: str,
        payload: str | None = None,
        destination: str | None = None,
        context: dict | None = None,
        on_ask: str = "handler",
    ) -> ExecutionResult:
        """Evaluate then enforce. ``on_ask`` controls ASK handling:

        * ``"handler"`` (default): resolve via the approval handler synchronously
          (used by tests / auto flows).
        * ``"defer"``: leave the approval PENDING and return an ``ASK`` result with
          the ``approval_id`` — the caller (e.g. an MCP host) surfaces it to a human
          and later calls ``execute_with_existing_approval``. The tool is not run.
        """
        req = self._build_request(tool_name, resource, goal, payload, destination, context)

        # 1) Evaluate FIRST. Any failure -> fail closed (tool never called).
        try:
            decision = self._client.evaluate(req)
        except GuardError as exc:
            logger.info("evaluate failed (%s) -> fail-closed, tool NOT executed", type(exc).__name__)
            return ExecutionResult(
                decision="ERROR", executed=False, authorized=False,
                execution_status="BLOCKED",
                reason=f"authorization undetermined ({type(exc).__name__}); failed closed",
            )

        label = decision.get("decision")
        event_id = decision.get("event_id")
        approval_id = decision.get("approval_id")
        risk = decision.get("risk_score")

        # 2) ALLOW -> execute.
        if label == "ALLOW":
            return self._run_tool(tool_name, req, "ALLOW", event_id, risk)

        # 3) DENY -> never execute.
        if label == "DENY":
            return ExecutionResult(
                decision="DENY", executed=False, authorized=False,
                execution_status="BLOCKED", reason=decision.get("reason", "denied"),
                event_id=event_id, risk_score=risk,
            )

        # 4) ASK -> human decision -> fingerprint-verified consume.
        if label == "ASK":
            base = ExecutionResult(
                decision="ASK", executed=False, authorized=False,
                execution_status="BLOCKED", event_id=event_id, approval_id=approval_id, risk_score=risk,
            )
            if on_ask == "defer":
                # Leave the approval PENDING for a human; do not run the tool.
                base.reason = decision.get("reason", "human approval required before execution")
                return base
            try:
                approve = self._approval.resolve(decision)
            except Exception as exc:  # a broken handler must not open the gate
                base.reason = f"approval handler error ({type(exc).__name__}); failed closed"
                return base

            if not approve:
                self._try(lambda: self._client.reject(approval_id, self._approver))
                base.reason = "human rejected the action; tool not executed"
                return base

            try:
                self._client.approve(approval_id, self._approver)
                consume = self._client.consume(approval_id, req)
            except GuardError as exc:
                base.reason = f"approval/consume failed ({type(exc).__name__}); failed closed"
                return base

            if not consume.get("authorized"):
                base.reason = f"consume refused: {consume.get('reason', 'not authorized')}"
                return base

            return self._run_tool(tool_name, req, "ASK", event_id, risk)

        # Unknown decision label -> fail closed.
        return ExecutionResult(
            decision=str(label), executed=False, authorized=False,
            execution_status="BLOCKED", reason="unrecognized decision; failed closed",
            event_id=event_id,
        )

    # -- reuse-attack surface: present an EXISTING approval for a NEW action
    def execute_with_existing_approval(
        self,
        approval_id: str,
        tool_name: str,
        resource: str,
        *,
        goal: str,
        payload: str | None = None,
        destination: str | None = None,
        context: dict | None = None,
    ) -> ExecutionResult:
        """Try to run a tool by consuming an approval that was granted for a
        (possibly different) action. Authorized only on an exact fingerprint match."""
        req = self._build_request(tool_name, resource, goal, payload, destination, context)
        try:
            consume = self._client.consume(approval_id, req)
        except GuardError as exc:
            return ExecutionResult(
                decision="ASK", executed=False, authorized=False,
                execution_status="BLOCKED",
                reason=f"consume failed ({type(exc).__name__}); failed closed",
                approval_id=approval_id,
            )
        if not consume.get("authorized"):
            return ExecutionResult(
                decision="ASK", executed=False, authorized=False,
                execution_status="BLOCKED",
                reason=f"consume refused: {consume.get('reason', 'not authorized')}",
                approval_id=approval_id,
            )
        return self._run_tool(tool_name, req, "ASK", None, None)

    def _try(self, fn) -> None:
        try:
            fn()
        except GuardError:
            pass
