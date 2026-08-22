"""
AgentGuardClient — a thin, reusable HTTP client for the Agent Guard API.

Responsibilities are strictly limited to API communication: it does NOT execute
tools and does NOT make security decisions. Every failure mode maps to a typed
GuardError so the caller can fail closed.

Security: the client never logs request payloads or any secret material — only
non-sensitive metadata (decision, resource, status).
"""

from __future__ import annotations

import logging

import httpx

from .errors import GuardAuthError, GuardProtocolError, GuardUnavailable

logger = logging.getLogger("agentguard.sdk.client")


class AgentGuardClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        api_key: str = "",
        timeout: float = 8.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key
        self._owns_client = client is None
        self._client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "AgentGuardClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- internals ---------------------------------------------------------
    def _headers(self) -> dict:
        return {"X-API-Key": self._api_key}

    def _request(self, method: str, path: str, json: dict | None = None) -> dict:
        try:
            resp = self._client.request(method, path, json=json, headers=self._headers())
        except httpx.TimeoutException as exc:
            raise GuardUnavailable(f"request timed out: {exc}") from exc
        except httpx.TransportError as exc:  # connection refused, DNS, etc.
            raise GuardUnavailable(f"cannot reach Agent Guard: {exc}") from exc

        if resp.status_code in (401, 403):
            raise GuardAuthError("authentication with Agent Guard failed")
        if resp.status_code >= 400:
            raise GuardProtocolError(f"unexpected status {resp.status_code}")
        try:
            return resp.json()
        except Exception as exc:  # malformed/undecodable body
            raise GuardProtocolError("malformed response from Agent Guard") from exc

    # -- API surface -------------------------------------------------------
    def evaluate(self, action: dict) -> dict:
        result = self._request("POST", "/guard/evaluate", json=action)
        logger.debug("evaluate: resource=%s -> %s", action.get("resource"), result.get("decision"))
        return result

    def get_approval(self, approval_id: str) -> dict:
        return self._request("GET", f"/approvals/{approval_id}")

    def get_audit_event(self, event_id: str) -> dict:
        return self._request("GET", f"/audit/{event_id}")

    def approve(self, approval_id: str, approver: str = "human") -> dict:
        return self._request("POST", f"/approvals/{approval_id}/approve", json={"approver": approver})

    def reject(self, approval_id: str, approver: str = "human") -> dict:
        return self._request("POST", f"/approvals/{approval_id}/reject", json={"approver": approver})

    def consume(self, approval_id: str, action: dict) -> dict:
        return self._request("POST", f"/approvals/{approval_id}/consume", json=action)

    def record_execution(self, event_id: str, status: str) -> dict:
        return self._request("POST", f"/audit/{event_id}/execution", json={"status": status})

    def register_agent(self, session_id: str, agent_name: str, source: str = "agent") -> dict:
        return self._request("POST", "/agents/register",
                             json={"session_id": session_id, "agent_name": agent_name, "source": source})
