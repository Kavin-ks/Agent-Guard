"""
Storage abstractions.

The service layer depends ONLY on these interfaces — never on a concrete DB. A
SQLite implementation ships for the prototype; a PostgreSQL adapter can be added
later behind the same interfaces without touching the security engine or service.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from agentguard.audit import AgentSession, ApprovalRequest, AuditEvent


class AuditStore(ABC):
    @abstractmethod
    def add(self, event: AuditEvent) -> None: ...

    @abstractmethod
    def get(self, event_id: str) -> AuditEvent | None: ...

    @abstractmethod
    def list(
        self,
        *,
        decision: str | None = None,
        session_id: str | None = None,
        source: str | None = None,
        exclude_source: str | None = None,
        resource_contains: str | None = None,
        min_risk: int | None = None,
        goal_drift: bool | None = None,
        approval_status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEvent]: ...

    @abstractmethod
    def count(self, **filters) -> int: ...

    @abstractmethod
    def set_approval_status(self, event_id: str, status: str, approval_id: str | None) -> None: ...

    @abstractmethod
    def set_execution_status(self, event_id: str, status: str) -> None: ...


class ApprovalStore(ABC):
    @abstractmethod
    def add(self, approval: ApprovalRequest) -> None: ...

    @abstractmethod
    def get(self, approval_id: str) -> ApprovalRequest | None: ...

    @abstractmethod
    def list(
        self, *, status: str | None = None, session_id: str | None = None,
        limit: int = 50, offset: int = 0,
    ) -> list[ApprovalRequest]: ...

    @abstractmethod
    def update(self, approval: ApprovalRequest) -> None: ...


class SessionStore(ABC):
    @abstractmethod
    def get(self, session_id: str) -> AgentSession | None: ...

    @abstractmethod
    def upsert(self, session: AgentSession) -> None: ...

    @abstractmethod
    def record_call(self, session_id: str, agent_name: str, source: str, decision: str) -> AgentSession: ...

    @abstractmethod
    def list(self, *, limit: int = 100) -> list[AgentSession]: ...
