"""
SQLite-backed persistence (survives application restarts).

Design:
  * Each store keeps its own connection (WAL mode) to a shared DB file — SQLite
    handles multi-connection access; writes are serialized with a process lock.
  * The full redacted model is stored as JSON in a ``data`` column; frequently
    filtered fields are also stored as indexed columns for fast queries.
  * No security logic lives here — this is pure storage.

Nothing raw/sensitive is written: the models handed in are already redacted.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from agentguard.audit import AgentSession, ApprovalRequest, AuditEvent

from .base import ApprovalStore, AuditStore, SessionStore

_LOCK = threading.RLock()


def _connect(path: str) -> sqlite3.Connection:
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")       # concurrent readers + one writer
    conn.execute("PRAGMA busy_timeout=5000;")      # wait up to 5s instead of erroring
    conn.execute("PRAGMA synchronous=NORMAL;")     # safe with WAL, faster
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _now() -> datetime:
    from datetime import timezone
    return datetime.now(timezone.utc)


class SqliteAuditStore(AuditStore):
    def __init__(self, path: str) -> None:
        self._conn = _connect(path)
        self._init()

    def _init(self) -> None:
        with _LOCK:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    action_id TEXT,
                    session_id TEXT,
                    decision TEXT,
                    risk_score INTEGER,
                    resource TEXT,
                    goal_drift INTEGER,
                    approval_status TEXT,
                    execution_status TEXT,
                    action_fingerprint TEXT,
                    source TEXT,
                    data TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
                CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision);
                CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id);
                CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_events(risk_score);
                CREATE INDEX IF NOT EXISTS idx_audit_drift ON audit_events(goal_drift);
                CREATE INDEX IF NOT EXISTS idx_audit_appr ON audit_events(approval_status);
                """
            )
            # Migrate pre-existing DBs that lack the source column BEFORE indexing it.
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(audit_events)")}
            if "source" not in cols:
                self._conn.execute("ALTER TABLE audit_events ADD COLUMN source TEXT")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_source ON audit_events(source)")
            self._conn.commit()

    def add(self, event: AuditEvent) -> None:
        with _LOCK:
            self._conn.execute(
                """INSERT OR REPLACE INTO audit_events
                   (event_id, created_at, action_id, session_id, decision, risk_score,
                    resource, goal_drift, approval_status, execution_status,
                    action_fingerprint, source, data)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.event_id, event.created_at.isoformat(), event.action_id,
                    event.session_id, event.decision, event.risk_score, event.resource,
                    1 if event.goal_drift else 0, event.approval_status,
                    event.execution_status, event.action_fingerprint, event.source,
                    event.model_dump_json(),
                ),
            )
            self._conn.commit()

    def get(self, event_id: str) -> AuditEvent | None:
        row = self._conn.execute(
            "SELECT data FROM audit_events WHERE event_id=?", (event_id,)
        ).fetchone()
        return AuditEvent.model_validate_json(row["data"]) if row else None

    def _where(self, decision, session_id, resource_contains, min_risk, goal_drift,
               approval_status, since, until, source=None, exclude_source=None):
        clauses, params = [], []
        if decision:
            clauses.append("decision=?"); params.append(decision)
        if session_id:
            clauses.append("session_id=?"); params.append(session_id)
        if source:
            clauses.append("source=?"); params.append(source)
        if exclude_source:
            clauses.append("(source IS NULL OR source<>?)"); params.append(exclude_source)
        if resource_contains:
            clauses.append("resource LIKE ?"); params.append(f"%{resource_contains}%")
        if min_risk is not None:
            clauses.append("risk_score>=?"); params.append(min_risk)
        if goal_drift is not None:
            clauses.append("goal_drift=?"); params.append(1 if goal_drift else 0)
        if approval_status:
            clauses.append("approval_status=?"); params.append(approval_status)
        if since:
            clauses.append("created_at>=?"); params.append(_iso(since))
        if until:
            clauses.append("created_at<=?"); params.append(_iso(until))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def list(self, *, decision=None, session_id=None, source=None, exclude_source=None,
             resource_contains=None, min_risk=None, goal_drift=None, approval_status=None,
             since=None, until=None, limit=50, offset=0) -> list[AuditEvent]:
        where, params = self._where(decision, session_id, resource_contains, min_risk,
                                    goal_drift, approval_status, since, until,
                                    source, exclude_source)
        rows = self._conn.execute(
            f"SELECT data FROM audit_events{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return [AuditEvent.model_validate_json(r["data"]) for r in rows]

    def count(self, *, decision=None, session_id=None, source=None, exclude_source=None,
              resource_contains=None, min_risk=None, goal_drift=None, approval_status=None,
              since=None, until=None) -> int:
        where, params = self._where(decision, session_id, resource_contains, min_risk,
                                    goal_drift, approval_status, since, until,
                                    source, exclude_source)
        row = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM audit_events{where}", params
        ).fetchone()
        return int(row["n"])

    def set_approval_status(self, event_id, status, approval_id) -> None:
        event = self.get(event_id)
        if event is None:
            return
        event.approval_status = status
        if approval_id is not None:
            event.approval_id = approval_id
        self.add(event)

    def set_execution_status(self, event_id, status) -> None:
        event = self.get(event_id)
        if event is None:
            return
        event.execution_status = status
        self.add(event)


class SqliteApprovalStore(ApprovalStore):
    def __init__(self, path: str) -> None:
        self._conn = _connect(path)
        self._init()

    def _init(self) -> None:
        with _LOCK:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    status TEXT,
                    session_id TEXT,
                    action_fingerprint TEXT,
                    data TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_appr_status ON approvals(status);
                CREATE INDEX IF NOT EXISTS idx_appr_created ON approvals(created_at);
                CREATE INDEX IF NOT EXISTS idx_appr_session ON approvals(session_id);
                """
            )
            self._conn.commit()

    def add(self, approval: ApprovalRequest) -> None:
        with _LOCK:
            self._conn.execute(
                """INSERT OR REPLACE INTO approvals
                   (approval_id, created_at, status, session_id, action_fingerprint, data)
                   VALUES (?,?,?,?,?,?)""",
                (approval.approval_id, approval.created_at.isoformat(), approval.status,
                 approval.session_id, approval.action_fingerprint, approval.model_dump_json()),
            )
            self._conn.commit()

    def get(self, approval_id: str) -> ApprovalRequest | None:
        row = self._conn.execute(
            "SELECT data FROM approvals WHERE approval_id=?", (approval_id,)
        ).fetchone()
        return ApprovalRequest.model_validate_json(row["data"]) if row else None

    def list(self, *, status=None, session_id=None, limit=50, offset=0) -> list[ApprovalRequest]:
        clauses, params = [], []
        if status:
            clauses.append("status=?"); params.append(status)
        if session_id:
            clauses.append("session_id=?"); params.append(session_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT data FROM approvals{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return [ApprovalRequest.model_validate_json(r["data"]) for r in rows]

    def update(self, approval: ApprovalRequest) -> None:
        self.add(approval)  # INSERT OR REPLACE


class SqliteSessionStore(SessionStore):
    """Registry of connected agent sessions (real agents, not demo)."""

    def __init__(self, path: str) -> None:
        self._conn = _connect(path)
        self._init()

    def _init(self) -> None:
        with _LOCK:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS agent_sessions (
                    session_id TEXT PRIMARY KEY,
                    last_seen TEXT NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sess_seen ON agent_sessions(last_seen);
                """
            )
            self._conn.commit()

    def get(self, session_id: str) -> AgentSession | None:
        row = self._conn.execute(
            "SELECT data FROM agent_sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        return AgentSession.model_validate_json(row["data"]) if row else None

    def upsert(self, session: AgentSession) -> None:
        with _LOCK:
            self._conn.execute(
                "INSERT OR REPLACE INTO agent_sessions (session_id, last_seen, data) VALUES (?,?,?)",
                (session.session_id, session.last_seen.isoformat(), session.model_dump_json()),
            )
            self._conn.commit()

    def record_call(self, session_id, agent_name, source, decision) -> AgentSession:
        with _LOCK:
            s = self.get(session_id) or AgentSession(
                session_id=session_id, agent_name=agent_name, source=source)
            s.agent_name = agent_name or s.agent_name
            s.source = source or s.source
            s.last_seen = _now()
            s.calls += 1
            s.last_decision = decision
            if decision == "ALLOW":
                s.allowed += 1
            elif decision == "ASK":
                s.asked += 1
            elif decision == "DENY":
                s.denied += 1
            self.upsert(s)
            return s

    def list(self, *, limit: int = 100) -> list[AgentSession]:
        rows = self._conn.execute(
            "SELECT data FROM agent_sessions ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [AgentSession.model_validate_json(r["data"]) for r in rows]
