import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api/client";
import type { AuditEvent } from "../types";
import { Loading, ErrorState, DecisionBadge } from "../components/common";
import { PipelineDiagram } from "../components/PipelineDiagram";
import { formatTime } from "../lib/format";

interface AgentRow {
  agent: string;
  session: string;
  actions: number;
  lastDecision: string;
  lastSeen: string;
}

function deriveAgents(events: AuditEvent[]): AgentRow[] {
  const map = new Map<string, AgentRow>();
  for (const e of events) {
    const key = `${e.agent_id}:${e.session_id}`;
    const row = map.get(key);
    if (row) {
      row.actions += 1;
    } else {
      map.set(key, { agent: e.agent_id, session: e.session_id, actions: 1,
                     lastDecision: e.decision, lastSeen: e.created_at });
    }
  }
  return [...map.values()].sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
}

export function IntegrationPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setEvents((await api.listAudit({ limit: 200 })).items);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load activity");
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  if (error && !events) return <ErrorState message={error} />;
  if (!events) return <Loading label="Loading integration status…" />;

  const agents = deriveAgents(events);
  const mcpActive = agents.some((a) => a.session.startsWith("mcp") || a.agent.includes("mcp"));
  const recent = events.slice(0, 8);

  return (
    <>
      <p className="pageintro">
        Agent Guard governs tool calls that agents route <b>through</b> it. Connect an MCP-capable
        IDE/agent (e.g. Claude Code) to the Agent Guard MCP server, or use the SDK/HTTP path — every
        tool call is then evaluated before it can execute. Agent Guard does not silently intercept an
        IDE's own internal tools; integration is required.
      </p>

      <div className="stat-grid" style={{ gridTemplateColumns: "repeat(4,1fr)" }}>
        <div className="stat">
          <div className="stat-label">MCP Server</div>
          <div className="stat-value" style={{ fontSize: 16, display: "flex", alignItems: "center", gap: 8 }}>
            <span className={`dot ${mcpActive ? "ok" : "off"}`} />
            {mcpActive ? "Active" : "Configured"}
          </div>
        </div>
        <div className="stat"><div className="stat-label">Connected agents</div><div className="stat-value">{agents.length}</div></div>
        <div className="stat"><div className="stat-label">Guarded calls</div><div className="stat-value">{events.length}</div></div>
        <div className="stat"><div className="stat-label">Blocked</div><div className="stat-value deny">{events.filter(e => e.decision === "DENY").length}</div></div>
      </div>

      <div className="info-2col" style={{ marginBottom: 18 }}>
        <div className="panel">
          <div className="panel-head"><span className="panel-title">Connect Claude Code (MCP)</span></div>
          <div style={{ padding: 16 }}>
            <ol className="steps" style={{ marginBottom: 14 }}>
              <li>Start the Agent Guard backend (uvicorn or <code>docker compose up</code>).</li>
              <li>Install the MCP deps: <code>pip install -r backend/requirements-mcp.txt</code>.</li>
              <li>Add the server to your project's <code>.mcp.json</code> (below), setting absolute paths, the API key, workspace, and goal.</li>
              <li>Reload the IDE — the guarded tools appear; every call is evaluated first.</li>
            </ol>
            <div className="codeblock">{`{
  "mcpServers": {
    "agent-guard": {
      "command": ".../backend/.venv/bin/python",
      "args": ["-m", "mcp_server"],
      "cwd": ".../backend",
      "env": {
        "AGENTGUARD_URL": "http://127.0.0.1:8000",
        "AGENTGUARD_API_KEY": "<backend key>",
        "AGENTGUARD_WORKSPACE": ".../your/project",
        "AGENTGUARD_GOAL": "Build a React frontend..."
      }
    }
  }
}`}</div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span className="panel-title">Generic SDK / HTTP path</span></div>
          <div style={{ padding: 16 }}>
            <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
              Any agent can wrap an existing tool with the SDK — no security code in the tool:
            </p>
            <div className="codeblock">{`from adapter import (GuardedExecutor,
    ToolRegistry, AgentGuardClient)

reg = ToolRegistry()
reg.add("delete_file", "delete", "file", delete_file)

client = AgentGuardClient(base_url, api_key)
guard = GuardedExecutor(client, reg)

r = guard.execute("delete_file", "src/old.jsx",
                  goal="Build a React frontend")
if r.executed:      # runs only if authorized
    use(r.output)`}</div>
            <p className="muted" style={{ fontSize: 12.5 }}>
              Or call <code>POST /guard/evaluate</code> directly and honor ALLOW / ASK / DENY. The
              deterministic engine remains the sole authority.
            </p>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="panel">
          <div className="panel-head"><span className="panel-title">Connected agents</span></div>
          <div className="panel-body">
            {agents.length === 0 ? (
              <div className="state">No agents have connected yet. Configure the MCP server or SDK above.</div>
            ) : (
              <>
                <div className="row head" style={{ gridTemplateColumns: "1fr 1fr 80px 100px 90px" }}>
                  <div>Agent</div><div>Session</div><div className="right">Calls</div><div className="right">Last</div><div className="right">Decision</div>
                </div>
                {agents.map((a) => (
                  <div className="row" key={a.agent + a.session} style={{ gridTemplateColumns: "1fr 1fr 80px 100px 90px", cursor: "default" }}>
                    <div className="res-main">{a.agent}</div>
                    <div className="res-sub mono">{a.session}</div>
                    <div className="right mono">{a.actions}</div>
                    <div className="right cell-time">{formatTime(a.lastSeen)}</div>
                    <div className="right"><DecisionBadge decision={a.lastDecision} /></div>
                  </div>
                ))}
              </>
            )}
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <div className="panel">
            <div className="panel-head"><span className="panel-title">Security flow</span></div>
            <PipelineDiagram decision={recent[0]?.decision ?? null} activeStage={recent[0] ? "decision" : undefined} />
          </div>
          <div className="panel">
            <div className="panel-head"><span className="panel-title">Recent guarded calls</span></div>
            <div className="panel-body">
              {recent.length === 0 ? <div className="state">No activity yet.</div> :
                recent.map((e) => (
                  <div className="row" key={e.event_id} style={{ gridTemplateColumns: "72px 1fr 84px", cursor: "default" }}>
                    <div className="cell-time">{formatTime(e.created_at)}</div>
                    <div className="res-main">{e.operation} {e.resource}</div>
                    <div className="right"><DecisionBadge decision={e.decision} /></div>
                  </div>
                ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
