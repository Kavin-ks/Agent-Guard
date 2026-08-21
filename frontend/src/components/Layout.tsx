import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { api } from "../api/client";

const NAV = [
  { to: "/", label: "Dashboard", icon: "▦", end: true },
  { to: "/approvals", label: "Approval Queue", icon: "⚑", end: false },
  { to: "/audit", label: "Audit Log", icon: "▤", end: false },
  { to: "/integration", label: "Integration", icon: "⇄", end: false },
  { to: "/demo", label: "Live Demo", icon: "▷", end: false },
];

const TITLES: Record<string, { t: string; s: string }> = {
  "/": { t: "Runtime Security Monitor", s: "Live evaluation of every agent action" },
  "/approvals": { t: "Approval Queue", s: "Human-in-the-loop review of ASK decisions" },
  "/audit": { t: "Audit Log", s: "Complete, redacted record of every decision" },
  "/integration": { t: "Agent & IDE Integration", s: "Connect MCP-capable agents through Agent Guard" },
  "/demo": { t: "Live Demo", s: "Scenarios run against the real Agent Guard backend" },
};

export function Layout() {
  const loc = useLocation();
  const meta = TITLES[loc.pathname] ?? { t: "Agent Guard", s: "" };
  const [online, setOnline] = useState<boolean | null>(null);
  const [version, setVersion] = useState<string>("");

  useEffect(() => {
    let alive = true;
    const check = () =>
      api.health()
        .then((h) => { if (alive) { setOnline(true); setVersion(h.version); } })
        .catch(() => { if (alive) setOnline(false); });
    check();
    const id = setInterval(check, 10000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="brand">
          <div className="brand-mark">AG</div>
          <div>
            <div className="brand-name">Agent Guard</div>
            <div className="brand-sub">Authorization Firewall</div>
          </div>
        </div>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} end={n.end}
            className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}>
            <span className="nav-icon">{n.icon}</span>{n.label}
          </NavLink>
        ))}
        <div className="nav-spacer" />
        <div className="nav-item" style={{ cursor: "default" }}>
          <span className={`dot ${online ? "ok" : "off"}`} />
          <span className="faint" style={{ fontSize: 12 }}>
            {online === null ? "Checking…" : online ? `Backend online · v${version}` : "Backend offline"}
          </span>
        </div>
      </nav>

      <div className="main">
        <div className="topbar">
          <div>
            <div className="page-title">{meta.t}</div>
            <div className="page-sub">{meta.s}</div>
          </div>
          <span className="badge demo" title="All data comes from the real Agent Guard backend">
            <span className="dot" style={{ background: "var(--brand)" }} />
            DEMO MODE · LIVE BACKEND
          </span>
        </div>
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
