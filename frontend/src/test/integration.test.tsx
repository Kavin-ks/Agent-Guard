import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { IntegrationPage } from "../pages/IntegrationPage";
import { auditEvent, agent } from "./fixtures";

vi.mock("../api/client", () => {
  class ApiError extends Error {
    constructor(m: string, public status = 0, public kind = "server") { super(m); }
  }
  return { ApiError, api: {
    listAudit: vi.fn(), listAgents: vi.fn(), listApprovals: vi.fn(), approve: vi.fn(),
    reject: vi.fn(), evaluate: vi.fn(), consume: vi.fn(), reportExecution: vi.fn(),
    getAudit: vi.fn(), health: vi.fn(),
  } };
});
import { api } from "../api/client";
const mList = api.listAudit as unknown as ReturnType<typeof vi.fn>;
const mAgents = api.listAgents as unknown as ReturnType<typeof vi.fn>;

describe("Integration page", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows MCP instructions and the REAL connected-agent registry", async () => {
    mList.mockResolvedValue({ items: [auditEvent()], total: 1, limit: 200, offset: 0 });
    mAgents.mockResolvedValue([agent({ agent_name: "Antigravity", status: "connected" })]);
    render(<IntegrationPage />);
    expect(await screen.findByText("Connect Claude Code (MCP)")).toBeInTheDocument();
    expect(screen.getAllByText("Connected agents").length).toBeGreaterThan(0);
    expect((await screen.findAllByText("Antigravity")).length).toBeGreaterThan(0);
    // MCP status Active because a real session is connected.
    expect(screen.getByText("Active")).toBeInTheDocument();
  });

  it("shows an empty state when no agents have connected", async () => {
    mList.mockResolvedValue({ items: [], total: 0, limit: 200, offset: 0 });
    mAgents.mockResolvedValue([]);
    render(<IntegrationPage />);
    expect(await screen.findByText(/No agents have connected yet/)).toBeInTheDocument();
  });
});
