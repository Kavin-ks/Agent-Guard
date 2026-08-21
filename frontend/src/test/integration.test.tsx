import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { IntegrationPage } from "../pages/IntegrationPage";
import { auditEvent } from "./fixtures";

vi.mock("../api/client", () => {
  class ApiError extends Error {
    constructor(m: string, public status = 0, public kind = "server") { super(m); }
  }
  return { ApiError, api: {
    listAudit: vi.fn(), listApprovals: vi.fn(), approve: vi.fn(), reject: vi.fn(),
    evaluate: vi.fn(), consume: vi.fn(), reportExecution: vi.fn(), getAudit: vi.fn(), health: vi.fn(),
  } };
});
import { api } from "../api/client";
const mList = api.listAudit as unknown as ReturnType<typeof vi.fn>;

describe("Integration page", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows MCP connection instructions and derives connected agents", async () => {
    mList.mockResolvedValue({
      items: [
        auditEvent({ agent_id: "mcp-agent", session_id: "mcp", decision: "ALLOW" }),
        auditEvent({ agent_id: "mcp-agent", session_id: "mcp", decision: "DENY", event_id: "ev2" }),
      ],
      total: 2, limit: 200, offset: 0,
    });
    render(<IntegrationPage />);
    expect(await screen.findByText("Connect Claude Code (MCP)")).toBeInTheDocument();
    expect(screen.getAllByText("Connected agents").length).toBeGreaterThan(0);
    // agent row derived from audit
    expect((await screen.findAllByText("mcp-agent")).length).toBeGreaterThan(0);
    // MCP status active because session starts with "mcp"
    expect(screen.getByText("Active")).toBeInTheDocument();
  });

  it("shows an empty state when no agents have connected", async () => {
    mList.mockResolvedValue({ items: [], total: 0, limit: 200, offset: 0 });
    render(<IntegrationPage />);
    expect(await screen.findByText(/No agents have connected yet/)).toBeInTheDocument();
  });
});
