import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { DashboardPage } from "../pages/DashboardPage";
import { auditEvent, denyEnv, askDelete } from "./fixtures";

vi.mock("../api/client", () => {
  class ApiError extends Error {
    constructor(m: string, public status = 0, public kind = "server") { super(m); }
  }
  return { ApiError, api: {
    listAudit: vi.fn(), listApprovals: vi.fn(), approve: vi.fn(), reject: vi.fn(),
    evaluate: vi.fn(), consume: vi.fn(), reportExecution: vi.fn(), getAudit: vi.fn(),
    health: vi.fn(), listAgents: vi.fn(() => Promise.resolve([])),
  } };
});
import { api, ApiError } from "../api/client";

const mockList = api.listAudit as unknown as ReturnType<typeof vi.fn>;
const mockAgents = api.listAgents as unknown as ReturnType<typeof vi.fn>;

describe("Dashboard", () => {
  beforeEach(() => { vi.clearAllMocks(); mockAgents.mockResolvedValue([]); });

  it("renders stats and live activity (dashboard rendering)", async () => {
    mockList.mockResolvedValue({ items: [auditEvent(), denyEnv, askDelete], total: 3, limit: 100, offset: 0 });
    render(<DashboardPage />);
    expect(await screen.findByText("Guarded Calls")).toBeInTheDocument();
    expect(await screen.findByText("Recent activity")).toBeInTheDocument();
  });

  it("displays an ALLOW action", async () => {
    mockList.mockResolvedValue({ items: [auditEvent()], total: 1, limit: 100, offset: 0 });
    render(<DashboardPage />);
    expect((await screen.findAllByText("read src/App.jsx")).length).toBeGreaterThan(0);
    expect((await screen.findAllByText("ALLOW")).length).toBeGreaterThan(0);
  });

  it("displays a DENY action", async () => {
    mockList.mockResolvedValue({ items: [denyEnv], total: 1, limit: 100, offset: 0 });
    render(<DashboardPage />);
    expect((await screen.findAllByText("read .env")).length).toBeGreaterThan(0);
    expect((await screen.findAllByText("DENY")).length).toBeGreaterThan(0);
  });

  it("opens action detail when a row is clicked", async () => {
    mockList.mockResolvedValue({ items: [denyEnv], total: 1, limit: 100, offset: 0 });
    render(<DashboardPage />);
    fireEvent.click((await screen.findAllByText("read .env"))[0]); // activity row
    expect(await screen.findByText("Action detail")).toBeInTheDocument();
    expect(screen.getByText("PR::**/.env")).toBeInTheDocument(); // matched rule in drawer
  });

  it("shows a loading state before data resolves", () => {
    mockList.mockReturnValue(new Promise(() => {})); // never resolves
    render(<DashboardPage />);
    expect(screen.getByText(/Connecting to Agent Guard/i)).toBeInTheDocument();
  });

  it("shows an error state on API failure", async () => {
    mockList.mockRejectedValue(new ApiError("Cannot reach Agent Guard backend", 0, "network"));
    render(<DashboardPage />);
    expect(await screen.findByText(/Cannot reach Agent Guard backend/i)).toBeInTheDocument();
  });
});
