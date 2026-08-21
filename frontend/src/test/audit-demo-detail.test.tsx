import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuditPage } from "../pages/AuditPage";
import { DemoPage } from "../pages/DemoPage";
import { ActionDetail } from "../components/ActionDetail";
import { auditEvent, denyEnv } from "./fixtures";

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

describe("Audit page", () => {
  beforeEach(() => vi.clearAllMocks());

  it("filters audit events by decision", async () => {
    mList.mockResolvedValue({ items: [denyEnv], total: 1, limit: 15, offset: 0 });
    render(<AuditPage />);
    await screen.findByText("read .env");
    // The first combobox is the Decision filter.
    fireEvent.change(screen.getAllByRole("combobox")[0], { target: { value: "DENY" } });
    await waitFor(() =>
      expect(mList).toHaveBeenCalledWith(expect.objectContaining({ decision: "DENY" })),
    );
  });
});

describe("Action detail redaction", () => {
  it("shows redacted secret fingerprints, never raw secrets", () => {
    const ev = auditEvent({
      sensitive_data_detected: true,
      secrets: [{ type: "anthropic_api_key", fingerprint: "sk-…HHHH", entropy: 4.6 }],
    });
    render(<ActionDetail event={ev} onClose={() => {}} />);
    expect(screen.getByText(/sk-…HHHH/)).toBeInTheDocument();
    // A full-looking secret must never appear.
    expect(screen.queryByText(/sk-ant-api03-[A-Za-z0-9]{10,}/)).toBeNull();
  });
});

describe("Demo page", () => {
  it("renders all five scenarios", () => {
    render(<DemoPage />);
    expect(screen.getByText("Safe frontend read")).toBeInTheDocument();
    expect(screen.getByText("Secret access")).toBeInTheDocument();
    expect(screen.getByText(/Destructive action → approve/)).toBeInTheDocument();
    expect(screen.getByText(/Destructive action → reject/)).toBeInTheDocument();
    expect(screen.getByText("Approval-reuse attack")).toBeInTheDocument();
  });

  it("runs a scenario against the backend and shows the decision", async () => {
    (api.evaluate as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      decision: "DENY", risk_score: 94, reason: "protected", event_id: "ev_env",
      approval_required: false, approval_id: null, execution_status: "BLOCKED",
    });
    render(<DemoPage />);
    fireEvent.click(screen.getAllByRole("button", { name: "Run" })[1]); // scenario 2
    await waitFor(() => expect(api.evaluate).toHaveBeenCalled());
    expect(await screen.findByText(/Tool execution prevented/)).toBeInTheDocument();
  });
});
