import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ApprovalsPage } from "../pages/ApprovalsPage";
import { approval } from "./fixtures";

vi.mock("../api/client", () => {
  class ApiError extends Error {
    constructor(m: string, public status = 0, public kind = "server") { super(m); }
  }
  return { ApiError, api: {
    listApprovals: vi.fn(), approve: vi.fn(), reject: vi.fn(),
    listAudit: vi.fn(), evaluate: vi.fn(), consume: vi.fn(), reportExecution: vi.fn(),
    getAudit: vi.fn(), health: vi.fn(),
  } };
});
import { api } from "../api/client";

const mList = api.listApprovals as unknown as ReturnType<typeof vi.fn>;
const mApprove = api.approve as unknown as ReturnType<typeof vi.fn>;
const mReject = api.reject as unknown as ReturnType<typeof vi.fn>;

describe("Approval Queue", () => {
  beforeEach(() => vi.clearAllMocks());

  it("displays a pending ASK approval card", async () => {
    mList.mockResolvedValue({ items: [approval()], total: 1, limit: 50, offset: 0 });
    render(<ApprovalsPage />);
    expect(await screen.findByText("delete src/generated.jsx")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
  });

  it("calls the real backend approve API when Approve is clicked", async () => {
    mList.mockResolvedValue({ items: [approval()], total: 1, limit: 50, offset: 0 });
    mApprove.mockResolvedValue(approval({ status: "APPROVED" }));
    render(<ApprovalsPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(mApprove).toHaveBeenCalledWith("ap_1"));
  });

  it("calls the real backend reject API when Reject is clicked", async () => {
    mList.mockResolvedValue({ items: [approval()], total: 1, limit: 50, offset: 0 });
    mReject.mockResolvedValue(approval({ status: "REJECTED" }));
    render(<ApprovalsPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Reject" }));
    await waitFor(() => expect(mReject).toHaveBeenCalledWith("ap_1"));
  });
});
