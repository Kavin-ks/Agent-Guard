// Presentation helpers. Risk bands are a display mapping over the backend's
// numeric risk_score — they never change any decision.

import type { Decision } from "../types";

export type RiskBand = "Low" | "Medium" | "High" | "Critical";

export function riskBand(score: number): RiskBand {
  if (score >= 85) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}

export function decisionClass(d: Decision | string): string {
  if (d === "ALLOW") return "allow";
  if (d === "ASK") return "ask";
  if (d === "DENY") return "deny";
  return "muted";
}

export function riskClass(score: number): string {
  return riskBand(score).toLowerCase();
}

export function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return iso;
  }
}

export function formatDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
