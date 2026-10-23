import type { ApiError, Approval, AuditEvent, EvaluateRequest, EvaluateResponse, Health, Scenario } from "../types";

const API_BASE = (import.meta.env.VITE_API_BASE_URL?.trim() || "/api").replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } catch {
    throw { error: "NETWORK_ERROR", message: "Could not reach the backend. Check that the server is running." } satisfies ApiError;
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as ApiError | null;
    throw payload ?? { error: "HTTP_ERROR", message: `The backend returned ${response.status}.` };
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<Health>("/health"),
  scenarios: () => request<{ scenarios: Scenario[] }>("/scenarios"),
  evaluate: (body: EvaluateRequest) => request<EvaluateResponse>("/evaluate", { method: "POST", body: JSON.stringify(body) }),
  events: () => request<{ events: AuditEvent[] }>("/events?limit=50"),
  approvals: (status?: "pending" | "approved" | "rejected") => request<{ approvals: Approval[] }>(`/approvals${status ? `?status=${status}` : ""}`),
  decide: (id: string, decision: "APPROVED" | "REJECTED", note: string) => request<{ approval: Approval; eventId: string; executed: boolean }>(`/approvals/${encodeURIComponent(id)}/decision`, {
    method: "POST", body: JSON.stringify({ decision, reviewer: "demo-reviewer", ...(note.trim() ? { note: note.trim() } : {}) }),
  }),
};

export function errorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error && typeof error.message === "string") return error.message;
  return "Something went wrong. Please try again.";
}

export function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "error" in error && typeof error.error === "string" ? error.error : undefined;
}
