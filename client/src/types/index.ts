export type Decision = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
export type ApprovalStatus = "PENDING" | "APPROVED" | "REJECTED";
export type Advisory = {
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
  signals: string[];
  summary: string;
};
export type EvaluateRequest = {
  agentId: string;
  tool: string;
  resource: string;
  context?: string;
};
export type EvaluateResponse = {
  eventId: string;
  decision: Decision;
  reason: string;
  ruleId: string;
  approvalId?: string;
  executed: boolean;
  advisory: Advisory | null;
  timestamp: string;
};
export type AuditEvent = {
  eventId: string;
  timestamp: string;
  agentId: string;
  tool: string;
  resource: string;
  decision: Decision;
  ruleId: string;
  reason: string;
  executed: boolean;
  approvalId: string | null;
  advisory: Advisory | null;
  type: "EVALUATION" | "APPROVAL_DECISION";
  approvalStatus?: "APPROVED" | "REJECTED" | null;
  reviewer?: string | null;
  note?: string | null;
};
export type Approval = {
  approvalId: string;
  eventId: string;
  tool: string;
  resource: string;
  status: ApprovalStatus;
  createdAt: string;
  decidedAt?: string;
  reviewer?: string;
  note?: string;
};
export type Scenario = { id: string; title: string; request: EvaluateRequest };
export type Health = {
  status: string;
  time: string;
  db: "connected" | "error";
  storage?: "mongodb" | "memory";
  ai: "available" | "unavailable" | "disabled";
};
export type ApiError = { error: string; message: string; details?: unknown[] };
