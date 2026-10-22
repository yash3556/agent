import type { EvaluateRequest } from "./schemas/evaluate.schema.js";

export type Decision = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
export type ApprovalStatus = "PENDING" | "APPROVED" | "REJECTED";
export type Advisory = {
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
  signals: string[];
  summary: string;
};

export interface AuditEvent {
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
}

export interface Approval {
  approvalId: string;
  eventId: string;
  agentId: string;
  tool: string;
  resource: string;
  status: ApprovalStatus;
  createdAt: string;
  decidedAt?: string;
  reviewer?: string;
  note?: string;
}

export interface Scenario {
  id: string;
  title: string;
  request: Omit<EvaluateRequest, "context">;
}
