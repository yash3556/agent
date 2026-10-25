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
  inspectionId?: string;
  destination?: "local" | "external";
};
export type EvaluateResponse = {
  eventId: string;
  decision: Decision | "INSPECTED";
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
  type: "EVALUATION" | "APPROVAL_DECISION" | "DOCUMENT_INSPECTION";
  documentName?: string;
  findingCount?: number;
  reportRiskLevel?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";
  reportStatus?: "COMPLETE" | "DETERMINISTIC_ONLY" | "PARTIAL";
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
  ai: "configured" | "unavailable" | "disabled";
};
export type InspectionResponse = {
  inspectionId: string;
  status: "COMPLETED";
  document: { originalName: string; mediaType: string; sizeBytes: number };
  findings: {
    id: string;
    category: "PERSONAL_DATA" | "CREDENTIAL" | "SUSPICIOUS_INSTRUCTION";
    type: string;
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    confidence: number;
    location: { page: number | null; line: number | null };
    evidence: string;
    description: string;
  }[];
  summary: {
    totalFindings: number;
    truncated: boolean;
    bySeverity: Record<"LOW" | "MEDIUM" | "HIGH" | "CRITICAL", number>;
  };
  analysis: {
    deterministic: "COMPLETED";
    aiAdvisory: "DISABLED" | "UNAVAILABLE" | "AVAILABLE" | "NOT_NEEDED";
    aiFailure?: { code: string; message: string };
  };
  report: {
    version: 1;
    status: "COMPLETE" | "DETERMINISTIC_ONLY" | "PARTIAL";
    riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";
    summary: string;
    truncated: boolean;
    findings: {
      id: string;
      source: "DETERMINISTIC" | "AI";
      category: string;
      type: string;
      severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
      confidence: number;
      explanation: string;
      recommendation: string;
      evidenceReferences: { page: number | null; line: number; chunk: number | null }[];
    }[];
    coverage: {
      extraction: "COMPLETED";
      deterministic: "COMPLETED" | "INCOMPLETE";
      ai: "COMPLETED" | "DISABLED" | "INCOMPLETE" | "UNAVAILABLE" | "NO_CONTENT" | "NO_FINDING_CONTEXT";
      totalChunks: number;
      completedChunks: number;
      failedChunks: number;
    };
  };
};
export type ApiError = { error: string; message: string; details?: unknown[] };
