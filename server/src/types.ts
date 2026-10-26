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
  decision: Decision | "INSPECTED";
  ruleId: string;
  reason: string;
  executed: boolean;
  approvalId: string | null;
  inspectionId?: string | null;
  destination?: "local" | "external" | null;
  advisory: Advisory | null;
  type: "EVALUATION" | "APPROVAL_DECISION" | "DOCUMENT_INSPECTION";
  documentName?: string;
  findingCount?: number;
  reportRiskLevel?: FindingSeverity | "UNKNOWN";
  reportStatus?: DocumentReportStatus;
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
  inspectionId?: string;
  destination?: "local" | "external";
  status: ApprovalStatus;
  createdAt: string;
  decidedAt?: string;
  reviewer?: string;
  note?: string;
}

export type FindingSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type FindingCategory = "PERSONAL_DATA" | "CREDENTIAL" | "SUSPICIOUS_INSTRUCTION";

export interface InspectionFinding {
  id: string;
  category: FindingCategory;
  type: string;
  severity: FindingSeverity;
  confidence: number;
  location: { page: number | null; line: number | null };
  evidence: string;
  description: string;
  ruleId?: string;
  maskedSample?: string;
}

export type DocumentReportStatus = "COMPLETE" | "DETERMINISTIC_ONLY" | "PARTIAL";
export type DocumentReportSource = "DETERMINISTIC" | "AI";

export interface DocumentReportFinding {
  id: string;
  source: DocumentReportSource;
  category: string;
  type: string;
  severity: FindingSeverity;
  confidence: number;
  ruleId?: string;
  explanation: string;
  recommendation: string;
  evidence: string;
  evidenceReferences: Array<{
    page: number | null;
    line: number;
    chunk: number | null;
  }>;
}

export type DocumentDocumentCoverage = {
  format: string; extractedPages: number | null; inspectedPages: number | null; textSegments: number;
  limitations: string[];
};

export type DocumentSummaryTopic = "BUSINESS" | "FINANCIAL" | "IDENTITY" | "CONTRACT" | "CONTACTS" | "OPERATIONS" | "CORRESPONDENCE";
export type DocumentSummaryPurpose = "PLAN" | "RECORD" | "AGREEMENT" | "COMMUNICATION" | "INSTRUCTIONS" | "MIXED_OR_UNCLEAR";
export type DocumentContentSummary = {
  status: "AI_EXCERPTS" | "DETERMINISTIC_FALLBACK" | "UNAVAILABLE";
  topics: DocumentSummaryTopic[];
  purpose: DocumentSummaryPurpose;
  text: string;
};

export type DocumentAIScope = {
  status: "COMPLETED" | "PARTIAL" | "DISABLED" | "UNAVAILABLE" | "SKIPPED"; submittedChunks: number;
  locations: Array<{ page: number | null; line: number }>; locationsTruncated: boolean; boundedRedactedExcerpts: true;
  completeDocumentReviewed: false;
};

export interface DocumentSecurityReport {
  version: 1;
  status: DocumentReportStatus;
  riskLevel: FindingSeverity | "UNKNOWN";
  summary: string;
  truncated: boolean;
  findings: DocumentReportFinding[];
  documentSummary?: DocumentContentSummary;
  documentCoverage?: DocumentDocumentCoverage;
  aiScope: DocumentAIScope;
  coverage: {
    extraction: "COMPLETED";
    deterministic: "COMPLETED" | "INCOMPLETE";
    ai: "COMPLETED" | "DISABLED" | "INCOMPLETE" | "UNAVAILABLE" | "NO_CONTENT" | "NO_FINDING_CONTEXT";
    totalChunks: number;
    completedChunks: number;
    failedChunks: number;
  };
}

export interface InspectionRecord {
  inspectionId: string;
  agentId: string;
  status: "COMPLETED" | "FAILED";
  originalName: string;
  mediaType: string;
  sizeBytes: number;
  sha256: string;
  findings: InspectionFinding[];
  summary: {
    totalFindings: number;
    truncated: boolean;
    bySeverity: Record<FindingSeverity, number>;
  };
  report?: DocumentSecurityReport;
  createdAt: string;
  expiresAt: Date;
}

export interface Scenario {
  id: string;
  title: string;
  request: Omit<EvaluateRequest, "context">;
}
