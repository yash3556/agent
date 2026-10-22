import { randomUUID } from "node:crypto";
import type { EvaluateRequest } from "../schemas/evaluate.schema.js";
import type { Advisory, AuditEvent, Decision } from "../types.js";

const sensitiveValuePatterns = [
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  /(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)/g,
  /\b(?:token|api[_-]?key|secret|password|credential)\s*[:=]\s*[^\s,;]+/gi,
  /\b(?:mongodb(?:\+srv)?|https?):\/\/[^\s]+/gi,
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]+=*/gi,
  /\b(?:sk|ghp|gho|xox[baprs])-?[A-Za-z0-9_-]{12,}\b/gi,
  /\bAKIA[0-9A-Z]{16}\b/g,
];

export function redact(value: string): string {
  return sensitiveValuePatterns.reduce(
    (safe, pattern) => safe.replace(pattern, "[REDACTED]"),
    value,
  );
}

export function createAuditEvent(input: {
  request: EvaluateRequest;
  decision: Decision;
  ruleId: string;
  reason: string;
  approvalId?: string | null;
  inspectionId?: string | null;
  destination?: "local" | "external";
  advisory?: Advisory | null;
  type?: "EVALUATION" | "APPROVAL_DECISION";
}): AuditEvent {
  return {
    eventId: `evt_${randomUUID()}`,
    timestamp: new Date().toISOString(),
    agentId: input.request.agentId,
    tool: input.request.tool,
    resource: redact(input.request.resource),
    decision: input.decision,
    ruleId: input.ruleId,
    reason: input.reason,
    executed: false,
    approvalId: input.approvalId ?? null,
    ...(input.inspectionId ? { inspectionId: input.inspectionId } : {}),
    ...(input.destination ? { destination: input.destination } : {}),
    advisory: input.advisory ?? null,
    type: input.type ?? "EVALUATION",
  };
}

export function createApprovalId(): string {
  return `apr_${randomUUID()}`;
}
