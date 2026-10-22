import { randomUUID } from "node:crypto";
import type { EvaluateRequest } from "../schemas/evaluate.schema.js";
import type { Advisory, AuditEvent, Decision } from "../types.js";

const sensitiveValuePatterns = [
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
    advisory: input.advisory ?? null,
    type: input.type ?? "EVALUATION",
  };
}

export function createApprovalId(): string {
  return `apr_${randomUUID()}`;
}
