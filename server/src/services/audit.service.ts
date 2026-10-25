import { randomUUID } from "node:crypto";
import type { EvaluateRequest } from "../schemas/evaluate.schema.js";
import type { Advisory, AuditEvent, Decision } from "../types.js";
import { redactSensitiveText } from "./redaction.js";

function sanitizeAdvisory(advisory: Advisory | null | undefined): Advisory | null {
  if (!advisory) return null;
  return {
    ...advisory,
    signals: advisory.signals.map(redactSensitiveText),
    summary: redactSensitiveText(advisory.summary),
  };
}

export function sanitizeAuditEvent(event: AuditEvent): AuditEvent {
  return {
    ...event,
    agentId: redactSensitiveText(event.agentId),
    tool: redactSensitiveText(event.tool),
    resource: redactSensitiveText(event.resource),
    reason: redactSensitiveText(event.reason),
    ...(event.documentName === undefined ? {} : { documentName: redactSensitiveText(event.documentName) }),
    ...(event.reviewer === undefined ? {} : {
      reviewer: event.reviewer === null ? null : redactSensitiveText(event.reviewer),
    }),
    ...(event.note === undefined ? {} : {
      note: event.note === null ? null : redactSensitiveText(event.note),
    }),
    advisory: sanitizeAdvisory(event.advisory),
  };
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
    resource: redactSensitiveText(input.request.resource),
    decision: input.decision,
    ruleId: input.ruleId,
    reason: redactSensitiveText(input.reason),
    executed: false,
    approvalId: input.approvalId ?? null,
    ...(input.inspectionId ? { inspectionId: input.inspectionId } : {}),
    ...(input.destination ? { destination: input.destination } : {}),
    advisory: sanitizeAdvisory(input.advisory),
    type: input.type ?? "EVALUATION",
  };
}

export function createApprovalId(): string {
  return `apr_${randomUUID()}`;
}
