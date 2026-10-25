import type { AuditStore } from "../config/database.js";
import { ApiError, AuditUnavailableError } from "../errors.js";
import { createApprovalId, createAuditEvent, sanitizeAuditEvent } from "./audit.service.js";
import { redactSensitiveText } from "./redaction.js";
import { evaluatePolicy } from "./policy-engine.js";
import { getRiskAdvisory } from "../ai/risk-advisor.js";
import { executeSyntheticTool, type ToolExecutor } from "./tool-simulator.js";
import type { Approval, AuditEvent } from "../types.js";
import type { EvaluateRequest } from "../schemas/evaluate.schema.js";

async function persist<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new AuditUnavailableError();
  }
}

export async function evaluateAction(
  store: AuditStore,
  request: EvaluateRequest,
  executeTool: ToolExecutor = executeSyntheticTool,
) {
  const inspection = request.inspectionId
    ? await persist(() => store.getInspection(request.inspectionId!))
    : null;
  const policy = evaluatePolicy({ ...request, inspection });
  const canonicalRequest = { ...request, resource: policy.normalizedResource };
  const advisory = await getRiskAdvisory({
    ...canonicalRequest,
    resource: redactSensitiveText(canonicalRequest.resource),
    ...(canonicalRequest.context === undefined
      ? {}
      : { context: redactSensitiveText(canonicalRequest.context) }),
  });
  const approvalId = policy.decision === "REQUIRE_APPROVAL" ? createApprovalId() : null;
  const event = createAuditEvent({
    request: canonicalRequest,
    decision: policy.decision,
    ruleId: policy.ruleId,
    reason: policy.reason,
    approvalId,
    inspectionId: request.inspectionId,
    destination: request.destination,
    advisory,
  });

  let approval: Approval | undefined;
  if (approvalId) {
    approval = {
      approvalId,
      eventId: event.eventId,
      agentId: request.agentId,
      tool: request.tool,
      resource: redactSensitiveText(policy.normalizedResource),
      ...(request.inspectionId ? { inspectionId: request.inspectionId } : {}),
      ...(request.destination ? { destination: request.destination } : {}),
      status: "PENDING",
      createdAt: event.timestamp,
    };
  }

  await persist(() => store.saveEvaluation(event, approval));

  if (policy.decision === "ALLOW") {
    try {
      executeTool(canonicalRequest);
    } catch (error) {
      if (error instanceof ApiError) throw error;
      event.reason = `${event.reason} Synthetic execution failed.`;
      await persist(() => store.updateEvent(event));
      throw new ApiError(500, "INTERNAL_ERROR", "The synthetic operation failed.");
    }

    event.executed = true;
    try {
      await store.updateEvent(event);
    } catch {
      throw new ApiError(
        500,
        "INTERNAL_ERROR",
        "The synthetic operation completed, but its audit outcome could not be recorded.",
      );
    }
  }

  return {
    eventId: event.eventId,
    decision: event.decision,
    reason: event.reason,
    ruleId: event.ruleId,
    ...(approvalId ? { approvalId } : {}),
    executed: event.executed,
    advisory: event.advisory,
    timestamp: event.timestamp,
  };
}

export async function listAuditEvents(store: AuditStore, limit: number): Promise<AuditEvent[]> {
  const events = await persist(() => store.listEvents(limit));
  return events.map(sanitizeAuditEvent);
}
