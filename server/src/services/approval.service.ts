import type { AuditStore } from "../config/database.js";
import { ApiError, AuditUnavailableError } from "../errors.js";
import type { ApprovalDecisionRequest } from "../schemas/evaluate.schema.js";
import { createAuditEvent, redact } from "./audit.service.js";
import { evaluatePolicy } from "./policy-engine.js";
import { executeSyntheticTool, type ToolExecutor } from "./tool-simulator.js";
import type { Approval, ApprovalStatus } from "../types.js";

async function persist<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new AuditUnavailableError();
  }
}

export async function listApprovals(
  store: AuditStore,
  status?: ApprovalStatus,
): Promise<Approval[]> {
  return persist(() => store.listApprovals(status));
}

async function removeUncommittedEvent(store: AuditStore, eventId: string): Promise<void> {
  try {
    await store.deleteEvent(eventId);
  } catch {
    console.error("Could not clean up an uncommitted approval audit event.");
    throw new AuditUnavailableError();
  }
}

export async function decideApproval(
  store: AuditStore,
  approvalId: string,
  input: ApprovalDecisionRequest,
  executeTool: ToolExecutor = executeSyntheticTool,
) {
  const existing = await persist(() => store.getApproval(approvalId));
  if (!existing) throw new ApiError(404, "NOT_FOUND", "Approval was not found.");
  if (existing.status !== "PENDING") {
    throw new ApiError(409, "ALREADY_DECIDED", "Approval has already been decided.");
  }

  const inspection = existing.inspectionId
    ? await persist(() => store.getInspection(existing.inspectionId!))
    : null;
  const policy = evaluatePolicy({
    tool: existing.tool,
    resource: existing.resource,
    agentId: existing.agentId,
    ...(existing.inspectionId ? { inspectionId: existing.inspectionId } : {}),
    ...(existing.destination ? { destination: existing.destination } : {}),
    inspection,
  });
  if (
    input.decision === "APPROVED"
    && (policy.decision !== "REQUIRE_APPROVAL" || !["R-004", "R-009"].includes(policy.ruleId))
  ) {
    if (existing.inspectionId) {
      throw new ApiError(409, "INSPECTION_UNAVAILABLE", "The inspected document is no longer eligible for export.");
    }
    throw new ApiError(500, "INTERNAL_ERROR", "Stored approval is no longer permitted.");
  }

  const reviewer = redact(input.reviewer);
  const note = input.note === undefined ? undefined : redact(input.note);
  const request = {
    agentId: existing.agentId,
    tool: existing.tool,
    resource: policy.normalizedResource,
  };
  const event = createAuditEvent({
    request,
    decision: "REQUIRE_APPROVAL",
    ruleId: input.decision === "REJECTED"
      ? existing.inspectionId ? "R-009" : "R-004"
      : policy.ruleId,
    reason: input.decision === "APPROVED"
      ? "The demo reviewer approved the action."
      : "The demo reviewer rejected the action.",
    approvalId,
    inspectionId: existing.inspectionId,
    destination: existing.destination,
    type: "APPROVAL_DECISION",
  });
  event.approvalStatus = input.decision;
  event.reviewer = reviewer;
  event.note = note ?? null;

  await persist(() => store.insertEvent(event));

  let transitioned: boolean;
  try {
    transitioned = await store.transitionApproval(
      approvalId,
      input.decision,
      event.timestamp,
      reviewer,
      note,
    );
  } catch {
    await removeUncommittedEvent(store, event.eventId);
    throw new AuditUnavailableError();
  }

  if (!transitioned) {
    await removeUncommittedEvent(store, event.eventId);
    const current = await persist(() => store.getApproval(approvalId));
    if (!current) throw new ApiError(404, "NOT_FOUND", "Approval was not found.");
    throw new ApiError(409, "ALREADY_DECIDED", "Approval has already been decided.");
  }

  if (input.decision === "APPROVED") {
    try {
      executeTool({ tool: existing.tool, resource: policy.normalizedResource });
    } catch {
      event.reason = `${event.reason} Synthetic execution failed.`;
      try {
        await store.updateEvent(event);
      } catch {
        throw new ApiError(500, "INTERNAL_ERROR", "The synthetic operation failed.");
      }
      throw new ApiError(500, "INTERNAL_ERROR", "The synthetic operation failed.");
    }
    event.executed = true;
  }

  try {
    await store.updateEvent(event);
  } catch {
    throw new ApiError(
      500,
      "INTERNAL_ERROR",
      "The synthetic operation completed, but its audit outcome could not be recorded.",
    );
  }
  const updatedApproval: Approval = {
    ...existing,
    status: input.decision,
    ...(existing.inspectionId ? { inspectionId: existing.inspectionId } : {}),
    ...(existing.destination ? { destination: existing.destination } : {}),
    decidedAt: event.timestamp,
    reviewer,
    ...(note === undefined ? {} : { note }),
  };

  return {
    approval: updatedApproval,
    eventId: event.eventId,
    executed: event.executed,
  };
}
