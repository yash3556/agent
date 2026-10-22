import { Router } from "express";
import type { AuditStore } from "../config/database.js";
import { ApiError } from "../errors.js";
import {
  approvalDecisionSchema,
  approvalIdSchema,
  approvalsQuerySchema,
} from "../schemas/evaluate.schema.js";
import { decideApproval, listApprovals } from "../services/approval.service.js";
import type { ApprovalStatus } from "../types.js";
import { executeSyntheticTool, type ToolExecutor } from "../services/tool-simulator.js";

const approvalStatusByFilter = {
  pending: "PENDING",
  approved: "APPROVED",
  rejected: "REJECTED",
} as const satisfies Record<"pending" | "approved" | "rejected", ApprovalStatus>;

export function createApprovalsRouter(
  store: AuditStore,
  executeTool: ToolExecutor = executeSyntheticTool,
): Router {
  const router = Router();

  router.get("/", async (request, response, next) => {
    try {
      const parsed = approvalsQuerySchema.safeParse(request.query);
      if (!parsed.success) {
        throw new ApiError(400, "VALIDATION_ERROR", "Query validation failed.", parsed.error.issues);
      }
      const status = parsed.data.status ? approvalStatusByFilter[parsed.data.status] : undefined;
      response.json({ approvals: await listApprovals(store, status) });
    } catch (error) {
      next(error);
    }
  });

  router.post("/:id/decision", async (request, response, next) => {
    try {
      const parsedId = approvalIdSchema.safeParse(request.params.id);
      if (!parsedId.success) throw new ApiError(404, "NOT_FOUND", "Approval was not found.");
      const parsed = approvalDecisionSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new ApiError(400, "VALIDATION_ERROR", "Request validation failed.", parsed.error.issues);
      }
      response.json(await decideApproval(store, parsedId.data, parsed.data, executeTool));
    } catch (error) {
      next(error);
    }
  });

  return router;
}
