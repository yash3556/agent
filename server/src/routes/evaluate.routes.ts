import { Router } from "express";
import type { AuditStore } from "../config/database.js";
import { ApiError } from "../errors.js";
import { evaluateRequestSchema } from "../schemas/evaluate.schema.js";
import { evaluateAction } from "../services/decision.service.js";
import { executeSyntheticTool, type ToolExecutor } from "../services/tool-simulator.js";

export function createEvaluateRouter(
  store: AuditStore,
  executeTool: ToolExecutor = executeSyntheticTool,
): Router {
  const router = Router();

  router.post("/", async (request, response, next) => {
    try {
      const parsed = evaluateRequestSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new ApiError(400, "VALIDATION_ERROR", "Request validation failed.", parsed.error.issues);
      }
      response.json(await evaluateAction(store, parsed.data, executeTool));
    } catch (error) {
      next(error);
    }
  });

  return router;
}
