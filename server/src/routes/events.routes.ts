import { Router } from "express";
import type { AuditStore } from "../config/database.js";
import { ApiError } from "../errors.js";
import { eventsQuerySchema } from "../schemas/evaluate.schema.js";
import { listAuditEvents } from "../services/decision.service.js";

export function createEventsRouter(store: AuditStore): Router {
  const router = Router();

  router.get("/", async (request, response, next) => {
    try {
      const parsed = eventsQuerySchema.safeParse(request.query);
      if (!parsed.success) {
        throw new ApiError(400, "VALIDATION_ERROR", "Query validation failed.", parsed.error.issues);
      }
      response.json({ events: await listAuditEvents(store, parsed.data.limit) });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
