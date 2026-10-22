import cors from "cors";
import express, { type ErrorRequestHandler } from "express";
import { getAiStatus } from "./ai/risk-advisor.js";
import type { AuditStore } from "./config/database.js";
import { ApiError } from "./errors.js";
import { createApprovalsRouter } from "./routes/approvals.routes.js";
import { createEvaluateRouter } from "./routes/evaluate.routes.js";
import { createEventsRouter } from "./routes/events.routes.js";
import type { Scenario } from "./types.js";
import { executeSyntheticTool, type ToolExecutor } from "./services/tool-simulator.js";

const scenarios: Scenario[] = [
  {
    id: "S1",
    title: "Read a public document",
    request: { agentId: "demo-agent", tool: "read_file", resource: "public/welcome.txt" },
  },
  {
    id: "S2",
    title: "Read a private file",
    request: { agentId: "demo-agent", tool: "read_file", resource: "private/payroll.csv" },
  },
  {
    id: "S3",
    title: "Export a sensitive report",
    request: { agentId: "demo-agent", tool: "export_report", resource: "sensitive-report" },
  },
];

export interface AppOptions {
  frontendOrigin?: string;
  executeTool?: ToolExecutor;
}

export function createApp(store: AuditStore, options: AppOptions = {}) {
  const app = express();
  const frontendOrigin = options.frontendOrigin
    ?? process.env.FRONTEND_ORIGIN
    ?? "http://localhost:5173";
  const executeTool = options.executeTool ?? executeSyntheticTool;

  app.disable("x-powered-by");
  app.use(cors({ origin: frontendOrigin }));
  app.use(express.json({ limit: "10kb", strict: true }));

  app.get("/api/health", async (_request, response, next) => {
    try {
      response.json({
        status: "ok",
        time: new Date().toISOString(),
        db: await store.isHealthy() ? "connected" : "error",
        storage: store.mode,
        ai: getAiStatus(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/scenarios", (_request, response) => {
    response.json({ scenarios });
  });

  app.use("/api/evaluate", createEvaluateRouter(store, executeTool));
  app.use("/api/events", createEventsRouter(store));
  app.use("/api/approvals", createApprovalsRouter(store, executeTool));

  app.use((_request, _response, next) => {
    next(new ApiError(404, "NOT_FOUND", "Route was not found."));
  });

  const errorHandler: ErrorRequestHandler = (error: unknown, _request, response, _next) => {
    if (error instanceof ApiError) {
      response.status(error.status).json({
        error: error.code,
        message: error.message,
        ...(error.details === undefined ? {} : { details: error.details }),
      });
      return;
    }

    const parserError = error as { status?: number; type?: string };
    if (parserError.status === 413 || parserError.type === "entity.too.large") {
      response.status(413).json({
        error: "PAYLOAD_TOO_LARGE",
        message: "Request body exceeds the 10 KB limit.",
      });
      return;
    }
    if (parserError.status === 400 || parserError.type === "entity.parse.failed") {
      response.status(400).json({
        error: "VALIDATION_ERROR",
        message: "Request body must be valid JSON.",
      });
      return;
    }

    console.error("Unhandled API error.");
    response.status(500).json({
      error: "INTERNAL_ERROR",
      message: "An unexpected server error occurred.",
    });
  };

  app.use(errorHandler);
  return app;
}
