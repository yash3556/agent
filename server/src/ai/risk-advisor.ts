import type { EvaluateRequest } from "../schemas/evaluate.schema.js";
import type { Advisory } from "../types.js";

export async function getRiskAdvisory(
  _request: Pick<EvaluateRequest, "tool" | "resource" | "context">,
): Promise<Advisory | null> {
  return null;
}

export function getAiStatus(): "available" | "unavailable" | "disabled" {
  return process.env.AI_PROVIDER && process.env.AI_PROVIDER !== "disabled"
    ? "unavailable"
    : "disabled";
}
