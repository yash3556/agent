import type { EvaluateRequest } from "../schemas/evaluate.schema.js";
import type { Advisory } from "../types.js";
import { getDocumentAIStatus } from "./document-analysis.js";

export async function getRiskAdvisory(
  _request: Pick<EvaluateRequest, "tool" | "resource" | "context">,
): Promise<Advisory | null> {
  return null;
}

export function getAiStatus(): "available" | "unavailable" | "disabled" {
  return getDocumentAIStatus();
}
