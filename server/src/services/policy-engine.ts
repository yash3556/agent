import type { EvaluateRequest } from "../schemas/evaluate.schema.js";
import type { Decision } from "../types.js";

export interface PolicyResult {
  decision: Decision;
  reason: string;
  ruleId: string;
  normalizedResource: string;
}

function decodeResource(resource: string): string | null {
  let decoded = resource;

  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      return null;
    }
  }

  return decoded.replace(/\\/g, "/");
}

export function evaluatePolicy(action: Pick<EvaluateRequest, "tool" | "resource">): PolicyResult {
  const decoded = decodeResource(action.resource);
  if (
    decoded === null
    || decoded.includes("..")
    || decoded.includes("\0")
    || decoded.startsWith("/")
    || /^[A-Za-z]:/.test(decoded)
  ) {
    return {
      decision: "BLOCK",
      reason: "Path traversal is not permitted.",
      ruleId: "R-001",
      normalizedResource: decoded ?? "[REDACTED]",
    };
  }

  const normalizedResource = decoded.replace(/^(?:\.\/)+/, "");

  if (action.tool === "read_file" && normalizedResource === "public/welcome.txt") {
    return {
      decision: "ALLOW",
      reason: "The policy permits access to this public resource.",
      ruleId: "R-002",
      normalizedResource,
    };
  }

  if (action.tool === "read_file" && normalizedResource.startsWith("private/")) {
    return {
      decision: "BLOCK",
      reason: "The request has no authorization to access the private resource.",
      ruleId: "R-003",
      normalizedResource,
    };
  }

  if (action.tool === "export_report" && normalizedResource === "sensitive-report") {
    return {
      decision: "REQUIRE_APPROVAL",
      reason: "The action is held until a human reviewer approves or rejects it.",
      ruleId: "R-004",
      normalizedResource,
    };
  }

  return {
    decision: "BLOCK",
    reason: "No policy permits this action (deny by default).",
    ruleId: "R-999",
    normalizedResource,
  };
}
