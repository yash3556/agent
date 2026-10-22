import type { EvaluateRequest } from "../schemas/evaluate.schema.js";
import type { Decision, InspectionRecord } from "../types.js";

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

type PolicyAction = Pick<EvaluateRequest, "tool" | "resource"> & Partial<
  Pick<EvaluateRequest, "agentId" | "inspectionId" | "destination">
> & {
  inspection?: InspectionRecord | null;
};

function result(
  decision: Decision,
  reason: string,
  ruleId: string,
  normalizedResource: string,
): PolicyResult {
  return { decision, reason, ruleId, normalizedResource };
}

export function evaluatePolicy(action: PolicyAction): PolicyResult {
  const decoded = decodeResource(action.resource);
  if (
    decoded === null
    || decoded.includes("..")
    || decoded.includes("\0")
    || decoded.startsWith("/")
    || /^[A-Za-z]:/.test(decoded)
  ) {
    return result("BLOCK", "Path traversal is not permitted.", "R-001", decoded ?? "[REDACTED]");
  }

  const normalizedResource = decoded.replace(/^(?:\.\/)+/, "");
  const documentAction = action.tool === "analyze_document" || action.inspectionId !== undefined
    || action.destination !== undefined || /^ins_/.test(normalizedResource);
  const inspection = action.inspection;

  if (documentAction && (
    !action.inspectionId
    || !inspection
    || inspection.status !== "COMPLETED"
    || inspection.expiresAt.getTime() <= Date.now()
    || inspection.agentId !== action.agentId
    || inspection.inspectionId !== action.inspectionId
    || normalizedResource !== action.inspectionId
  )) {
    return result(
      "BLOCK",
      "A completed inspection owned by this agent is required.",
      "R-005",
      normalizedResource,
    );
  }

  if (action.tool === "analyze_document") {
    if (
      action.agentId === "demo-agent"
      && action.destination === "local"
      && inspection
    ) {
      return result(
        "ALLOW",
        "The completed inspection may be analyzed locally; findings do not execute document instructions.",
        "R-006",
        normalizedResource,
      );
    }
    return result(
      "BLOCK",
      "Local document analysis is not permitted for this action or destination.",
      "R-999",
      normalizedResource,
    );
  }

  if (action.tool === "export_report" && action.inspectionId && inspection) {
    if (action.agentId !== "demo-agent" || action.destination !== "external") {
      return result(
        "BLOCK",
        "Document export is not permitted for this agent or destination.",
        "R-999",
        normalizedResource,
      );
    }
    if (inspection.findings.some((finding) => finding.category === "CREDENTIAL")) {
      return result(
        "BLOCK",
        "External export is prohibited because credential-like content was detected.",
        "R-007",
        normalizedResource,
      );
    }
    if (inspection.findings.some((finding) => finding.category === "SUSPICIOUS_INSTRUCTION")) {
      return result(
        "BLOCK",
        "External export is prohibited because suspicious instructions were detected.",
        "R-008",
        normalizedResource,
      );
    }
    if (inspection.summary.truncated) {
      return result(
        "BLOCK",
        "External export is prohibited because the complete finding set could not be reported.",
        "R-010",
        normalizedResource,
      );
    }
    if (inspection.findings.some((finding) => finding.category === "PERSONAL_DATA")) {
      return result(
        "REQUIRE_APPROVAL",
        "External export of detected personal data requires human approval.",
        "R-009",
        normalizedResource,
      );
    }
    return result(
      "BLOCK",
      "No policy permits external export of this document.",
      "R-999",
      normalizedResource,
    );
  }

  if (action.tool === "read_file" && normalizedResource === "public/welcome.txt") {
    return result("ALLOW", "The policy permits access to this public resource.", "R-002", normalizedResource);
  }

  if (action.tool === "read_file" && normalizedResource.startsWith("private/")) {
    return result(
      "BLOCK",
      "The request has no authorization to access the private resource.",
      "R-003",
      normalizedResource,
    );
  }

  if (action.tool === "export_report" && normalizedResource === "sensitive-report") {
    return result(
      "REQUIRE_APPROVAL",
      "The action is held until a human reviewer approves or rejects it.",
      "R-004",
      normalizedResource,
    );
  }

  return result("BLOCK", "No policy permits this action (deny by default).", "R-999", normalizedResource);
}
