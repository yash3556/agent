import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../src/services/policy-engine.js";
import type { InspectionRecord } from "../src/types.js";

function inspection(findings: InspectionRecord["findings"], truncated = false): InspectionRecord {
  const inspectionId = "ins_12345678-1234-1234-1234-123456789abc";
  return {
    inspectionId,
    agentId: "demo-agent",
    status: "COMPLETED",
    originalName: "synthetic.txt",
    mediaType: "text/plain",
    sizeBytes: 1,
    sha256: "0".repeat(64),
    findings,
    summary: {
      totalFindings: findings.length,
      truncated,
      bySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    },
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000),
  };
}

describe("deterministic policy engine", () => {
  it("allows only the whitelisted public demo file", () => {
    expect(evaluatePolicy({ tool: "read_file", resource: "public/welcome.txt" })).toMatchObject({
      decision: "ALLOW",
      ruleId: "R-002",
    });
  });

  it("blocks private files and unknown tools/resources by default", () => {
    expect(evaluatePolicy({ tool: "read_file", resource: "private/payroll.csv" })).toMatchObject({
      decision: "BLOCK",
      ruleId: "R-003",
    });
    expect(evaluatePolicy({ tool: "shell", resource: "public/welcome.txt" })).toMatchObject({
      decision: "BLOCK",
      ruleId: "R-999",
    });
    expect(evaluatePolicy({ tool: "read_file", resource: "public/other.txt" })).toMatchObject({
      decision: "BLOCK",
      ruleId: "R-999",
    });
  });

  it("requires approval for the one sensitive synthetic report", () => {
    expect(evaluatePolicy({ tool: "export_report", resource: "sensitive-report" })).toMatchObject({
      decision: "REQUIRE_APPROVAL",
      ruleId: "R-004",
    });
  });

  it("permits owned local analysis but blocks external export without findings", () => {
    const inspectionId = "ins_12345678-1234-1234-1234-123456789abc";
    const data = inspection([]);
    const shared = {
      agentId: "demo-agent",
      resource: inspectionId,
      inspectionId,
      inspection: data,
    };
    expect(evaluatePolicy({ ...shared, tool: "analyze_document", destination: "local" }))
      .toMatchObject({ decision: "ALLOW", ruleId: "R-006" });
    expect(evaluatePolicy({ ...shared, tool: "export_report", destination: "external" }))
      .toMatchObject({ decision: "BLOCK", ruleId: "R-999" });
  });

  it("requires approval for personal data and blocks credential or incomplete reports", () => {
    const inspectionId = "ins_12345678-1234-1234-1234-123456789abc";
    const personalFinding = {
      id: "finding_demo",
      category: "PERSONAL_DATA" as const,
      type: "EMAIL_ADDRESS",
      severity: "MEDIUM" as const,
      confidence: 0.9,
      location: { page: null, line: 1 },
      evidence: "[REDACTED_EMAIL]",
      description: "Email-like content found.",
    };
    const credentialFinding = { ...personalFinding, category: "CREDENTIAL" as const };
    const shared = {
      agentId: "demo-agent",
      resource: inspectionId,
      inspectionId,
      tool: "export_report",
      destination: "external" as const,
    };
    expect(evaluatePolicy({ ...shared, inspection: inspection([personalFinding]) }))
      .toMatchObject({ decision: "REQUIRE_APPROVAL", ruleId: "R-009" });
    expect(evaluatePolicy({ ...shared, inspection: inspection([credentialFinding]) }))
      .toMatchObject({ decision: "BLOCK", ruleId: "R-007" });
    expect(evaluatePolicy({ ...shared, inspection: inspection([], true) }))
      .toMatchObject({ decision: "BLOCK", ruleId: "R-010" });
  });

  it.each([
    "../private/payroll.csv",
    "public/../private/payroll.csv",
    "%2e%2e/private/payroll.csv",
    "%252e%252e/private/payroll.csv",
    "..\\private\\payroll.csv",
    "/public/welcome.txt",
    "C:\\private\\payroll.csv",
    "public/%00welcome.txt",
  ])("blocks traversal and absolute path input: %s", (resource) => {
    expect(evaluatePolicy({ tool: "read_file", resource })).toMatchObject({
      decision: "BLOCK",
      ruleId: "R-001",
    });
  });
});