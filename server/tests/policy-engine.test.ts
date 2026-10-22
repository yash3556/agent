import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../src/services/policy-engine.js";

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