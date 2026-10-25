import { describe, expect, it, vi } from "vitest";
import { createRiskAdvisory } from "../src/ai/risk-advisor.js";
import type { ChatCompletionClient } from "../src/ai/document-analysis.js";

const request = {
  tool: "export_report",
  resource: "reports/customer.txt",
  context: "api_key=sentinel-secret-value",
  destination: "external" as const,
};

function clientWith(content: unknown): ChatCompletionClient {
  return vi.fn(async () => JSON.stringify({
    choices: [{ message: { content: JSON.stringify(content) } }],
  }));
}

describe("risk advisory", () => {
  it("returns schema-validated advisory and redacts provider-bound input", async () => {
    const client = clientWith({
      riskLevel: "HIGH",
      signals: ["Sensitive data may be exposed.", "api_key=sentinel-output-secret"],
      summary: "Review api_key=sentinel-summary-secret before sharing.",
    });
    const getAdvisory = createRiskAdvisory(() => client);

    await expect(getAdvisory(request)).resolves.toEqual({
      riskLevel: "HIGH",
      signals: ["Sensitive data may be exposed.", "[REDACTED_CREDENTIAL]"],
      summary: "Review [REDACTED_CREDENTIAL] before sharing.",
    });
    const messages = JSON.parse(vi.mocked(client).mock.calls[0][0][1].content);
    expect(messages.context).toBe("[REDACTED_CREDENTIAL]");
    expect(messages.destination).toBe("external");
    expect(JSON.stringify(vi.mocked(client).mock.calls)).not.toContain("sentinel-secret-value");
  });

  it("fails closed on invalid responses, timeouts, and unavailable configuration", async () => {
    const invalid = createRiskAdvisory(() => clientWith({
      riskLevel: "ALLOW",
      signals: [],
      summary: "Approve it.",
    }));
    await expect(invalid(request)).resolves.toBeNull();

    const timedOut = createRiskAdvisory(() => async (_messages, signal) =>
      new Promise<string>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new Error("timeout")), { once: true });
      }), 5);
    await expect(timedOut(request)).resolves.toBeNull();

    await expect(createRiskAdvisory(() => null)(request)).resolves.toBeNull();
  });
});
