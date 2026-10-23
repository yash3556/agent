import { createServer } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createDocumentAnalyzer,
  createOpenAICompatibleProvider,
  hasSafeAIBaseURLShape,
  resolveSafeAIAddresses,
  type DocumentAIProvider,
} from "../src/ai/document-analysis.js";
import type { ScanSummary } from "../src/services/content-scanner.js";
import type { InspectionFinding } from "../src/types.js";

const emptySummary: ScanSummary = {
  totalFindings: 0,
  truncated: false,
  bySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
};

const noFindings: InspectionFinding[] = [];

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AI-assisted document analysis", () => {
  it("keeps the provider disabled by default and emits deterministic-only coverage", async () => {
    const previous = process.env.AI_PROVIDER;
    delete process.env.AI_PROVIDER;
    try {
      const result = await createDocumentAnalyzer().analyze(
        [{ text: "No known patterns.", page: null }],
        noFindings,
        emptySummary,
      );
      expect(result.aiAdvisory).toBe("DISABLED");
      expect(result.report).toMatchObject({
        status: "DETERMINISTIC_ONLY",
        coverage: { extraction: "COMPLETED", deterministic: "COMPLETED", ai: "DISABLED" },
      });
    } finally {
      if (previous === undefined) delete process.env.AI_PROVIDER;
      else process.env.AI_PROVIDER = previous;
    }
  });

  it("redacts sensitive values before provider calls and covers every chunk within limits", async () => {
    const received: string[] = [];
    const provider: DocumentAIProvider = {
      async analyzeChunk(chunk) {
        received.push(chunk.lines.map((line) => line.text).join(""));
        return [];
      },
    };
    const source = `Contact alice@example.test; api_key=sample-secret-value\n${"x".repeat(40_000)}`;
    const result = await createDocumentAnalyzer(provider).analyze(
      [{ text: source, page: 2 }],
      noFindings,
      emptySummary,
    );

    const sanitized = received.join("");
    expect(sanitized).not.toContain("alice@example.test");
    expect(sanitized).not.toContain("sample-secret-value");
    expect(sanitized).toContain("[REDACTED]");
    expect(sanitized).toContain("x".repeat(40_000));
    expect(JSON.stringify(result.report)).not.toContain("alice@example.test");
    expect(JSON.stringify(result.report)).not.toContain("sample-secret-value");
    expect(result.report).toMatchObject({
      status: "COMPLETE",
      coverage: {
        ai: "COMPLETED",
        totalChunks: received.length,
        completedChunks: received.length,
        failedChunks: 0,
      },
    });
    expect(received.length).toBeGreaterThan(1);
    expect(received.every((chunk) => Buffer.byteLength(chunk, "utf8") <= 32 * 1024)).toBe(true);
  });

  it("marks provider failures and timeouts as incomplete instead of claiming completion", async () => {
    const failureAnalyzer = createDocumentAnalyzer({
      async analyzeChunk() {
        throw new Error("provider failure");
      },
    });
    const failed = await failureAnalyzer.analyze([{ text: "content", page: null }], noFindings, emptySummary);
    expect(failed.report).toMatchObject({
      status: "PARTIAL",
      coverage: { ai: "INCOMPLETE", totalChunks: 1, completedChunks: 0, failedChunks: 1 },
    });

    const timeoutProvider: DocumentAIProvider = {
      analyzeChunk(_chunk, signal) {
        return new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
        });
      },
    };
    const timedOut = await createDocumentAnalyzer(timeoutProvider, { totalTimeoutMs: 10 })
      .analyze([{ text: "content", page: null }], noFindings, emptySummary);
    expect(timedOut.report.coverage).toMatchObject({
      ai: "INCOMPLETE",
      completedChunks: 0,
      failedChunks: 1,
    });
  });

  it("reports unprocessed chunks when the safe chunk cap is reached", async () => {
    const analyzeChunk = vi.fn(async () => []);
    const result = await createDocumentAnalyzer({ analyzeChunk }, { maxChunks: 1 })
      .analyze([{ text: "a".repeat(40_000), page: null }], noFindings, emptySummary);

    expect(analyzeChunk).toHaveBeenCalledTimes(1);
    expect(result.report.status).toBe("PARTIAL");
    expect(result.report.coverage.totalChunks).toBeGreaterThan(1);
    expect(result.report.coverage.completedChunks).toBe(1);
    expect(result.report.coverage.failedChunks).toBe(result.report.coverage.totalChunks - 1);
  });

  it("bounds concurrent provider requests across simultaneous inspections", async () => {
    let active = 0;
    let maximumActive = 0;
    const provider: DocumentAIProvider = {
      async analyzeChunk() {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await new Promise((resolve) => setTimeout(resolve, 10));
        active -= 1;
        return [];
      },
    };
    const analyze = () => createDocumentAnalyzer(provider)
      .analyze([{ text: "content", page: null }], noFindings, emptySummary);
    const reports = await Promise.all([analyze(), analyze(), analyze(), analyze()]);

    expect(maximumActive).toBeLessThanOrEqual(3);
    expect(reports.some(({ report }) => report.status === "PARTIAL")).toBe(true);
  });

  it("marks reports partial when validated findings exceed the report cap", async () => {
    const provider: DocumentAIProvider = {
      async analyzeChunk(chunk) {
        return Array.from({ length: 4 }, (_, index) => ({
          category: "OTHER" as const,
          type: `CONTEXTUAL_RISK_${chunk.index}_${index}`,
          severity: "MEDIUM" as const,
          confidence: 0.7,
          explanation: "A contextual risk requires review.",
          recommendation: "Review the referenced document content.",
          evidenceReferences: [{ page: null, line: 1 }],
        }));
      },
    };
    const result = await createDocumentAnalyzer(provider)
      .analyze([{ text: "x".repeat(1_000_000), page: null }], noFindings, emptySummary);

    expect(result.report.findings).toHaveLength(100);
    expect(result.report.truncated).toBe(true);
    expect(result.report.status).toBe("PARTIAL");
    expect(result.report.coverage.ai).toBe("COMPLETED");
  });

  it("rejects malformed Chat Completions output and fabricated evidence references", async () => {
    const chunk = { index: 1, lines: [{ segment: 0, page: 1, line: 1, text: "sample" }] };
    const providerFor = (content: string) => createOpenAICompatibleProvider(
      {
        baseUrl: "https://api.openai.com/v1",
        model: "test-model",
        apiKey: "test-secret",
      },
      async (_endpoint, _apiKey, _body, _signal) => JSON.stringify({
        choices: [{ message: { content } }],
      }),
    );

    await expect(providerFor("not-json").analyzeChunk(chunk, new AbortController().signal)).rejects.toThrow();
    await expect(providerFor(JSON.stringify({ findings: [{ category: "UNKNOWN" }] }))
      .analyzeChunk(chunk, new AbortController().signal)).rejects.toThrow();

    const fabricatedReference: DocumentAIProvider = {
      async analyzeChunk() {
        return [{
          category: "OTHER",
          type: "CONTEXTUAL_RISK",
          severity: "HIGH",
          confidence: 0.8,
          explanation: "A risk was observed.",
          recommendation: "Review the document.",
          evidenceReferences: [{ page: 99, line: 99 }],
        }];
      },
    };
    const result = await createDocumentAnalyzer(fabricatedReference)
      .analyze([{ text: "sample", page: 1 }], noFindings, emptySummary);
    expect(result.report).toMatchObject({
      status: "PARTIAL",
      coverage: { ai: "INCOMPLETE", failedChunks: 1 },
      findings: [],
    });
  });

  it("redacts sensitive data echoed in provider-generated report fields", async () => {
    const provider: DocumentAIProvider = {
      async analyzeChunk() {
        return [{
          category: "OTHER",
          type: "CONTEXTUAL_RISK",
          severity: "HIGH",
          confidence: 0.8,
          explanation: "Found api_key=echoed-secret-value in the excerpt.",
          recommendation: "Contact alice@example.test to rotate the value.",
          evidenceReferences: [{ page: null, line: 1 }],
        }];
      },
    };
    const result = await createDocumentAnalyzer(provider)
      .analyze([{ text: "no sensitive content", page: null }], noFindings, emptySummary);

    expect(JSON.stringify(result.report)).not.toContain("echoed-secret-value");
    expect(JSON.stringify(result.report)).not.toContain("alice@example.test");
    expect(result.report.findings[0]?.explanation).toContain("[REDACTED]");
  });

  it("rejects unsafe provider destinations and requires explicit loopback opt-in", () => {
    expect(hasSafeAIBaseURLShape("https://api.example.test/v1")).toBe(true);
    expect(hasSafeAIBaseURLShape("http://api.example.test/v1")).toBe(false);
    expect(hasSafeAIBaseURLShape("https://user:password@api.example.test/v1")).toBe(false);
    expect(hasSafeAIBaseURLShape("https://169.254.169.254")).toBe(false);
    expect(hasSafeAIBaseURLShape("https://127.0.0.1")).toBe(false);
    expect(hasSafeAIBaseURLShape("http://localhost:8080")).toBe(false);
    expect(hasSafeAIBaseURLShape("http://localhost:8080", true)).toBe(true);
    expect(hasSafeAIBaseURLShape("https://localhost:8443", true)).toBe(true);
  });

  it("rejects non-public DNS/IP resolutions unless loopback is explicitly enabled", async () => {
    await expect(resolveSafeAIAddresses("169.254.169.254", true)).rejects.toThrow();
    await expect(resolveSafeAIAddresses("127.0.0.1", false)).rejects.toThrow();
    await expect(resolveSafeAIAddresses("127.0.0.1", true)).resolves.toEqual([
      { address: "127.0.0.1", family: 4 },
    ]);
  });

  it("does not follow provider redirects", async () => {
    let redirectedRequests = 0;
    const server = createServer((request, response) => {
      if (request.url === "/redirect-target") redirectedRequests += 1;
      response.writeHead(302, { location: "/redirect-target" });
      response.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Mock server did not bind a TCP port.");
    try {
      const provider = createOpenAICompatibleProvider({
        baseUrl: `http://127.0.0.1:${address.port}/v1`,
        model: "test-model",
        apiKey: "test-secret",
        allowLoopback: true,
      });
      await expect(provider.analyzeChunk(
        { index: 1, lines: [{ segment: 0, page: null, line: 1, text: "content" }] },
        new AbortController().signal,
      )).rejects.toThrow();
      expect(redirectedRequests).toBe(0);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
