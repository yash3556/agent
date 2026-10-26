import { createServer } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createDocumentAnalyzer,
  createOpenAICompatibleProvider,
  getAIRequestSummary,
  getDocumentAIStatus,
  hasSafeAIBaseURLShape,
  resolveSafeAIAddresses,
  type DocumentAIProvider,
} from "../src/ai/document-analysis.js";
import type { ScanSummary } from "../src/services/content-scanner.js";
import { scanText } from "../src/services/content-scanner.js";
import type { InspectionFinding } from "../src/types.js";

const emptySummary: ScanSummary = {
  totalFindings: 0,
  truncated: false,
  bySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
};

const noFindings: InspectionFinding[] = [];

function findingAt(page: number | null, line = 1): InspectionFinding {
  return {
    id: "finding_test",
    category: "PERSONAL_DATA",
    type: "PHONE_NUMBER",
    severity: "MEDIUM",
    confidence: 0.78,
    location: { page, line },
    evidence: "[REDACTED_PHONE]",
    description: "A phone-number-like pattern was detected.",
  };
}

function summaryWithFinding(): ScanSummary {
  return {
    ...emptySummary,
    totalFindings: 1,
    bySeverity: { ...emptySummary.bySeverity, MEDIUM: 1 },
  };
}

function analyzeText(analyzer: ReturnType<typeof createDocumentAnalyzer>, text: string, page: number | null = null) {
  const finding = findingAt(page);
  return analyzer.analyze(
    [{ text, page }],
    [finding],
    summaryWithFinding(),
    [0],
    [{ segment: 0, page, line: 1, start: 0, end: Math.min(20, text.length) }],
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AI-assisted document analysis", () => {
  it("reports configuration state without claiming a live provider check", () => {
    const previous = {
      provider: process.env.AI_PROVIDER,
      baseUrl: process.env.AI_BASE_URL,
      model: process.env.AI_MODEL,
      apiKey: process.env.AI_API_KEY,
      loopback: process.env.AI_ALLOW_LOOPBACK,
    };
    process.env.AI_PROVIDER = "openai-compatible";
    process.env.AI_BASE_URL = "https://api.groq.com/openai/v1";
    process.env.AI_MODEL = "openai/gpt-oss-20b";
    process.env.AI_API_KEY = "placeholder-test-key";
    delete process.env.AI_ALLOW_LOOPBACK;
    try {
      expect(getDocumentAIStatus()).toBe("configured");
      expect(getAIRequestSummary()).toEqual({
        provider: "openai-compatible",
        hostname: "api.groq.com",
        model: "openai/gpt-oss-20b",
        endpointPathSuffix: "/chat/completions",
        requestParameters: ["model", "messages", "response_format"],
        responseFormat: "json_schema_strict",
      });
      expect(JSON.stringify(getAIRequestSummary())).not.toContain("placeholder-test-key");
    } finally {
      if (previous.provider === undefined) delete process.env.AI_PROVIDER;
      else process.env.AI_PROVIDER = previous.provider;
      if (previous.baseUrl === undefined) delete process.env.AI_BASE_URL;
      else process.env.AI_BASE_URL = previous.baseUrl;
      if (previous.model === undefined) delete process.env.AI_MODEL;
      else process.env.AI_MODEL = previous.model;
      if (previous.apiKey === undefined) delete process.env.AI_API_KEY;
      else process.env.AI_API_KEY = previous.apiKey;
      if (previous.loopback === undefined) delete process.env.AI_ALLOW_LOOPBACK;
      else process.env.AI_ALLOW_LOOPBACK = previous.loopback;
    }
  });

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

  it("does not claim AI succeeded when extraction produced no analyzable chunks", async () => {
    const result = await createDocumentAnalyzer({
      async analyzeChunk() {
        throw new Error("should not be called");
      },
    }).analyze([], noFindings, emptySummary);

    expect(result.aiAdvisory).toBe("NOT_NEEDED");
    expect(result.report.coverage).toMatchObject({
      ai: "NO_CONTENT",
      totalChunks: 0,
      completedChunks: 0,
      failedChunks: 0,
    });
  });

  it("does not send a document without deterministic finding context to the provider", async () => {
    const analyzeChunk = vi.fn(async () => []);
    const result = await createDocumentAnalyzer({ analyzeChunk })
      .analyze([{ text: "ordinary content with no deterministic finding", page: 1 }], noFindings, emptySummary);

    expect(analyzeChunk).not.toHaveBeenCalled();
    expect(result.aiAdvisory).toBe("NOT_NEEDED");
    expect(result.report).toMatchObject({
      status: "DETERMINISTIC_ONLY",
      coverage: { ai: "NO_FINDING_CONTEXT", totalChunks: 0, completedChunks: 0, failedChunks: 0 },
    });
  });

  it("sends only bounded finding context and a safe structure summary to the provider", async () => {
    const received: string[] = [];
    const provider: DocumentAIProvider = {
      async analyzeChunk(chunk) {
        received.push(JSON.stringify(chunk));
        return [];
      },
    };
    const source = [
      "unrelated-document-sentinel",
      "Additional unselected line.",
      "Contact alice@example.test; api_key=sample-secret-value",
      "Nearby permitted context.",
      "unrelated-tail-sentinel-".repeat(2_000),
    ].join("\n");
    const scan = scanText([{ text: source, page: 2 }]);
    const result = await createDocumentAnalyzer(provider).analyze(
      [{ text: source, page: 2 }],
      scan.findings,
      scan.summary,
      scan.findingSegments,
      scan.findingLocations,
    );

    const sanitized = received.join("");
    expect(sanitized).not.toContain("alice@example.test");
    expect(sanitized).not.toContain("sample-secret-value");
    expect(sanitized).not.toContain("unrelated-document-sentinel");
    expect(sanitized).not.toContain("unrelated-tail-sentinel");
    expect(sanitized).toContain("[REDACTED_EMAIL]");
    expect(sanitized).toContain("[REDACTED_CREDENTIAL]");
    expect(sanitized).toContain('"structure"');
    expect(sanitized).toContain('"findingCount":2');
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
    expect(received).toHaveLength(1);
    expect(received.every((chunk) => Buffer.byteLength(chunk, "utf8") <= 32 * 1024)).toBe(true);
  });

  it("redacts detector values in the actual provider request body and preserves finding locations", async () => {
    let requestBody = "";
    const provider = createOpenAICompatibleProvider({
      baseUrl: "https://api.example.test/v1",
      model: "test-model",
      apiKey: "test-provider-key",
    }, async (_endpoint, _apiKey, body) => {
      requestBody = body;
      return JSON.stringify({
        choices: [{ message: { content: JSON.stringify({
          findings: [],
          documentSummary: { topics: [], purpose: "MIXED_OR_UNCLEAR", summary: "No supported subject was identified." },
        }) } }],
      });
    });
    const source = [
      "Contact sentinel.person@example.test or 415-555-0182.",
      "api_key=sentinel-api-secret-value",
      "Bearer sentinelBearerValue0123456789",
      "mongodb://agent:sentinel-db-password@db.example.test/records",
      "AKIAIOSFODNN7EXAMPLE",
      "-----BEGIN PRIVATE KEY-----",
      "sentinel-private-key-body",
      "-----END PRIVATE KEY-----",
    ].join("\n");
    const segments = [{ text: source, page: 7 }];
    const scan = scanText(segments);
    const result = await createDocumentAnalyzer(provider).analyze(
      segments,
      scan.findings,
      scan.summary,
      scan.findingSegments,
      scan.findingLocations,
    );
    const safeLines = JSON.stringify(JSON.parse(requestBody).messages[1].content);

    for (const sentinel of [
      "sentinel.person@example.test",
      "415-555-0182",
      "sentinel-api-secret-value",
      "sentinelBearerValue0123456789",
      "sentinel-db-password",
      "AKIAIOSFODNN7EXAMPLE",
      "sentinel-private-key-body",
    ]) {
      expect(requestBody).not.toContain(sentinel);
    }
    expect(safeLines).toContain("[REDACTED_EMAIL]");
    expect(safeLines).toContain("[REDACTED_PHONE]");
    expect(safeLines).toContain("[REDACTED_CREDENTIAL]");
    expect(safeLines).toContain("[REDACTED_CONNECTION_STRING]");
    expect(result.report.findings.map(({ type }) => type)).toEqual(
      expect.arrayContaining([
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDENTIAL_LIKE",
        "BEARER_TOKEN_LIKE",
        "DATABASE_CONNECTION_STRING",
        "CLOUD_ACCESS_KEY_LIKE",
        "PRIVATE_KEY_MARKER",
      ]),
    );
    expect(result.report.findings.every(({ evidenceReferences }) =>
      evidenceReferences.every(({ page, line }) => page === 7 && line > 0),
    )).toBe(true);
  });

  it("marks provider failures and timeouts as incomplete instead of claiming completion", async () => {
    const failureAnalyzer = createDocumentAnalyzer({
      async analyzeChunk() {
        throw new Error("provider failure");
      },
    });
    const deterministicFinding: InspectionFinding = {
      id: "finding_phone",
      category: "PERSONAL_DATA",
      type: "PHONE_NUMBER",
      severity: "MEDIUM",
      confidence: 0.78,
      location: { page: 1, line: 1 },
      evidence: "[REDACTED_PHONE]",
      description: "A phone-number-like pattern was detected.",
    };
    const failed = await failureAnalyzer.analyze(
      [{ text: "content", page: 1 }],
      [deterministicFinding],
      { ...emptySummary, totalFindings: 1, bySeverity: { ...emptySummary.bySeverity, MEDIUM: 1 } },
      [0],
    );
    expect(failed.report).toMatchObject({
      status: "PARTIAL",
      coverage: { ai: "INCOMPLETE", totalChunks: 1, completedChunks: 0, failedChunks: 1 },
      findings: [{ id: "finding_phone", source: "DETERMINISTIC", type: "PHONE_NUMBER" }],
    });
    expect(failed.aiAdvisory).toBe("UNAVAILABLE");
    expect(failed.aiFailure).toMatchObject({ code: "CONNECTION_FAILED" });
    expect(failed.report.summary).toContain("AI analysis failed - deterministic scan completed.");

    const timeoutProvider = createOpenAICompatibleProvider({
      baseUrl: "https://api.openai.com/v1",
      model: "test-model",
      apiKey: "test-secret",
    }, async (_endpoint, _apiKey, _body, signal) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new Error("mock HTTP timeout")), { once: true });
    }));
    const timedOut = await createDocumentAnalyzer(timeoutProvider, { totalTimeoutMs: 10 })
      .analyze(
        [{ text: "content", page: null }],
        [findingAt(null)],
        summaryWithFinding(),
        [0],
        [{ segment: 0, page: null, line: 1, start: 0, end: 7 }],
      );
    expect(timedOut.report.coverage).toMatchObject({
      ai: "INCOMPLETE",
      completedChunks: 0,
      failedChunks: 1,
    });
    expect(timedOut.aiFailure).toMatchObject({ code: "TIMEOUT" });
  });

  it("reports unprocessed chunks when the safe chunk cap is reached", async () => {
    const analyzeChunk = vi.fn(async () => []);
    const source = Array.from(
      { length: 120 },
      (_, index) => `line-${index}-${"x".repeat(700)} person${index}@example.test`,
    ).join("\n");
    const scan = scanText([{ text: source, page: null }]);
    const result = await createDocumentAnalyzer({ analyzeChunk }, { maxChunks: 1 })
      .analyze(
        [{ text: source, page: null }],
        scan.findings,
        scan.summary,
        scan.findingSegments,
        scan.findingLocations,
      );

    expect(analyzeChunk).toHaveBeenCalledTimes(1);
    expect(result.report.status).toBe("PARTIAL");
    expect(result.report.coverage.totalChunks).toBeGreaterThan(1);
    expect(result.report.coverage.completedChunks).toBe(1);
    expect(result.report.coverage.failedChunks).toBe(result.report.coverage.totalChunks - 1);
    expect(result.aiFailure).toMatchObject({ code: "ANALYSIS_LIMIT" });
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
    const analyze = () => analyzeText(createDocumentAnalyzer(provider), "content");
    const reports = await Promise.all([analyze(), analyze(), analyze(), analyze()]);

    expect(maximumActive).toBeLessThanOrEqual(3);
    expect(reports.some(({ report }) => report.status === "PARTIAL")).toBe(true);
  });

  it("marks reports partial when validated findings exceed the report cap", async () => {
    const provider: DocumentAIProvider = {
      async analyzeChunk(chunk) {
        return Array.from({ length: 12 }, (_, index) => ({
          category: "OTHER" as const,
          type: `CONTEXTUAL_RISK_${chunk.index}_${index}`,
          severity: "MEDIUM" as const,
          confidence: 0.7,
          explanation: "A contextual risk requires review.",
          recommendation: "Review the referenced document content.",
          evidenceReferences: [{
            page: chunk.lines[0].page,
            line: chunk.lines[0].line,
          }],
        }));
      },
    };
    const source = Array.from({ length: 540 }, () => "x".repeat(1_000)).join("\n");
    const findings = Array.from({ length: 180 }, (_, index) => ({
      ...findingAt(null, index * 3 + 2),
      id: `finding_${index}`,
    }));
    const locations = findings.map((finding) => ({
      segment: 0,
      page: null,
      line: finding.location.line ?? 1,
      start: 500,
      end: 510,
    }));
    const result = await createDocumentAnalyzer(provider)
      .analyze(
        [{ text: source, page: null }],
        findings,
        { ...summaryWithFinding(), totalFindings: findings.length },
        findings.map(() => 0),
        locations,
      );

    expect(result.report.findings.filter(({ source: findingSource }) => findingSource === "AI")).toHaveLength(100);
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
    const invalidResponse = await analyzeText(createDocumentAnalyzer(providerFor("not-json")), "sample");
    expect(invalidResponse.aiFailure).toMatchObject({ code: "INVALID_RESPONSE" });
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
      .analyze(
        [{ text: "sample", page: 1 }],
        [findingAt(1)],
        summaryWithFinding(),
        [0],
        [{ segment: 0, page: 1, line: 1, start: 0, end: 6 }],
      );
    expect(result.report).toMatchObject({
      status: "PARTIAL",
      coverage: { ai: "INCOMPLETE", failedChunks: 1 },
    });
    expect(result.report.findings.some(({ source: findingSource }) => findingSource === "AI")).toBe(false);
  });

  it("classifies safe provider response failures and requests strict schema for GPT-OSS", async () => {
    const chunk = { index: 1, lines: [{ segment: 0, page: 1, line: 1, text: "Synthetic receipt total: 12.00" }] };
    const validContent = JSON.stringify({ findings: [], documentSummary: { topics: ["FINANCIAL"], purpose: "RECORD", summary: "A receipt records a total." } });
    let requestBody: any;
    const provider = (envelope: unknown) => createOpenAICompatibleProvider({
      baseUrl: "https://api.groq.com/openai/v1",
      model: "openai/gpt-oss-20b",
      apiKey: "synthetic-test-key",
    }, async (endpoint, _apiKey, body) => {
      expect(endpoint.hostname).toBe("api.groq.com");
      expect(endpoint.pathname).toBe("/openai/v1/chat/completions");
      requestBody = JSON.parse(body);
      return { body: JSON.stringify(envelope), statusCode: 200 };
    });
    const signal = new AbortController().signal;
    const valid = await provider({ choices: [{ finish_reason: "stop", message: { content: validContent } }] }).analyzeChunk(chunk, signal);
    expect(valid).toEqual([]);
    expect(valid.documentSummary).toMatchObject({ topics: ["FINANCIAL"], purpose: "RECORD" });
    expect(requestBody.response_format).toMatchObject({
      type: "json_schema",
      json_schema: { strict: true, schema: { required: ["findings", "documentSummary"], additionalProperties: false } },
    });
    expect(requestBody.response_format.json_schema.schema.properties.findings.items.additionalProperties).toBe(false);
    expect(requestBody.response_format.json_schema.schema.properties.findings.items.required)
      .toEqual(["category", "type", "severity", "confidence", "explanation", "recommendation", "evidenceReferences"]);
    const topicSchema = requestBody.response_format.json_schema.schema.properties.documentSummary.properties.topics;
    expect(topicSchema).toEqual({
      type: "array",
      maxItems: 4,
      items: { type: "string", enum: ["BUSINESS", "FINANCIAL", "IDENTITY", "CONTRACT", "CONTACTS", "OPERATIONS", "CORRESPONDENCE"] },
    });
    expect(requestBody.messages[0].content).toContain("Choose zero to four topics");
    expect(requestBody.messages[0].content).toContain("BUSINESS, FINANCIAL, IDENTITY, CONTRACT, CONTACTS, OPERATIONS, CORRESPONDENCE");
    const assertStrictSchema = (schema: any): void => {
      if (schema.type === "object") {
        expect(schema.additionalProperties).toBe(false);
        expect(schema.required).toEqual(Object.keys(schema.properties));
        Object.values(schema.properties).forEach(assertStrictSchema);
      } else if (schema.type === "array") {
        assertStrictSchema(schema.items);
      } else if (Array.isArray(schema.type)) {
        expect(schema.type).toEqual(["integer", "null"]);
      } else {
        expect(["string", "number", "integer"]).toContain(schema.type);
      }
    };
    assertStrictSchema(requestBody.response_format.json_schema.schema);

    const rejects = async (envelope: unknown, code: string, contentPresent: boolean) => {
      const caught = await provider(envelope).analyzeChunk(chunk, signal).catch((error) => error);
      expect(caught.aiFailure).toMatchObject({ code, diagnostics: { httpStatus: 200, contentPresent } });
      return caught.aiFailure;
    };
    const malformed = await rejects({ choices: [{ finish_reason: "stop", message: { content: "not-json" } }] }, "INVALID_RESPONSE", true);
    expect(malformed.diagnostics.responseLength).toBe(8);
    const invalidContent = JSON.stringify({ findings: [], documentSummary: {} });
    const mismatch = await rejects({ choices: [{ finish_reason: "stop", message: { content: invalidContent } }] }, "INVALID_RESPONSE", true);
    expect(mismatch.diagnostics.validationPaths).toContain("documentSummary.topics");
    expect(mismatch.diagnostics.validationDetails).toEqual([{
      path: "documentSummary.topics",
      expectedType: "array of supported topic enum values (max 4)",
      receivedType: "missing",
      invalidEnumValue: false,
    }]);
    const rejectsContent = async (content: unknown) => rejects({
      choices: [{ finish_reason: "stop", message: { content: JSON.stringify(content) } }],
    }, "INVALID_RESPONSE", true);
    const wrongTopicType = await rejectsContent({
      findings: [], documentSummary: { topics: "FINANCIAL", purpose: "RECORD", summary: "A synthetic sample." },
    });
    expect(wrongTopicType.diagnostics.validationDetails?.[0]).toMatchObject({
      receivedType: "string", invalidEnumValue: false,
    });
    const unknownTopic = await rejectsContent({
      findings: [], documentSummary: { topics: ["PEOPLE"], purpose: "RECORD", summary: "A synthetic sample." },
    });
    expect(unknownTopic.diagnostics.validationDetails?.[0]).toMatchObject({
      receivedType: "array<string>", invalidEnumValue: true,
    });
    const missingSummary = await rejectsContent({
      findings: [], documentSummary: { topics: ["FINANCIAL"], purpose: "RECORD" },
    });
    expect(missingSummary.diagnostics.validationPaths).toContain("documentSummary.summary");
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    await analyzeText(createDocumentAnalyzer(provider({ choices: [{ finish_reason: "stop", message: { content: invalidContent } }] })), "synthetic safe content");
    await analyzeText(createDocumentAnalyzer(provider({
      choices: [{
        finish_reason: "stop",
        message: { content: JSON.stringify({
          findings: [],
          documentSummary: { topics: ["PRIVATE_TOPIC_SENTINEL"], purpose: "RECORD", summary: "Synthetic summary." },
        }) },
      }],
    })), "synthetic safe content");
    const log = JSON.stringify(warning.mock.calls);
    expect(log).toContain("documentSummary.topics");
    expect(log).toContain("expectedType");
    expect(log).toContain("receivedType");
    expect(log).toContain('"invalidEnumValue":true');
    expect(log).toContain('"httpStatus":200');
    expect(log).not.toContain("PRIVATE_TOPIC_SENTINEL");
    expect(log).not.toContain("synthetic safe content");
    await rejects({ choices: [{ finish_reason: "stop", message: { content: "" } }] }, "INVALID_RESPONSE", false);
    await rejects({ choices: [{ finish_reason: "stop", message: { content: null, refusal: "private response" } }] }, "MODEL_REFUSAL", false);
    await rejects({ choices: [{ finish_reason: "length", message: { content: validContent } }] }, "TRUNCATED_RESPONSE", true);
  });

  it("validates consecutive provider responses without carrying topics across requests", async () => {
    const contents = [
      { findings: [], documentSummary: { topics: ["FINANCIAL"], purpose: "RECORD", summary: "Synthetic receipt." } },
      { findings: [], documentSummary: { topics: ["IDENTITY"], purpose: "RECORD", summary: "Synthetic identity sample." } },
    ];
    const provider = createOpenAICompatibleProvider({
      baseUrl: "https://api.groq.com/openai/v1",
      model: "openai/gpt-oss-20b",
      apiKey: "synthetic-test-key",
    }, async (_endpoint, _apiKey, body) => {
      expect(JSON.parse(body).response_format.json_schema.strict).toBe(true);
      const next = contents.shift();
      if (!next) throw new Error("Unexpected extra provider call.");
      return {
        body: JSON.stringify({
          choices: [{ finish_reason: "stop", message: { content: JSON.stringify(next) } }],
        }),
        statusCode: 200,
      };
    });
    const chunk = { index: 1, lines: [{ segment: 0, page: 1, line: 1, text: "Synthetic data." }] };
    const first = await provider.analyzeChunk(chunk, new AbortController().signal);
    const second = await provider.analyzeChunk(chunk, new AbortController().signal);
    expect(first.documentSummary?.topics).toEqual(["FINANCIAL"]);
    expect(second.documentSummary?.topics).toEqual(["IDENTITY"]);
    expect(contents).toHaveLength(0);
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
    const result = await analyzeText(createDocumentAnalyzer(provider), "no sensitive content");

    expect(JSON.stringify(result.report)).not.toContain("echoed-secret-value");
    expect(JSON.stringify(result.report)).not.toContain("alice@example.test");
    expect(result.report.findings.find(({ source: findingSource }) => findingSource === "AI")?.explanation)
      .toContain("[REDACTED_CREDENTIAL]");
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

  it("accepts public provider DNS across address families and rejects mixed unsafe answers", async () => {
    expect(hasSafeAIBaseURLShape("https://api.openai.com/v1")).toBe(true);
    expect(hasSafeAIBaseURLShape("https://api.openai.com/v1/chat/completions")).toBe(true);
    await expect(resolveSafeAIAddresses("api.openai.com", false, async () => [
      { address: "104.18.32.47", family: 4 },
      { address: "2606:4700::6812:202f", family: 6 },
    ])).resolves.toHaveLength(2);
    await expect(resolveSafeAIAddresses("api.openai.com", false, async () => [
      { address: "104.18.32.47", family: 4 },
      { address: "10.0.0.8", family: 4 },
    ])).rejects.toMatchObject({ code: "DESTINATION_REJECTED" });
    await expect(resolveSafeAIAddresses("api.openai.com", false, async () => {
      throw new Error("private resolver detail");
    })).rejects.toMatchObject({ code: "DNS_FAILED" });
  });

  it("sends the accepted OpenAI endpoint through the mocked HTTP transport", async () => {
    let endpoint = "";
    const provider = createOpenAICompatibleProvider({
      baseUrl: "https://api.openai.com/v1",
      model: "test-model",
      apiKey: "test-secret",
    }, async (requestEndpoint) => {
      endpoint = requestEndpoint.toString();
      return JSON.stringify({
        choices: [{ message: { content: JSON.stringify({
          findings: [],
          documentSummary: { topics: [], purpose: "MIXED_OR_UNCLEAR", summary: "No supported subject was identified." },
        }) } }],
      });
    });
    const result = await provider.analyzeChunk(
      { index: 1, lines: [{ segment: 0, page: null, line: 1, text: "sample" }] },
      new AbortController().signal,
    );

    expect(endpoint).toBe("https://api.openai.com/v1/chat/completions");
    expect(result).toEqual([]);
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

  it.each([
    [400, "REQUEST_REJECTED", "invalid_request_error", "json_validate_failed"],
    [401, "AUTHENTICATION_FAILED", "invalid_request_error", "invalid_api_key"],
    [403, "ACCESS_DENIED", "permission_error", "insufficient_permissions"],
    [404, "MODEL_OR_ENDPOINT_NOT_FOUND", "invalid_request_error", "model_not_found"],
    [429, "RATE_LIMITED", "rate_limit_error", "rate_limit_exceeded"],
    [429, "RATE_LIMITED", undefined, undefined],
    [429, "CREDITS_EXHAUSTED", "insufficient_quota", "insufficient_quota"],
    [403, "PROVIDER_LIMIT_REACHED", "organization_usage_limit", "organization_usage_limit"],
    [429, "PROVIDER_LIMIT_REACHED", "project_rate_limit_exceeded", "project_rate_limit_exceeded"],
    [500, "PROVIDER_ERROR", "server_error", "internal_error"],
  ] as const)("classifies sanitized provider metadata for HTTP %i (%s)", async (status, code, errorType, errorCode) => {
    const server = createServer((_request, response) => {
      response.writeHead(status, {
        "content-type": "application/json",
        "retry-after": "12",
        "x-request-id": "req/test-123",
      });
      response.end(JSON.stringify({
        error: {
          ...(errorType ? { type: errorType } : {}),
          ...(errorCode ? { code: errorCode } : {}),
          message: status === 400
            ? "Invalid response_format: unsupported JSON schema keyword; private detail"
            : "private provider detail",
        },
      }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Mock server did not bind a TCP port.");
    try {
      const analyzer = createDocumentAnalyzer(createOpenAICompatibleProvider({
        baseUrl: `http://127.0.0.1:${address.port}/v1`,
        model: "test-model",
        apiKey: "test-secret",
        allowLoopback: true,
      }));
      const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);
      const result = await analyzeText(analyzer, "ordinary text");
      expect(result.aiAdvisory).toBe("UNAVAILABLE");
      expect(result.aiFailure).toMatchObject({
        code,
        diagnostics: {
          httpStatus: status,
          ...(status === 400 ? {
            providerErrorType: "invalid_request_error",
            providerMessageCategory: "SCHEMA_REJECTED",
          } : {}),
          ...(errorCode ? { providerErrorCode: errorCode } : {}),
        },
        providerResponse: {
          statusCode: status,
          retryAfter: "12",
          requestId: "reqtest-123",
          ...(errorType ? { errorType } : {}),
          ...(errorCode ? { errorCode } : {}),
        },
      });
      expect(JSON.stringify(result)).not.toContain("private provider detail");
      expect(JSON.stringify(result)).not.toContain("unsupported JSON schema keyword");
      expect(JSON.stringify(result)).not.toContain("test-secret");
      if (status === 400) {
        expect(JSON.stringify(result)).toContain('"code":"REQUEST_REJECTED"');
        const log = JSON.stringify(warning.mock.calls);
        expect(log).toContain("SCHEMA_REJECTED");
        expect(log).not.toContain("unsupported JSON schema keyword");
        expect(log).not.toContain("private detail");
      }
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("reports connection failures without exposing the provider URL", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Mock server did not bind a TCP port.");
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));

    const result = await analyzeText(createDocumentAnalyzer(createOpenAICompatibleProvider({
      baseUrl: `http://127.0.0.1:${address.port}/v1`,
      model: "test-model",
      apiKey: "test-secret",
      allowLoopback: true,
    })), "ordinary text");
    expect(result.aiFailure).toMatchObject({ code: "CONNECTION_FAILED" });
    expect(JSON.stringify(result)).not.toContain(`127.0.0.1:${address.port}`);
    expect(JSON.stringify(result)).not.toContain("test-secret");
  });
});
