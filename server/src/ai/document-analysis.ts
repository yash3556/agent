// server/src/ai/document-analysis.ts
import { lookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type {
  DocumentSecurityReport,
  DocumentReportFinding,
  FindingCategory,
  FindingSeverity,
  InspectionFinding,
} from "../types.js";
import type { ScanSummary } from "../services/content-scanner.js";
import { redactSensitiveText } from "../services/redaction.js";
import type { TextSegment } from "../services/content-scanner.js";

const DEFAULT_BASE_URL = "https://api.openai.com/v1";
const MAX_CHUNK_BYTES = 32 * 1024;
const MAX_CHUNKS = 128;
let activeAIRequests = 0;
const MAX_ACTIVE_AI_REQUESTS = 3;

export function utf8ByteLength(input: string): number {
  return Buffer.byteLength(input, "utf8");
}

export function chunkByUtf8Bytes(
  text: string,
  maxChunkBytes: number = MAX_CHUNK_BYTES,
): string[] {
  const chunks: string[] = [];
  let current = "";
  let currentBytes = 0;

  for (const char of text) {
    const charBytes = utf8ByteLength(char);
    if (currentBytes + charBytes > maxChunkBytes && current.length > 0) {
      chunks.push(current);
      current = "";
      currentBytes = 0;
    }
    current += char;
    currentBytes += charBytes;
  }

  if (current.length > 0) chunks.push(current);
  return chunks;
}

export const FindingCategorySchema = z.custom<FindingCategory>(
  (v) => typeof v === "string",
  { message: "Expected FindingCategory" },
);

export const FindingSeveritySchema = z.custom<FindingSeverity>(
  (v) => typeof v === "string",
  { message: "Expected FindingSeverity" },
);

export const InspectionFindingSchema = z.custom<InspectionFinding>(
  (v) => typeof v === "object" && v !== null,
  { message: "Expected InspectionFinding" },
);

export const DocumentReportFindingSchema = z.custom<DocumentReportFinding>(
  (v) => typeof v === "object" && v !== null,
  { message: "Expected DocumentReportFinding" },
);

export const ScanSummarySchema = z.custom<ScanSummary>(
  (v) => typeof v === "object" && v !== null,
  { message: "Expected ScanSummary" },
);

export const DocumentSecurityReportSchema = z.custom<DocumentSecurityReport>(
  (v) => typeof v === "object" && v !== null,
  { message: "Expected DocumentSecurityReport" },
);

export function createDocumentReportFinding<T extends { evidence?: string }>(
  finding: T,
  redactEvidence = true,
): T {
  if (!redactEvidence || finding.evidence === undefined) return finding;
  return { ...finding, evidence: redactSensitiveText(finding.evidence) };
}

const PRIVATE_RANGES = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const) {
  PRIVATE_RANGES.addSubnet(
    network,
    prefix,
    isIP(network) === 6 ? "ipv6" : "ipv4",
  );
}

export function isPrivateAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 0) return false;
  return PRIVATE_RANGES.check(ip, family === 6 ? "ipv6" : "ipv4");
}

function isLoopback(address: string): boolean {
  if (isIP(address) === 4) return address.startsWith("127.");
  return address.toLowerCase() === "::1";
}

export function hasSafeAIBaseURLShape(baseUrlText: string, allowLoopback = false): boolean {
  try {
    const url = new URL(baseUrlText);
    const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const fam = isIP(host);
    const literalLoopback = fam > 0 && isLoopback(host);
    const hostnameLoopback = host === "localhost" || host.endsWith(".localhost");
    const isLoop = literalLoopback || hostnameLoopback;
    const hasPort = url.port !== "" && url.port !== (url.protocol === "https:" ? "443" : "80");
    if (!["https:", "http:"].includes(url.protocol) || !host || url.username || url.password || url.search || url.hash) return false;
    if (decodeURIComponent(url.pathname).split("/").includes("..") || url.pathname.includes("\\")) return false;
    if (fam > 0 && !literalLoopback && isPrivateAddress(host)) return false;
    if (url.protocol === "http:" && (!allowLoopback || !isLoop)) return false;
    if (isLoop && !allowLoopback) return false;
    if (url.protocol === "https:" && hasPort && !isLoop) return false;
    return true;
  } catch {
    return false;
  }
}

export async function resolveSafeAIAddresses(
  hostname: string,
  allowLoopback = false,
  resolver?: (host: string) => Promise<Array<{ address: string; family: number }>>,
): Promise<Array<{ address: string; family: number }>> {
  const norm = hostname.replace(/^\[|\]$/g, "");
  const fam = isIP(norm);
  let records: Array<{ address: string; family: number }>;
  try {
    if (resolver) {
      records = await resolver(norm);
    } else if (fam > 0) {
      records = [{ address: norm, family: fam }];
    } else {
      records = await lookup(norm, { all: true, verbatim: true });
    }
  } catch {
    const error: any = new Error("DNS resolution failed");
    error.code = "DNS_FAILED";
    throw error;
  }
  if (!records || records.length === 0) {
    const error: any = new Error("No DNS records");
    error.code = "DNS_FAILED";
    throw error;
  }
  const allLoop = records.every((r) => isLoopback(r.address));
  if (allLoop) {
    if (!allowLoopback) {
      const error: any = new Error("Loopback is not allowed");
      error.code = "DESTINATION_REJECTED";
      throw error;
    }
    return records;
  }
  if (records.some((r) => isPrivateAddress(r.address) || isLoopback(r.address))) {
    const error: any = new Error("Private or loopback address rejected");
    error.code = "DESTINATION_REJECTED";
    throw error;
  }
  return records;
}

export function getDocumentAIStatus(): "configured" | "unavailable" | "disabled" {
  const provider = process.env.AI_PROVIDER?.trim().toLowerCase() || "disabled";
  if (provider === "disabled") return "disabled";
  if (provider !== "openai-compatible") return "unavailable";

  const model = process.env.AI_MODEL?.trim();
  const apiKey = process.env.AI_API_KEY?.trim();
  const allowLoopback = process.env.AI_ALLOW_LOOPBACK === "true";
  const baseUrl = process.env.AI_BASE_URL?.trim() || DEFAULT_BASE_URL;
  if (!model || model.length > 256 || /[\u0000-\u001f\u007f]/.test(model)
    || !apiKey || apiKey.length > 4096 || /[\r\n]/.test(apiKey)) {
    return "unavailable";
  }
  return hasSafeAIBaseURLShape(baseUrl, allowLoopback) ? "configured" : "unavailable";
}

export function getAIAnalysisStatus(): "configured" | "unavailable" | "disabled" {
  return getDocumentAIStatus();
}

export interface DocumentTextLine {
  segment: number;
  page: number | null;
  line: number;
  text: string;
}

export interface DocumentTextChunk {
  index: number;
  lines: DocumentTextLine[];
  structure?: {
    findingCount: number;
    [key: string]: unknown;
  };
}

export interface DocumentAIProvider {
  analyzeChunk(chunk: DocumentTextChunk, signal: AbortSignal): Promise<any[]>;
}

export interface OpenAICompatibleProviderOptions {
  baseUrl: string;
  model: string;
  apiKey: string;
  allowLoopback?: boolean;
}

export type ChatCompletionTransport = (
  endpoint: URL,
  apiKey: string,
  body: string,
  signal: AbortSignal,
  allowLoopback: boolean,
) => Promise<string>;

export type ChatCompletionClient = (
  messages: Array<{ role: "system" | "user"; content: string }>,
  signal: AbortSignal,
) => Promise<string>;

export interface DocumentAnalyzerOptions {
  maxChunks?: number;
  maxConcurrentRequests?: number;
  totalTimeoutMs?: number;
}

async function postJSON(
  endpoint: URL,
  apiKey: string,
  body: string,
  signal: AbortSignal,
  allowLoopback: boolean,
): Promise<string> {
  const addresses = await resolveSafeAIAddresses(endpoint.hostname, allowLoopback);
  const selected = addresses[0];
  const isHttps = endpoint.protocol === "https:";
  const port = endpoint.port ? Number(endpoint.port) : (isHttps ? 443 : 80);
  const reqFn = isHttps ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    let finished = false;
    const req = reqFn(
      {
        host: selected.address,
        port,
        path: `${endpoint.pathname}${endpoint.search}`,
        method: "POST",
        headers: {
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body, "utf8"),
          host: endpoint.host,
        },
        timeout: 8000,
        servername: isHttps && isIP(endpoint.hostname) === 0 ? endpoint.hostname : undefined,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          if (finished) return;
          finished = true;
          const status = res.statusCode ?? 500;
          const bodyText = Buffer.concat(chunks).toString("utf8");
          if (status < 200 || status >= 300) {
            let errorType: string | undefined;
            let errorCode: string | undefined;
            try {
              const parsed = JSON.parse(bodyText);
              errorType = parsed?.error?.type;
              errorCode = parsed?.error?.code;
            } catch {}

            const retryAfter = res.headers["retry-after"] as string | undefined;
            const rawReqId = res.headers["x-request-id"] as string | undefined;
            const requestId = rawReqId ? rawReqId.replace(/[^a-zA-Z0-9_-]/g, "") : undefined;

            let code = "PROVIDER_ERROR";
            if (status === 401) {
              code = "AUTHENTICATION_FAILED";
            } else if (status === 403) {
              code = (errorType === "organization_usage_limit" || errorCode === "organization_usage_limit")
                ? "PROVIDER_LIMIT_REACHED"
                : "ACCESS_DENIED";
            } else if (status === 404) {
              code = "MODEL_OR_ENDPOINT_NOT_FOUND";
            } else if (status === 429) {
              if (errorCode === "insufficient_quota") code = "CREDITS_EXHAUSTED";
              else if (errorCode === "project_rate_limit_exceeded") code = "PROVIDER_LIMIT_REACHED";
              else code = "RATE_LIMITED";
            }

            const err: any = new Error(`Provider returned HTTP ${status}`);
            err.aiFailure = {
              code,
              providerResponse: {
                statusCode: status,
                ...(retryAfter ? { retryAfter } : {}),
                ...(requestId ? { requestId } : {}),
                ...(errorType ? { errorType } : {}),
                ...(errorCode ? { errorCode } : {}),
              },
            };
            reject(err);
            return;
          }
          resolve(bodyText);
        });
        res.on("error", () => {
          if (finished) return;
          finished = true;
          const err: any = new Error("Response read error");
          err.aiFailure = { code: "CONNECTION_FAILED" };
          reject(err);
        });
      },
    );

    const onAbort = () => {
      if (finished) return;
      finished = true;
      req.destroy();
      const err: any = new Error("Provider request aborted");
      err.aiFailure = { code: "TIMEOUT" };
      reject(err);
    };
    signal.addEventListener("abort", onAbort, { once: true });

    req.on("timeout", () => {
      if (finished) return;
      finished = true;
      req.destroy();
      const err: any = new Error("Provider request timeout");
      err.aiFailure = { code: "TIMEOUT" };
      reject(err);
    });

    req.on("error", () => {
      if (finished) return;
      finished = true;
      const err: any = new Error("Connection failed");
      err.aiFailure = { code: "CONNECTION_FAILED" };
      reject(err);
    });

    req.write(body);
    req.end();
  });
}

export function createConfiguredChatCompletionClient(
  transport: ChatCompletionTransport = postJSON,
): ChatCompletionClient | null {
  if (getDocumentAIStatus() !== "configured") return null;
  const baseUrl = process.env.AI_BASE_URL?.trim() || DEFAULT_BASE_URL;
  const endpoint = new URL(`${baseUrl.replace(/\/+$/, "")}/chat/completions`);
  const model = process.env.AI_MODEL!.trim();
  const apiKey = process.env.AI_API_KEY!.trim();
  const allowLoopback = process.env.AI_ALLOW_LOOPBACK === "true";
  return (messages, signal) => transport(
    endpoint,
    apiKey,
    JSON.stringify({ model, messages }),
    signal,
    allowLoopback,
  );
}

const aiCategorySchema = z.enum([
  "PERSONAL_DATA",
  "CREDENTIAL",
  "SUSPICIOUS_INSTRUCTION",
  "PROMPT_INJECTION",
  "DATA_EXFILTRATION",
  "POLICY_BYPASS",
  "MALICIOUS_CODE",
  "OTHER",
]);

const aiChunkResponseSchema = z.object({
  findings: z.array(z.object({
    category: aiCategorySchema,
    type: z.string().trim().min(1).max(64),
    severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    confidence: z.number().min(0).max(1),
    explanation: z.string().trim().min(1).max(500),
    recommendation: z.string().trim().min(1).max(500),
    evidenceReferences: z.array(z.object({
      page: z.number().int().positive().nullable(),
      line: z.number().int().positive(),
    }).strict()).min(1).max(5),
  }).strict()).max(12),
}).strict();

export function createOpenAICompatibleProvider(
  options: OpenAICompatibleProviderOptions,
  transport: ChatCompletionTransport = postJSON,
): DocumentAIProvider {
  if (
    !options.model.trim()
    || options.model.length > 256
    || /[\u0000-\u001f\u007f]/.test(options.model)
    || !options.apiKey.trim()
    || options.apiKey.length > 4096
    || /[\r\n]/.test(options.apiKey)
  ) {
    throw new Error("Invalid provider options.");
  }
  const endpoint = new URL(options.baseUrl.replace(/\/+$/, "") + "/chat/completions");

  return {
    async analyzeChunk(chunk: DocumentTextChunk, signal: AbortSignal) {
      const safeLines = chunk.lines.map((l) => ({
        ...l,
        text: redactSensitiveText(l.text),
      }));
      const body = JSON.stringify({
        model: options.model,
        messages: [
          { role: "system", content: "You are a document security scanner." },
          { role: "user", content: JSON.stringify({ chunkIndex: chunk.index, lines: safeLines }) },
        ],
      });
      const res = await transport(endpoint, options.apiKey, body, signal, !!options.allowLoopback);
      let parsed: any;
      try {
        parsed = JSON.parse(res);
      } catch {
        const err: any = new Error("Invalid JSON in provider response");
        err.aiFailure = { code: "INVALID_RESPONSE" };
        throw err;
      }
      const content = parsed?.choices?.[0]?.message?.content;
      if (typeof content !== "string") {
        const err: any = new Error("Invalid content shape");
        err.aiFailure = { code: "INVALID_RESPONSE" };
        throw err;
      }
      let findingsObj: any;
      try {
        findingsObj = JSON.parse(content);
      } catch {
        const err: any = new Error("Invalid JSON in content");
        err.aiFailure = { code: "INVALID_RESPONSE" };
        throw err;
      }
      const validated = aiChunkResponseSchema.safeParse(findingsObj);
      if (!validated.success) {
        const err: any = new Error("Provider findings do not match schema");
        err.aiFailure = { code: "INVALID_RESPONSE" };
        throw err;
      }
      return validated.data.findings;
    },
  };
}

export interface AIFailureDetails {
  code: string;
  providerResponse?: {
    statusCode: number;
    retryAfter?: string;
    requestId?: string;
    errorType?: string;
    errorCode?: string;
  };
}

export interface DocumentAnalyzer {
  analyze(
    segments: TextSegment[],
    deterministicFindings: InspectionFinding[],
    deterministicSummary: ScanSummary,
    findingSegments?: number[],
    findingLocations?: Array<{ segment: number; page: number | null; line: number; start: number; end: number }>,
  ): Promise<{
    report: DocumentSecurityReport;
    aiAdvisory: "DISABLED" | "UNAVAILABLE" | "AVAILABLE" | "NOT_NEEDED";
    aiFailure?: AIFailureDetails;
  }>;
}

export function createDocumentAnalyzer(
  provider?: DocumentAIProvider,
  options: DocumentAnalyzerOptions = {},
): DocumentAnalyzer {
  const maxChunks = Math.max(1, Math.min(128, options.maxChunks ?? 128));
  const totalTimeoutMs = Math.max(1, Math.min(30_000, options.totalTimeoutMs ?? 30_000));

  return {
    async analyze(segments, deterministicFindings, deterministicSummary, _findingSegments, findingLocations) {
      const severityOrder: FindingSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
      const detRisk = [...severityOrder].reverse().find((sev) =>
        deterministicFindings.some((f) => f.severity === sev),
      ) ?? "UNKNOWN";

      const configuredStatus = getDocumentAIStatus();
      const aiAdvisory: "DISABLED" | "UNAVAILABLE" | "AVAILABLE" | "NOT_NEEDED" = provider
        ? "AVAILABLE"
        : configuredStatus === "configured"
          ? "AVAILABLE"
          : configuredStatus === "disabled" ? "DISABLED" : "UNAVAILABLE";

      const makeDeterministicFindings = () => deterministicFindings.map((finding, index) => {
        const location = findingLocations?.[index];
        return {
          id: finding.id,
          source: "DETERMINISTIC" as const,
          category: finding.category,
          type: finding.type,
          severity: finding.severity,
          confidence: finding.confidence,
          explanation: finding.description,
          recommendation: "Review the finding using the original document in your secure workflow.",
          evidenceReferences: [{
            page: location?.page ?? finding.location.page,
            line: location?.line ?? finding.location.line ?? 1,
            chunk: null,
          }],
        };
      });

      if (aiAdvisory === "DISABLED") {
        return {
          report: {
            version: 1,
            status: "DETERMINISTIC_ONLY",
            riskLevel: detRisk,
            summary: `${deterministicFindings.length} deterministic finding(s) were reported.`,
            truncated: deterministicSummary.truncated,
            findings: makeDeterministicFindings(),
            coverage: {
              extraction: "COMPLETED",
              deterministic: "COMPLETED",
              ai: "DISABLED",
              totalChunks: segments.length,
              completedChunks: 0,
              failedChunks: 0,
            },
          },
          aiAdvisory: "DISABLED",
        };
      }

      if (segments.length === 0) {
        return {
          report: {
            version: 1,
            status: "DETERMINISTIC_ONLY",
            riskLevel: detRisk,
            summary: "0 deterministic finding(s) were reported.",
            truncated: false,
            findings: [],
            coverage: {
              extraction: "COMPLETED",
              deterministic: "COMPLETED",
              ai: "NO_CONTENT",
              totalChunks: 0,
              completedChunks: 0,
              failedChunks: 0,
            },
          },
          aiAdvisory: "NOT_NEEDED",
        };
      }

      if (deterministicFindings.length === 0) {
        return {
          report: {
            version: 1,
            status: "DETERMINISTIC_ONLY",
            riskLevel: "UNKNOWN",
            summary: "0 deterministic finding(s) were reported.",
            truncated: deterministicSummary.truncated,
            findings: [],
            coverage: {
              extraction: "COMPLETED",
              deterministic: "COMPLETED",
              ai: "NO_FINDING_CONTEXT",
              totalChunks: 0,
              completedChunks: 0,
              failedChunks: 0,
            },
          },
          aiAdvisory: "NOT_NEEDED",
        };
      }

      if (aiAdvisory === "UNAVAILABLE" && !provider) {
        return {
          report: {
            version: 1,
            status: "DETERMINISTIC_ONLY",
            riskLevel: detRisk,
            summary: `${deterministicFindings.length} deterministic finding(s) were reported.`,
            truncated: deterministicSummary.truncated,
            findings: makeDeterministicFindings(),
            coverage: {
              extraction: "COMPLETED",
              deterministic: "COMPLETED",
              ai: "UNAVAILABLE",
              totalChunks: segments.length,
              completedChunks: 0,
              failedChunks: segments.length,
            },
          },
          aiAdvisory,
          aiFailure: { code: "PROVIDER_UNAVAILABLE" },
        };
      }

      const activeProvider = provider ?? createOpenAICompatibleProvider({
        baseUrl: process.env.AI_BASE_URL?.trim() || DEFAULT_BASE_URL,
        model: process.env.AI_MODEL?.trim() || "test-model",
        apiKey: process.env.AI_API_KEY?.trim() || "",
        allowLoopback: process.env.AI_ALLOW_LOOPBACK === "true",
      });

      const targetLines = new Set<string>();
      if (findingLocations && findingLocations.length > 0) {
        for (const loc of findingLocations) {
          for (let l = Math.max(1, loc.line - 1); l <= loc.line + 1; l++) {
            targetLines.add(`${loc.segment}:${l}`);
          }
        }
      } else {
        for (const f of deterministicFindings) {
          const l = f.location.line ?? 1;
          for (let lineNum = Math.max(1, l - 1); lineNum <= l + 1; lineNum++) {
            targetLines.add(`0:${lineNum}`);
          }
        }
      }

      const chunks: DocumentTextChunk[] = [];
      let currentLines: DocumentTextLine[] = [];
      let currentBytes = 0;

      const finishChunk = () => {
        if (currentLines.length > 0) {
          chunks.push({
            index: chunks.length + 1,
            lines: currentLines,
            structure: {
              findingCount: deterministicFindings.length,
              totalSegments: segments.length,
            },
          });
          currentLines = [];
          currentBytes = 0;
        }
      };

      const privateKeyRegex = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/gi;
      segments.forEach((segment, segIdx) => {
        const textWithRedactedKeys = segment.text.replace(
          privateKeyRegex,
          (b) => `[REDACTED_PRIVATE_KEY]${b.match(/\r\n|\r|\n/g)?.join("") ?? ""}`,
        );
        const lines = textWithRedactedKeys.split(/\r\n|\r|\n/);
        lines.forEach((lineText, lineIdx) => {
          const lineNum = lineIdx + 1;
          if (!targetLines.has(`${segIdx}:${lineNum}`)) return;
          const safeText = redactSensitiveText(lineText);
          const lineObj: DocumentTextLine = {
            segment: segIdx,
            page: segment.page,
            line: lineNum,
            text: safeText,
          };
          const lineBytes = Buffer.byteLength(JSON.stringify(lineObj), "utf8");
          if (currentLines.length > 0 && currentBytes + lineBytes > 32 * 1024) {
            finishChunk();
          }
          currentLines.push(lineObj);
          currentBytes += lineBytes;
        });
      });
      finishChunk();

      if (chunks.length === 0) {
        chunks.push({
          index: 1,
          lines: [{ segment: 0, page: segments[0].page, line: 1, text: redactSensitiveText(segments[0].text.slice(0, 100)) }],
          structure: { findingCount: deterministicFindings.length, totalSegments: segments.length },
        });
      }

      const totalChunks = chunks.length;
      const chunksToAnalyze = chunks.slice(0, maxChunks);
      const isChunkCapped = totalChunks > maxChunks;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), totalTimeoutMs);

      let completedChunks = 0;
      let failedChunks = 0;
      let lastFailure: AIFailureDetails | undefined;
      const aiFindings: DocumentReportFinding[] = [];

      if (activeAIRequests >= MAX_ACTIVE_AI_REQUESTS) {
        clearTimeout(timeout);
        return {
          report: {
            version: 1,
            status: "PARTIAL",
            riskLevel: detRisk,
            summary: `${deterministicFindings.length} deterministic finding(s) were reported. AI analysis failed - deterministic scan completed.`,
            truncated: true,
            findings: makeDeterministicFindings(),
            coverage: {
              extraction: "COMPLETED",
              deterministic: "COMPLETED",
              ai: "INCOMPLETE",
              totalChunks,
              completedChunks: 0,
              failedChunks: totalChunks,
            },
          },
          aiAdvisory: "UNAVAILABLE",
          aiFailure: { code: "CONNECTION_FAILED" },
        };
      }

      for (const ch of chunksToAnalyze) {
        if (controller.signal.aborted) {
          failedChunks += 1;
          lastFailure = { code: "TIMEOUT" };
          continue;
        }

        activeAIRequests += 1;
        try {
          const rawFindings = await activeProvider.analyzeChunk(ch, controller.signal);
          let validChunk = true;
          for (const rf of rawFindings) {
            for (const ref of rf.evidenceReferences ?? []) {
              const matches = ch.lines.some((l) => l.page === ref.page && l.line === ref.line);
              if (!matches) {
                validChunk = false;
                break;
              }
            }
            if (!validChunk) break;
          }

          if (!validChunk) {
            failedChunks += 1;
            continue;
          }

          completedChunks += 1;
          for (const rf of rawFindings) {
            aiFindings.push({
              id: `ai_${randomUUID()}`,
              source: "AI",
              category: rf.category,
              type: redactSensitiveText(rf.type),
              severity: rf.severity,
              confidence: rf.confidence,
              explanation: redactSensitiveText(rf.explanation),
              recommendation: redactSensitiveText(rf.recommendation),
              evidenceReferences: rf.evidenceReferences.map((ref: any) => ({
                page: ref.page,
                line: ref.line,
                chunk: ch.index,
              })),
            });
          }
        } catch (err: any) {
          failedChunks += 1;
          lastFailure = err.aiFailure ?? { code: "CONNECTION_FAILED" };
        } finally {
          activeAIRequests -= 1;
        }
      }

      clearTimeout(timeout);

      if (isChunkCapped) {
        failedChunks += totalChunks - maxChunks;
        lastFailure = { code: "ANALYSIS_LIMIT" };
      }

      if (controller.signal.aborted) {
        lastFailure = { code: "TIMEOUT" };
      }

      const isTruncated = aiFindings.length > 100 || isChunkCapped;
      const boundedAIFindings = aiFindings.slice(0, 100);
      const allFindings = [...makeDeterministicFindings(), ...boundedAIFindings];

      const allRisk = [...severityOrder].reverse().find((sev) =>
        allFindings.some((f) => f.severity === sev),
      ) ?? detRisk;

      const isFailed = failedChunks > 0;
      const reportStatus: DocumentSecurityReport["status"] = isFailed || isTruncated ? "PARTIAL" : "COMPLETE";
      const coverageAI: DocumentSecurityReport["coverage"]["ai"] = isFailed ? "INCOMPLETE" : "COMPLETED";

      let summary = `${allFindings.length} finding(s) reported.`;
      if (isFailed && completedChunks === 0) {
        summary = `${deterministicFindings.length} deterministic finding(s) were reported. AI analysis failed - deterministic scan completed.`;
      }

      return {
        report: {
          version: 1,
          status: reportStatus,
          riskLevel: allRisk,
          summary,
          truncated: isTruncated || deterministicSummary.truncated,
          findings: allFindings,
          coverage: {
            extraction: "COMPLETED",
            deterministic: "COMPLETED",
            ai: coverageAI,
            totalChunks,
            completedChunks,
            failedChunks,
          },
        },
        aiAdvisory: isFailed && completedChunks === 0 ? "UNAVAILABLE" : "AVAILABLE",
        ...(lastFailure ? { aiFailure: lastFailure } : {}),
      };
    },
  };
}

export function createConfiguredDocumentAnalyzer(): DocumentAnalyzer {
  return createDocumentAnalyzer();
}

export { redactSensitiveText };
export type { ScanSummary };
export type {
  DocumentSecurityReport,
  DocumentReportFinding,
  FindingCategory,
  FindingSeverity,
  InspectionFinding,
};
export { randomUUID };
