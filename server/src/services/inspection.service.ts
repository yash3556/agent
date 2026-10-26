import { createHash, randomUUID } from "node:crypto";
import path from "node:path";
import type { AuditStore } from "../config/database.js";
import { ApiError, AuditUnavailableError } from "../errors.js";
import type { DocumentFormat } from "./document-parser.js";
import { extractDocumentText } from "./document-parser.js";
import { MAX_DOCUMENT_BYTES } from "./document-limits.js";
import { scanText } from "./content-scanner.js";
import type { InspectionRecord } from "../types.js";
import {
  createConfiguredDocumentAnalyzer,
  documentSummaryPurposeValues,
  documentSummaryTopicValues,
  redactDocumentText,
} from "../ai/document-analysis.js";
import type { AIFailureDetails, DocumentAnalyzer } from "../ai/document-analysis.js";
import { z } from "zod";

export { MAX_DOCUMENT_BYTES } from "./document-limits.js";
const INSPECTION_RETENTION_MS = 24 * 60 * 60 * 1000;
const documentCoverageSchema = z.object({
  format: z.string().min(1).max(16),
  extractedPages: z.number().int().nonnegative().nullable(),
  inspectedPages: z.number().int().nonnegative().nullable(),
  textSegments: z.number().int().nonnegative(),
  limitations: z.array(z.string().max(160)).max(4),
}).strict();
const documentSummarySchema = z.object({
  status: z.enum(["AI_EXCERPTS", "DETERMINISTIC_FALLBACK", "UNAVAILABLE"]),
  topics: z.array(z.enum(documentSummaryTopicValues)).max(7),
  purpose: z.enum(documentSummaryPurposeValues),
  text: z.string().min(1).max(500),
}).strict();

const acceptedMediaTypes: Record<DocumentFormat, string[]> = {
  pdf: ["application/pdf", "application/octet-stream"],
  docx: [
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/octet-stream",
  ],
  txt: ["text/plain", "application/octet-stream"],
  csv: ["text/csv", "application/csv", "application/octet-stream"],
  json: ["application/json", "text/json", "application/octet-stream"],
  markdown: ["text/markdown", "text/x-markdown", "text/plain", "application/octet-stream"],
  xlsx: [
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/octet-stream",
  ],
};

function detectFormat(file: Express.Multer.File): {
  format: DocumentFormat;
  mediaType: string;
  extension: string;
} {
  const extension = path.extname(path.win32.basename(file.originalname)).toLowerCase();
  let format: DocumentFormat;
  let mediaType: string;
  if (extension === ".pdf") {
    format = "pdf";
    mediaType = "application/pdf";
    if (file.buffer.subarray(0, 5).toString("ascii") !== "%PDF-") {
      throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "File content does not match PDF format.");
    }
  } else if (extension === ".docx") {
    format = "docx";
    mediaType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    if (file.buffer.subarray(0, 4).toString("hex") !== "504b0304") {
      throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "File content does not match DOCX format.");
    }
  } else if (extension === ".txt") {
    format = "txt";
    mediaType = "text/plain";
  } else if (extension === ".csv") {
    format = "csv";
    mediaType = "text/csv";
  } else if (extension === ".json") {
    format = "json";
    mediaType = "application/json";
  } else if (extension === ".md" || extension === ".markdown") {
    format = "markdown";
    mediaType = "text/markdown";
  } else if (extension === ".xlsx") {
    format = "xlsx";
    mediaType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    if (file.buffer.subarray(0, 4).toString("hex") !== "504b0304") {
      throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "File content does not match XLSX format.");
    }
  } else {
    throw new ApiError(
      415,
      "UNSUPPORTED_MEDIA_TYPE",
      "Only PDF, DOCX, TXT, CSV, JSON, Markdown, and XLSX files are supported.",
    );
  }

  const declaredType = file.mimetype.toLowerCase().split(";")[0].trim();
  if (!acceptedMediaTypes[format].includes(declaredType)) {
    throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Declared media type does not match the supported format.");
  }
  return { format, mediaType, extension: format === "markdown" ? "md" : format };
}

function safeFilename(originalName: string, extension: string): string {
  const basename = path.win32.basename(originalName.normalize("NFKC"))
    .replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "");
  const stem = redactDocumentText(path.win32.parse(basename).name)
    .replace(/[<>:"|?*]/g, "_")
    .replace(/[. ]+$/g, "")
    .trim();
  const limitedStem = [...stem].slice(0, 120).join("");
  return `${limitedStem || "document"}.${extension}`;
}

export async function inspectDocument(
  store: AuditStore,
  agentId: string,
  file: Express.Multer.File,
  documentAnalyzer: DocumentAnalyzer = createConfiguredDocumentAnalyzer(),
): Promise<{
  inspectionId: string;
  status: "COMPLETED";
  document: { originalName: string; mediaType: string; sizeBytes: number };
  findings: InspectionRecord["findings"];
  summary: InspectionRecord["summary"];
  analysis: {
    deterministic: "COMPLETED";
    aiAdvisory: "DISABLED" | "UNAVAILABLE" | "AVAILABLE" | "NOT_NEEDED";
    aiFailure?: AIFailureDetails;
  };
  report: NonNullable<InspectionRecord["report"]> & {
    documentCoverage: NonNullable<InspectionRecord["report"]>["documentCoverage"];
  };
}> {
  if (!file.buffer.length) {
    throw new ApiError(422, "DOCUMENT_UNREADABLE", "Empty documents cannot be inspected.");
  }
  if (file.buffer.length > MAX_DOCUMENT_BYTES) {
    throw new ApiError(413, "PAYLOAD_TOO_LARGE", "Document exceeds the 5 MiB limit.");
  }

  const { format, mediaType, extension } = detectFormat(file);
  const segments = await extractDocumentText(format, file.buffer);
  const scan = scanText(segments);
  const analysis = await documentAnalyzer.analyze(
    segments,
    scan.findings,
    scan.summary,
    scan.findingSegments,
    scan.findingLocations,
  );
  const pdfPages = format === "pdf" ? segments.filter((segment) => segment.page !== null).length : null;
  const report = {
    ...analysis.report,
    documentSummary: documentSummarySchema.parse(analysis.report.documentSummary ?? {
      status: analysis.aiAdvisory === "AVAILABLE" ? "UNAVAILABLE" : "DETERMINISTIC_FALLBACK",
      topics: [],
      purpose: "MIXED_OR_UNCLEAR",
      text: analysis.aiAdvisory === "DISABLED"
        ? "The inspection scanned extracted text for supported security patterns. A meaningful content summary is unavailable because AI analysis is disabled."
        : analysis.aiAdvisory === "UNAVAILABLE"
          ? "The inspection scanned extracted text for supported security patterns. A meaningful content summary is unavailable because AI analysis did not complete."
          : analysis.aiAdvisory === "AVAILABLE"
            ? "AI analysis ran on sanitized excerpts but produced no usable semantic summary."
            : "No semantic summary was produced because no finding-related excerpts were sent to AI.",
    }),
    documentCoverage: documentCoverageSchema.parse({
      format,
      extractedPages: pdfPages,
      inspectedPages: pdfPages,
      textSegments: segments.length,
      limitations: [
        "Summary uses selected sanitized excerpts and is not a complete semantic review of all extracted content.",
        ...(format === "pdf" ? [
          "OCR is not performed; image-only page content may not be extracted.",
          "PDF text is flattened per page; line references are extracted-text lines, not visual coordinates.",
        ] : []),
        ...(format === "pdf" && segments.every((segment) => !segment.text.trim())
          ? ["No selectable text was extracted from these pages."]
          : []),
      ],
    }),
  };
  const now = new Date();
  const safeName = safeFilename(file.originalname, extension);
  const record: InspectionRecord = {
    inspectionId: `ins_${randomUUID()}`,
    agentId,
    status: "COMPLETED",
    originalName: safeName,
    mediaType,
    sizeBytes: file.size,
    sha256: createHash("sha256").update(file.buffer).digest("hex"),
    findings: scan.findings,
    summary: scan.summary,
    report,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + INSPECTION_RETENTION_MS),
  };

  try {
    await store.saveInspection(record);
    await store.insertEvent({
      eventId: `evt_${randomUUID()}`,
      timestamp: now.toISOString(),
      agentId,
      tool: "inspect_document",
      resource: record.inspectionId,
      decision: "INSPECTED",
      ruleId: "DOC-001",
      reason: `Document inspection completed with ${report.findings.length} reported finding(s); no action was authorized.`,
      executed: false,
      approvalId: null,
      inspectionId: record.inspectionId,
      advisory: null,
      type: "DOCUMENT_INSPECTION",
      documentName: safeName,
      findingCount: report.findings.length,
      reportRiskLevel: report.riskLevel,
      reportStatus: report.status,
    });
  } catch {
    try {
      await store.deleteInspection(record.inspectionId);
    } catch {
      console.error("Could not clean up a failed document inspection.");
    }
    throw new AuditUnavailableError();
  }

  return {
    inspectionId: record.inspectionId,
    status: "COMPLETED",
    document: {
      originalName: safeName,
      mediaType,
      sizeBytes: file.size,
    },
    findings: record.findings,
    summary: record.summary,
    analysis: {
      deterministic: "COMPLETED",
      aiAdvisory: analysis.aiAdvisory,
      ...(analysis.aiFailure ? { aiFailure: analysis.aiFailure } : {}),
    },
    report,
  };
}
