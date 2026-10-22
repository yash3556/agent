import { createHash, randomUUID } from "node:crypto";
import path from "node:path";
import type { AuditStore } from "../config/database.js";
import { ApiError, AuditUnavailableError } from "../errors.js";
import { redact } from "./audit.service.js";
import type { DocumentFormat } from "./document-parser.js";
import { extractDocumentText } from "./document-parser.js";
import { scanText } from "./content-scanner.js";
import type { InspectionRecord } from "../types.js";

export const MAX_DOCUMENT_BYTES = 5 * 1024 * 1024;
const INSPECTION_RETENTION_MS = 24 * 60 * 60 * 1000;

const acceptedMediaTypes: Record<DocumentFormat, string[]> = {
  pdf: ["application/pdf", "application/octet-stream"],
  docx: [
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/octet-stream",
  ],
  txt: ["text/plain", "application/octet-stream"],
};

function detectFormat(file: Express.Multer.File): { format: DocumentFormat; mediaType: string } {
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
  } else {
    throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Only PDF, DOCX, and TXT files are supported.");
  }

  const declaredType = file.mimetype.toLowerCase();
  if (!acceptedMediaTypes[format].includes(declaredType)) {
    throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Declared media type does not match the supported format.");
  }
  return { format, mediaType };
}

function safeFilename(originalName: string, format: DocumentFormat): string {
  const basename = path.win32.basename(originalName).replace(/[\u0000-\u001f\u007f]/g, "");
  const stem = redact(path.win32.parse(basename).name);
  const limitedStem = [...stem].slice(0, 120).join("");
  return `${limitedStem || "document"}.${format}`;
}

export async function inspectDocument(
  store: AuditStore,
  agentId: string,
  file: Express.Multer.File,
): Promise<{
  inspectionId: string;
  status: "COMPLETED";
  document: { originalName: string; mediaType: string; sizeBytes: number };
  findings: InspectionRecord["findings"];
  summary: InspectionRecord["summary"];
  analysis: { deterministic: "COMPLETED"; aiAdvisory: "DISABLED" | "UNAVAILABLE" };
}> {
  if (!file.buffer.length) {
    throw new ApiError(422, "DOCUMENT_UNREADABLE", "Empty documents cannot be inspected.");
  }
  if (file.buffer.length > MAX_DOCUMENT_BYTES) {
    throw new ApiError(413, "PAYLOAD_TOO_LARGE", "Document exceeds the 5 MiB limit.");
  }

  const { format, mediaType } = detectFormat(file);
  const segments = await extractDocumentText(format, file.buffer);
  const scan = scanText(segments);
  const now = new Date();
  const safeName = safeFilename(file.originalname, format);
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
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + INSPECTION_RETENTION_MS),
  };

  try {
    await store.saveInspection(record);
  } catch {
    throw new AuditUnavailableError();
  }

  const aiStatus = process.env.AI_PROVIDER && process.env.AI_PROVIDER !== "disabled"
    ? "UNAVAILABLE"
    : "DISABLED";
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
    analysis: { deterministic: "COMPLETED", aiAdvisory: aiStatus },
  };
}
