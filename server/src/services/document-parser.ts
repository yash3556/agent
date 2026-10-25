import { Worker } from "node:worker_threads";
import { ApiError } from "../errors.js";
import type { TextSegment } from "./content-scanner.js";
import {
  DOCUMENT_PARSER_TIMEOUT_MS,
  MAX_CONCURRENT_DOCUMENT_INSPECTIONS,
} from "./document-limits.js";

export type DocumentFormat = "pdf" | "docx" | "txt" | "csv" | "json" | "markdown" | "xlsx";

let activeParsers = 0;

export async function extractDocumentText(
  format: DocumentFormat,
  buffer: Buffer,
): Promise<TextSegment[]> {
  if (activeParsers >= MAX_CONCURRENT_DOCUMENT_INSPECTIONS) {
    throw new ApiError(503, "INSPECTION_UNAVAILABLE", "Document inspection capacity is full.");
  }

  activeParsers += 1;
  const bytes = Uint8Array.from(buffer);
  let worker: Worker | undefined;

  try {
    const workerInstance = new Worker(new URL("./document-parser.worker.ts", import.meta.url), {
      workerData: { format, bytes },
      execArgv: ["--import", "tsx"],
      resourceLimits: {
        maxOldGenerationSizeMb: 128,
        maxYoungGenerationSizeMb: 32,
        stackSizeMb: 4,
      },
    });
    worker = workerInstance;
    return await new Promise<TextSegment[]>((resolve, reject) => {
      const timeout = setTimeout(() => {
        void workerInstance.terminate();
        reject(new ApiError(422, "DOCUMENT_UNREADABLE", "Document parsing exceeded its time limit."));
      }, DOCUMENT_PARSER_TIMEOUT_MS);

      workerInstance.once("message", (message: {
        ok: boolean;
        code?: string;
        segments?: TextSegment[];
      }) => {
        clearTimeout(timeout);
        if (message.ok && message.segments) {
          resolve(message.segments);
        } else if (message.code === "UNSUPPORTED_MEDIA_TYPE") {
          reject(new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "File content does not match its declared format."));
        } else {
          reject(new ApiError(422, "DOCUMENT_UNREADABLE", "Document could not be safely parsed."));
        }
      });
      workerInstance.once("error", () => {
        clearTimeout(timeout);
        reject(new ApiError(422, "DOCUMENT_UNREADABLE", "Document could not be safely parsed."));
      });
      workerInstance.once("exit", (code) => {
        clearTimeout(timeout);
        if (code !== 0) {
          reject(new ApiError(422, "DOCUMENT_UNREADABLE", "Document parser stopped unexpectedly."));
        }
      });
    });
  } finally {
    await worker?.terminate();
    activeParsers -= 1;
    bytes.fill(0);
  }
}
