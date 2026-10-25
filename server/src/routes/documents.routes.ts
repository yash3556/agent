import { Router } from "express";
import multer from "multer";
import type { AuditStore } from "../config/database.js";
import { ApiError } from "../errors.js";
import { documentInspectFieldsSchema } from "../schemas/evaluate.schema.js";
import { inspectDocument, MAX_DOCUMENT_BYTES } from "../services/inspection.service.js";
import { MAX_CONCURRENT_DOCUMENT_INSPECTIONS } from "../services/document-limits.js";
import { createConfiguredDocumentAnalyzer } from "../ai/document-analysis.js";
import type { DocumentAnalyzer } from "../ai/document-analysis.js";

let activeInspections = 0;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_DOCUMENT_BYTES,
    files: 1,
    fields: 1,
    parts: 2,
    fieldSize: 1024,
  },
});

export function createDocumentsRouter(
  store: AuditStore,
  documentAnalyzer: DocumentAnalyzer = createConfiguredDocumentAnalyzer(),
): Router {
  const router = Router();

  router.post("/inspect", (request, response, next) => {
    if (activeInspections >= MAX_CONCURRENT_DOCUMENT_INSPECTIONS) {
      next(new ApiError(503, "INSPECTION_UNAVAILABLE", "Document inspection capacity is full."));
      return;
    }
    activeInspections += 1;
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      activeInspections -= 1;
    };
    response.locals.releaseDocumentAdmission = release;
    request.once("aborted", release);
    next();
  }, (request, response, next) => {
    const release = response.locals.releaseDocumentAdmission as (() => void) | undefined;
    upload.single("file")(request, response, (error: unknown) => {
      if (error && error instanceof multer.MulterError) {
        release?.();
        const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
        const code = status === 413 ? "PAYLOAD_TOO_LARGE" : "VALIDATION_ERROR";
        next(new ApiError(status, code, status === 413
          ? "Document exceeds the 5 MiB limit."
          : "Multipart document request is invalid."));
        return;
      }
      if (error) release?.();
      next(error);
    });
  }, async (request, response, next) => {
    const buffer = request.file?.buffer;
    const release = response.locals.releaseDocumentAdmission as (() => void) | undefined;
    try {
      const fields = documentInspectFieldsSchema.safeParse(request.body);
      if (!fields.success) {
        throw new ApiError(400, "VALIDATION_ERROR", "Request validation failed.", fields.error.issues);
      }
      if (!request.file) {
        throw new ApiError(400, "VALIDATION_ERROR", "A document file is required.");
      }
      response.status(201).json(
        await inspectDocument(store, fields.data.agentId, request.file, documentAnalyzer),
      );
    } catch (error) {
      next(error);
    } finally {
      buffer?.fill(0);
      release?.();
    }
  });

  return router;
}
