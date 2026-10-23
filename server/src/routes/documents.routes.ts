import { Router } from "express";
import multer from "multer";
import type { AuditStore } from "../config/database.js";
import { ApiError } from "../errors.js";
import { documentInspectFieldsSchema } from "../schemas/evaluate.schema.js";
import { inspectDocument, MAX_DOCUMENT_BYTES } from "../services/inspection.service.js";
import { createConfiguredDocumentAnalyzer } from "../ai/document-analysis.js";
import type { DocumentAnalyzer } from "../ai/document-analysis.js";

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
    upload.single("file")(request, response, (error: unknown) => {
      if (error && error instanceof multer.MulterError) {
        const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
        const code = status === 413 ? "PAYLOAD_TOO_LARGE" : "VALIDATION_ERROR";
        next(new ApiError(status, code, status === 413
          ? "Document exceeds the 5 MiB limit."
          : "Multipart document request is invalid."));
        return;
      }
      next(error);
    });
  }, async (request, response, next) => {
    const buffer = request.file?.buffer;
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
    }
  });

  return router;
}
