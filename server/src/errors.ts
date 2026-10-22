export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class AuditUnavailableError extends ApiError {
  constructor() {
    super(503, "AUDIT_UNAVAILABLE", "Audit persistence is unavailable.");
    this.name = "AuditUnavailableError";
  }
}
