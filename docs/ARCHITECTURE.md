# AgentShield Architecture

## Backend request flow

`POST /api/evaluate` validates the canonical `{ agentId, tool, resource,
context? }` body with Zod, decodes and normalizes the resource, then evaluates
the deterministic policy rules in order. The policy engine has final authority.
An evaluation audit event (and pending approval, when applicable) must be
persisted before a synthetic operation is run. If persistence is unavailable,
the API returns `503 AUDIT_UNAVAILABLE` and does not execute the operation.

- `ALLOW`: run the explicitly whitelisted synthetic operation and record its
  execution outcome.
- `BLOCK`: never invoke a tool.
- `REQUIRE_APPROVAL`: create a `PENDING` approval; do not execute until a
  backend decision accepts the original operation.

Approval decisions are claimed with a conditional `status=PENDING` update.
Only one concurrent/repeated decision can win that state transition. The
approval transition, operation execution, and final audit update are separate
steps, not one atomic transaction. A process failure between those steps can
leave execution status uncertain. The backend re-checks policy before running
the original approved operation. Rejection never executes.

## Components

- `src/routes/`: Express endpoints and request validation.
- `src/schemas/`: Zod request/query schemas.
- `src/services/policy-engine.ts`: ordered deterministic rules and deny-by-default.
- `src/services/decision.service.ts`: evaluation, audit-before-execution flow.
- `src/services/approval.service.ts`: backend-owned approval transitions and execution.
- `src/services/tool-simulator.ts`: bounded synthetic operations only.
- `src/routes/documents.routes.ts` and
  `src/services/inspection.service.ts`: bounded multipart upload, media/type
  validation, transient parsing/scanning, redacted findings, and storage.
- `src/services/document-parser*.ts`: isolated worker parsing for PDF, DOCX,
  and UTF-8 TXT with time, memory, page, entry, and expanded-size bounds.
- `src/services/content-scanner.ts`: deterministic pattern detectors; findings
  and summaries contain redacted evidence only.
- `src/config/database.ts`: MongoDB persistence and explicitly selected
  in-memory development/test implementation, including expiring inspections.
- `src/ai/risk-advisor.ts`: optional advisory boundary; never authorizes or runs tools.

MongoDB is selected with `STORAGE_MODE=mongodb`; the sample development
environment explicitly uses `STORAGE_MODE=memory`. The memory store is
non-persistent and must not be treated as an audit database. Health responses
include the selected mode in the additive `storage` field.

## Document inspection flow

`POST /api/documents/inspect` accepts one file and `agentId`; the backend
validates extension, declared media type, and content signature/container,
then parses in a bounded worker. Only the document hash, sanitized filename,
media type, size, server-side findings, and expiry are persisted. Raw file and
extracted text are not stored. Evaluations accept a server-issued inspection
ID and destination; they load findings from storage and check status, expiry,
resource binding, and demo-agent ownership before policy evaluation. External
export is synthetic only, blocked by default, and never contacts a remote
destination.

## Policy rules

See [API_CONTRACT.md](./API_CONTRACT.md) for the canonical rule table. Path
traversal and absolute-path checks run before allow rules. Only
`read_file(public/welcome.txt)`, `export_report(sensitive-report)`, local
`analyze_document`, and inspection-bound synthetic export are implemented.
Unknown tools/resources are denied. See [POLICY_RULES.md](./POLICY_RULES.md)
for content findings, priority, and limitations.

## Security boundaries

- No real filesystem, shell, or network tools exist.
- Context is untrusted and is not persisted.
- Document text is treated as untrusted data; prompt-like text never changes
  the policy. Finding evidence is redacted, and incomplete reports cannot
  authorize external export.
- Credential detection covers a limited set of labeled key/value patterns and
  one AWS-style access-key-like format. It does not detect every secret format;
  a bare secret-looking string may not produce a finding. The scanner is not
  comprehensive malware detection or a complete DLP system.
- Demo ownership uses a caller-supplied `agentId`; this is not authentication.
- Audit resource, reviewer label, and reviewer note values are redacted.
- AI failures or missing configuration do not affect policy decisions.
- CORS is restricted to `FRONTEND_ORIGIN`; JSON bodies are limited to 10 KB.
- Approval reviewer labels are for the demo only, not authentication or
  production authorization.
- Policy reasons are complete, spaced backend strings; clients should display
  the supplied reason verbatim rather than rebuilding it.
