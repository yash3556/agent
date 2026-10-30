# AgentShield API Contract

**Version:** 1.2
**Status:** Canonical shared contract  
**Base path:** `/api`

This document mirrors the AgentShield Architecture & API Contract v1.2. It is
the source of truth for endpoint paths, request and response fields, decision
values, and scenario IDs. The backend owns policy decisions, approval state, and
execution. The frontend displays backend results and never executes tools. AI is
optional and advisory only.

## Shared types

```ts
type Decision = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
type ApprovalStatus = "PENDING" | "APPROVED" | "REJECTED";
type Advisory = {
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
  signals: string[];
  summary: string;
};

interface EvaluateRequest {
  agentId: string;
  tool: string;
  resource: string;
  context?: string;
  inspectionId?: string;
  destination?: "local" | "external";
}

interface AuditEvent {
  eventId: string;
  timestamp: string;
  agentId: string;
  tool: string;
  resource: string;
  decision: Decision | "INSPECTED";
  ruleId: string;
  reason: string;
  executed: boolean;
  approvalId: string | null;
  inspectionId?: string | null;
  destination?: "local" | "external" | null;
  advisory: Advisory | null;
  type: "EVALUATION" | "APPROVAL_DECISION" | "DOCUMENT_INSPECTION";
  documentName?: string;
  findingCount?: number;
  reportRiskLevel?: FindingSeverity | "UNKNOWN";
  reportStatus?: "COMPLETE" | "DETERMINISTIC_ONLY" | "PARTIAL";
  approvalStatus?: "APPROVED" | "REJECTED" | null;
  reviewer?: string | null;
  note?: string | null;
}

interface Approval {
  approvalId: string;
  eventId: string;
  agentId: string;
  tool: string;
  resource: string;
  inspectionId?: string;
  destination?: "local" | "external";
  status: ApprovalStatus;
  createdAt: string;
  decidedAt?: string;
  reviewer?: string;
  note?: string;
}

type FindingCategory = "PERSONAL_DATA" | "CREDENTIAL" | "SUSPICIOUS_INSTRUCTION";
type FindingSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

interface InspectionFinding {
  id: string;
  category: FindingCategory;
  type: string;
  severity: FindingSeverity;
  confidence: number;
  location: { page: number | null; line: number | null };
  evidence: string;
  description: string;
}
```

Audit events never contain raw `context` or synthetic file contents. Sensitive
values, including secrets in a resource or reviewer note, are redacted before
persistence and display. The approval contains only the original policy-checked
synthetic operation and must never be used to execute arbitrary input.

## Endpoints

### `GET /api/health`

Always returns HTTP 200 while the server is running, including when MongoDB is
unavailable.

```json
{
  "status": "ok",
  "time": "2026-10-24T10:00:00.000Z",
  "db": "connected",
  "storage": "memory",
  "ai": "disabled",
  "aiRequest": null
}
```

`db` is `"connected"` or `"error"`. `ai` is `"configured"`, `"unavailable"`, or
`"disabled"` based on local AI provider configuration. `"configured"` does not
mean a live provider request has succeeded; AI completion is reported per
inspection. **[Additional field]** `storage` reports `"mongodb"` or
`"memory"` so clients can distinguish a working but non-persistent development
store from MongoDB persistence. `aiRequest` is `null` unless AI is configured;
otherwise it reports the non-secret provider, model, hostname, endpoint suffix,
request parameter names, and response-format mode. It never contains the API
key, prompt, document excerpt, or provider response. Do not expose connection
strings or internal errors.

### `GET /api/scenarios`

Returns canonical prefilled requests. Scenario IDs are UI conveniences and are
never accepted as authorization input. S4 is stretch scope and must be omitted
until implemented; S1–S3 are required.

```json
{
  "scenarios": [
    {
      "id": "S1",
      "title": "Read a public document",
      "request": {
        "agentId": "demo-agent",
        "tool": "read_file",
        "resource": "public/welcome.txt"
      }
    },
    {
      "id": "S2",
      "title": "Read a private file",
      "request": {
        "agentId": "demo-agent",
        "tool": "read_file",
        "resource": "private/payroll.csv"
      }
    },
    {
      "id": "S3",
      "title": "Export a sensitive report",
      "request": {
        "agentId": "demo-agent",
        "tool": "export_report",
        "resource": "sensitive-report"
      }
    }
  ]
}
```

### `POST /api/evaluate`

**Request**

```json
{
  "agentId": "demo-agent",
  "tool": "read_file",
  "resource": "public/welcome.txt",
  "context": "Optional untrusted text"
}
```

- `agentId`: required trimmed string, 1–64 characters, identifier characters
  only.
- `tool`: required well-formed identifier. `read_file`, `export_report`, and
  `analyze_document` are supported; other well-formed names are accepted and
  denied by policy.
- `resource`: required string, 1–256 characters; decoded and normalized before
  policy evaluation.
- `context`: optional string up to 1,000 characters. It is untrusted, never
  authorizes an operation, and is not stored raw.
- `inspectionId`: optional server-issued identifier returned after successful
  document inspection. Findings are always loaded from backend storage, never
  accepted from the caller.
- `destination`: optional `local` or `external` operation context. Document
  actions require both fields and an inspection owned by the supplied demo
  agent; a client-supplied `agentId` is not authenticated identity.
- Unknown fields are stripped. Wrong types, missing fields, object-valued
  context, and malformed identifiers return 400.
- JSON bodies are limited to 10 KB.

**200 response**

```json
{
  "eventId": "evt_opaque",
  "decision": "ALLOW",
  "reason": "The policy permits access to this public resource.",
  "ruleId": "R-002",
  "executed": true,
  "advisory": null,
  "timestamp": "2026-10-24T10:00:00.000Z"
}
```

`approvalId` is present only for `REQUIRE_APPROVAL`. `advisory` is always
present: it is either `null` or `{ "riskLevel": "LOW|MEDIUM|HIGH|UNKNOWN",
"signals": string[], "summary": string }`. `executed` is true only after the
synthetic operation runs. It is always false for `BLOCK` and pending approval.
Audit persistence must succeed before any operation executes.

### `POST /api/documents/inspect`

Accepts `multipart/form-data` with one `file` part and one `agentId` field.
Supported file extensions and content types are PDF, DOCX, UTF-8 TXT, CSV,
JSON, Markdown (`.md` or `.markdown`), and XLSX. The declared type and file
contents/container structure are checked; text formats require valid UTF-8,
JSON must parse, and CSV quoting must be well formed. The filename does not
determine the security findings. Files are limited to 5 MiB, extracted text
to 1 MiB, PDF documents to 100 pages, and DOCX/XLSX archives to 500 entries /
10 MiB expanded content; XLSX is limited to 100 worksheets. At most three
inspections per server process are admitted concurrently, and parsing is
limited to 30 seconds per document. Unsupported, malformed, encrypted,
macro-enabled, embedded, or over-limit documents fail closed.

**201 response**

```json
{
  "inspectionId": "ins_opaque",
  "status": "COMPLETED",
  "document": {
    "originalName": "synthetic-contact.txt",
    "mediaType": "text/plain",
    "sizeBytes": 27
  },
  "findings": [{
    "id": "finding_opaque",
    "category": "PERSONAL_DATA",
    "type": "EMAIL_ADDRESS",
    "severity": "MEDIUM",
    "confidence": 0.95,
    "location": { "page": null, "line": 1 },
    "evidence": "[REDACTED_EMAIL]",
    "description": "An email address pattern was detected."
  }],
  "summary": {
    "totalFindings": 1,
    "truncated": false,
    "bySeverity": { "LOW": 0, "MEDIUM": 1, "HIGH": 0, "CRITICAL": 0 }
  },
  "analysis": { "deterministic": "COMPLETED", "aiAdvisory": "DISABLED" },
  "report": {
    "version": 1,
    "status": "DETERMINISTIC_ONLY",
    "riskLevel": "MEDIUM",
    "summary": "Deterministic scan reported 1 finding(s); AI analysis is disabled.",
    "truncated": false,
    "findings": [{
      "id": "finding_opaque",
      "source": "DETERMINISTIC",
      "category": "PERSONAL_DATA",
      "type": "EMAIL_ADDRESS",
      "severity": "MEDIUM",
      "confidence": 0.95,
      "explanation": "An email address pattern was detected.",
      "recommendation": "Minimize or redact personal data and verify that sharing is authorized.",
      "evidenceReferences": [{ "page": null, "line": 1, "chunk": 1 }]
    }],
    "coverage": {
      "extraction": "COMPLETED",
      "deterministic": "COMPLETED",
      "ai": "DISABLED",
      "totalChunks": 1,
      "completedChunks": 0,
      "failedChunks": 0
    }
  }
}
```

`analysis.aiAdvisory` is `DISABLED`, `UNAVAILABLE`, `AVAILABLE`, or
`NOT_NEEDED`. `AVAILABLE` means all submitted AI chunks completed successfully;
`NOT_NEEDED` means no provider call was made because no deterministic finding
context was available. An incomplete request is `UNAVAILABLE`. When AI analysis fails, the response
includes a sanitized `analysis.aiFailure` with a stable `code` and actionable
`message`. Supported codes include `AUTHENTICATION_FAILED`, `ACCESS_DENIED`,
`MODEL_OR_ENDPOINT_NOT_FOUND`, `RATE_LIMITED`, `PROVIDER_ERROR`, `TIMEOUT`,
`INVALID_RESPONSE`, `CONNECTION_FAILED`, `DNS_FAILED`, `DESTINATION_REJECTED`,
`CREDITS_EXHAUSTED`, `PROVIDER_LIMIT_REACHED`, and `CONFIGURATION_INVALID`.
For HTTP failures, `providerResponse` may include only status code, sanitized
provider error type/code, `Retry-After`, and request ID. Generic HTTP 429
responses remain `RATE_LIMITED`; quota or organization/project classifications
require matching structured provider codes. Response bodies, credentials,
authorization data, and provider URLs are never returned.
`ANALYSIS_LIMIT` means some chunks were skipped because of configured safety
limits; it is not a provider error.
Deterministic findings are preserved when AI fails. The additive `report.status` is
`COMPLETE` only when deterministic findings are not truncated and all AI chunks
complete without report truncation; it is `DETERMINISTIC_ONLY` when AI is
disabled, no extractable text exists, or no deterministic finding context is
available; and it is `PARTIAL` when
the provider is unavailable for non-empty content, chunks are incomplete, or a
finding cap omits report findings. `report.truncated` is true when a finding
cap omits report findings.
Always use `report.coverage` to determine scan coverage. A top-level inspection
`status: "COMPLETED"` means the inspection request finished; it does not mean
the security report is complete.

Report findings identify their `source` as `DETERMINISTIC` or `AI`. The legacy
`findings` and `summary` fields remain deterministic-only. AI findings are
advisory and are not policy inputs. Evidence is a bounded redacted excerpt with page, extracted-line, and chunk coordinates; `report.documentCoverage` lists parser scope/limits, while `report.aiScope` reports AI status, submitted excerpts, up to 100 locations, and confirms the full document was not reviewed.

The frontend can request policy evaluation for local analysis or a synthetic
external export using the returned `inspectionId`. The backend returns the
authoritative `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL` result and records an
audit event. AI findings do not alter that decision. No real external export is
performed. The downloadable JSON report keeps its finding-based advisory
suggestion separate from `policyDecision`; the suggestion is non-binding, while
an evaluated backend decision is authoritative.

Only a hash, bounded metadata, redacted deterministic findings, the bounded
sanitized report, and expiry are persisted. Raw upload, extracted text,
prompts, and raw provider responses are not stored. Inspection records expire
after 24 hours; authorization checks expiry immediately, independent of
MongoDB TTL cleanup timing. Deterministic findings are capped at 100 entries;
if more are detected, `summary.truncated` is true and external export remains
blocked by R-010. AI processing uses at most 128 chunks of 32 KiB each, two
parallel requests per inspection and three concurrent provider requests
process-wide, an 8-second request timeout, and a 30-second total time budget.
Unprocessed or failed chunks are counted and reported as incomplete.

AI is disabled by default. To opt in, set server-side `AI_PROVIDER` to
`openai-compatible`, configure `AI_MODEL` and `AI_API_KEY`, and optionally set
`AI_BASE_URL` (default `https://api.openai.com/v1`; `/chat/completions` is
appended). The API key is never returned to clients or logged. `AI_BASE_URL`
must use HTTPS to a public destination; DNS results are checked and pinned,
private/non-public destinations are rejected, and redirects are not followed.
HTTP/HTTPS loopback endpoints require the explicit `AI_ALLOW_LOOPBACK=true`
setting and are intended only for trusted local development.

When enabled, the configured external provider receives only bounded excerpts
from deterministic finding lines and up to one adjacent line on either side.
Each excerpt is capped, recognized email, phone, credential, connection-string,
cloud-key, and private-key values are replaced with typed placeholders, and a
counts-only structure summary accompanies it. The full extracted document is
never included in an AI request. No file bytes, filename, agent ID, or
inspection ID are sent. The shared redaction utility is also applied to
user-controlled strings before audit/approval persistence and API return.
Redaction is pattern-based, not comprehensive: unrecognized secrets or
confidential text inside an allowed excerpt may remain. Documents with no
deterministic findings are not sent to AI, so AI coverage is reported as
`NO_FINDING_CONTEXT` rather than implying a full-document AI scan. Operators
must assess provider retention and data-sharing terms before enabling it.

The optional evaluation advisory uses the same configured provider and sends
only bounded `tool`, `resource`, `destination`, and `context` values after
redaction; `agentId` is not sent separately, though a resource may itself be an
inspection ID. Its strict output schema and five-second timeout are advisory
only. Provider errors, invalid output, or saturation produce `advisory: null`
and never change the deterministic policy decision.

To use a report, submit `POST /api/evaluate` with `tool: "analyze_document"`,
`destination: "local"`, and both `resource` and `inspectionId` set to the
returned ID. External `export_report` actions require `destination: "external"`
and are blocked by default; credential/suspicious findings or truncated reports
block, and personal-data findings require approval.

### `GET /api/events`

Returns document inspection, policy evaluation, and approval audit events
newest first. A successful document inspection creates a `DOCUMENT_INSPECTION`
event with the sanitized filename, opaque inspection ID, finding count, report
risk/status, timestamp, and `decision: "INSPECTED"`. This is an informational
scan record, not an authorization decision. Raw file content and findings'
evidence are not included.

- `limit`: optional integer 1–200, default 50.
- Invalid query values return 400.

```json
{ "events": [] }
```

### `GET /api/approvals`

Returns approval records.

- `status`: optional `pending`, `approved`, or `rejected`, case-insensitive.
- Omit it to return all approval records. Invalid values return 400.

```json
{ "approvals": [] }
```

### `POST /api/approvals/:id/decision`

**Request**

```json
{
  "decision": "APPROVED",
  "reviewer": "demo-reviewer",
  "note": "Reviewed for demo"
}
```

`decision` must be `APPROVED` or `REJECTED`; `reviewer` is a required bounded
demo label (not identity verification); `note` is optional and bounded.

**200 response**

```json
{
  "approval": {
    "approvalId": "apr_opaque",
    "eventId": "evt_opaque",
    "tool": "export_report",
    "resource": "sensitive-report",
    "status": "APPROVED",
    "createdAt": "2026-10-24T10:00:00.000Z",
    "decidedAt": "2026-10-24T10:01:00.000Z",
    "reviewer": "demo-reviewer",
    "note": "Reviewed for demo"
  },
  "eventId": "evt_opaque",
  "executed": true
}
```

Only `PENDING` approvals may transition once. The conditional status update
allows only one concurrent request to win the state transition. It is **not**
an atomic transaction spanning the audit event, approval state, operation
execution, and final audit update. On approval, the backend re-checks the
stored tool/resource and, for document operations, re-fetches the inspection
before executing only the original bounded synthetic operation. On rejection,
nothing executes. A process failure after transition can leave an approved
record whose execution result is uncertain; this is not a guarantee suitable
for real side-effecting tools.

## Policy rules

Evaluate in order; first match wins. Resource decoding/normalization and
traversal checks run before any allow rule.

| Rule | Condition | Decision | Reason |
| --- | --- | --- | --- |
| R-001 | Resource has traversal (`..`), is absolute (leading `/` or `\`, drive letter), contains NUL, or decodes to one of these | BLOCK | Path traversal is not permitted. |
| R-005 | A document action has a missing, expired, incomplete, mismatched, or differently owned inspection | BLOCK | A completed inspection owned by this agent is required. |
| R-006 | `demo-agent` runs `analyze_document` on its completed inspection with `destination=local` | ALLOW | Local analysis is synthetic; document instructions are untrusted data. |
| R-007 | External export inspection includes a credential-like finding | BLOCK | Credential-like content must not be exported. |
| R-008 | External export inspection includes a suspicious-instruction finding | BLOCK | Suspicious instructions must not be exported. |
| R-010 | External export finding report is truncated | BLOCK | Incomplete findings cannot authorize external export. |
| R-009 | External export inspection includes personal-data findings and no higher-priority block applies | REQUIRE_APPROVAL | Human review is required before export. |
| R-002 | `tool=read_file` and normalized resource is exactly whitelisted `public/welcome.txt` under `public/` | ALLOW | The policy permits access to this public resource. |
| R-003 | `tool=read_file` and resource starts with `private/` | BLOCK | The request has no authorization to access the private resource. |
| R-004 | `tool=export_report` and resource is `sensitive-report` | REQUIRE_APPROVAL | The action is held until a human reviewer approves or rejects it. |
| R-999 | Anything else, including unknown tools/resources | BLOCK | No policy permits this action (deny by default). |

For document actions, R-005 runs before document policy rules. R-007, R-008,
and R-010 take precedence over R-009. Only bounded synthetic operations exist;
document inspection does not add real filesystem, shell, or external network
execution. Context and extracted document content are untrusted data. AI cannot
change a decision, authorize, or execute an action.

## Audit and approval records

An evaluation event records `eventId`, server `timestamp`, `agentId`, `tool`,
normalized/redacted `resource`, `decision`, `ruleId`, `reason`, `executed`,
`approvalId` (null when not applicable), `advisory` (null when unavailable),
and `type: "EVALUATION"`.

Each successful document upload also creates a `DOCUMENT_INSPECTION` event.
Its `INSPECTED` marker means only that scanning completed; it is distinct from
the policy decisions `ALLOW`, `BLOCK`, and `REQUIRE_APPROVAL`. The event
includes bounded summary metadata but no raw document content or evidence.

An approval outcome creates an event with `type: "APPROVAL_DECISION"`,
`approvalStatus`, reviewer and redacted note. It links to the original
`approvalId` and preserves the original decision/rule. Do not store raw context
or synthetic file contents.

## Errors

All errors use one envelope:

```json
{
  "error": "VALIDATION_ERROR",
  "message": "Human-readable summary",
  "details": []
}
```

`details` is optional. Supported status/code pairs:

| HTTP | Error | Meaning |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR` | Invalid or missing fields/query values. |
| 404 | `NOT_FOUND` | Unknown route or approval ID. |
| 409 | `ALREADY_DECIDED` | Approval is already APPROVED or REJECTED. |
| 409 | `INSPECTION_UNAVAILABLE` | The inspection expired or is no longer eligible for approval. |
| 413 | `PAYLOAD_TOO_LARGE` | JSON body exceeds 10 KB or upload exceeds 5 MiB. |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Unsupported extension, declared type, or format signature. |
| 422 | `DOCUMENT_UNREADABLE` | Empty, malformed, unsafe, or unsupported document structure. |
| 500 | `INTERNAL_ERROR` | Unexpected error; do not leak internals. |
| 503 | `AUDIT_UNAVAILABLE` | Required audit/inspection persistence failed; no operation executed. |
| 503 | `INSPECTION_UNAVAILABLE` | The process has reached its concurrent inspection capacity. |
| 503 | `INSPECTION_UNAVAILABLE` | Parser capacity is full. |

If MongoDB is unavailable or the initial required audit write fails,
evaluation returns `503 AUDIT_UNAVAILABLE` and executes nothing. If an approval
decision audit insert or conditional state transition fails before a successful
transition, it returns `503 AUDIT_UNAVAILABLE` and does not execute. Failures
after a successful transition are different: the record may already be
APPROVED, and execution or its final audit update may have occurred or failed;
the caller must inspect the approval and audit state rather than assume a
retry is safe. The current tools are synthetic and bounded. Health still
returns 200 with `db: "error"`. AI absence, timeout, or invalid output never
affects decisions; the response advisory is `null`.

Policy `reason` values are complete human-readable backend strings and include
normal word spacing. Clients should display the returned value verbatim. For
example, R-007 is “External export is prohibited because credential-like
content was detected.”; R-009 is “External export of detected personal data
requires human approval.”

#### Current detector coverage (informational, not a security guarantee)

The deterministic scanner detects email and phone-like patterns, selected
India identity patterns (PAN, IFSC, UPI, contextual DOB, and Verhoeff-validated
Aadhaar), Luhn-validated payment cards, MOD-97-validated IBANs, context-labeled
bank accounts, and financial table headers. GSTIN detection checks format only,
not its checksum.
It also detects selected labeled credential key/value patterns, one cloud
access-key-like format, and selected suspicious-instruction phrases. For
credentials, examples of supported labels are `api_key`, `access_token`,
`password`, `passwd`, `secret`, and `client_secret`; values must contain at
least six non-whitespace characters. It also checks an `AKIA` prefix followed by 16 uppercase
alphanumeric characters. Bare secret-looking strings and other credential
formats are not guaranteed to be detected. Use a labeled synthetic value such
as `api_key=sample-secret-value` when demonstrating this detector.

This is not comprehensive malware detection, DLP, or proof that a clean
document is safe. `agentId` and `reviewer` are demo labels, not authenticated
identities. Local MongoDB tests exercise persistence across fresh store
instances and concurrent approval claims; they do not establish atomic
approval-and-execution guarantees, production durability, or safe retries for
real side effects.

If a synthetic operation has already run but persisting its final execution
outcome fails, return `500 INTERNAL_ERROR` rather than the fail-closed 503
(execution may have occurred). The initial audit record remains, but its
`executed` value may still be false. This is limited to the current bounded,
side-effect-free synthetic tools and must be resolved before integrating any
real tool.
