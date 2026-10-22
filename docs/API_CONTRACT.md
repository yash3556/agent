# AgentShield API Contract

**Version:** 1.1  
**Status:** Canonical shared contract  
**Base path:** `/api`

This document mirrors the AgentShield Architecture & API Contract v1.1. It is
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
}

interface AuditEvent {
  eventId: string;
  timestamp: string;
  agentId: string;
  tool: string;
  resource: string;
  decision: Decision;
  ruleId: string;
  reason: string;
  executed: boolean;
  approvalId: string | null;
  advisory: Advisory | null;
  type: "EVALUATION" | "APPROVAL_DECISION";
  approvalStatus?: "APPROVED" | "REJECTED" | null;
  reviewer?: string | null;
  note?: string | null;
}

interface Approval {
  approvalId: string;
  eventId: string;
  tool: string;
  resource: string;
  status: ApprovalStatus;
  createdAt: string;
  decidedAt?: string;
  reviewer?: string;
  note?: string;
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
  "ai": "disabled"
}
```

`db` is `"connected"` or `"error"`. `ai` is `"available"`, `"unavailable"`, or
`"disabled"`. **[Additional field]** `storage` reports `"mongodb"` or
`"memory"` so clients can distinguish a working but non-persistent development
store from MongoDB persistence. Do not expose connection strings or internal
errors.

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
- `tool`: required well-formed identifier. `read_file` and `export_report` are
  supported; other well-formed names are accepted and denied by policy.
- `resource`: required string, 1–256 characters; decoded and normalized before
  policy evaluation.
- `context`: optional string up to 1,000 characters. It is untrusted, never
  authorizes an operation, and is not stored raw.
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

### `GET /api/events`

Returns audit events newest first.

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

Only `PENDING` approvals may transition once. A conditional status update must
ensure concurrent requests cannot decide or execute twice. On approval, the
backend re-checks that the stored tool/resource still match the explicit
approval policy and executes only that original synthetic operation. On
rejection, nothing executes. Persist the approval decision before execution and
record its `APPROVAL_DECISION` audit event and execution outcome.

## Policy rules

Evaluate in order; first match wins. Resource decoding/normalization and
traversal checks run before any allow rule.

| Rule | Condition | Decision | Reason |
| --- | --- | --- | --- |
| R-001 | Resource has traversal (`..`), is absolute (leading `/` or `\`, drive letter), contains NUL, or decodes to one of these | BLOCK | Path traversal is not permitted. |
| R-002 | `tool=read_file` and normalized resource is exactly whitelisted `public/welcome.txt` under `public/` | ALLOW | The policy permits access to this public resource. |
| R-003 | `tool=read_file` and resource starts with `private/` | BLOCK | The request has no authorization to access the private resource. |
| R-004 | `tool=export_report` and resource is `sensitive-report` | REQUIRE_APPROVAL | The action is held until a human reviewer approves or rejects it. |
| R-999 | Anything else, including unknown tools/resources | BLOCK | No policy permits this action (deny by default). |

Only synthetic, whitelisted `read_file` and `export_report` operations exist.
There is no real filesystem, shell, or external network execution. Context is
untrusted data. AI cannot change a decision, authorize, or execute an action.

## Audit and approval records

An evaluation event records `eventId`, server `timestamp`, `agentId`, `tool`,
normalized/redacted `resource`, `decision`, `ruleId`, `reason`, `executed`,
`approvalId` (null when not applicable), `advisory` (null when unavailable),
and `type: "EVALUATION"`.

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
| 413 | `PAYLOAD_TOO_LARGE` | Body exceeds 10 KB. |
| 500 | `INTERNAL_ERROR` | Unexpected error; do not leak internals. |
| 503 | `AUDIT_UNAVAILABLE` | Audit persistence failed; no operation executed. |

If MongoDB is unavailable or an audit write fails, evaluation returns
`503 AUDIT_UNAVAILABLE` and executes nothing. An approval decision returns the
same error without advancing state or executing. Health still returns 200 with
`db: "error"`. AI absence, timeout, or invalid output never affects decisions;
the response advisory is `null`.

If a synthetic operation has already run but persisting its final execution
outcome fails, return `500 INTERNAL_ERROR` rather than the fail-closed 503
(execution may have occurred). The initial audit record remains, but its
`executed` value may still be false. This is limited to the current bounded,
side-effect-free synthetic tools and must be resolved before integrating any
real tool.
