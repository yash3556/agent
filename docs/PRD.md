# AgentShield Product Requirements Document

**Version:** MVP aligned to AgentShield PRD v1.1
**Target:** HackIndia AI & CyberTech Hackathon 2026
**Product owner:** Team Alpha Niketes

## Product summary

AgentShield is a security firewall between an AI agent and its tools. It
evaluates each proposed action before execution and returns exactly one
deterministic decision: `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`. Decisions and
execution outcomes are recorded in an audit trail. Optional AI risk analysis
may add context but must never authorize an action or change the policy result.

The canonical API shapes and scenario IDs are defined in
[API_CONTRACT.md](./API_CONTRACT.md); this PRD does not redefine them.

## Problem and users

An AI agent can be manipulated, misconfigured, or given too much access. Without
a security gate, it may access private data or perform sensitive actions without
review or an explanation.

- **Agent/demo operator:** submits a proposed action and sees the decision and
  explanation.
- **Security reviewer:** approves or rejects a held synthetic action.
- **Auditor:** reviews the decision, reason, timestamp, and execution result.
- **Developer:** may inspect an optional AI risk advisory, clearly separated
  from authorization.

## MVP goals

1. Deterministically evaluate a proposed action on the backend.
2. Deny unknown tools and resources by default; reject path traversal before
   any allow rule.
3. Execute only bounded synthetic operations after a recorded `ALLOW`, or after
   a backend-owned approval transition.
4. Persist redacted audit events and approvals in MongoDB; fail closed with
   `503 AUDIT_UNAVAILABLE` when required audit persistence is unavailable.
5. Expose the shared API, with Zod validation and consistent errors, for the UI
   and test clients.
6. Keep core authorization functional with AI disabled.
7. Present truthful loading, empty, error, disconnected, decision, approval,
   and audit states in the frontend.
8. Inspect supported documents with deterministic content detectors before
    applying document-operation policy; never persist raw document content.

## Non-goals

- Real filesystem access, shell commands, arbitrary tool integrations, or
  external-network execution.
- Real data access or data exfiltration.
- Production identity, authentication, RBAC, SSO, multi-tenancy, or compliance
  claims. The demo reviewer label is not identity verification.
- Comprehensive malware detection, complete DLP coverage, or a claim that
  documents with no detected findings are safe.
- AI-controlled policy, AI execution, fabricated metrics, or decorative
  analytics.
- Production deployment or scaling.

## Canonical demo scenarios

| ID | Request | Expected policy result | Execution |
| --- | --- | --- | --- |
| S1 | `read_file("public/welcome.txt")` | `ALLOW`, rule `R-002` | Synthetic read runs after the audit write succeeds. |
| S2 | `read_file("private/payroll.csv")` | `BLOCK`, rule `R-003` | Never runs. |
| S3 | `export_report("sensitive-report")` | `REQUIRE_APPROVAL`, rule `R-004` | Does not run while pending; only the original operation can run after approval. |
| S4 (stretch) | Path traversal with suspicious context | `BLOCK`, rule `R-001` | Never runs; optional AI advisory may indicate elevated risk. |

S1–S3 are required. S4 and AI integration are stretch work after the core,
approval, persistence, and UI flows are stable. Scenario IDs prefill requests;
they are not authorization tokens.

## Functional requirements and current status

| ID | Requirement | Current status |
| --- | --- | --- |
| FR-1 | Validate canonical evaluation request, evaluate it, audit it, return the shared response. | Backend implemented; memory tests and local MongoDB persistence integration tests pass. |
| FR-2 | Return one deterministic decision with reason and rule ID. | Implemented in the policy engine. |
| FR-3 | Validate malformed input; deny unknown tools/resources; block traversal before allow. | Implemented and unit tested. |
| FR-4 | Never execute `BLOCK` or pending actions; execute only whitelisted synthetic operations. | Implemented and API tested. |
| FR-5 | Persist redacted decisions and execution outcomes. | Local MongoDB persistence across fresh store instances is verified; unavailable-endpoint evaluation returns 503 without execution. Production recovery behavior remains unverified. |
| FR-6 | Frontend displays the backend result and never authorizes or executes. | Not implemented; frontend files are placeholders. |
| FR-7 | Return canonical S1–S3 scenarios. | Implemented. |
| FR-8 | List audit events newest first. | Implemented. |
| FR-9 | List, approve, and reject once; record outcomes; execute only on approval. | Memory/API and local MongoDB concurrent decision tests pass. The conditional approval transition prevents multiple winners, but transition, execution, and final audit are not atomic; execution outcome may be uncertain after a process failure. |
| FR-10 | Optional validated, timed AI risk advisory with safe fallback. | Implemented as an optional, bounded provider call. Redacted inputs are schema-validated on return; unavailable, invalid, or timed-out advisory responses return `null` without affecting policy decisions. |
| FR-11 | UI loading, errors, 503, and disconnected states. | Not implemented; requires frontend/API integration. |
| FR-12 | Health reports backend, database, storage mode, and AI status. | Implemented. |
| FR-13 | Audit persistence outage fails closed before tool execution. | Tested with a failing in-memory adapter and an unavailable MongoDB endpoint; stopping/restarting the database service has not been tested. |
| FR-14 | Restrict CORS, cap request size, and keep secrets in environment. | Implemented with configured origin, 10 KB JSON limit, and ignored `.env`; deployment settings need review. |
| FR-15 | Inspect PDF, DOCX, and UTF-8 TXT content, return redacted findings, bind reports to their demo agent, and apply findings-aware policy before simulated document actions. | Backend implementation and tests added; local MongoDB persistence across fresh stores, concurrent approval claims, and unavailable-database behavior have been exercised. These do not prove atomic approval/execution or production durability. Parser limits, unauthenticated demo identity, and heuristic detection coverage remain limitations. |

## Acceptance criteria

The MVP is ready for an integrated demo only when all of these are verified:

- S1, S2, and S3 work through the actual frontend and backend.
- `BLOCK` and pending approvals demonstrably do not execute.
- Approval executes only the original synthetic action once; rejection never
  executes; unknown ID is 404 and repeat decision is 409.
- The audit view reflects the backend decision and final execution outcome.
- MongoDB persistence works across fresh store instances; an unavailable
  endpoint returns 503 without execution. A real service stop/restart check is
  still required before claiming that specific rehearsal.
- Supported document uploads are parsed/scanned; mismatched, malformed, and
  unsafe files fail closed. Findings are server-owned and redacted.
- Document ownership, expiry, policy findings, and approval are rechecked
  server-side; no raw document text is stored.
- The app works with AI disabled; any AI feature is advisory and schema
  validated.
- UI loading, empty, API error, disconnected, and database error states are
  visible and understandable.
- A clean clone follows the documented install and run steps.
- Tests, type checks, and build results are reported from actual command output.

## Current honest readiness assessment

The backend policy/API core has a passing test suite and type check, but this
does **not** mean the complete MVP is done. Backend document inspection is
implemented for PDF, DOCX, and UTF-8 TXT with heuristic, bounded scanning.
Credential detection recognizes selected labeled values and one access-key-like
format; it can miss bare or unfamiliar credential formats. The scanner is not
comprehensive malware detection and a clean result is not a safety guarantee.
Local MongoDB persistence across fresh store instances, concurrent approval
decisions, and an unavailable-database evaluation have been integration-tested;
this is not a guarantee of atomic approval-and-execution, a full server-process
restart test, or production durability. The demo agent and reviewer labels are
not authenticated identities. The frontend remains scaffold-level and AI
provider analysis is not implemented. Until frontend integration and a complete
dashboard walkthrough pass, use the backend/API runbook rather than claiming an
end-to-end dashboard demo.
