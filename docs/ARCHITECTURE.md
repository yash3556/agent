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
Concurrent/repeated decisions cannot claim the same record twice. The backend
re-checks policy before running the original approved operation. Rejection never
executes.

## Components

- `src/routes/`: Express endpoints and request validation.
- `src/schemas/`: Zod request/query schemas.
- `src/services/policy-engine.ts`: ordered deterministic rules and deny-by-default.
- `src/services/decision.service.ts`: evaluation, audit-before-execution flow.
- `src/services/approval.service.ts`: backend-owned approval transitions and execution.
- `src/services/tool-simulator.ts`: bounded synthetic operations only.
- `src/config/database.ts`: MongoDB persistence and explicitly selected
  in-memory development/test implementation.
- `src/ai/risk-advisor.ts`: optional advisory boundary; never authorizes or runs tools.

MongoDB is selected with `STORAGE_MODE=mongodb`; the sample development
environment explicitly uses `STORAGE_MODE=memory`. The memory store is
non-persistent and must not be treated as an audit database. Health responses
include the selected mode in the additive `storage` field.

## Policy rules

See [API_CONTRACT.md](./API_CONTRACT.md) for the canonical rule table. Path
traversal and absolute-path checks run before allow rules. Only
`read_file(public/welcome.txt)` and `export_report(sensitive-report)` are
implemented as synthetic operations. Unknown tools/resources are denied.

## Security boundaries

- No real filesystem, shell, or network tools exist.
- Context is untrusted and is not persisted.
- Audit resource, reviewer label, and reviewer note values are redacted.
- AI failures or missing configuration do not affect policy decisions.
- CORS is restricted to `FRONTEND_ORIGIN`; JSON bodies are limited to 10 KB.
- Approval reviewer labels are for the demo only, not authentication or
  production authorization.
