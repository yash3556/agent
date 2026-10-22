# AgentShield Policy Rules

**Policy version:** MVP v1.1
**Authority:** Backend deterministic policy engine
**Canonical contract:** [API_CONTRACT.md](./API_CONTRACT.md)

## Policy invariants

- The backend policy engine is the sole authority for `ALLOW`, `BLOCK`, and
  `REQUIRE_APPROVAL`.
- Evaluate rules in order; the first matching rule wins.
- Unknown tools, resources, and unsupported tool/resource combinations are
  denied by default.
- Normalize and validate the resource before applying an allow rule.
- A scenario ID, frontend state, reviewer note, or agent-supplied context never
  grants permission.
- A `BLOCK` never invokes an executor.
- `REQUIRE_APPROVAL` creates a pending record and does not invoke an executor.
  The backend re-checks the stored operation and permits execution only after a
  successful one-time approval transition.
- Only explicitly whitelisted synthetic tools may execute. No real filesystem,
  shell, or external-network access exists.
- Document findings are generated server-side; callers cannot supply or modify
  trusted findings.
- Current document actions require the `demo-agent` label. This is client
  supplied and is not authentication.
- A clean scan permits local synthetic analysis only, not external export.
- AI advisory output cannot change a decision, create approval, or invoke a
  tool.

## Evaluation order

| Order | Rule ID | Match condition | Decision | Explanation | Execution |
| --- | --- | --- | --- | --- | --- |
| 1 | R-001 | Resource contains a traversal sequence (`..`), is absolute (leading `/` or `\`, or drive-letter path), contains NUL, or becomes one of these after decoding. | `BLOCK` | Path traversal is not permitted. | Never. |
| 2 | R-005 | A document action has a missing, expired, incomplete, mismatched, or differently owned inspection. | `BLOCK` | A completed inspection owned by this agent is required. | Never. |
| 3 | R-006 | `tool=analyze_document`, owner is `demo-agent`, inspection matches, and `destination=local`. | `ALLOW` | Local analysis is synthetic; document instructions are untrusted data. | Run only after audit persistence. |
| 4 | R-007 | External export inspection has a `CREDENTIAL` finding. | `BLOCK` | Credential-like content is prohibited from export. | Never. |
| 5 | R-008 | External export inspection has a `SUSPICIOUS_INSTRUCTION` finding. | `BLOCK` | Suspicious instructions are prohibited from export. | Never. |
| 6 | R-010 | External export findings are truncated because more than 100 were detected. | `BLOCK` | Incomplete findings cannot authorize external export. | Never. |
| 7 | R-009 | External export inspection has `PERSONAL_DATA` findings and no higher-priority block applies. | `REQUIRE_APPROVAL` | Human approval is required before the synthetic export simulation. | Not while pending; approval re-fetches and rechecks the inspection. |
| 8 | R-002 | `tool=read_file` and the normalized resource is the exact whitelist entry `public/welcome.txt` under `public/`. | `ALLOW` | The policy permits access to this public resource. | Run the bounded synthetic read only after the initial audit event is saved. |
| 9 | R-003 | `tool=read_file` and normalized resource starts with `private/`. | `BLOCK` | The request has no authorization to access the private resource. | Never. |
| 10 | R-004 | `tool=export_report` and normalized resource is exactly `sensitive-report`. | `REQUIRE_APPROVAL` | The action is held until a human reviewer approves or rejects it. | Not while pending. On approval, execute only this original synthetic operation once. |
| 11 | R-999 | Every other combination, including unknown tools, resources, or unlisted reports. | `BLOCK` | No policy permits this action (deny by default). | Never. |

For document actions, R-005 runs before the content rules. Credential,
suspicious-instruction, and truncated reports are blocked before considering
personal-data approval. Clean external exports remain blocked.

## Resource handling

1. Validate that `resource` is a string of 1–256 characters.
2. Decode percent-encoded input repeatedly within a bounded number of passes.
   Invalid encodings fail closed.
3. Treat backslashes as path separators for traversal/absolute checks.
4. Reject traversal markers, NUL, absolute roots, and drive-letter paths before
   any allow rule is evaluated.
5. Normalize benign leading `./` before matching the whitelist.
6. Do not map user paths to the real host filesystem. The synthetic tool
   simulator uses an in-memory whitelist only.

Examples that must be blocked by R-001 include `../private/payroll.csv`,
`public/../private/payroll.csv`, `%2e%2e/private/payroll.csv`,
`%252e%252e/private/payroll.csv`, `..\private\payroll.csv`,
`/public/welcome.txt`, `C:\private\payroll.csv`, and an encoded NUL.

## Approval rules

- Only policy results `R-004` and `R-009` can create an approval.
- A new approval starts `PENDING`; only `PENDING` can transition to `APPROVED`
  or `REJECTED`.
- The transition uses a conditional backend-side update so concurrent requests
  cannot both decide or execute.
- The backend re-fetches and re-evaluates the stored tool/resource and, for
  document exports, the inspection owner, expiry, and current findings before
  execution.
- `APPROVED` executes only the original synthetic operation; `REJECTED` never
  executes. Both outcomes are audited.
- An already resolved record returns HTTP 409 `ALREADY_DECIDED`; an unknown
  approval returns 404 `NOT_FOUND`.
- The reviewer string is a demo label, not authentication or identity
  verification.
- The conditional pending-state update prevents two concurrent requests from
  both winning the approval transition. It does **not** make the transition,
  execution, and final audit update one atomic transaction.
- A process failure after the approval transition but before execution or
  before the final audit update can leave an approved record whose execution
  outcome is uncertain. The current synthetic executor is bounded and has no
  external side effects; this design is not a guarantee for real tools.

## Audit and failure behavior

- Persist the redacted evaluation event (and pending approval, if any) before
  executing an allowed operation.
- If the initial audit/approval persistence fails, return
  `503 AUDIT_UNAVAILABLE` and do not execute.
- Never persist raw context or synthetic file contents. Redact secrets from
  resource and reviewer note values.
- Persist only the upload hash, bounded file metadata, owner agent ID, redacted
  findings, and expiry for inspections; never persist raw upload or extracted
  text. Every policy read checks expiry independently of MongoDB TTL cleanup.
- Record the final `executed` outcome. If an operation has already completed
  but its final audit update fails, return `500 INTERNAL_ERROR`, not a
  misleading pre-execution 503. This edge case is documented; adding
  side-effectful real tools requires a stronger transactional/outbox design.
- AI unavailable, disabled, timed out, or invalid must not affect policy
  decisions; current implementation returns `advisory: null`.
- Policy reason strings are ordinary human-readable text with spaces. For
  example, R-007 returns “External export is prohibited because credential-like
  content was detected.” and R-009 returns “External export of detected
  personal data requires human approval.” Consumers should display the
  backend-provided `reason` verbatim rather than constructing it from fragments.

## Current verification

The policy unit tests cover the public allow, private block, sensitive-report
approval, unknown tool/resource, and traversal variants. API tests assert that
blocked and pending actions are not executed, audit-write failure fails closed,
and approval decisions execute at most once. A local MongoDB integration suite
has verified persistence across fresh store instances, concurrent decisions,
and unavailable-database fail-closed behavior; this does not establish
transactional execution or production durability.

## Document inspection limitations

- Only PDF, DOCX, and UTF-8 TXT are supported. Bounds are 5 MiB per upload,
  1 MiB extracted text, 100 PDF pages, 500 DOCX entries, and 10 MiB expanded
  DOCX content.
- Email, phone-like, credential-like, and suspicious-instruction patterns are
  heuristics, not a complete DLP or malware scanner.
- Credential detection currently recognizes a limited set of labeled
  key/value forms (`api_key`, `access_token`, `password`, `passwd`, `secret`,
  `client_secret`) when the value has at least six non-whitespace characters,
  plus an AWS access-key-like `AKIA` prefix followed by 16 uppercase
  alphanumeric characters. A bare secret-looking string without a recognized
  label or format is not guaranteed to produce a `CREDENTIAL` finding. This
  limitation is why a credential-only test must use a supported synthetic
  pattern, for example `api_key=sample-secret-value`.
- At most 100 findings are returned. `summary.truncated` signals a larger set
  and blocks external export.
- This scanner does not comprehensively identify malware, malicious files,
  obfuscated secrets, or all personal data. Successful parsing and no findings
  do not prove a document safe.
- DOCX body paragraphs are inspected; unsupported embedded or macro content is
  rejected. PDF embedded files and non-text objects are not executed.
- Uploaded content is not sent to an AI provider. AI remains disabled and
  advisory-only.
- The `agentId` and reviewer label are caller-supplied demo values, not
  authenticated identities. Ownership matching is not authorization against a
  verified person or service.
