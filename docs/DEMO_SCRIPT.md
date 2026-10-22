# AgentShield Demo Runbook

**Target demo:** 28 October 2026
**Required flows:** S1 allow, S2 block, S3 approval, audit review
**Canonical requests and response fields:** [API_CONTRACT.md](./API_CONTRACT.md)

## Readiness note

The backend core is implemented and its current tests/type check pass, but the
frontend pages are still placeholders and AI provider analysis is not
implemented. Local MongoDB persistence across fresh store instances, concurrent
approval decisions, and evaluation against an unavailable MongoDB endpoint
have passed integration tests. A physical database stop/restart and full
frontend workflow have not been verified. This document supports a
**backend/API rehearsal**, not a complete dashboard demo. Do not claim a UI or
AI flow until each has actually been run.

## Backend/API rehearsal

### 1. Start the API in explicit development-memory mode

From the repository root, install once and create the local environment file:

```powershell
npm install
Copy-Item server\.env.example server\.env
```

Confirm `STORAGE_MODE=memory` in `server\.env` for this API-only rehearsal.
This store is non-persistent: restarting the server clears events and approvals.
Start the backend:

```powershell
npm run dev --workspace @agentshield/server
```

In a second PowerShell window, check health:

```powershell
Invoke-RestMethod http://localhost:3001/api/health
```

Expect HTTP 200, `status: ok`, `db: connected`, `storage: memory`, and
`ai: disabled`. This confirms API availability, not durable audit persistence.

### 2. Load canonical demo scenarios

```powershell
$scenarios = Invoke-RestMethod http://localhost:3001/api/scenarios
$scenarios.scenarios | Format-Table id, title
```

Expected scenarios are S1, S2, and S3. S4 is stretch scope and is not currently
served.

### 3. Run S1 — allowed synthetic public read

```powershell
$s1 = @{
  agentId = 'demo-agent'
  tool = 'read_file'
  resource = 'public/welcome.txt'
} | ConvertTo-Json
$allow = Invoke-RestMethod http://localhost:3001/api/evaluate `
  -Method Post -ContentType 'application/json' -Body $s1
$allow | Format-List
```

Expected: `decision: ALLOW`, `ruleId: R-002`, `executed: true`, and
`advisory: null`. The synthetic data is in memory; no real file is read.

### 4. Run S2 — denied private-file request

```powershell
$s2 = @{
  agentId = 'demo-agent'
  tool = 'read_file'
  resource = 'private/payroll.csv'
} | ConvertTo-Json
$block = Invoke-RestMethod http://localhost:3001/api/evaluate `
  -Method Post -ContentType 'application/json' -Body $s2
$block | Format-List
```

Expected: `decision: BLOCK`, `ruleId: R-003`, `executed: false`. No tool runs.

### 5. Run S3 — hold, then approve or reject

```powershell
$s3 = @{
  agentId = 'demo-agent'
  tool = 'export_report'
  resource = 'sensitive-report'
} | ConvertTo-Json
$pending = Invoke-RestMethod http://localhost:3001/api/evaluate `
  -Method Post -ContentType 'application/json' -Body $s3
$pending | Format-List
```

Expected: `decision: REQUIRE_APPROVAL`, `ruleId: R-004`, an `approvalId`, and
`executed: false`. The operation remains pending until the decision request.

Inspect pending records and choose **one** outcome:

```powershell
Invoke-RestMethod 'http://localhost:3001/api/approvals?status=pending' |
  ConvertTo-Json -Depth 5
```

Approve:

```powershell
$decision = @{
  decision = 'APPROVED'
  reviewer = 'demo-reviewer'
  note = 'Approved for synthetic demo'
} | ConvertTo-Json
Invoke-RestMethod "http://localhost:3001/api/approvals/$($pending.approvalId)/decision" `
  -Method Post -ContentType 'application/json' -Body $decision |
  ConvertTo-Json -Depth 5
```

Expected: approval status `APPROVED`, `executed: true`. Alternatively submit
`REJECTED` instead of `APPROVED`; expected `executed: false`. Do not submit both
decisions for the same approval; a second decision is expected to return HTTP
409 `ALREADY_DECIDED`. The conditional transition allows only one concurrent
decision to win, but state transition, execution, and final audit update are
not atomic. Do not present this as a guarantee for real side-effecting tools.

### 6. Inspect audit results

```powershell
Invoke-RestMethod 'http://localhost:3001/api/events?limit=50' |
  ConvertTo-Json -Depth 8
```

Confirm events show the event IDs, timestamps, decisions, policy rule/reason,
approval outcome, redacted data, and execution status. Memory data will be lost
when the process restarts.

### 7. Exercise a fail-closed input

```powershell
$traversal = @{
  agentId = 'demo-agent'
  tool = 'read_file'
  resource = 'public/../private/payroll.csv'
} | ConvertTo-Json
Invoke-RestMethod http://localhost:3001/api/evaluate `
  -Method Post -ContentType 'application/json' -Body $traversal
```

Expected: `BLOCK`, rule `R-001`, `executed: false`.

### 8. Inspect a synthetic document and evaluate its findings

Create a small synthetic TXT document. Do not use real personal data or
credentials:

```powershell
Set-Content -Path .\synthetic-contact.txt -NoNewline -Value 'Contact alice@example.test'
$inspection = (curl.exe -sS -F 'agentId=demo-agent' `
  -F 'file=@synthetic-contact.txt;type=text/plain' `
  http://localhost:3001/api/documents/inspect | ConvertFrom-Json)
$inspection | ConvertTo-Json -Depth 8
```

Expect HTTP 201, a server-issued `inspectionId`, a `PERSONAL_DATA` finding with
`[REDACTED_EMAIL]` evidence, and `analysis.aiAdvisory: DISABLED`. The email
value is synthetic; the API response must not echo it.

Run local analysis:

```powershell
$analysis = @{
  agentId = 'demo-agent'
  tool = 'analyze_document'
  resource = $inspection.inspectionId
  inspectionId = $inspection.inspectionId
  destination = 'local'
} | ConvertTo-Json
Invoke-RestMethod http://localhost:3001/api/evaluate `
  -Method Post -ContentType 'application/json' -Body $analysis |
  ConvertTo-Json -Depth 5
```

Expect `ALLOW`, rule `R-006`, and `executed: true`; execution is a synthetic
local-analysis result only. For external export, use the same inspection ID
with `tool='export_report'` and `destination='external'`. Personal-data
findings must produce `REQUIRE_APPROVAL`, with `executed: false`; only after a
server-side approval transition does the bounded synthetic export simulation
run. It never sends data externally. Credential-like findings, suspicious
instructions, incomplete reports, unknown ownership, or expired inspections
must block or fail closed. Clean scans do not authorize external export.

If demonstrating credential detection, use a synthetic supported key/value
pattern such as `api_key=sample-secret-value` (or `password=demo-pass-123`).
The scanner currently checks only selected credential labels with values of at
least six non-whitespace characters, plus an `AKIA`-prefixed access-key-like
format. A plain unlabeled string such as `sample-secret-value` is not guaranteed
to produce a credential finding. Do not use real secrets.

Optional cleanup of the synthetic sample:

```powershell
Remove-Item .\synthetic-contact.txt
```

## Full demo sequence after frontend integration

1. Start MongoDB, API, and UI; verify `/api/health` reports `db: connected` and
   `storage: mongodb`.
2. Show the real backend health state in the dashboard.
3. Run S1 and explain `ALLOW` and `Executed: yes`.
4. Run S2 and explain `BLOCK` and `Executed: no`.
5. Run S3 and show it held with `Executed: no`.
6. Approve or reject once in the Approval Queue and show the backend result.
7. Open the Audit Log and confirm those same persisted events and outcomes.
8. Optionally demonstrate S4/AI only if path traversal tests pass and a real,
   schema-validated AI integration is available; explain AI cannot override
   policy.
9. State the actual limitations: synthetic tools; heuristic content scanning
   that is not comprehensive malware detection; caller-supplied demo identity;
   non-atomic approval/execution; and any feature not implemented.

## Go/no-go checklist

- [ ] Clean install and backend/frontend builds succeed; report actual output.
- [ ] Live MongoDB persistence and restart behavior have been verified.
- [ ] MongoDB outage returns 503 before executing; health still reports API up
  and `db: error`.
- [ ] S1, S2, S3 pass through the actual UI and API.
- [ ] Pending and blocked operations demonstrably do not execute.
- [ ] Approval/rejection, 404, 409, and concurrent decision behavior verified;
  explain that this does not make execution and audit updates atomic.
- [ ] Audit values are redacted and outcome rows match backend state.
- [ ] Loading, empty, API error, disconnected, and DB-error UI states verified.
- [ ] AI disabled path works; any shown AI advisory is real and explicitly
  labeled advisory.
- [ ] Backup recording/screenshots prepared and demo machine rehearsed.
