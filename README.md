# AgentShield

AgentShield is an AI Agent Security Firewall. The backend evaluates each
proposed synthetic tool action before execution. Deterministic policy is the
sole authority; AI advisory is optional and cannot authorize or execute actions.

## Backend development

Requirements: Node.js 22.13+ and npm. MongoDB is required for persistent audit
events, approvals, and document inspection metadata. An explicitly configured
in-memory store is available for development and tests; it is not persistent.

```powershell
npm install
Copy-Item server\.env.example server\.env
npm run dev --workspace @agentshield/server
```

The sample environment selects `STORAGE_MODE=memory`. To use MongoDB, set
`STORAGE_MODE=mongodb` and configure `MONGODB_URI` and `MONGODB_DATABASE` in
`server/.env`. The API reports database availability at `GET /api/health` and
fails closed with `503 AUDIT_UNAVAILABLE` when configured MongoDB cannot
persist the required audit record. Never commit `.env` files or credentials.

Run backend validation and tests:

```powershell
npm run build --workspace @agentshield/server
npm run test --workspace @agentshield/server
```

The normal test command skips live MongoDB integration tests unless
`MONGODB_TEST_URI` is set. To run them against a local test database:

```powershell
$env:MONGODB_TEST_URI = 'mongodb://127.0.0.1:27017'
npm run test --workspace @agentshield/server
```

The integration suite creates and drops uniquely named `agentshield_test_*`
databases and requires permission to create/drop databases and apply temporary
collection validators. Never point it at production data.

The API listens on port 3001 by default and permits the configured
`FRONTEND_ORIGIN` (default `http://localhost:5173`). See
[docs/API_CONTRACT.md](docs/API_CONTRACT.md) for canonical v1.2 request,
response, policy, approval, and error contracts. Document inspection is
available at `POST /api/documents/inspect` for bounded PDF, DOCX, and UTF-8 TXT
uploads. It returns deterministic findings and a structured security report
without persisting raw document text.

## Current scope

The backend exposes health, S1–S3 demo scenarios, action evaluation, audit
events, approval listing/decisions, and document inspection/evaluation. The
scanner uses bounded deterministic patterns, not a comprehensive DLP or
malware scanner. Credential detection covers selected labeled key/value forms
and an AWS-style access-key-like pattern; a bare secret-looking value or
unrecognized format may not be detected. A clean scan is not proof a document
is safe. Tools operate only on synthetic data; no real filesystem,
shell, or external network execution is available. Document export is only a
synthetic simulation and is blocked by default; findings may block or require
approval. The demo `agentId` and reviewer labels are not authentication.

Approval uses a conditional state transition to ensure only one competing
request wins, but the transition, execution, and final audit update are not an
atomic transaction. Execution outcome can be uncertain if the process fails
between those steps. This workflow is not suitable for real side-effecting
tools without stronger transactional or recovery design.

Document inspection optionally supports an OpenAI-compatible Chat Completions
provider. AI is disabled by default. To opt in, set `AI_PROVIDER=openai-compatible`,
`AI_MODEL`, and `AI_API_KEY` in `server/.env`; `AI_BASE_URL` defaults to
`https://api.openai.com/v1`. The adapter appends `/chat/completions`, validates
HTTPS/public destinations, pins resolved addresses, rejects redirects, and
permits loopback development URLs only with `AI_ALLOW_LOOPBACK=true`. Never
expose or commit the API key.

With AI enabled, bounded chunks of extracted text are sent to the configured
provider after heuristic redaction of recognized email, phone, and credential
patterns. No file bytes, filename, agent ID, or inspection ID are sent. This
redaction is not comprehensive; enabling AI shares document content with that
provider under its data-handling terms. Raw text and raw provider responses
are not persisted. The report labels disabled or incomplete coverage and AI
findings remain advisory; deterministic policy is still the sole authority.
Tests mock the provider and do not verify a live external integration. The
frontend remains scaffold-level and is not yet an integrated dashboard.
