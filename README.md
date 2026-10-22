# AgentShield

AgentShield is an AI Agent Security Firewall. The backend evaluates each
proposed synthetic tool action before execution. Deterministic policy is the
sole authority; AI advisory is optional and cannot authorize or execute actions.

## Backend development

Requirements: Node.js 20+ and npm. MongoDB is required for persistent audit
events and approvals. An explicitly configured in-memory store is available for
development and tests; it is not persistent.

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

The API listens on port 3001 by default and permits the configured
`FRONTEND_ORIGIN` (default `http://localhost:5173`). See
[docs/API_CONTRACT.md](docs/API_CONTRACT.md) for canonical v1.1 request,
response, policy, approval, and error contracts.

## Current scope

The backend exposes health, S1–S3 demo scenarios, action evaluation, audit
events, and approval listing/decisions. Tools operate only on bounded synthetic
data; they do not access the real filesystem, shell, or external network.
No AI provider integration is included yet: advisory results are currently
`null`, and AI reports disabled by default (or unavailable if a provider name
is configured).
