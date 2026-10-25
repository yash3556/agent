import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ArrowRight, Check, CircleAlert, Clipboard, ClipboardCheck, Download, FileClock, FileSearch, LayoutDashboard, Printer, RefreshCw, Search, Server, Shield, Upload, Workflow, X } from "lucide-react";
import { api, errorCode, errorMessage } from "./lib/api";
import type { Advisory, Approval, AuditEvent, Decision, EvaluateRequest, EvaluateResponse, Health, InspectionResponse, Scenario } from "./types";
import { StatusBadge } from "./components/StatusBadge";

type Page = "simulator" | "dashboard" | "approvals" | "audit" | "documents" | "system";
const nav: { id: Page; label: string; glyph: ReactNode }[] = [
  { id: "dashboard", label: "Overview", glyph: <LayoutDashboard size={18}/> },
  { id: "documents", label: "Document Inspection", glyph: <FileSearch size={18}/> },
  { id: "simulator", label: "Policy Evaluation", glyph: <Workflow size={18}/> },
  { id: "approvals", label: "Approvals", glyph: <ClipboardCheck size={18}/> },
  { id: "audit", label: "Audit Logs", glyph: <FileClock size={18}/> },
  { id: "system", label: "API / System Status", glyph: <Server size={18}/> },
];
const emptyRequest: EvaluateRequest = { agentId: "demo-agent", tool: "read_file", resource: "public/welcome.txt" };

function pageFromPath(): Page {
  const match = location.pathname.replace(/^\//, "") as Page;
  return ["dashboard", "approvals", "audit", "documents", "system"].includes(match) ? match : "simulator";
}
function dateTime(value: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
function ago(value: string) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
function Icon({ children }: { children: ReactNode }) { return <span className="icon" aria-hidden="true">{children}</span>; }
function ErrorBanner({ children }: { children: ReactNode }) { return <div className="error-banner" role="alert"><Icon><CircleAlert size={17}/></Icon><span>{children}</span></div>; }
function EmptyState({ title, detail }: { title: string; detail?: string }) {
  return <div className="empty-state"><span className="empty-icon" aria-hidden="true"><Shield size={25}/></span><strong>{title}</strong>{detail && <span>{detail}</span>}</div>;
}
function ApiStatus({ health, error }: { health: Health | null; error: boolean }) {
  return <div className={`api-status ${health && !error ? "online" : "offline"}`} title={health ? `Database ${health.db}; AI ${health.ai}` : "Backend status unavailable"}>
    <span className="health-dot" />{health && !error ? "Backend connected" : "Backend disconnected"}
    {health && !error && <span className="api-detail">DB {health.db} · AI {health.ai}</span>}
  </div>;
}
function AdvisoryCard({ advisory }: { advisory: Advisory | null }) {
  return <section className="card advisory-card">
    <div className="section-heading"><div><span className="eyebrow">OPTIONAL ANALYSIS</span><h3>Advisory</h3></div><span className="advisory-label">Advisory only</span></div>
    {!advisory ? <p className="muted">AI analysis unavailable. Decision unaffected.</p> : <>
      <div className="advisory-risk"><span className="muted">Risk level</span><span className={`risk-pill risk-${advisory.riskLevel.toLowerCase()}`}>{advisory.riskLevel === "UNKNOWN" ? "Risk level unknown" : advisory.riskLevel}</span></div>
      <p>{advisory.summary}</p>{advisory.signals.length > 0 && <ul className="signal-list">{advisory.signals.map((signal, index) => <li key={`${signal}-${index}`}>{signal}</li>)}</ul>}
    </>}
  </section>;
}
function DecisionResult({ result, onApprovals }: { result: EvaluateResponse; onApprovals: () => void }) {
  const step = 3;
  return <div className="result-stack">
    <section className={`card result-card decision-${result.decision.toLowerCase()}`}>
      <div className="result-top"><div><span className="eyebrow">POLICY DECISION</span><h2><StatusBadge status={result.decision} /></h2></div><span className="result-time">{dateTime(result.timestamp)}</span></div>
      <p className="result-reason">{result.reason}</p>
      <div className="result-meta"><div><span>Rule</span><code>{result.ruleId}</code></div><div><span>Event ID</span><code>{result.eventId}</code></div><div><span>Execution</span><strong className={result.executed ? "executed-yes" : "executed-no"}>{result.executed ? <Check size={13}/> : <X size={13}/>} Executed: {result.executed ? "yes" : "no"}</strong></div></div>
      {result.decision === "REQUIRE_APPROVAL" && <button className="text-link" onClick={onApprovals}>Review this request in Approvals <ArrowRight size={14}/></button>}
    </section>
    <section className="pipeline card" aria-label="Evaluation pipeline">
      {["Agent", "AgentShield", "Decision", "Audit Log"].map((label, index) => <div className={`pipeline-step ${index <= step ? "complete" : ""}`} key={label}><span>{index < step ? "✓" : index + 1}</span><small>{label}</small></div>)}
    </section>
    <AdvisoryCard advisory={result.advisory} />
  </div>;
}
function EventTable({ events, compact = false }: { events: AuditEvent[]; compact?: boolean }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  if (!events.length) return <EmptyState title="No actions evaluated yet. Run a scenario in the Action Simulator." />;
  return <div className="table-wrap"><table><thead><tr><th>Time</th><th>Event ID</th><th>Action</th><th>Decision</th><th>Reason</th><th>Rule</th><th>Executed</th><th>Advisory</th></tr></thead>
    <tbody>{events.slice(0, compact ? 8 : 200).map((event) => <FragmentRow key={event.eventId} event={event} expanded={expanded === event.eventId} toggle={() => setExpanded(expanded === event.eventId ? null : event.eventId)} />)}</tbody>
  </table></div>;
}
function FragmentRow({ event, expanded, toggle }: { event: AuditEvent; expanded: boolean; toggle: () => void }) {
  const status: Decision | "APPROVED" | "REJECTED" | "INSPECTED" = event.type === "APPROVAL_DECISION" ? event.approvalStatus ?? "REJECTED" : event.decision;
  const actionName = event.type === "DOCUMENT_INSPECTION" ? event.documentName ?? "Document inspection" : event.tool;
  return <>
    <tr className="event-row">
      <td className="nowrap" title={dateTime(event.timestamp)}>{ago(event.timestamp)}</td>
      <td><button className="copy-id" title="Copy event ID" aria-label={`Copy event ID ${event.eventId}`} onClick={(e) => { e.stopPropagation(); void navigator.clipboard?.writeText(event.eventId); }}>{event.eventId}<Clipboard size={13} aria-hidden="true"/></button></td>
      <td><code>{actionName}</code><br /><code className="muted-code">{event.resource}</code>{event.type === "DOCUMENT_INSPECTION" && <><br/><small>{event.findingCount ?? 0} findings · {event.reportStatus?.toLowerCase().replace("_", " ")}</small></>}</td><td><StatusBadge status={status} /></td>
      <td className="reason-cell"><button className="reason-toggle" aria-expanded={expanded} onClick={toggle}>{event.reason}<span>{expanded ? "Show less" : "Details"}</span></button></td><td><code>{event.ruleId}</code></td>
      <td><span className={event.executed ? "executed-yes" : "executed-no"}>{event.executed ? "✓ Yes" : "— No"}</span></td>
      <td>{event.advisory ? <span className={`risk-pill risk-${event.advisory.riskLevel.toLowerCase()}`}>{event.advisory.riskLevel}</span> : "—"}</td>
    </tr>
    {expanded && <tr className="expanded-row"><td colSpan={8}><div><strong>{event.type === "APPROVAL_DECISION" ? "Approval decision" : event.type === "DOCUMENT_INSPECTION" ? "Document inspection" : "Evaluation event"}</strong><p>{event.reason}</p><span>Agent: <code>{event.agentId}</code></span>{event.type === "DOCUMENT_INSPECTION" && <span>Report risk: {event.reportRiskLevel ?? "UNKNOWN"} · Rule: <code>{event.ruleId}</code></span>}{event.approvalId && <span>Approval ID: <code>{event.approvalId}</code></span>}{event.reviewer && <span>Reviewer: {event.reviewer}</span>}{event.note && <span>Note: {event.note}</span>}</div></td></tr>}
  </>;
}

export default function App() {
  const [page, setPage] = useState<Page>(pageFromPath);
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState(false);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [pendingCount, setPendingCount] = useState(0);
  const [globalError, setGlobalError] = useState("");

  const refreshEvents = useCallback(async () => { const data = await api.events(); setEvents(data.events); }, []);
  const refreshApprovals = useCallback(async () => { const data = await api.approvals("pending"); setPendingCount(data.approvals.length); }, []);
  const refreshData = useCallback(async () => {
    const results = await Promise.allSettled([refreshEvents(), refreshApprovals()]);
    if (results[0].status === "rejected") setEvents([]);
    if (results[1].status === "rejected") setPendingCount(0);
    if (results.some((result) => result.status === "rejected")) setGlobalError("Could not refresh the audit log or approvals. Latest data may be unavailable.");
    else setGlobalError("");
  }, [refreshApprovals, refreshEvents]);
  const refreshHealth = useCallback(async () => {
    try { const status = await api.health(); setHealth(status); setHealthError(false); }
    catch { setHealth(null); setHealthError(true); }
  }, []);
  const refreshAll = useCallback(async () => { await Promise.all([refreshHealth(), refreshData()]); }, [refreshData, refreshHealth]);

  useEffect(() => {
    void refreshHealth();
    void api.scenarios().then(({ scenarios: items }) => setScenarios(items)).catch(() => setScenarios([]));
    void refreshData();
    const timer = window.setInterval(() => { void refreshHealth(); }, 15000);
    const pop = () => setPage(pageFromPath());
    window.addEventListener("popstate", pop);
    return () => { window.clearInterval(timer); window.removeEventListener("popstate", pop); };
  }, [refreshData, refreshHealth]);

  const navigate = (next: Page) => { history.pushState({}, "", next === "simulator" ? "/" : `/${next}`); setPage(next); setGlobalError(""); };
  const onEvaluated = async () => { await refreshData(); };

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="/" onClick={(event) => { event.preventDefault(); navigate("simulator"); }}><img src="/logo.svg" alt=""/><span>AgentShield<small>SECURITY CONSOLE</small></span></a>
      <div className="nav-caption">WORKSPACE</div>
      <nav aria-label="Main navigation">{nav.map((item) => <button key={item.id} title={item.label} className={`nav-item ${page === item.id ? "active" : ""}`} onClick={() => navigate(item.id)} aria-current={page === item.id ? "page" : undefined}><Icon>{item.glyph}</Icon><span>{item.label}</span>{item.id === "approvals" && pendingCount > 0 && <span className="nav-count">{pendingCount}</span>}</button>)}</nav>
      <div className="sidebar-footer"><span className="environment-dot"/><span>Synthetic demo environment</span><small>v1.1 · Policy controlled</small></div>
    </aside>
    <div className="workspace"><header className="topbar"><div className="mobile-brand"><img src="/logo.svg" alt=""/> AgentShield</div><div className="breadcrumb"><span>Workspace</span><span aria-hidden="true">/</span><strong>{nav.find((item) => item.id === page)?.label}</strong></div><div className="topbar-right"><span className="demo-badge"><span/>LOCAL DEMO</span><ApiStatus health={health} error={healthError} /><button className="refresh-button" onClick={() => void refreshAll()} aria-label="Refresh backend status and activity" title="Refresh status and activity"><RefreshCw size={15}/><span>Refresh</span></button></div></header>
      <main className="main-content">
        {globalError && page !== "simulator" && <ErrorBanner>{globalError}</ErrorBanner>}
        {page === "simulator" && <Simulator scenarios={scenarios} backendReady={Boolean(health && !healthError)} globalError={globalError} onEvaluated={onEvaluated} onApprovals={() => navigate("approvals")} />}
        {page === "dashboard" && <Dashboard events={events} pendingCount={pendingCount} health={health} healthError={healthError} error={globalError} onNavigate={navigate} onRefresh={() => void refreshAll()} />}
        {page === "approvals" && <Approvals onChanged={async () => { await refreshData(); }} />}
        {page === "audit" && <Audit events={events} error={globalError} />}
        {page === "documents" && <DocumentInspection onApprovals={() => navigate("approvals")} onActionEvaluated={refreshData} />}
        {page === "system" && <SystemStatus health={health} error={healthError} onRefresh={() => void refreshAll()} />}
      </main>
    </div>
  </div>;
}

function Simulator({ scenarios, backendReady, globalError, onEvaluated, onApprovals }: { scenarios: Scenario[]; backendReady: boolean; globalError: string; onEvaluated: () => Promise<void>; onApprovals: () => void }) {
  const [form, setForm] = useState<EvaluateRequest>(emptyRequest);
  const [selected, setSelected] = useState("");
  const [result, setResult] = useState<EvaluateResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [errorCodeValue, setErrorCodeValue] = useState("");
  useEffect(() => { if (!backendReady) setResult(null); }, [backendReady]);
  const pickScenario = (scenario: Scenario) => { setSelected(scenario.id); setForm({ ...scenario.request }); setResult(null); setError(""); };
  const setField = (field: keyof EvaluateRequest, value: string) => setForm((current) => ({ ...current, [field]: value }));
  const evaluate = async (event: FormEvent) => {
    event.preventDefault(); setResult(null); setError(""); setErrorCodeValue(""); setBusy(true);
    try { const response = await api.evaluate({ agentId: form.agentId, tool: form.tool, resource: form.resource, ...(form.context?.trim() ? { context: form.context } : {}) }); setResult(response); await onEvaluated(); }
    catch (failure) { setResult(null); setError(errorMessage(failure)); setErrorCodeValue(errorCode(failure) ?? ""); }
    finally { setBusy(false); }
  };
  return <>
    <div className="page-intro"><div><span className="eyebrow">POLICY PLAYGROUND</span><h1>Policy Evaluation</h1><p>Evaluate a proposed action against the backend security policy.</p></div><div className="intro-mark" aria-hidden="true"><Shield size={22}/></div></div>
    {!backendReady && <ErrorBanner>Could not reach the backend. Check that the server is running. The simulator is disabled until it reconnects.</ErrorBanner>}
    {globalError && <ErrorBanner>{globalError}</ErrorBanner>}
    {error && <ErrorBanner>{error}{errorCodeValue === "AUDIT_UNAVAILABLE" ? " The action was not executed. Try again later." : ""}</ErrorBanner>}
    <div className="simulator-grid">
      <div className="left-column">
        <section className="card scenario-section"><div className="section-heading"><div><span className="eyebrow">START WITH A SCENARIO</span><h2>Demo scenarios</h2></div><span className="count-note">{scenarios.length} available</span></div>
          {scenarios.length === 0 ? <p className="muted scenario-loading">{backendReady ? "Loading scenarios…" : "Scenarios will appear when the backend connects."}</p> : <div className="scenario-list">{scenarios.map((scenario) => <button className={`scenario-card ${selected === scenario.id ? "selected" : ""}`} key={scenario.id} onClick={() => pickScenario(scenario)} aria-pressed={selected === scenario.id}><span className="scenario-id">{scenario.id}</span><span className="scenario-info"><strong>{scenario.title}</strong><code>{scenario.request.tool} · {scenario.request.resource}</code></span><span className="scenario-arrow" aria-hidden="true">→</span></button>)}</div>}
        </section>
        <form className="card request-form" onSubmit={evaluate}><div className="section-heading"><div><span className="eyebrow">CUSTOM OR PREFILLED</span><h2>Action request</h2></div><span className="untrusted-chip">Untrusted input</span></div>
          <label>Agent ID<input value={form.agentId} maxLength={64} required onChange={(e) => setField("agentId", e.target.value)} placeholder="demo-agent" /></label>
          <label>Tool<select value={form.tool} onChange={(e) => setField("tool", e.target.value)}><option value="read_file">read_file</option><option value="export_report">export_report</option></select></label>
          <label>Resource<input className="mono-input" value={form.resource} maxLength={256} required onChange={(e) => setField("resource", e.target.value)} placeholder="public/welcome.txt" /></label>
          <label>Context <span className="field-optional">Optional · never authorizes an action</span><textarea value={form.context ?? ""} maxLength={1000} rows={3} onChange={(e) => setField("context", e.target.value)} placeholder="Add untrusted demo text…"/><span className="char-count">{form.context?.length ?? 0}/1000</span></label>
          <button className="primary-button evaluate-button" type="submit" disabled={busy || !backendReady}><span>{busy ? "◌" : "⌁"}</span>{busy ? "Evaluating…" : "Evaluate action"}<span className="button-shortcut">↵</span></button>
        </form>
      </div>
      <div className="right-column">{busy ? <div className="card result-placeholder"><span className="spinner"/><span className="eyebrow">POLICY ENGINE</span><h2>Evaluating request…</h2><p className="muted">Waiting for the backend decision.</p></div> : result ? <DecisionResult result={result} onApprovals={onApprovals} /> : <div className="card result-placeholder"><span className="placeholder-shield" aria-hidden="true">◇</span><span className="eyebrow">YOUR RESULT</span><h2>Ready when you are</h2><p>Choose a scenario or enter an action, then evaluate it to see the policy decision.</p><div className="placeholder-rule"><span className="health-dot"/>Decisions come directly from the backend</div></div>}</div>
    </div>
  </>;
}

function Dashboard({ events, pendingCount, health, healthError, error, onNavigate, onRefresh }: { events: AuditEvent[]; pendingCount: number; health: Health | null; healthError: boolean; error: string; onNavigate: (page: Page) => void; onRefresh: () => void }) {
  const stats = [
    { label: "Backend", value: health && !healthError ? "Healthy" : "Unavailable", mark: <Server size={17}/>, tone: health && !healthError ? "green" : "red" },
    { label: "Database", value: health && !healthError ? health.db : "Unknown", mark: "DB", tone: health?.db === "connected" && !healthError ? "green" : "amber" },
    { label: "AI provider", value: health && !healthError ? health.ai : "Unknown", mark: "AI", tone: health?.ai === "configured" && !healthError ? "navy" : "amber" },
    { label: "Recent events · 50 max", value: events.length, mark: <FileClock size={17}/>, tone: "navy" },
  ];
  return <>
    <div className="page-intro"><div><span className="eyebrow">SECURITY OPERATIONS</span><h1>Overview</h1><p>Backend health and recent policy activity.</p></div><button className="outline-button refresh-inline" onClick={onRefresh}><RefreshCw size={14}/> Refresh data</button></div>
    {error && <ErrorBanner>{error}</ErrorBanner>}
    <div className="stats-grid">{stats.map((stat) => <section className="card stat-card" key={stat.label}><div className={`stat-icon ${stat.tone}`} aria-hidden="true">{stat.mark}</div><div><span>{stat.label}</span><strong className="status-value">{stat.value}</strong></div></section>)}</div>
    <div className="quick-actions"><button className="quick-action" onClick={() => onNavigate("documents")}><FileSearch size={17}/><span><strong>Inspect a document</strong><small>Upload PDF, DOCX, or TXT</small></span><ArrowRight size={15}/></button><button className="quick-action" onClick={() => onNavigate("simulator")}><Workflow size={17}/><span><strong>Evaluate an action</strong><small>Run a policy decision</small></span><ArrowRight size={15}/></button><button className="quick-action" onClick={() => onNavigate("approvals")}><ClipboardCheck size={17}/><span><strong>Review approvals</strong><small>{pendingCount} pending</small></span><ArrowRight size={15}/></button></div>
    <section className="card table-card"><div className="section-heading table-heading"><div><span className="eyebrow">LATEST ACTIVITY</span><h2>Recent audit events</h2></div><span className="muted">{events.length} event{events.length === 1 ? "" : "s"}</span></div><EventTable events={events} compact /></section>
  </>;
}

function DocumentInspection({ onApprovals, onActionEvaluated }: { onApprovals: () => void; onActionEvaluated: () => Promise<void> }) {
  const [agentId, setAgentId] = useState("demo-agent");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<InspectionResponse | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [policyResult, setPolicyResult] = useState<EvaluateResponse | null>(null);
  const [policyError, setPolicyError] = useState("");
  const [policyBusy, setPolicyBusy] = useState(false);

  const inspect = async (event: FormEvent) => {
    event.preventDefault();
    if (!file) {
      setError("Choose a PDF, DOCX, or TXT file to inspect.");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setError("The file exceeds the 5 MiB upload limit.");
      return;
    }
    setError("");
    setResult(null);
    setPolicyResult(null);
    setPolicyError("");
    setBusy(true);
    try {
      const inspection = await api.inspectDocument(file, agentId);
      setResult(inspection);
      await onActionEvaluated();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  const evaluateAction = async (tool: "analyze_document" | "export_report", destination: "local" | "external") => {
    if (!result) return;
    setPolicyBusy(true);
    setPolicyError("");
    setPolicyResult(null);
    try {
      const evaluation = await api.evaluate({
        agentId,
        tool,
        resource: result.inspectionId,
        inspectionId: result.inspectionId,
        destination,
      });
      setPolicyResult(evaluation);
      await onActionEvaluated();
    } catch (failure) {
      setPolicyError(errorMessage(failure));
    } finally {
      setPolicyBusy(false);
    }
  };

  const downloadReport = () => {
    if (!result) return;
    const report = {
      title: "AgentShield document security report",
      generatedAt: new Date().toISOString(),
      document: result.document,
      inspectionId: result.inspectionId,
      analysis: result.analysis,
      report: result.report,
      deterministicSummary: result.summary,
      policyDecision: policyResult ? {
        decision: policyResult.decision,
        ruleId: policyResult.ruleId,
        reason: policyResult.reason,
        approvalId: policyResult.approvalId,
      } : null,
      limitations: "A clean scan is not proof a document is safe. AI findings are advisory and do not authorize actions.",
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${result.document.originalName.replace(/\.[^.]+$/, "")}-security-report.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const hasInstructionRisk = result?.report.findings.some((finding) =>
    ["SUSPICIOUS_INSTRUCTION", "PROMPT_INJECTION", "POLICY_BYPASS", "DATA_EXFILTRATION"].includes(finding.category),
  ) ?? false;
  const hasSensitiveRisk = result?.report.findings.some((finding) =>
    ["PERSONAL_DATA", "CREDENTIAL"].includes(finding.category),
  ) ?? false;
  const timelineFindings = result ? [...result.report.findings].sort((left, right) => {
    const leftReference = left.evidenceReferences[0];
    const rightReference = right.evidenceReferences[0];
    return (leftReference?.page ?? Number.MAX_SAFE_INTEGER) - (rightReference?.page ?? Number.MAX_SAFE_INTEGER)
      || (leftReference?.line ?? 0) - (rightReference?.line ?? 0)
      || (leftReference?.chunk ?? 0) - (rightReference?.chunk ?? 0);
  }) : [];

  return <>
    <div className="page-intro"><div><span className="eyebrow">DOCUMENT SECURITY</span><h1>Document inspection</h1><p>Upload a document for bounded extraction and security scanning.</p></div></div>
    <form className="card document-upload" onSubmit={(event) => void inspect(event)}>
      <div className="section-heading"><div><span className="eyebrow">UPLOAD FOR ANALYSIS</span><h2>Choose a document</h2></div><span className="untrusted-chip">Untrusted file</span></div>
      <label className="document-agent">Agent ID<input value={agentId} maxLength={64} required onChange={(event) => setAgentId(event.target.value)} /></label>
      <label className="document-file">
        <Upload size={20}/>
        <strong>{file ? file.name : "Choose a file to inspect"}</strong>
        <span>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MiB` : "PDF, DOCX, TXT, CSV, JSON, Markdown, or XLSX · maximum 5 MiB"}</span>
        <input type="file" accept=".pdf,.docx,.txt,.csv,.json,.md,.markdown,.xlsx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/csv,application/csv,application/json,text/json,text/markdown,text/x-markdown,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" onChange={(event) => { setFile(event.target.files?.[0] ?? null); setResult(null); setError(""); }} />
      </label>
      <p className="document-privacy">The raw upload is not stored. The backend stores the document hash, bounded metadata, and redacted findings for up to 24 hours. If AI analysis is enabled, redacted extracted text may be sent to the configured provider. Scanning is not a guarantee that a document is safe.</p>
      {error && <ErrorBanner>{error}</ErrorBanner>}
      <button className="primary-button" type="submit" disabled={busy || !file}><Upload size={15}/>{busy ? "Inspecting…" : "Upload and inspect"}</button>
    </form>
    {result && <section className="card inspection-result">
      <div className="section-heading"><div><span className="eyebrow">DOCUMENT SECURITY REPORT</span><h2>{result.document.originalName}</h2></div><div className="report-actions"><span className={`risk-pill risk-${result.report.riskLevel.toLowerCase()}`}>{result.report.riskLevel} risk</span><button className="outline-button" type="button" onClick={downloadReport}><Download size={14}/> JSON report</button><button className="outline-button" type="button" onClick={() => window.print()}><Printer size={14}/> Print / PDF</button></div></div>
      <p>{result.analysis.aiFailure
        ? `${result.analysis.aiFailure.code === "ANALYSIS_LIMIT" ? "AI analysis incomplete" : "AI analysis failed"} — deterministic scan completed.`
        : result.report.summary}</p>
      <div className="inspection-meta"><span>Inspection ID <code>{result.inspectionId}</code></span><span>{result.summary.totalFindings} deterministic finding{result.summary.totalFindings === 1 ? "" : "s"}</span><span>AI analysis: {result.analysis.aiAdvisory === "AVAILABLE" ? "completed" : result.analysis.aiAdvisory === "NOT_NEEDED" ? "not run (no safe finding context)" : result.analysis.aiAdvisory === "DISABLED" ? "disabled" : result.analysis.aiFailure ? "failed" : "unavailable"}</span><span>Extraction: {result.report.coverage.extraction.toLowerCase()}</span><span>Coverage: {result.report.coverage.deterministic.toLowerCase()} deterministic · {result.report.coverage.completedChunks}/{result.report.coverage.totalChunks} AI chunks completed · {result.report.coverage.failedChunks} failed</span></div>
      <div className="report-summary-grid">
        <div><span>Threat findings</span><strong>{result.report.findings.length}</strong></div>
        <div><span>Sensitive-data indicators</span><strong>{result.report.findings.filter((finding) => ["PERSONAL_DATA", "CREDENTIAL"].includes(finding.category)).length}</strong></div>
        <div><span>Analysis coverage</span><strong>{result.report.coverage.totalChunks === 0 ? "No text" : `${Math.round(result.report.coverage.completedChunks / result.report.coverage.totalChunks * 100)}%`}</strong><small>{result.report.coverage.completedChunks} / {result.report.coverage.totalChunks} chunks analyzed</small></div>
        <div><span>Recommended policy action</span><strong>{hasInstructionRisk || result.report.findings.some((finding) => finding.category === "CREDENTIAL") ? "BLOCK" : hasSensitiveRisk ? "HUMAN REVIEW" : "EVALUATE"}</strong><small>Recommendation only; backend policy decides</small></div>
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((severity) => <div key={severity}><span>{severity} findings</span><strong>{result.report.findings.filter((finding) => finding.severity === severity).length}</strong></div>)}
      </div>
      {(hasInstructionRisk || hasSensitiveRisk) && <aside className="threat-correlation"><strong>Why this may be risky</strong><p>{hasInstructionRisk && hasSensitiveRisk
        ? "Instruction-like content and sensitive-data indicators co-occur in this document. Together they can increase the risk of unauthorized disclosure; this correlation is a heuristic, not proof of intent."
        : hasInstructionRisk
          ? "Instruction-like content may attempt to influence an agent's task or tool use. Treat document contents as untrusted input."
          : "Sensitive-data indicators were found. Verify authorization and destination before sharing; credentials should be rotated if they were exposed."}</p></aside>}
      {result.analysis.aiFailure && <ErrorBanner>{result.analysis.aiFailure.message} Deterministic findings are still available; AI output is advisory only.</ErrorBanner>}
      <section className="policy-evaluation">
        <div><span className="eyebrow">BACKEND ENFORCEMENT</span><h3>Evaluate a requested action</h3><p>AI findings are advisory. The backend policy engine alone returns ALLOW, BLOCK, or REQUIRE_APPROVAL.</p></div>
        <div className="report-actions"><button className="primary-button" type="button" disabled={policyBusy} onClick={() => void evaluateAction("analyze_document", "local")}>Evaluate local analysis</button><button className="outline-button" type="button" disabled={policyBusy} onClick={() => void evaluateAction("export_report", "external")}>Evaluate external export</button></div>
      </section>
      {policyError && <ErrorBanner>{policyError}</ErrorBanner>}
      {policyResult && <section className={`card report-policy-result decision-${policyResult.decision.toLowerCase()}`}>
        <div className="section-heading"><div><span className="eyebrow">POLICY DECISION · {policyResult.ruleId}</span><h3><StatusBadge status={policyResult.decision}/></h3></div><span className="muted">Audit event <code>{policyResult.eventId}</code></span></div>
        <p>{policyResult.reason}</p>
        {policyResult.decision === "REQUIRE_APPROVAL" && <button type="button" className="text-link" onClick={onApprovals}>Review pending approval <ArrowRight size={14}/></button>}
      </section>}
      {result.report.truncated && <ErrorBanner>Some findings were omitted because the report reached its result limit.</ErrorBanner>}
      {result.report.findings.length === 0 ? <EmptyState title="No findings reported." detail="A clean scan is not proof that the document is safe." /> : <div className="inspection-findings">{timelineFindings.map((finding) => <article className="inspection-finding" key={finding.id}>
        <div><span className={`risk-pill risk-${finding.severity.toLowerCase()}`}>{finding.severity}</span><strong>{finding.type.replaceAll("_", " ")}</strong><span className="finding-source">{finding.source}</span></div>
        <p>{finding.explanation}</p><p className="muted">{finding.recommendation}</p>
        <details><summary>Evidence viewer</summary><p>{finding.source === "DETERMINISTIC"
          ? result.findings.find((item) => item.type === finding.type && item.location.page === finding.evidenceReferences[0]?.page && item.location.line === finding.evidenceReferences[0]?.line)?.evidence ?? "Redacted evidence marker unavailable."
          : "Raw excerpts are withheld; AI evidence is represented by source coordinates only."}</p></details>
        {finding.evidenceReferences.length > 0 && <small>Threat timeline: {finding.evidenceReferences.map((reference) => [reference.page !== null ? `page ${reference.page}` : null, reference.line ? `line ${reference.line}` : null, reference.chunk !== null ? `chunk ${reference.chunk}` : null].filter(Boolean).join(", ")).join("; ")}</small>}
      </article>)}</div>}
    </section>}
  </>;
}

function SystemStatus({ health, error, onRefresh }: { health: Health | null; error: boolean; onRefresh: () => void }) {
  return <>
    <div className="page-intro"><div><span className="eyebrow">CONNECTIVITY</span><h1>API / System Status</h1><p>Live health response from the configured API origin.</p></div><button className="outline-button refresh-inline" onClick={onRefresh}><RefreshCw size={14}/> Check again</button></div>
    {error || !health ? <section className="card system-error" role="alert"><CircleAlert size={20}/><div><h2>Backend status unavailable</h2><p>Could not reach <code>/api/health</code>. Check that the API is running, the API base URL is configured correctly, and cross-origin access is allowed.</p><button className="outline-button" onClick={onRefresh}>Retry connection</button></div></section> : <>
      <section className="card system-health-banner"><span className="health-dot"/><div><strong>Backend responded · {health.status}</strong><small>Health check at {dateTime(health.time)}</small></div></section>
      <div className="system-grid"><StatusDetail title="Backend" value={health.status} description="API health endpoint response" healthy={health.status === "ok"}/><StatusDetail title="Database" value={health.db} description="Current persistence connectivity" healthy={health.db === "connected"}/><StatusDetail title="Storage mode" value={health.storage ?? "Not reported"} description={health.storage === "memory" ? "Development storage; data is not persistent." : "Storage mode reported by backend."} healthy={health.db === "connected"}/><StatusDetail title="AI provider" value={health.ai} description={health.ai === "disabled" ? "AI is disabled by configuration." : health.ai === "configured" ? "AI settings are loaded; actual status appears after a document analysis request." : "AI settings are missing or invalid."} healthy={health.ai !== "unavailable"}/></div>
    </>}
  </>;
}

function StatusDetail({ title, value, description, healthy }: { title: string; value: string; description: string; healthy: boolean }) {
  return <section className="card status-detail"><div><span className={`health-dot ${healthy ? "" : "status-dot-error"}`}/><span className="eyebrow">{title}</span></div><strong>{value}</strong><p>{description}</p></section>;
}

function Audit({ events, error }: { events: AuditEvent[]; error: string }) {
  const [filter, setFilter] = useState("ALL");
  const [query, setQuery] = useState("");
  const visible = events.filter((event) => {
    const state = event.type === "APPROVAL_DECISION" ? event.approvalStatus ?? "" : event.decision;
    const matchesFilter = filter === "ALL" || state === filter;
    const haystack = `${event.eventId} ${event.agentId} ${event.tool} ${event.documentName ?? ""} ${event.resource} ${event.reason} ${event.ruleId} ${event.approvalId ?? ""}`.toLowerCase();
    return matchesFilter && haystack.includes(query.toLowerCase());
  });
  return <>
    <div className="page-intro"><div><span className="eyebrow">TRACEABILITY</span><h1>Audit Log</h1><p>Document inspections, policy evaluations, and approval outcomes, newest first.</p></div><span className="records-count">{visible.length} records</span></div>
    {error && <ErrorBanner>{error}</ErrorBanner>}
    <section className="card table-card"><div className="audit-toolbar"><div className="filter-control"><label htmlFor="decision-filter">Activity</label><select id="decision-filter" value={filter} onChange={(e) => setFilter(e.target.value)}><option value="ALL">All activity</option><option value="INSPECTED">Document inspections</option><option value="ALLOW">Allowed</option><option value="BLOCK">Blocked</option><option value="REQUIRE_APPROVAL">Requires approval</option><option value="APPROVED">Approved</option><option value="REJECTED">Rejected</option></select></div><label className="search-control"><Search size={15} aria-hidden="true"/><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search events" aria-label="Search audit events" /></label></div>
      {visible.length === 0 ? <EmptyState title={events.length ? "No events match these filters." : "No events recorded yet. Upload a document or evaluate an action."} /> : <EventTable events={visible} />}
    </section>
  </>;
}

function Approvals({ onChanged }: { onChanged: () => Promise<void> }) {
  const [tab, setTab] = useState<"pending" | "decided">("pending");
  const [pending, setPending] = useState<Approval[]>([]);
  const [decided, setDecided] = useState<Approval[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [executionOutcomes, setExecutionOutcomes] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState("");
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    const [pendingResult, decidedResult, eventsResult] = await Promise.allSettled([api.approvals("pending"), api.approvals(), api.events()]);
    setPending(pendingResult.status === "fulfilled" ? pendingResult.value.approvals : []);
    setDecided(decidedResult.status === "fulfilled" ? decidedResult.value.approvals.filter((approval) => approval.status !== "PENDING") : []);
    setEvents(eventsResult.status === "fulfilled" ? eventsResult.value.events : []);
    const failure = [pendingResult, decidedResult, eventsResult].find((result) => result.status === "rejected");
    setError(failure?.status === "rejected" ? errorMessage(failure.reason) : "");
    setLoading(false);
  }, []);
  useEffect(() => { void load(); }, [load]);
  const decide = async (approval: Approval, decision: "APPROVED" | "REJECTED") => {
    setBusyId(approval.approvalId); setError("");
    try {
      const outcome = await api.decide(approval.approvalId, decision, notes[approval.approvalId] ?? "");
      setPending((current) => current.filter((item) => item.approvalId !== approval.approvalId));
      setDecided((current) => [outcome.approval, ...current.filter((item) => item.approvalId !== approval.approvalId)]);
      setExecutionOutcomes((current) => ({ ...current, [approval.approvalId]: outcome.executed }));
      setTab("decided");
      await onChanged(); await load();
    } catch (failure) {
      const code = errorCode(failure);
      setError(code === "NOT_FOUND" ? "This approval no longer exists." : code === "ALREADY_DECIDED" ? "This approval was already decided." : code === "AUDIT_UNAVAILABLE" ? "Audit log unavailable. The action was not executed. Try again later." : errorMessage(failure));
      if (code === "NOT_FOUND" || code === "ALREADY_DECIDED") await load();
    } finally { setBusyId(""); }
  };
  const list = tab === "pending" ? pending : decided;
  return <>
    <div className="page-intro"><div><span className="eyebrow">HUMAN REVIEW</span><h1>Approvals</h1><p>Review sensitive actions before the backend proceeds.</p></div><div className="reviewer-label"><span className="reviewer-avatar">DR</span><span>Demo reviewer<small>Not identity-verified</small></span></div></div>
    {error && <ErrorBanner>{error}</ErrorBanner>}
    <section className="card approvals-card"><div className="approval-tabs" role="tablist" aria-label="Approval state"><button role="tab" aria-selected={tab === "pending"} className={tab === "pending" ? "active" : ""} onClick={() => setTab("pending")}>Pending <span>{pending.length}</span></button><button role="tab" aria-selected={tab === "decided"} className={tab === "decided" ? "active" : ""} onClick={() => setTab("decided")}>Decided <span>{decided.length}</span></button></div>
      {loading ? <div className="loading-line"><span className="spinner small"/> Loading approvals…</div> : !list.length ? <EmptyState title={tab === "pending" ? "No pending approvals." : "No decisions yet."} detail={tab === "pending" ? "Actions that need human review will appear here." : undefined} /> : <div className="approval-list">{list.map((approval) => {
        const outcome = events.find((event) => event.type === "APPROVAL_DECISION" && event.approvalId === approval.approvalId);
        return <article className="approval-row" key={approval.approvalId}><div className="approval-main"><div className="approval-tool"><span className="tool-mark">⌘</span><div><strong>{approval.tool}</strong><code>{approval.resource}</code></div></div><div className="approval-time"><span>Requested</span><strong>{dateTime(approval.createdAt)}</strong><code title={approval.eventId}>Event {approval.eventId}</code></div><div className="approval-time"><span>Approval ID</span><code>{approval.approvalId}</code></div><div className="approval-status">{approval.status === "PENDING" ? <StatusBadge status="PENDING"/> : <StatusBadge status={approval.status}/>}</div></div>
          {approval.status === "PENDING" ? <div className="approval-actions"><label className="note-field">Reviewer note <span className="field-optional">Optional</span><input maxLength={500} value={notes[approval.approvalId] ?? ""} onChange={(e) => setNotes((current) => ({ ...current, [approval.approvalId]: e.target.value }))} placeholder="Add a note for the audit trail" /></label><div className="action-buttons"><button className="primary-button" disabled={Boolean(busyId)} onClick={() => void decide(approval, "APPROVED")}>{busyId === approval.approvalId ? "Saving…" : "✓ Approve"}</button><button className="outline-button" disabled={Boolean(busyId)} onClick={() => void decide(approval, "REJECTED")}>× Reject</button></div></div> : <div className="decision-summary"><span>Reviewed by <strong>{approval.reviewer ?? "demo-reviewer"}</strong></span><span>{approval.decidedAt ? dateTime(approval.decidedAt) : ""}</span><span>Executed: <strong className={(outcome?.executed ?? executionOutcomes[approval.approvalId]) ? "executed-yes" : "executed-no"}>{(outcome?.executed ?? executionOutcomes[approval.approvalId]) ? "yes" : "no"}</strong></span>{approval.note && <span className="decision-note">“{approval.note}”</span>}</div>}
        </article>;
      })}</div>}
    </section>
  </>;
}
