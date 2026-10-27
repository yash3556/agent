import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { ArrowRight, Check, CircleAlert, Clipboard, ClipboardCheck, Download, FileClock, FileSearch, LayoutDashboard, Printer, RefreshCw, Search, Server, Shield, Upload, Workflow, X } from "lucide-react";
import { api, errorCode, errorMessage } from "./lib/api";
import type { Advisory, Approval, AuditEvent, Decision, EvaluateRequest, EvaluateResponse, Health, InspectionResponse, Scenario } from "./types";
import { StatusBadge } from "./components/StatusBadge";
import { ServiceHealthStrip } from "./components/ServiceHealthStrip";
import { PrimaryNavigation } from "./components/PrimaryNavigation";

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
const policyRules: { id: string; condition: string; decision: Decision }[] = [
  { id: "R-001", condition: "Traversal, absolute paths, NUL, or malformed resource encoding.", decision: "BLOCK" },
  { id: "R-005", condition: "Document action has no valid, complete inspection owned by this agent.", decision: "BLOCK" },
  { id: "R-006", condition: "demo-agent analyzes its completed inspection locally.", decision: "ALLOW" },
  { id: "R-007", condition: "External export contains a credential-like finding.", decision: "BLOCK" },
  { id: "R-008", condition: "External export contains a suspicious-instruction finding.", decision: "BLOCK" },
  { id: "R-010", condition: "External export report has truncated findings.", decision: "BLOCK" },
  { id: "R-009", condition: "External export contains personal-data findings and no higher-priority block applies.", decision: "REQUIRE_APPROVAL" },
  { id: "R-002", condition: "read_file targets the exact public/welcome.txt resource.", decision: "ALLOW" },
  { id: "R-003", condition: "read_file targets a private/ resource.", decision: "BLOCK" },
  { id: "R-004", condition: "export_report targets sensitive-report.", decision: "REQUIRE_APPROVAL" },
  { id: "R-999", condition: "No earlier rule permits the requested tool and resource (deny by default).", decision: "BLOCK" },
];

function pageFromPath(): Page {
  const match = location.pathname.replace(/^\//, "") as Page;
  return ["dashboard", "approvals", "audit", "documents", "system"].includes(match) ? match : "simulator";
}
function dateTime(value: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
function aiFailureLabel(code: string) {
  const labels: Record<string, string> = {
    TIMEOUT: "AI provider timed out", INVALID_RESPONSE: "AI provider returned an invalid response",
    CONNECTION_FAILED: "AI provider connection failed", DNS_FAILED: "AI provider address could not be resolved",
    DESTINATION_REJECTED: "AI provider destination was rejected", AUTHENTICATION_FAILED: "AI provider authentication failed",
    RATE_LIMITED: "AI provider rate limit reached", CREDITS_EXHAUSTED: "AI provider quota exhausted",
    PROVIDER_LIMIT_REACHED: "AI provider usage limit reached", MODEL_OR_ENDPOINT_NOT_FOUND: "AI model or endpoint was not found",
    PROVIDER_ERROR: "AI provider returned an error", PROVIDER_UNAVAILABLE: "AI provider is unavailable",
    ANALYSIS_LIMIT: "AI analysis reached its configured limit",
  };
  return labels[code] ? `${labels[code]} (${code})` : "AI analysis did not complete";
}
function recommendedAction(category: string, existing: string) {
  if (category === "CREDENTIAL") return "If active or exposed, rotate the credential through its issuer and review dependent integrations.";
  if (category === "PERSONAL_DATA") return "Confirm authorization and need-to-know; redact personal data before disclosure.";
  if (category === "SUSPICIOUS_INSTRUCTION") return "Treat instruction-like text as untrusted and verify requested actions through a trusted channel.";
  return existing;
}
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
function MatchedRule({ ruleId }: { ruleId: string }) {
  const rule = policyRules.find((item) => item.id === ruleId);
  return rule ? <div className="matched-rule"><span className="eyebrow">MATCHED RULE · {rule.id}</span><span>{rule.condition}</span></div> : null;
}
function PolicyRuleReference() {
  return <details className="policy-reference">
    <summary><span><span className="eyebrow">POLICY REFERENCE</span><strong>Current backend rules</strong></span><span className="count-note">{policyRules.length} rules · read only</span></summary>
    <p>Rules are evaluated by the backend in order. This reference describes the current implementation; it cannot edit or override a decision.</p>
    <div className="policy-rule-table"><table>
      <thead><tr><th>Order</th><th>Condition</th><th>Decision</th></tr></thead>
      <tbody>{policyRules.map((rule, index) => <tr key={rule.id}><td><code>{String(index + 1).padStart(2, "0")} · {rule.id}</code></td><td>{rule.condition}</td><td><StatusBadge status={rule.decision}/></td></tr>)}</tbody>
    </table></div>
  </details>;
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
      <MatchedRule ruleId={result.ruleId}/>
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
  if (!events.length) return <EmptyState title="No recent audit events." detail="Evaluate an action or inspect a document to create activity." />;
  return <div className="table-wrap"><table><thead><tr><th>Time</th><th>Event ID</th><th>Action</th><th>Decision</th><th>Reason</th><th>Rule</th><th>Executed</th><th>Advisory</th></tr></thead>
    <tbody>{events.slice(0, compact ? 8 : 200).map((event) => <FragmentRow key={event.eventId} event={event} expanded={expanded === event.eventId} toggle={() => setExpanded(expanded === event.eventId ? null : event.eventId)} />)}</tbody>
  </table></div>;
}

function AnimatedMetric({ value }: { value: number | string }) {
  const [displayed, setDisplayed] = useState<number | string>(value);
  const previous = useRef<number | string>(value);
  useEffect(() => {
    const from = previous.current;
    previous.current = value;
    if (typeof value !== "number" || typeof from !== "number" || value === from
      || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setDisplayed(value);
      return;
    }
    const start = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / 360);
      const eased = 1 - (1 - progress) ** 3;
      setDisplayed(Math.round(from + (value - from) * eased));
      if (progress < 1) frame = window.requestAnimationFrame(tick);
    };
    frame = window.requestAnimationFrame(tick);
    return () => window.cancelAnimationFrame(frame);
  }, [value]);
  return <>{displayed}</>;
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
  const [eventsLoaded, setEventsLoaded] = useState(false);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenariosError, setScenariosError] = useState("");
  const [pendingCount, setPendingCount] = useState<number | null>(null);
  const [globalError, setGlobalError] = useState("");

  const refreshEvents = useCallback(async () => { const data = await api.events(); setEvents(data.events); }, []);
  const refreshApprovals = useCallback(async () => { const data = await api.approvals("pending"); setPendingCount(data.approvals.length); }, []);
  const refreshData = useCallback(async () => {
    const results = await Promise.allSettled([refreshEvents(), refreshApprovals()]);
    if (results[0].status === "fulfilled") setEventsLoaded(true);
    const failures = results.flatMap((result, index) => result.status === "rejected"
      ? [`${index === 0 ? "Audit history" : "Approvals"}: ${errorMessage(result.reason)}`]
      : []);
    setGlobalError(failures.length ? `Refresh incomplete. ${failures.join(" ")}` : "");
  }, [refreshApprovals, refreshEvents]);
  const refreshHealth = useCallback(async () => {
    try { const status = await api.health(); setHealth(status); setHealthError(false); }
    catch { setHealth(null); setHealthError(true); }
  }, []);
  const refreshAll = useCallback(async () => { await Promise.all([refreshHealth(), refreshData()]); }, [refreshData, refreshHealth]);

  useEffect(() => {
    void refreshHealth();
    void api.scenarios().then(({ scenarios: items }) => { setScenarios(items); setScenariosError(""); }).catch((failure) => setScenariosError(errorMessage(failure)));
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
      <a className="brand" href="/" onClick={(event) => { event.preventDefault(); navigate("dashboard"); }}><img src="/logo.svg" alt=""/><span>AgentShield<small>AI SECURITY FIREWALL</small></span></a>
      <div className="nav-caption">WORKSPACE</div>
      <PrimaryNavigation items={nav} activePage={page} pendingCount={pendingCount} onNavigate={navigate} />
      <div className="sidebar-footer"><span className="environment-dot"/><span>Synthetic demo environment</span><small>Policy controlled · No real tools</small></div>
    </aside>
    <div className="workspace"><header className="topbar"><div className="mobile-brand"><img src="/logo.svg" alt=""/> AgentShield</div><div className="breadcrumb"><span>WORKSPACE</span><span aria-hidden="true">/</span><strong>{nav.find((item) => item.id === page)?.label}</strong></div><div className="topbar-right"><span className="demo-badge"><span/>DEMO · SYNTHETIC</span><ApiStatus health={health} error={healthError} /><button className="refresh-button" onClick={() => void refreshAll()} aria-label="Refresh backend status and activity" title="Refresh status and activity"><RefreshCw size={15}/><span>Refresh</span></button></div></header>
      <main key={page} className="main-content">
        {globalError && !["simulator", "dashboard", "approvals", "audit"].includes(page) && <ErrorBanner>{globalError}</ErrorBanner>}
        {page === "simulator" && <Simulator scenarios={scenarios} scenariosError={scenariosError} backendReady={Boolean(health && !healthError)} globalError={globalError} onEvaluated={onEvaluated} onApprovals={() => navigate("approvals")} />}
        {page === "dashboard" && <Dashboard events={events} eventsLoaded={eventsLoaded} pendingCount={pendingCount} health={health} healthError={healthError} error={globalError} onNavigate={navigate} onRefresh={() => void refreshAll()} />}
        {page === "approvals" && <Approvals onChanged={async () => { await refreshData(); }} />}
        {page === "audit" && <Audit events={events} eventsLoaded={eventsLoaded} error={globalError} />}
        {page === "documents" && <DocumentInspection onApprovals={() => navigate("approvals")} onActionEvaluated={refreshData} />}
        {page === "system" && <SystemStatus health={health} error={healthError} onRefresh={() => void refreshAll()} />}
      </main>
    </div>
  </div>;
}

function Simulator({ scenarios, scenariosError, backendReady, globalError, onEvaluated, onApprovals }: { scenarios: Scenario[]; scenariosError: string; backendReady: boolean; globalError: string; onEvaluated: () => Promise<void>; onApprovals: () => void }) {
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
    {scenariosError && <ErrorBanner>Could not load demo scenarios. {scenariosError}</ErrorBanner>}
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
    <PolicyRuleReference/>
  </>;
}

function Dashboard({ events, eventsLoaded, pendingCount, health, healthError, error, onNavigate, onRefresh }: { events: AuditEvent[]; eventsLoaded: boolean; pendingCount: number | null; health: Health | null; healthError: boolean; error: string; onNavigate: (page: Page) => void; onRefresh: () => void }) {
  const evaluations = events.filter((event) => event.type === "EVALUATION");
  const inspections = events.filter((event) => event.type === "DOCUMENT_INSPECTION");
  const findingCount = inspections.reduce((total, event) => total + (event.findingCount ?? 0), 0);
  const decisionCounts = [
    { label: "Allowed", value: evaluations.filter((event) => event.decision === "ALLOW").length, tone: "allow" },
    { label: "Blocked", value: evaluations.filter((event) => event.decision === "BLOCK").length, tone: "block" },
    { label: "Needs approval", value: evaluations.filter((event) => event.decision === "REQUIRE_APPROVAL").length, tone: "review" },
  ];
  const decisionTotal = evaluations.length;
  const stats = [
    { label: "Policy evaluations", value: eventsLoaded ? evaluations.length : "—", mark: <Workflow size={17}/>, tone: "navy", note: eventsLoaded ? "in latest 50 events" : "history unavailable" },
    { label: "Allowed", value: eventsLoaded ? decisionCounts[0].value : "—", mark: <Check size={17}/>, tone: "green", note: "backend decisions" },
    { label: "Blocked", value: eventsLoaded ? decisionCounts[1].value : "—", mark: <Shield size={17}/>, tone: "red", note: "backend decisions" },
    { label: "Pending approvals", value: pendingCount ?? "—", mark: <ClipboardCheck size={17}/>, tone: "amber", note: pendingCount === null ? "queue unavailable" : "current queue" },
    { label: "Inspection findings", value: eventsLoaded ? findingCount : "—", mark: <FileSearch size={17}/>, tone: "navy", note: eventsLoaded ? `across ${inspections.length} recent inspections` : "history unavailable" },
  ];
  return <>
    <div className="page-intro"><div><span className="eyebrow">SECURITY OPERATIONS / SUMMARY</span><h1>Overview</h1><p>Backend health and the latest available policy activity.</p></div><button className="outline-button refresh-inline" onClick={onRefresh}><RefreshCw size={14}/> Refresh data</button></div>
    {error && <ErrorBanner>{error}</ErrorBanner>}
    <div className="stats-grid">{stats.map((stat) => <section className="card stat-card" key={stat.label}><div className={`stat-icon ${stat.tone}`} aria-hidden="true">{stat.mark}</div><div><span>{stat.label}</span><strong className="status-value"><AnimatedMetric value={stat.value}/></strong><small>{stat.note}</small></div></section>)}</div>
    <ServiceHealthStrip health={health} hasError={healthError} />
    <section className="card decision-summary">
      <div className="section-heading"><div><span className="eyebrow">POLICY OUTCOMES</span><h2>Recent decisions</h2></div><span className="count-note">{eventsLoaded ? `${decisionTotal} evaluations · latest 50 audit events` : "Awaiting audit history"}</span></div>
      {!eventsLoaded ? <p className="muted">Policy decisions are unavailable until the audit history loads.</p> : decisionTotal === 0 ? <p className="muted">No policy evaluations in the currently available event history.</p> : <div className="decision-breakdown">
        {decisionCounts.map((decision) => <div className="decision-row" key={decision.label}>
          <div><span className={`decision-key ${decision.tone}`} aria-hidden="true"/><strong>{decision.label}</strong><span className="decision-count">{decision.value}</span></div>
          <div className="decision-track" role="img" aria-label={`${decision.label}: ${decision.value} of ${decisionTotal} recent evaluations`}><span className={decision.tone} style={{ width: `${decision.value / decisionTotal * 100}%` }}/></div>
        </div>)}
      </div>}
    </section>
    <div className="quick-actions"><button className="quick-action" onClick={() => onNavigate("documents")}><FileSearch size={17}/><span><strong>Inspect a document</strong><small>PDF, DOCX, TXT, CSV, JSON, Markdown, XLSX</small></span><ArrowRight size={15}/></button><button className="quick-action" onClick={() => onNavigate("simulator")}><Workflow size={17}/><span><strong>Evaluate an action</strong><small>Run a policy decision</small></span><ArrowRight size={15}/></button><button className="quick-action" onClick={() => onNavigate("approvals")}><ClipboardCheck size={17}/><span><strong>Review approvals</strong><small>{pendingCount === null ? "Queue unavailable" : `${pendingCount} pending`}</small></span><ArrowRight size={15}/></button></div>
    <section className="card table-card"><div className="section-heading table-heading"><div><span className="eyebrow">LATEST ACTIVITY</span><h2>Recent audit events</h2></div><span className="muted">{eventsLoaded ? `${events.length} events · up to 50` : "History unavailable"}</span></div><p className="activity-freshness">History refreshes on request and after actions; this view is not a live event stream.</p>{eventsLoaded ? <EventTable events={events} compact /> : <EmptyState title="Audit history unavailable." detail="Refresh after confirming the backend is reachable." />}</section>
  </>;
}

function DocumentInspection({ onApprovals, onActionEvaluated }: { onApprovals: () => void; onActionEvaluated: () => Promise<void> }) {
  const [agentId, setAgentId] = useState("demo-agent");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<InspectionResponse | null>(null);
  const [error, setError] = useState("");
  const [uploadErrorCode, setUploadErrorCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [policyResult, setPolicyResult] = useState<EvaluateResponse | null>(null);
  const [policyError, setPolicyError] = useState("");
  const [policyBusy, setPolicyBusy] = useState(false);

  const inspect = async (event: FormEvent) => {
    event.preventDefault();
    if (!file) {
      setError("Choose a supported PDF, DOCX, TXT, CSV, JSON, Markdown, or XLSX file to inspect.");
      setUploadErrorCode("");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setError("The file exceeds the 5 MiB upload limit.");
      setUploadErrorCode("PAYLOAD_TOO_LARGE");
      return;
    }
    setError("");
    setUploadErrorCode("");
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
      setUploadErrorCode(errorCode(failure) ?? "");
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
      advisorySuggestion: {
        decision: reportSuggestion,
        source: "report findings",
        authoritative: false,
      },
      policyDecision: policyResult ? {
        authority: "backend policy engine",
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
  const prioritizedRecommendations = result ? [...new Set([...result.report.findings]
    .sort((left, right) => ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(left.severity)
      - ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(right.severity))
    .map((finding) => recommendedAction(finding.category, finding.recommendation)))] : [];
  const policyLabel = policyResult ? `${policyResult.decision} · ${policyResult.ruleId}` : "No action evaluated";
  const reportSuggestion = hasInstructionRisk || result?.report.findings.some((finding) => finding.category === "CREDENTIAL")
    ? "BLOCK"
    : hasSensitiveRisk ? "HUMAN REVIEW" : "EVALUATE";

  return <>
    <div className="page-intro"><div><span className="eyebrow">DOCUMENT SECURITY</span><h1>Document inspection</h1><p>Upload a document for bounded extraction and security scanning.</p></div></div>
    <form className="card document-upload" aria-busy={busy} onSubmit={(event) => void inspect(event)}>
      <div className="section-heading"><div><span className="eyebrow">UPLOAD FOR ANALYSIS</span><h2>Choose a document</h2></div><span className="untrusted-chip">Untrusted file</span></div>
      <label className="document-agent">Agent ID<input value={agentId} maxLength={64} required onChange={(event) => setAgentId(event.target.value)} /></label>
      <label className="document-file">
        <Upload size={20}/>
        <strong>{file ? file.name : "Choose a file to inspect"}</strong>
        <span>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MiB` : "PDF, DOCX, TXT, CSV, JSON, Markdown, or XLSX · maximum 5 MiB"}</span>
        <input type="file" accept=".pdf,.docx,.txt,.csv,.json,.md,.markdown,.xlsx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/csv,application/csv,application/json,text/json,text/markdown,text/x-markdown,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" onChange={(event) => { setFile(event.target.files?.[0] ?? null); setResult(null); setError(""); setUploadErrorCode(""); }} />
      </label>
      <p className="document-privacy">The raw upload is not stored. The backend stores the document hash, bounded metadata, and redacted findings for up to 24 hours. If AI analysis is enabled, redacted extracted text may be sent to the configured provider. Scanning is not a guarantee that a document is safe.</p>
      {error && <ErrorBanner>{error}{uploadErrorCode && <> <code>({uploadErrorCode})</code></>}</ErrorBanner>}
      <button className="primary-button" type="submit" disabled={busy || !file}><Upload size={15}/>{busy ? "Inspecting…" : "Upload and inspect"}</button>
      {busy && <p className="inspection-progress" role="status" aria-live="polite">Inspection is running on the backend. A percentage estimate is not available.</p>}
    </form>
    {result && <section className="card inspection-result">
      <div className="section-heading"><div><span className="eyebrow">DOCUMENT SECURITY REPORT</span><h2>{result.document.originalName}</h2></div><div className="report-actions"><span className={`risk-pill risk-${result.report.riskLevel.toLowerCase()}`}>{result.report.riskLevel} risk</span><button className="outline-button" type="button" onClick={downloadReport}><Download size={14}/> JSON report</button><button className="outline-button" type="button" onClick={() => window.print()}><Printer size={14}/> Print / PDF</button></div></div>
      <p>{result.analysis.aiFailure
        ? `${result.analysis.aiFailure.code === "ANALYSIS_LIMIT" ? "AI analysis incomplete" : "AI analysis failed"} — deterministic scan completed.`
        : result.report.summary}</p>
      <div className="inspection-meta"><span>Inspection ID <code>{result.inspectionId}</code></span><span>{result.summary.totalFindings} deterministic finding{result.summary.totalFindings === 1 ? "" : "s"}</span><span>AI analysis: {result.analysis.aiAdvisory === "AVAILABLE" ? "completed" : result.analysis.aiAdvisory === "NOT_NEEDED" ? "not run (no safe finding context)" : result.analysis.aiAdvisory === "DISABLED" ? "disabled" : result.analysis.aiFailure ? "failed" : "unavailable"}</span><span>Extraction: {result.report.coverage.extraction.toLowerCase()}</span><span>Coverage: {result.report.coverage.deterministic.toLowerCase()} deterministic · {result.report.coverage.completedChunks}/{result.report.coverage.totalChunks} AI chunks completed · {result.report.coverage.failedChunks} failed</span></div>
      <div className="report-detail-grid">
        <article className="report-detail-card"><h3>Document Summary</h3><p><strong>{result.report.documentCoverage.format.toUpperCase()}</strong> · {result.document.originalName}</p><p>{result.report.documentCoverage.extractedPages === null ? `${result.report.documentCoverage.textSegments} extracted text segment(s); page count is not available.` : `${result.report.documentCoverage.extractedPages} pages extracted; ${result.report.documentCoverage.inspectedPages} pages inspected.`}</p><p><strong>{result.report.documentSummary.status === "AI_EXCERPTS" ? "AI summary of selected sanitized excerpts" : "Content summary unavailable"}</strong></p><p>{result.report.documentSummary.text}</p><p>Coverage: deterministic scanning processed all extracted text. This summary is distinct from security findings and does not cover every page semantically.</p>{result.report.documentCoverage.limitations.map((limitation) => <small key={limitation}>{limitation}</small>)}</article>
        <article className="report-detail-card"><h3>Security Overview</h3><p>Risk level: <strong>{result.report.riskLevel}</strong> · {result.report.findings.length} report finding(s)</p><p>Finding-based suggestion (non-binding): <strong>{reportSuggestion}</strong></p><p>Backend policy decision (authoritative): <strong>{policyLabel}</strong></p><p>AI findings are advisory; only deterministic findings drive backend policy.</p></article>
        <article className="report-detail-card"><h3>AI Analysis Scope</h3><p>Status: <strong>{result.report.aiScope.status}</strong> · {result.report.aiScope.submittedChunks} sanitized excerpt chunk(s) submitted.</p><p>{result.report.aiScope.submittedChunks ? "When called, AI received redacted, bounded excerpts only." : "No excerpts were submitted to AI."} The complete document was not reviewed by AI; this is not a complete semantic summary of every page.</p><small>Excerpt locations: {result.report.aiScope.locations.length ? result.report.aiScope.locations.map((location) => `${location.page === null ? "text" : `page ${location.page}`}, line ${location.line}`).join("; ") : "None recorded."}{result.report.aiScope.locationsTruncated ? " · Showing first 100 locations." : ""}</small></article>
      </div>
      <section className="finding-section"><h3>Sensitive Findings</h3>
      <div className="report-summary-grid">
        <div><span>Threat findings</span><strong>{result.report.findings.length}</strong></div>
        <div><span>Sensitive-data indicators</span><strong>{result.report.findings.filter((finding) => ["PERSONAL_DATA", "CREDENTIAL"].includes(finding.category)).length}</strong></div>
        <div><span>AI analysis completion</span><strong>{result.report.aiScope.submittedChunks === 0 ? "Not called" : `${Math.round(result.report.coverage.completedChunks / result.report.aiScope.submittedChunks * 100)}%`}</strong><small>{result.report.coverage.completedChunks} completed · {result.report.coverage.failedChunks} failed of {result.report.aiScope.submittedChunks} submitted chunks</small></div>
        <div><span>Finding-based suggestion · Non-binding</span><strong>{reportSuggestion}</strong><small>Not a policy decision. Authoritative backend result: {policyLabel}</small></div>
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((severity) => <div key={severity}><span>{severity} findings</span><strong>{result.report.findings.filter((finding) => finding.severity === severity).length}</strong></div>)}
      </div>
      <article className="report-detail-card recommendations"><h3>Recommended Actions</h3>{prioritizedRecommendations.length ? <ol>{prioritizedRecommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}</ol> : <p>No finding-specific remediation was generated; review the document before sharing.</p>}</article>
      {(hasInstructionRisk || hasSensitiveRisk) && <aside className="threat-correlation"><strong>Why this may be risky</strong><p>{hasInstructionRisk && hasSensitiveRisk
        ? "Instruction-like content and sensitive-data indicators co-occur in this document. Together they can increase the risk of unauthorized disclosure; this correlation is a heuristic, not proof of intent."
        : hasInstructionRisk
          ? "Instruction-like content may attempt to influence an agent's task or tool use. Treat document contents as untrusted input."
          : "Sensitive-data indicators were found. Verify authorization and destination before sharing; credentials should be rotated if they were exposed."}</p></aside>}
      {result.analysis.aiFailure && <ErrorBanner>{aiFailureLabel(result.analysis.aiFailure.code)}. Deterministic inspection completed; AI output is advisory only.</ErrorBanner>}
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
        <div><span className={`risk-pill risk-${finding.severity.toLowerCase()}`}>{finding.severity}</span><strong>{finding.type.replaceAll("_", " ")}</strong><span className="finding-source">{finding.category.replaceAll("_", " ")} · {finding.source}</span></div>
        <p>{finding.explanation}</p><p className="muted">{finding.recommendation}</p>
        <details><summary>Evidence &amp; Locations</summary><p><code>{finding.evidence}</code></p><small>Confidence {(finding.confidence * 100).toFixed(0)}%{finding.ruleId ? ` · Rule ${finding.ruleId}` : ""}</small></details>
        {finding.evidenceReferences.length > 0 && <small>Threat timeline: {finding.evidenceReferences.map((reference) => [reference.page !== null ? `page ${reference.page}` : null, reference.line ? `line ${reference.line}` : null, reference.chunk !== null ? `chunk ${reference.chunk}` : null].filter(Boolean).join(", ")).join("; ")}</small>}
      </article>)}</div>}
      </section>
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

function Audit({ events, eventsLoaded, error }: { events: AuditEvent[]; eventsLoaded: boolean; error: string }) {
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
      {visible.length === 0 ? <EmptyState title={!eventsLoaded ? "Audit history unavailable." : events.length ? "No events match these filters." : "No events recorded yet."} detail={!eventsLoaded ? "Refresh after confirming the backend is reachable." : events.length ? undefined : "Upload a document or evaluate an action to create activity."} /> : <EventTable events={visible} />}
    </section>
  </>;
}

function Approvals({ onChanged }: { onChanged: () => Promise<void> }) {
  const [tab, setTab] = useState<"pending" | "decided">("pending");
  const [pending, setPending] = useState<Approval[]>([]);
  const [decided, setDecided] = useState<Approval[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [pendingLoaded, setPendingLoaded] = useState(false);
  const [decidedLoaded, setDecidedLoaded] = useState(false);
  const [executionOutcomes, setExecutionOutcomes] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState("");
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    const [pendingResult, decidedResult, eventsResult] = await Promise.allSettled([api.approvals("pending"), api.approvals(), api.events()]);
    if (pendingResult.status === "fulfilled") {
      setPending(pendingResult.value.approvals);
      setPendingLoaded(true);
    }
    if (decidedResult.status === "fulfilled") {
      setDecided(decidedResult.value.approvals.filter((approval) => approval.status !== "PENDING"));
      setDecidedLoaded(true);
    }
    if (eventsResult.status === "fulfilled") setEvents(eventsResult.value.events);
    const failures = [pendingResult, decidedResult, eventsResult].flatMap((result) =>
      result.status === "rejected" ? [errorMessage(result.reason)] : []);
    setError(failures.join(" "));
    setLoading(false);
  }, []);
  useEffect(() => { void load(); }, [load]);
  const decide = async (approval: Approval, decision: "APPROVED" | "REJECTED") => {
    setBusyId(approval.approvalId); setError(""); setSuccess("");
    try {
      const outcome = await api.decide(approval.approvalId, decision, notes[approval.approvalId] ?? "");
      setSuccess(decision === "REJECTED"
        ? "Approval rejected. The backend reports that the operation was not executed."
        : outcome.executed
          ? "Approval recorded. The backend reports the synthetic action was executed."
          : "Approval recorded. The backend reports the action was not executed.");
      setPending((current) => current.filter((item) => item.approvalId !== approval.approvalId));
      setDecided((current) => [outcome.approval, ...current.filter((item) => item.approvalId !== approval.approvalId)]);
      setExecutionOutcomes((current) => ({ ...current, [approval.approvalId]: outcome.executed }));
      setTab("decided");
      await onChanged(); await load();
    } catch (failure) {
      const code = errorCode(failure);
      setSuccess("");
      setError(code === "NOT_FOUND" ? "This approval no longer exists." : code === "ALREADY_DECIDED" ? "This approval was already decided." : code === "AUDIT_UNAVAILABLE" ? "Audit log unavailable. The action was not executed. Try again later." : errorMessage(failure));
      if (code === "NOT_FOUND" || code === "ALREADY_DECIDED") await load();
    } finally { setBusyId(""); }
  };
  const list = tab === "pending" ? pending : decided;
  const listLoaded = tab === "pending" ? pendingLoaded : decidedLoaded;
  return <>
    <div className="page-intro"><div><span className="eyebrow">HUMAN REVIEW</span><h1>Approvals</h1><p>Review sensitive actions before the backend proceeds.</p></div><div className="approval-header-actions"><div className="reviewer-label"><span className="reviewer-avatar">DR</span><span>Demo reviewer<small>Not identity-verified</small></span></div><button className="outline-button" type="button" disabled={loading} onClick={() => void load()}><RefreshCw size={14}/> Refresh queue</button></div></div>
    {error && <ErrorBanner>{error}</ErrorBanner>}
    {success && <div className="approval-success" role="status" aria-live="polite"><Check size={15}/>{success}</div>}
    <section className="card approvals-card"><div className="approval-tabs" role="tablist" aria-label="Approval state"><button role="tab" aria-selected={tab === "pending"} className={tab === "pending" ? "active" : ""} onClick={() => setTab("pending")}>Pending <span>{pendingLoaded ? pending.length : "—"}</span></button><button role="tab" aria-selected={tab === "decided"} className={tab === "decided" ? "active" : ""} onClick={() => setTab("decided")}>Decided <span>{decidedLoaded ? decided.length : "—"}</span></button></div>
      {loading ? <div className="loading-line"><span className="spinner small"/> Loading approvals…</div> : !list.length && !listLoaded ? <div className="loading-line" role="alert">Could not load this approval list. Retry after checking the backend.</div> : !list.length ? <EmptyState title={tab === "pending" ? "No pending approvals." : "No decisions yet."} detail={tab === "pending" ? "Actions that need human review will appear here." : undefined} /> : <div className="approval-list">{list.map((approval) => {
        const outcome = events.find((event) => event.type === "APPROVAL_DECISION" && event.approvalId === approval.approvalId);
        const requestEvent = events.find((event) => event.type === "EVALUATION" && event.approvalId === approval.approvalId);
        return <article className="approval-row" key={approval.approvalId}><div className="approval-main"><div className="approval-tool"><span className="tool-mark"><Workflow size={16}/></span><div><strong>{approval.tool}</strong><code>{approval.resource}</code></div></div><div className="approval-time"><span>Requested</span><strong>{dateTime(approval.createdAt)}</strong><code title={approval.eventId}>Event {approval.eventId}</code></div><div className="approval-time"><span>Approval ID</span><code>{approval.approvalId}</code></div><div className="approval-status">{approval.status === "PENDING" ? <StatusBadge status="PENDING"/> : <StatusBadge status={approval.status}/>}</div></div>
          <div className="approval-context"><p>{requestEvent?.reason ?? "Original policy rationale is not present in the latest 50 audit events."}</p><div><span>Agent <code>{requestEvent?.agentId ?? approval.agentId}</code></span>{requestEvent?.advisory && <span>Advisory risk <strong className={`risk-pill risk-${requestEvent.advisory.riskLevel.toLowerCase()}`}>{requestEvent.advisory.riskLevel}</strong></span>}</div></div>
          {approval.status === "PENDING" ? <div className="approval-actions"><label className="note-field">Reviewer note <span className="field-optional">Optional</span><input maxLength={500} value={notes[approval.approvalId] ?? ""} onChange={(e) => setNotes((current) => ({ ...current, [approval.approvalId]: e.target.value }))} placeholder="Add a note for the audit trail" /></label><div className="action-buttons"><button className="primary-button" disabled={Boolean(busyId)} onClick={() => void decide(approval, "APPROVED")}>{busyId === approval.approvalId ? "Saving…" : "✓ Approve"}</button><button className="outline-button" disabled={Boolean(busyId)} onClick={() => void decide(approval, "REJECTED")}>× Reject</button></div></div> : <div className="decision-summary"><span>Reviewed by <strong>{approval.reviewer ?? "demo-reviewer"}</strong></span><span>{approval.decidedAt ? dateTime(approval.decidedAt) : ""}</span><span>Executed: <strong className={(outcome?.executed ?? executionOutcomes[approval.approvalId]) ? "executed-yes" : "executed-no"}>{(outcome?.executed ?? executionOutcomes[approval.approvalId]) ? "yes" : "no"}</strong></span>{approval.note && <span className="decision-note">“{approval.note}”</span>}</div>}
        </article>;
      })}</div>}
    </section>
  </>;
}
