import { useState, type FormEvent } from "react";
import { FileSearch, Upload } from "lucide-react";
import { api, errorCode, errorMessage } from "../lib/api";
import type { DocumentInspectionResponse, DocumentReportFinding, InspectionFinding } from "../types";
import "./DocumentInspection.css";

const MAX_DOCUMENT_BYTES = 5 * 1024 * 1024;

function formatSize(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

function DocumentFinding({ finding }: { finding: DocumentReportFinding }) {
  return <article className="document-finding">
    <div className="document-finding-heading">
      <div><span className="eyebrow">{finding.source} · {finding.category} · {finding.type}</span><h3>{finding.explanation}</h3></div>
      <span className={`risk-pill risk-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
    </div>
    <p><strong>Recommendation:</strong> {finding.recommendation}</p>
    <div className="document-references"><strong>Evidence references:</strong> {finding.evidenceReferences.length
      ? finding.evidenceReferences.map((reference, index) => <span key={`${finding.id}-${index}`}>
        {reference.page === null ? "Page unavailable" : `Page ${reference.page}`}
        {reference.line ? `, line ${reference.line}` : ""}
        {reference.chunk === null ? "" : `, chunk ${reference.chunk}`}
      </span>)
      : <span>None provided</span>}</div>
  </article>;
}

function LegacyFinding({ finding }: { finding: InspectionFinding }) {
  return <article className="document-finding">
    <div className="document-finding-heading">
      <div><span className="eyebrow">DETERMINISTIC · {finding.category} · {finding.type}</span><h3>{finding.description}</h3></div>
      <span className={`risk-pill risk-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
    </div>
    <p><strong>Evidence:</strong> <code>{finding.evidence}</code></p>
    <div className="document-references"><strong>Location:</strong>
      <span>{finding.location.page === null ? "Page unavailable" : `Page ${finding.location.page}`}
        {finding.location.line === null ? "" : `, line ${finding.location.line}`}</span>
    </div>
  </article>;
}

function InspectionResult({ result }: { result: DocumentInspectionResponse }) {
  const report = result.report;
  return <div className="inspection-results">
    <section className="card inspection-result-card">
      <div className="section-heading"><div><span className="eyebrow">INSPECTION RESULT</span><h2>{result.document.originalName}</h2></div>
        {report && <span className={`report-status report-${report.status.toLowerCase()}`}>{report.status.replaceAll("_", " ")}</span>}
      </div>
      <p>{report?.summary ?? `Inspection completed with ${result.summary.totalFindings} deterministic finding(s).`}</p>
      <div className="inspection-meta">
        <span>Size: {formatSize(result.document.sizeBytes)}</span>
        <span>Deterministic findings: {result.summary.totalFindings}{result.summary.truncated ? " or more (truncated)" : ""}</span>
        <span>By severity: {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((severity) => `${severity} ${result.summary.bySeverity[severity]}`).join(" · ")}</span>
        <span>AI advisory: {result.analysis.aiAdvisory}</span>
      </div>
      {report && <div className="coverage-grid" aria-label="Inspection coverage">
        <div><span>Extraction</span><strong>{report.coverage.extraction}</strong></div>
        <div><span>Deterministic scan</span><strong>{report.coverage.deterministic}</strong></div>
        <div><span>AI analysis</span><strong>{report.coverage.ai}</strong></div>
        <div><span>Chunks</span><strong>{report.coverage.completedChunks} / {report.coverage.totalChunks} completed</strong></div>
        <div><span>Failed chunks</span><strong>{report.coverage.failedChunks}</strong></div>
      </div>}
      {report && report.status === "PARTIAL" && <p className="coverage-warning">This is a partial report; some analysis chunks or findings may be incomplete. Do not treat it as a complete AI scan.</p>}
      {report && report.status === "DETERMINISTIC_ONLY" && <p className="coverage-warning">This is a deterministic-only report; no complete AI scan was performed.</p>}
      {!report && <p className="muted legacy-report-note">This response has no additive report; showing the legacy deterministic findings and summary.</p>}
    </section>

    {report && <section className="card inspection-findings">
      <div className="section-heading"><div><span className="eyebrow">SECURITY REPORT</span><h2>Report findings</h2></div><span className="count-note">{report.findings.length} findings</span></div>
      {report.findings.length
        ? <div className="document-finding-list">{report.findings.map((finding) => <DocumentFinding key={finding.id} finding={finding}/>)}</div>
        : <p className="muted">No report findings.</p>}
      {report.truncated && <p className="coverage-warning">The report finding limit was reached; this report may omit findings.</p>}
    </section>}

    <section className="card inspection-findings">
      <div className="section-heading"><div><span className="eyebrow">DETERMINISTIC SCAN</span><h2>Deterministic findings</h2></div><span className="count-note">{result.findings.length}{result.summary.truncated ? "+" : ""} findings</span></div>
      {result.findings.length
        ? <div className="document-finding-list">{result.findings.map((finding) => <LegacyFinding key={finding.id} finding={finding}/>)}</div>
        : <p className="muted">No deterministic findings.</p>}
    </section>
  </div>;
}

export function DocumentInspection() {
  const [agentId, setAgentId] = useState("demo-agent");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<DocumentInspectionResponse | null>(null);
  const [error, setError] = useState("");
  const [errorCodeValue, setErrorCodeValue] = useState("");
  const [busy, setBusy] = useState(false);

  const inspect = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    setErrorCodeValue("");
    setResult(null);
    if (!file) {
      setError("Choose a PDF, DOCX, or UTF-8 TXT file to inspect.");
      return;
    }
    if (file.size > MAX_DOCUMENT_BYTES) {
      setError("The selected file exceeds the 5 MiB limit.");
      return;
    }
    if (!agentId.trim()) {
      setError("Enter an agent label.");
      return;
    }

    setBusy(true);
    try {
      setResult(await api.inspectDocument(file, agentId.trim()));
    } catch (failure) {
      setError(errorMessage(failure));
      setErrorCodeValue(errorCode(failure) ?? "");
    } finally {
      setBusy(false);
    }
  };

  return <>
    <div className="page-intro"><div><span className="eyebrow">DOCUMENT SECURITY</span><h1>Document inspection</h1><p>Upload a document to review deterministic findings and AI-assisted analysis coverage.</p></div><div className="intro-mark" aria-hidden="true"><FileSearch size={22}/></div></div>
    {error && <div className="error-banner" role="alert"><span>{error}{errorCodeValue && <> <code>({errorCodeValue})</code></>}</span></div>}
    <form className="card request-form inspection-form" onSubmit={(event) => void inspect(event)}>
      <div className="section-heading"><div><span className="eyebrow">UPLOAD A DOCUMENT</span><h2>Inspect a file</h2></div><span className="count-note">PDF, DOCX, or TXT · max 5 MiB</span></div>
      <label>Agent label
        <input value={agentId} onChange={(event) => setAgentId(event.target.value)} maxLength={128} autoComplete="off"/>
        <span className="field-optional">Demo label only; it is not an authenticated identity.</span>
      </label>
      <label>Document
        <input type="file" accept=".pdf,.docx,.txt,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain" onChange={(event) => { setFile(event.currentTarget.files?.[0] ?? null); setResult(null); setError(""); setErrorCodeValue(""); }}/>
      </label>
      {file && <p className="selected-file"><strong>{file.name}</strong> · {formatSize(file.size)}</p>}
      <p className="muted inspection-privacy-note">Provider configuration stays on the server. This page does not collect or send API keys.</p>
      <button className="primary-button evaluate-button" type="submit" disabled={busy}>{busy ? "Inspecting…" : <><Upload size={15}/> Inspect document</>}</button>
    </form>
    {result && <InspectionResult result={result}/>}
  </>;
}
