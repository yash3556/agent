import { deflateRawSync } from "node:zlib";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app.js";
import { MemoryAuditStore } from "../src/config/database.js";
import { executeSyntheticTool } from "../src/services/tool-simulator.js";
import { createDocumentAnalyzer } from "../src/ai/document-analysis.js";

function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function makeZip(entries: Record<string, string>): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  for (const [name, value] of Object.entries(entries)) {
    const nameBytes = Buffer.from(name);
    const content = Buffer.from(value);
    const compressed = deflateRawSync(content);
    const checksum = crc32(content);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    localParts.push(local, nameBytes, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, nameBytes);
    offset += local.length + nameBytes.length + compressed.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(entries).length, 8);
  end.writeUInt16LE(Object.keys(entries).length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...localParts, centralDirectory, end]);
}

function makeDocx(text: string): Buffer {
  return makeZip({
    "[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
    "word/document.xml": `<?xml version="1.0"?><x:document xmlns:x="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><x:body><x:p><x:r><x:t>${text}</x:t></x:r></x:p></x:body></x:document>`,
  });
}

describe("document inspection API", () => {
  it("extracts and scans TXT, PDF, and DOCX content without returning raw sensitive values", async () => {
    const cases = [
      {
        name: "sample.txt",
        type: "text/plain",
        data: Buffer.from("Contact alice@example.test"),
      },
      {
        name: "sample.docx",
        type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        data: makeDocx("Contact alice@example.test"),
      },
      {
        name: "sample.pdf",
        type: "application/pdf",
        data: Buffer.from("%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n5 0 obj\n<< /Length 54 >>\nstream\nBT /F1 12 Tf 72 720 Td (Contact alice@example.test) Tj ET\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"),
      },
    ];

    for (const item of cases) {
      const store = new MemoryAuditStore();
      const response = await request(createApp(store))
        .post("/api/documents/inspect")
        .field("agentId", "demo-agent")
        .attach("file", item.data, { filename: item.name, contentType: item.type });

      expect(response.status, item.name).toBe(201);
      expect(response.body).toMatchObject({
        status: "COMPLETED",
        analysis: { deterministic: "COMPLETED", aiAdvisory: "DISABLED" },
        summary: { totalFindings: 1 },
        findings: [{ category: "PERSONAL_DATA", evidence: "[REDACTED_EMAIL]" }],
      });
      expect(JSON.stringify(response.body)).not.toContain("alice@example.test");
    }
  });

  it("rejects empty, mismatched, malformed, macro-enabled, and unsupported files", async () => {
    const app = createApp(new MemoryAuditStore());
    const empty = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.alloc(0), { filename: "empty.txt", contentType: "text/plain" });
    expect(empty.status).toBe(422);

    const mismatch = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("not a pdf"), { filename: "fake.pdf", contentType: "application/pdf" });
    expect(mismatch.status).toBe(415);

    const malformed = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("%PDF-not-valid"), { filename: "broken.pdf", contentType: "application/pdf" });
    expect(malformed.status).toBe(422);

    const macroDocx = makeZip({
      "[Content_Types].xml": `<?xml version="1.0"?><Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
      "word/document.xml": `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>`,
      "word/vbaProject.bin": "macro",
    });
    const macro = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", macroDocx, {
        filename: "macro.docx",
        contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      });
    expect(macro.status).toBe(422);

    const unsupported = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("data"), { filename: "file.bin", contentType: "application/octet-stream" });
    expect(unsupported.status).toBe(415);

    const malformedDocx = makeZip({
      "[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
      "word/document.xml": `<x:document xmlns:x="http://www.w3.org/2006"><x:body></x:document>`,
    });
    const malformedXml = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", malformedDocx, {
        filename: "malformed.docx",
        contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      });
    expect(malformedXml.status).toBe(422);

    const entityDocx = makeZip({
      "[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
      "word/document.xml": `<!DOCTYPE x:document [<!ENTITY xxe SYSTEM "file:///unavailable">]><x:document xmlns:x="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><x:body><x:p><x:r><x:t>&xxe;</x:t></x:r></x:p></x:body></x:document>`,
    });
    const entity = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", entityDocx, {
        filename: "entity.docx",
        contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      });
    expect(entity.status).toBe(422);
  });

  it("enforces upload and extracted-text size limits", async () => {
    const app = createApp(new MemoryAuditStore());
    const uploadTooLarge = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.alloc(5 * 1024 * 1024 + 1, 97), {
        filename: "large.txt",
        contentType: "text/plain",
      });
    expect(uploadTooLarge.status).toBe(413);

    const textTooLarge = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.alloc(1024 * 1024 + 1, 97), {
        filename: "large-text.txt",
        contentType: "text/plain",
      });
    expect(textTooLarge.status).toBe(422);
  });

  it("redacts sensitive values from uploaded filenames", async () => {
    const response = await request(createApp(new MemoryAuditStore()))
      .post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("ordinary document"), {
        filename: "alice@example.test.txt",
        contentType: "text/plain",
      });

    expect(response.status).toBe(201);
    expect(response.body.document.originalName).toBe("[REDACTED].txt");
    expect(JSON.stringify(response.body)).not.toContain("alice@example.test");
  });

  it("enforces ownership and policy findings before any execution", async () => {
    const store = new MemoryAuditStore();
    const executeTool = vi.fn(executeSyntheticTool);
    const app = createApp(store, { executeTool });
    const inspected = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("Contact alice@example.test"), {
        filename: "contact.txt",
        contentType: "text/plain",
      });
    const inspectionId = inspected.body.inspectionId as string;

    const wrongOwner = await request(app).post("/api/evaluate").send({
      agentId: "other-agent",
      tool: "analyze_document",
      resource: inspectionId,
      inspectionId,
      destination: "local",
    });
    expect(wrongOwner.body).toMatchObject({ decision: "BLOCK", ruleId: "R-005", executed: false });
    expect(executeTool).not.toHaveBeenCalled();

    const localAnalysis = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "analyze_document",
      resource: inspectionId,
      inspectionId,
      destination: "local",
    });
    expect(localAnalysis.body).toMatchObject({ decision: "ALLOW", ruleId: "R-006", executed: true });

    const exportRequest = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: inspectionId,
      inspectionId,
      destination: "external",
    });
    expect(exportRequest.body).toMatchObject({ decision: "REQUIRE_APPROVAL", ruleId: "R-009", executed: false });
    expect(executeTool).toHaveBeenCalledTimes(1);

    const approvalId = exportRequest.body.approvalId as string;
    const approved = await request(app).post(`/api/approvals/${approvalId}/decision`).send({
      decision: "APPROVED",
      reviewer: "demo-reviewer",
    });
    expect(approved.status).toBe(200);
    expect(approved.body.executed).toBe(true);
    expect(executeTool).toHaveBeenCalledTimes(2);
  });

  it("blocks credential exports and rejects expired-inspection approvals without execution", async () => {
    const store = new MemoryAuditStore();
    const executeTool = vi.fn(executeSyntheticTool);
    const app = createApp(store, { executeTool });
    const inspected = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("api_key=sample-secret-value"), {
        filename: "credential.txt",
        contentType: "text/plain",
      });
    expect(inspected.body.findings[0]).toMatchObject({ category: "CREDENTIAL" });

    const blocked = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: inspected.body.inspectionId,
      inspectionId: inspected.body.inspectionId,
      destination: "external",
    });
    expect(blocked.body).toMatchObject({ decision: "BLOCK", ruleId: "R-007", executed: false });

    const personal = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("alice@example.test"), {
        filename: "personal.txt",
        contentType: "text/plain",
      });
    const pending = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: personal.body.inspectionId,
      inspectionId: personal.body.inspectionId,
      destination: "external",
    });
    await store.saveInspection({
      inspectionId: personal.body.inspectionId,
      agentId: "demo-agent",
      status: "COMPLETED",
      originalName: "expired.txt",
      mediaType: "text/plain",
      sizeBytes: 1,
      sha256: "0".repeat(64),
      findings: [],
      summary: { totalFindings: 0, truncated: false, bySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 } },
      createdAt: new Date(0).toISOString(),
      expiresAt: new Date(0),
    });
    const rejected = await request(app).post(`/api/approvals/${pending.body.approvalId}/decision`).send({
      decision: "APPROVED",
      reviewer: "demo-reviewer",
    });
    expect(rejected.status).toBe(409);
    expect(rejected.body.error).toBe("INSPECTION_UNAVAILABLE");
    expect(executeTool).not.toHaveBeenCalled();
  });

  it("blocks external export when the finding report is truncated", async () => {
    const store = new MemoryAuditStore();
    const executeTool = vi.fn(executeSyntheticTool);
    const app = createApp(store, { executeTool });
    const content = Array.from({ length: 150 }, (_, index) => `person${index}@example.test`).join("\n");
    const inspected = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from(content), { filename: "many-findings.txt", contentType: "text/plain" });
    expect(inspected.status).toBe(201);
    expect(inspected.body.findings).toHaveLength(100);
    expect(inspected.body.summary).toMatchObject({ totalFindings: 150, truncated: true });

    const response = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: inspected.body.inspectionId,
      inspectionId: inspected.body.inspectionId,
      destination: "external",
    });
    expect(response.body).toMatchObject({ decision: "BLOCK", ruleId: "R-010", executed: false });
    expect(executeTool).not.toHaveBeenCalled();
  });

  it("keeps AI findings advisory and never weakens deterministic policy blocks", async () => {
    const store = new MemoryAuditStore();
    const executeTool = vi.fn(executeSyntheticTool);
    const documentAnalyzer = createDocumentAnalyzer({
      async analyzeChunk(chunk) {
        return [{
          category: "CREDENTIAL",
          type: "AI_CREDENTIAL_RISK",
          severity: "CRITICAL",
          confidence: 0.99,
          explanation: "The excerpt may contain a credential.",
          recommendation: "Review and rotate affected credentials.",
          evidenceReferences: [{ page: null, line: 1 }],
        }];
      },
    });
    const app = createApp(store, { executeTool, documentAnalyzer });

    const cleanInspection = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("ordinary content"), {
        filename: "ordinary.txt",
        contentType: "text/plain",
      });
    expect(cleanInspection.status).toBe(201);
    expect(cleanInspection.body).toMatchObject({
      analysis: { aiAdvisory: "AVAILABLE" },
      report: { status: "COMPLETE", findings: [{ source: "AI", category: "CREDENTIAL" }] },
      findings: [],
    });

    const aiOnlyExport = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: cleanInspection.body.inspectionId,
      inspectionId: cleanInspection.body.inspectionId,
      destination: "external",
    });
    expect(aiOnlyExport.body).toMatchObject({
      decision: "BLOCK",
      ruleId: "R-999",
      executed: false,
    });

    const credentialInspection = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("api_key=sample-secret-value"), {
        filename: "credential.txt",
        contentType: "text/plain",
      });
    const deterministicBlock = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: credentialInspection.body.inspectionId,
      inspectionId: credentialInspection.body.inspectionId,
      destination: "external",
    });
    expect(deterministicBlock.body).toMatchObject({
      decision: "BLOCK",
      ruleId: "R-007",
      executed: false,
    });
    expect(executeTool).not.toHaveBeenCalled();
    expect(JSON.stringify(await store.getInspection(cleanInspection.body.inspectionId)))
      .not.toContain("ordinary content");
  });
});
