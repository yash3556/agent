import { deflateRawSync } from "node:zlib";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app.js";
import { MemoryAuditStore } from "../src/config/database.js";
import { executeSyntheticTool } from "../src/services/tool-simulator.js";
import { createDocumentAnalyzer } from "../src/ai/document-analysis.js";

afterEach(() => {
  vi.restoreAllMocks();
});

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

function makeXlsx(text: string, sheetCount = 1): Buffer {
  const sheetElements = Array.from({ length: sheetCount }, (_, index) =>
    `<sheet name="Sheet${index + 1}" sheetId="${index + 1}" r:id="rId${index + 1}"/>`).join("");
  const relationships = Array.from({ length: sheetCount }, (_, index) =>
    `<Relationship Id="rId${index + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${index + 1}.xml"/>`).join("");
  const entries: Record<string, string> = {
    "[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>`,
    "xl/workbook.xml": `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheetElements}</sheets></workbook>`,
    "xl/_rels/workbook.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${relationships}<Relationship Id="rId${sheetCount + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>`,
    "xl/sharedStrings.xml": `<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>${text}</t></si></sst>`,
  };
  for (let index = 1; index <= sheetCount; index += 1) {
    entries[`xl/worksheets/sheet${index}.xml`] =
      `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>`;
  }
  return makeZip(entries);
}

describe("document inspection API", () => {
  it("keeps recognized secrets out of provider requests, reports, audit storage, and logs", async () => {
    const store = new MemoryAuditStore();
    const providerChunks: string[] = [];
    const analyzer = createDocumentAnalyzer({
      async analyzeChunk(chunk) {
        providerChunks.push(JSON.stringify(chunk));
        return [{
          category: "OTHER",
          type: "api_key=sentinel-provider-type",
          severity: "HIGH",
          confidence: 0.8,
          explanation: "Provider echoed api_key=sentinel-provider-explanation.",
          recommendation: "Rotate redis://user:sentinel-provider-password@host.example.test/db",
          evidenceReferences: [{
            page: chunk.lines[0].page,
            line: chunk.lines[0].line,
          }],
        }];
      },
    });
    const logger = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const source = [
      "sentinel-outside-selected-context",
      "Second line outside the finding context.",
      "Ordinary context before a detected line.",
      "Contact sentinel.person@example.test; api_key=sentinel-api-secret-value; mongodb://user:sentinel-db-password@db.example.test/app",
      "Ordinary context after a detected line.",
      "Second context boundary.",
      "-----BEGIN PRIVATE KEY-----",
      "sentinel-private-key-material",
      "-----END PRIVATE KEY-----",
      "sentinel-document-tail",
    ].join("\n");
    const response = await request(createApp(store, { documentAnalyzer: analyzer }))
      .post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from(source), {
        filename: "sentinel-file@example.test.txt",
        contentType: "text/plain",
      });

    expect(response.status).toBe(201);
    expect(response.body.document.originalName).toContain("[REDACTED_EMAIL]");
    expect(response.body.findings.map(({ type }: { type: string }) => type)).toEqual(
      expect.arrayContaining(["EMAIL_ADDRESS", "CREDENTIAL_LIKE", "DATABASE_CONNECTION_STRING"]),
    );
    expect(response.body.findings[0].location).toMatchObject({ page: null, line: 4 });
    expect(response.body.report.findings.some(({ source: findingSource }: { source: string }) =>
      findingSource === "AI",
    )).toBe(true);

    const persistedValues = JSON.stringify({
      response: response.body,
      inspection: await store.getInspection(response.body.inspectionId),
      events: await store.listEvents(50),
      logs: logger.mock.calls,
    });
    const providerPayload = providerChunks.join("");
    for (const sentinel of [
      "sentinel-outside-selected-context",
      "sentinel-document-tail",
      "sentinel.person@example.test",
      "sentinel-api-secret-value",
      "sentinel-db-password",
      "sentinel-private-key-material",
      "sentinel-file@example.test",
      "sentinel-provider-type",
      "sentinel-provider-explanation",
      "sentinel-provider-password",
    ]) {
      expect(providerPayload).not.toContain(sentinel);
      expect(persistedValues).not.toContain(sentinel);
    }
    expect(providerPayload).toContain("[REDACTED_EMAIL]");
    expect(providerPayload).toContain("[REDACTED_CREDENTIAL]");
    expect(providerPayload).toContain("[REDACTED_CONNECTION_STRING]");
    expect(logger).not.toHaveBeenCalled();
    logger.mockRestore();
  });

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
      expect((await store.listEvents(50))[0]).toMatchObject({
        type: "DOCUMENT_INSPECTION",
        tool: "inspect_document",
        decision: "INSPECTED",
        inspectionId: response.body.inspectionId,
        documentName: item.name,
        findingCount: 1,
      });
      const auditResponse = await request(createApp(store)).get("/api/events");
      expect(auditResponse.body.events[0]).toMatchObject({
        type: "DOCUMENT_INSPECTION",
        documentName: item.name,
        decision: "INSPECTED",
      });
      expect(JSON.stringify(response.body)).not.toContain("alice@example.test");
    }
  });

  it("extracts and scans CSV, JSON, Markdown, and XLSX documents", async () => {
    const cases = [
      {
        name: "contacts.csv",
        type: "text/csv",
        data: Buffer.from("name,email\nAlice,alice@example.test"),
        mediaType: "text/csv",
      },
      {
        name: "contacts.json",
        type: "application/json",
        data: Buffer.from('{"email":"alice\\u0040example.test"}'),
        mediaType: "application/json",
      },
      {
        name: "notes.md",
        type: "text/markdown",
        data: Buffer.from("# Contact\n\nalice@example.test"),
        mediaType: "text/markdown",
      },
      {
        name: "contacts.xlsx",
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        data: makeXlsx("alice@example.test"),
        mediaType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      },
    ];

    for (const item of cases) {
      const response = await request(createApp(new MemoryAuditStore()))
        .post("/api/documents/inspect")
        .field("agentId", "demo-agent")
        .attach("file", item.data, { filename: item.name, contentType: item.type });

      expect(response.status, item.name).toBe(201);
      expect(response.body.document.mediaType, item.name).toBe(item.mediaType);
      expect(response.body.findings[0]).toMatchObject({
        type: "EMAIL_ADDRESS",
        evidence: "[REDACTED_EMAIL]",
      });
    }
  });

  it("rejects content that does not match CSV, JSON, Markdown, and XLSX declarations", async () => {
    const cases = [
      {
        name: "broken.csv",
        type: "text/csv",
        data: Buffer.from('name,"unclosed'),
      },
      {
        name: "broken.json",
        type: "application/json",
        data: Buffer.from('{"email":'),
      },
      {
        name: "binary.md",
        type: "text/markdown",
        data: Buffer.from([0xff, 0x00, 0xfe]),
      },
      {
        name: "not-a-workbook.xlsx",
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        data: makeDocx("not a spreadsheet"),
      },
    ];

    for (const item of cases) {
      const response = await request(createApp(new MemoryAuditStore()))
        .post("/api/documents/inspect")
        .field("agentId", "demo-agent")
        .attach("file", item.data, { filename: item.name, contentType: item.type });
      expect(response.status, item.name).toBe(415);
      expect(response.body.error, item.name).toBe("UNSUPPORTED_MEDIA_TYPE");
    }

    const wrongDeclaredType = await request(createApp(new MemoryAuditStore()))
      .post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from('{"ok":true}'), {
        filename: "valid.json",
        contentType: "text/markdown",
      });
    expect(wrongDeclaredType.status).toBe(415);
  });

  it("keeps inspection data sanitized when audit persistence and cleanup fail", async () => {
    class AuditFailureStore extends MemoryAuditStore {
      deletedInspectionId = "";

      override async insertEvent(): Promise<void> {
        throw new Error("audit store unavailable");
      }

      override async deleteInspection(inspectionId: string): Promise<void> {
        this.deletedInspectionId = inspectionId;
        throw new Error("cleanup unavailable");
      }
    }
    const store = new AuditFailureStore();
    const logger = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await request(createApp(store))
      .post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("Contact sentinel.audit@example.test"), {
        filename: "api_key=sentinel-filename-secret.txt",
        contentType: "text/plain",
      });

    expect(response.status).toBe(503);
    expect(response.body.error).toBe("AUDIT_UNAVAILABLE");
    expect(store.deletedInspectionId).toMatch(/^ins_/);
    const orphanedInspection = await store.getInspection(store.deletedInspectionId);
    expect(orphanedInspection?.originalName).toContain("[REDACTED_CREDENTIAL]");
    const visibleFailureData = JSON.stringify({
      response: response.body,
      inspection: orphanedInspection,
      logs: logger.mock.calls,
    });
    expect(visibleFailureData).not.toContain("sentinel.audit@example.test");
    expect(visibleFailureData).not.toContain("sentinel-filename-secret");
    expect(logger.mock.calls).toEqual([["Could not clean up a failed document inspection."]]);
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

    const csvTextTooLarge = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.alloc(1024 * 1024 + 1, 97), {
        filename: "large.csv",
        contentType: "text/csv",
      });
    expect(csvTextTooLarge.status).toBe(422);

    const xlsxTextTooLarge = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", makeXlsx("a".repeat(1024 * 1024 + 1)), {
        filename: "large.xlsx",
        contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      });
    expect(xlsxTextTooLarge.status).toBe(422);

    const tooManySheets = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", makeXlsx("small", 101), {
        filename: "many-sheets.xlsx",
        contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      });
    expect(tooManySheets.status).toBe(422);

    const tooManyParagraphs = await request(app).post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", makeZip({
        "[Content_Types].xml": `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
        "word/document.xml": `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${"<w:p/>".repeat(1001)}</w:body></w:document>`,
      }), {
        filename: "many-paragraphs.docx",
        contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      });
    expect(tooManyParagraphs.status).toBe(422);
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
    expect(response.body.document.originalName).toBe("[REDACTED_EMAIL].txt");
    expect(JSON.stringify(response.body)).not.toContain("alice@example.test");
  });

  it("normalizes hostile filenames and bounds the displayed name", async () => {
    const response = await request(createApp(new MemoryAuditStore()))
      .post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("ordinary document"), {
        filename: "..\\..\\alice@example.test\u202e<>.markdown",
        contentType: "text/markdown",
      });

    expect(response.status).toBe(201);
    const name = response.body.document.originalName as string;
    expect(name).toMatch(/\.md$/);
    expect(name).not.toMatch(/[\\/]/);
    expect(name).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/);
    expect(name).not.toContain("alice@example.test");
    expect(Array.from(name.slice(0, -3)).length).toBeLessThanOrEqual(120);
  });

  it("admits no more than three concurrent document inspections", async () => {
    const delegate = createDocumentAnalyzer();
    let entered = 0;
    let notifyThreeEntered: () => void = () => undefined;
    let releaseAnalyzer: () => void = () => undefined;
    const threeEntered = new Promise<void>((resolve) => {
      notifyThreeEntered = resolve;
    });
    const analyzerGate = new Promise<void>((resolve) => {
      releaseAnalyzer = resolve;
    });
    const analyzer = {
      async analyze(...args: Parameters<typeof delegate.analyze>) {
        entered += 1;
        if (entered === 3) notifyThreeEntered();
        await analyzerGate;
        return delegate.analyze(...args);
      },
    };
    const app = createApp(new MemoryAuditStore(), { documentAnalyzer: analyzer });
    const upload = () => request(app)
      .post("/api/documents/inspect")
      .field("agentId", "demo-agent")
      .attach("file", Buffer.from("Contact alice@example.test"), {
        filename: "contact.txt",
        contentType: "text/plain",
      });
    const admitted = [upload(), upload(), upload()];
    const completed = Promise.all(admitted);
    await threeEntered;

    const rejected = await upload();
    expect(rejected.status).toBe(503);
    expect(rejected.body.error).toBe("INSPECTION_UNAVAILABLE");

    releaseAnalyzer();
    const responses = await completed;
    expect(responses.map((response) => response.status)).toEqual([201, 201, 201]);

    const afterCapacityRelease = await upload();
    expect(afterCapacityRelease.status).toBe(201);
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

  it("keeps AI findings advisory and never weakens deterministic policy decisions", async () => {
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
      .attach("file", Buffer.from("Contact 415-555-0182"), {
        filename: "ordinary.txt",
        contentType: "text/plain",
      });
    expect(cleanInspection.status).toBe(201);
    expect(cleanInspection.body).toMatchObject({
      analysis: { aiAdvisory: "AVAILABLE" },
      report: {
        status: "COMPLETE",
        findings: [
          { source: "DETERMINISTIC", category: "PERSONAL_DATA" },
          { source: "AI", category: "CREDENTIAL" },
        ],
      },
      findings: [{ type: "PHONE_NUMBER" }],
    });

    const aiOnlyExport = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: cleanInspection.body.inspectionId,
      inspectionId: cleanInspection.body.inspectionId,
      destination: "external",
    });
    expect(aiOnlyExport.body).toMatchObject({
      decision: "REQUIRE_APPROVAL",
      ruleId: "R-009",
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
      .not.toContain("415-555-0182");
  });
});
