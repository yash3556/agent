import { DOMParser } from "@xmldom/xmldom";
import * as pdfjs from "pdfjs-dist/legacy/build/pdf.mjs";
import { isMainThread, parentPort, workerData } from "node:worker_threads";
import yauzl, { type Entry, type ZipFile } from "yauzl";
import type { TextSegment } from "./content-scanner.js";

const MAX_EXTRACTED_TEXT_BYTES = 1024 * 1024;
const MAX_DOCX_ENTRIES = 500;
const MAX_DOCX_UNCOMPRESSED_BYTES = 10 * 1024 * 1024;
const MAX_DOCX_XML_BYTES = 2 * 1024 * 1024;
const MAX_PDF_PAGES = 100;
const MAX_XLSX_SHEETS = 100;
const MAX_TEXT_SEGMENTS = 1000;
const WORD_NAMESPACE = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const CONTENT_TYPES_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/content-types";
const SPREADSHEET_NAMESPACE = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const OFFICE_RELATIONSHIPS_NAMESPACE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const PACKAGE_RELATIONSHIPS_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/relationships";

type DocumentFormat = "pdf" | "docx" | "txt" | "csv" | "json" | "markdown" | "xlsx";

class UnsupportedDocumentFormatError extends Error {}

function ensureSegmentLimits(segments: TextSegment[]): TextSegment[] {
  if (
    segments.length > MAX_TEXT_SEGMENTS
    || Buffer.byteLength(segments.map((segment) => segment.text).join("\n")) > MAX_EXTRACTED_TEXT_BYTES
  ) {
    throw new Error("Extracted document text exceeds the supported limit.");
  }
  return segments;
}

function decodeText(buffer: Buffer): string {
  if (buffer.length > MAX_EXTRACTED_TEXT_BYTES) {
    throw new Error("Extracted document text exceeds the supported limit.");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    throw new UnsupportedDocumentFormatError("Text document is not valid UTF-8.");
  }
  if (text.includes("\0") || /[\u0001-\u0008\u000B\u000C\u000E-\u001F]/.test(text)) {
    throw new UnsupportedDocumentFormatError("Text document contains binary control characters.");
  }
  return text;
}

function parseXml(xml: string) {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("XML declarations are not permitted.");
  let parseFailed = false;
  const document = new DOMParser({
    onError: (level) => {
      if (level !== "warning") parseFailed = true;
    },
  }).parseFromString(xml, "application/xml");
  if (parseFailed || document.getElementsByTagName("parsererror").length > 0) {
    throw new Error("Malformed XML.");
  }
  return document;
}

function parseDocx(buffer: Buffer): Promise<TextSegment[]> {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(
      buffer,
      { lazyEntries: true, validateEntrySizes: true, strictFileNames: true },
      (openError, zipFile) => {
        if (openError || !zipFile) {
          reject(new Error("Invalid DOCX ZIP container."));
          return;
        }

        const zip: ZipFile = zipFile;
        let settled = false;
        const fail = (error: Error) => {
          if (settled) return;
          settled = true;
          zip.close();
          reject(error);
        };
        if (zip.entryCount < 2 || zip.entryCount > MAX_DOCX_ENTRIES) {
          fail(new Error("DOCX entry count is outside the supported limit."));
          return;
        }

        let declaredTotal = 0;
        let count = 0;
        let documentXml: Buffer | undefined;
        let contentTypesXml: Buffer | undefined;
        let hasDocument = false;
        zip.on("error", (error: Error) => {
          if (!settled) {
            settled = true;
            reject(new Error("Invalid DOCX ZIP data."));
          }
        });

        zip.on("end", () => {
          if (settled) return;
          settled = true;
          if (!contentTypesXml || !hasDocument || !documentXml) {
            reject(new Error("DOCX is missing required document parts."));
            return;
          }
          try {
            const contentTypes = parseXml(new TextDecoder("utf-8", { fatal: true }).decode(contentTypesXml));
            const mainDocumentType = Array.from(
              contentTypes.getElementsByTagNameNS(CONTENT_TYPES_NAMESPACE, "Override"),
            )
              .find((node) => node.getAttribute("PartName") === "/word/document.xml")
              ?.getAttribute("ContentType");
            if (mainDocumentType !== "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml") {
              reject(new Error("DOCX document content type is unsupported."));
              return;
            }
            const xml = new TextDecoder("utf-8", { fatal: true }).decode(documentXml);
            const document = parseXml(xml);
            if (!document.documentElement || document.documentElement.namespaceURI !== WORD_NAMESPACE) {
              throw new Error("DOCX main document namespace is unsupported.");
            }
            const paragraphs = Array.from(document.getElementsByTagNameNS(WORD_NAMESPACE, "p"));
            if (paragraphs.length > MAX_TEXT_SEGMENTS) {
              throw new Error("DOCX paragraph count is outside the supported limit.");
            }
            const segments = paragraphs.map((paragraph) => ({
              text: Array.from(paragraph.getElementsByTagNameNS(WORD_NAMESPACE, "t"))
                .map((node) => node.textContent ?? "")
                .join(""),
              page: null,
            }));
            resolve(ensureSegmentLimits(segments));
          } catch {
            reject(new Error("DOCX document XML could not be parsed safely."));
          }
        });

        const nextEntry = (entry: Entry) => {
          count += 1;
          declaredTotal += entry.uncompressedSize;
          if (
            count > MAX_DOCX_ENTRIES
            || declaredTotal > MAX_DOCX_UNCOMPRESSED_BYTES
            || entry.isEncrypted()
            || !entry.canDecodeFileData()
            || entry.compressedSize === 0 && entry.uncompressedSize > 0
            || entry.compressedSize > 0 && entry.uncompressedSize / entry.compressedSize > 200
            || entry.fileName.startsWith("/")
            || entry.fileName.split(/[\\/]/).includes("..")
          ) {
            fail(new Error("DOCX contains unsupported or unsafe ZIP entries."));
            return;
          }

          const name = entry.fileName.replace(/\\/g, "/");
          const isDocumentXml = name === "word/document.xml";
          const isContentTypesXml = name === "[Content_Types].xml";
          if (isDocumentXml) hasDocument = true;
          if ((isDocumentXml || isContentTypesXml) && entry.uncompressedSize > MAX_DOCX_XML_BYTES) {
            fail(new Error("DOCX XML exceeds the supported limit."));
            return;
          }
          if (name.toLowerCase().endsWith("vbaproject.bin") || name.startsWith("word/embeddings/")) {
            fail(new Error("Macro-enabled or embedded DOCX content is unsupported."));
            return;
          }

          zip.openReadStream(entry, (streamError, stream) => {
            if (streamError || !stream) {
              fail(new Error("DOCX ZIP entry could not be read."));
              return;
            }
            const chunks: Buffer[] = [];
            let entryBytes = 0;
            stream.on("data", (chunk: Buffer) => {
              entryBytes += chunk.length;
              if (
                entryBytes > entry.uncompressedSize
                || entryBytes > (isDocumentXml || isContentTypesXml
                  ? MAX_DOCX_XML_BYTES
                  : MAX_DOCX_UNCOMPRESSED_BYTES)
              ) {
                const error = new Error("DOCX expanded content exceeds the supported limit.");
                fail(error);
                stream.destroy(error);
                return;
              }
              if (isDocumentXml || isContentTypesXml) chunks.push(chunk);
            });
            stream.on("error", () => fail(new Error("DOCX ZIP entry could not be decompressed.")));
            stream.on("end", () => {
              if (settled) return;
              if (entryBytes !== entry.uncompressedSize) {
                fail(new Error("DOCX ZIP entry size did not match its declared size."));
                return;
              }
              if (isDocumentXml) documentXml = Buffer.concat(chunks);
              if (isContentTypesXml) contentTypesXml = Buffer.concat(chunks);
              zip.readEntry();
            });
          });
        };

        zip.on("entry", nextEntry);
        zip.readEntry();
      },
    );
  });
}

async function parsePdf(buffer: Buffer): Promise<TextSegment[]> {
  if (buffer.length < 8 || buffer.subarray(0, 5).toString("ascii") !== "%PDF-") {
    throw new Error("PDF signature is invalid.");
  }
  const loadingTask = pdfjs.getDocument({
    data: new Uint8Array(buffer),
    useSystemFonts: false,
    stopAtErrors: true,
    maxImageSize: 0,
  });
  try {
    const document = await loadingTask.promise;
    if (document.numPages < 1 || document.numPages > MAX_PDF_PAGES) {
      throw new Error("PDF page count is outside the supported limit.");
    }
    const segments: TextSegment[] = [];
    let extractedBytes = 0;
    for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
      const page = await document.getPage(pageNumber);
      const content = await page.getTextContent();
      const text = content.items
        .filter((item) => "str" in item)
        .map((item) => "str" in item ? item.str : "")
        .join(" ");
      extractedBytes += Buffer.byteLength(text);
      if (extractedBytes > MAX_EXTRACTED_TEXT_BYTES) {
        throw new Error("Extracted document text exceeds the supported limit.");
      }
      segments.push({ text, page: pageNumber });
      page.cleanup();
    }
    return ensureSegmentLimits(segments);
  } finally {
    await loadingTask.destroy();
  }
}

function validateCsv(text: string): void {
  let inQuotedField = false;
  let afterQuotedField = false;
  let atFieldStart = true;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (inQuotedField) {
      if (character === '"') {
        if (text[index + 1] === '"') {
          index += 1;
        } else {
          inQuotedField = false;
          afterQuotedField = true;
        }
      }
      continue;
    }
    if (afterQuotedField) {
      if (character === ",") {
        afterQuotedField = false;
        atFieldStart = true;
      } else if (character === "\r" || character === "\n") {
        afterQuotedField = false;
        atFieldStart = true;
      } else {
        throw new UnsupportedDocumentFormatError("CSV quoting is invalid.");
      }
      continue;
    }
    if (character === "," || character === "\r" || character === "\n") {
      atFieldStart = true;
    } else if (character === '"') {
      if (!atFieldStart) throw new UnsupportedDocumentFormatError("CSV quoting is invalid.");
      inQuotedField = true;
      atFieldStart = false;
    } else {
      atFieldStart = false;
    }
  }
  if (inQuotedField) throw new UnsupportedDocumentFormatError("CSV quoting is invalid.");
}

async function parseTextFormat(format: "txt" | "csv" | "json" | "markdown", buffer: Buffer): Promise<TextSegment[]> {
  const text = decodeText(buffer);
  if (format === "csv") validateCsv(text);
  if (format === "json") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new UnsupportedDocumentFormatError("JSON syntax is invalid.");
    }
    const extracted = JSON.stringify(parsed);
    if (typeof extracted !== "string") throw new Error("JSON content could not be extracted.");
    return ensureSegmentLimits([{ text: extracted, page: null }]);
  }
  return ensureSegmentLimits([{ text, page: null }]);
}

function safeWorkbookTarget(target: string): string | undefined {
  if (
    target.startsWith("/")
    || target.includes("\\")
    || target.split("/").some((part) => part === ".." || part === "")
  ) return undefined;
  const resolved = `xl/${target}`;
  return resolved.startsWith("xl/worksheets/") && resolved.endsWith(".xml")
    ? resolved
    : undefined;
}

function parseSharedStrings(buffer: Buffer | undefined): string[] {
  if (!buffer) return [];
  const document = parseXml(new TextDecoder("utf-8", { fatal: true }).decode(buffer));
  if (document.documentElement?.namespaceURI !== SPREADSHEET_NAMESPACE) {
    throw new Error("XLSX shared strings namespace is unsupported.");
  }
  return Array.from(document.getElementsByTagNameNS(SPREADSHEET_NAMESPACE, "si"))
    .map((item) => Array.from(item.getElementsByTagNameNS(SPREADSHEET_NAMESPACE, "t"))
      .map((node) => node.textContent ?? "")
      .join(""));
}

function parseWorksheet(buffer: Buffer, sharedStrings: string[]): string {
  const document = parseXml(new TextDecoder("utf-8", { fatal: true }).decode(buffer));
  if (document.documentElement?.namespaceURI !== SPREADSHEET_NAMESPACE) {
    throw new Error("XLSX worksheet namespace is unsupported.");
  }
  const rows = Array.from(document.getElementsByTagNameNS(SPREADSHEET_NAMESPACE, "row"));
  return rows.map((row) => Array.from(row.getElementsByTagNameNS(SPREADSHEET_NAMESPACE, "c"))
    .map((cell) => {
      const type = cell.getAttribute("t");
      if (type === "inlineStr") {
        const inline = cell.getElementsByTagNameNS(SPREADSHEET_NAMESPACE, "is").item(0);
        return inline
          ? Array.from(inline.getElementsByTagNameNS(SPREADSHEET_NAMESPACE, "t"))
            .map((node) => node.textContent ?? "")
            .join("")
          : "";
      }
      const value = cell.getElementsByTagNameNS(SPREADSHEET_NAMESPACE, "v").item(0)?.textContent ?? "";
      if (type === "s") {
        const index = Number(value);
        if (!Number.isInteger(index) || index < 0 || index >= sharedStrings.length) {
          throw new Error("XLSX shared string reference is invalid.");
        }
        return sharedStrings[index];
      }
      return value;
    })
    .join("\t"))
    .join("\n");
}

function parseXlsx(buffer: Buffer): Promise<TextSegment[]> {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(
      buffer,
      { lazyEntries: true, validateEntrySizes: true, strictFileNames: true },
      (openError, zipFile) => {
        if (openError || !zipFile) {
          reject(new Error("Invalid XLSX ZIP container."));
          return;
        }

        const zip = zipFile;
        let settled = false;
        let declaredTotal = 0;
        let count = 0;
        const parts = new Map<string, Buffer>();
        const fail = (error: Error) => {
          if (settled) return;
          settled = true;
          zip.close();
          reject(error);
        };
        zip.on("error", (error: Error) => fail(error));
        zip.on("entry", (entry: Entry) => {
          count += 1;
          declaredTotal += entry.uncompressedSize;
          const name = entry.fileName.replace(/\\/g, "/");
          if (
            count > MAX_DOCX_ENTRIES
            || declaredTotal > MAX_DOCX_UNCOMPRESSED_BYTES
            || entry.isEncrypted()
            || !entry.canDecodeFileData()
            || entry.compressedSize === 0 && entry.uncompressedSize > 0
            || entry.compressedSize > 0 && entry.uncompressedSize / entry.compressedSize > 200
            || name.startsWith("/")
            || name.split("/").includes("..")
            || name.toLowerCase().endsWith("vbaproject.bin")
            || name.startsWith("xl/embeddings/")
          ) {
            fail(new Error("XLSX contains unsupported or unsafe ZIP entries."));
            return;
          }
          const isWorksheet = name.startsWith("xl/worksheets/") && name.endsWith(".xml");
          const isRequiredPart = [
            "[Content_Types].xml",
            "xl/workbook.xml",
            "xl/_rels/workbook.xml.rels",
            "xl/sharedStrings.xml",
          ].includes(name);
          if ((isWorksheet || isRequiredPart) && entry.uncompressedSize > MAX_DOCX_XML_BYTES) {
            fail(new Error("XLSX XML exceeds the supported limit."));
            return;
          }
          const collect = isWorksheet || isRequiredPart;
          zip.openReadStream(entry, (streamError, stream) => {
            if (streamError || !stream) {
              fail(new Error("XLSX ZIP entry could not be read."));
              return;
            }
            const chunks: Buffer[] = [];
            let entryBytes = 0;
            stream.on("data", (chunk: Buffer) => {
              entryBytes += chunk.length;
              if (
                entryBytes > entry.uncompressedSize
                || collect && entryBytes > MAX_DOCX_XML_BYTES
              ) {
                const error = new Error("XLSX expanded content exceeds the supported limit.");
                fail(error);
                stream.destroy(error);
                return;
              }
              if (collect) chunks.push(chunk);
            });
            stream.on("error", (error: Error) => fail(error));
            stream.on("end", () => {
              if (settled) return;
              if (entryBytes !== entry.uncompressedSize) {
                fail(new Error("XLSX ZIP entry size did not match its declared size."));
                return;
              }
              if (collect) parts.set(name, Buffer.concat(chunks));
              zip.readEntry();
            });
          });
        });
        zip.on("end", () => {
          if (settled) return;
          settled = true;
          try {
            const contentTypesBuffer = parts.get("[Content_Types].xml");
            const workbookBuffer = parts.get("xl/workbook.xml");
            const relationshipsBuffer = parts.get("xl/_rels/workbook.xml.rels");
            if (!contentTypesBuffer || !workbookBuffer || !relationshipsBuffer) {
              throw new UnsupportedDocumentFormatError("XLSX package is missing required parts.");
            }
            const contentTypes = parseXml(new TextDecoder("utf-8", { fatal: true }).decode(contentTypesBuffer));
            const workbookType = Array.from(contentTypes.getElementsByTagNameNS(CONTENT_TYPES_NAMESPACE, "Override"))
              .find((node) => node.getAttribute("PartName") === "/xl/workbook.xml")
              ?.getAttribute("ContentType");
            if (workbookType !== "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml") {
              throw new UnsupportedDocumentFormatError("XLSX workbook content type is unsupported.");
            }
            const workbook = parseXml(new TextDecoder("utf-8", { fatal: true }).decode(workbookBuffer));
            if (workbook.documentElement?.namespaceURI !== SPREADSHEET_NAMESPACE) {
              throw new UnsupportedDocumentFormatError("XLSX workbook namespace is unsupported.");
            }
            const relationships = parseXml(new TextDecoder("utf-8", { fatal: true }).decode(relationshipsBuffer));
            if (relationships.documentElement?.namespaceURI !== PACKAGE_RELATIONSHIPS_NAMESPACE) {
              throw new Error("XLSX relationship namespace is unsupported.");
            }
            const relationTargets = new Map<string, { target: string; type: string }>();
            for (const relation of Array.from(
              relationships.getElementsByTagNameNS(PACKAGE_RELATIONSHIPS_NAMESPACE, "Relationship"),
            )) {
              if (relation.getAttribute("TargetMode") === "External") {
                throw new Error("XLSX external relationships are unsupported.");
              }
              const id = relation.getAttribute("Id");
              const target = relation.getAttribute("Target");
              const type = relation.getAttribute("Type");
              if (!id || !target || !type) throw new Error("XLSX relationship is invalid.");
              relationTargets.set(id, { target, type });
            }
            const sheets = Array.from(workbook.getElementsByTagNameNS(SPREADSHEET_NAMESPACE, "sheet"));
            if (sheets.length < 1 || sheets.length > MAX_XLSX_SHEETS) {
              throw new Error("XLSX sheet count is outside the supported limit.");
            }
            const sheetPaths = sheets.map((sheet) => {
              const relationId = sheet.getAttributeNS(OFFICE_RELATIONSHIPS_NAMESPACE, "id");
              const relation = relationId ? relationTargets.get(relationId) : undefined;
              const target = relation && safeWorkbookTarget(relation.target);
              if (!relation?.type.endsWith("/worksheet") || !target || !parts.has(target)) {
                throw new Error("XLSX worksheet reference is invalid.");
              }
              return target;
            });
            const sharedStrings = parseSharedStrings(parts.get("xl/sharedStrings.xml"));
            const segments = sheetPaths.map((sheetPath) => {
              const sheetBuffer = parts.get(sheetPath);
              if (!sheetBuffer) throw new Error("XLSX worksheet part is missing.");
              return { text: parseWorksheet(sheetBuffer, sharedStrings), page: null };
            });
            resolve(ensureSegmentLimits(segments));
          } catch (error) {
            reject(error);
          }
        });
        zip.readEntry();
      },
    );
  });
}

async function parse(format: DocumentFormat, buffer: Buffer): Promise<TextSegment[]> {
  if (format === "pdf") return parsePdf(buffer);
  if (format === "docx") return parseDocx(buffer);
  if (format === "xlsx") return parseXlsx(buffer);
  return parseTextFormat(format, buffer);
}

if (!isMainThread && parentPort) {
  const input = workerData as { format: DocumentFormat; bytes: Uint8Array };
  void parse(input.format, Buffer.from(input.bytes))
    .then((segments) => parentPort?.postMessage({ ok: true, segments }))
    .catch((error: unknown) => parentPort?.postMessage({
      ok: false,
      code: error instanceof UnsupportedDocumentFormatError
        ? "UNSUPPORTED_MEDIA_TYPE"
        : "DOCUMENT_UNREADABLE",
    }));
}
