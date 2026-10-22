import { DOMParser } from "@xmldom/xmldom";
import * as pdfjs from "pdfjs-dist/legacy/build/pdf.mjs";
import { isMainThread, parentPort, workerData } from "node:worker_threads";
import yauzl, { type Entry, type ZipFile } from "yauzl";
import type { TextSegment } from "./content-scanner.js";

const MAX_TEXT_BYTES = 1024 * 1024;
const MAX_DOCX_ENTRIES = 500;
const MAX_DOCX_UNCOMPRESSED_BYTES = 10 * 1024 * 1024;
const MAX_DOCX_XML_BYTES = 2 * 1024 * 1024;
const MAX_PDF_PAGES = 100;
const WORD_NAMESPACE = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const CONTENT_TYPES_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/content-types";

type DocumentFormat = "pdf" | "docx" | "txt";

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
            const segments = paragraphs.map((paragraph) => ({
              text: Array.from(paragraph.getElementsByTagNameNS(WORD_NAMESPACE, "t"))
                .map((node) => node.textContent ?? "")
                .join(""),
              page: null,
            }));
            const totalTextBytes = Buffer.byteLength(segments.map((segment) => segment.text).join("\n"));
            if (totalTextBytes > MAX_TEXT_BYTES) {
              reject(new Error("Extracted document text exceeds the supported limit."));
              return;
            }
            resolve(segments);
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
                fail(new Error("DOCX expanded content exceeds the supported limit."));
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
      if (extractedBytes > MAX_TEXT_BYTES) {
        throw new Error("Extracted document text exceeds the supported limit.");
      }
      segments.push({ text, page: pageNumber });
      page.cleanup();
    }
    return segments;
  } finally {
    await loadingTask.destroy();
  }
}

async function parseTxt(buffer: Buffer): Promise<TextSegment[]> {
  if (buffer.length > MAX_TEXT_BYTES) {
    throw new Error("Extracted document text exceeds the supported limit.");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  if (text.includes("\0") || /[\u0001-\u0008\u000B\u000C\u000E-\u001F]/.test(text)) {
    throw new Error("TXT contains unsupported binary control characters.");
  }
  return [{ text, page: null }];
}

async function parse(format: DocumentFormat, buffer: Buffer): Promise<TextSegment[]> {
  if (format === "pdf") return parsePdf(buffer);
  if (format === "docx") return parseDocx(buffer);
  return parseTxt(buffer);
}

if (!isMainThread && parentPort) {
  const input = workerData as { format: DocumentFormat; bytes: Uint8Array };
  void parse(input.format, Buffer.from(input.bytes))
    .then((segments) => parentPort?.postMessage({ ok: true, segments }))
    .catch(() => parentPort?.postMessage({ ok: false, error: "DOCUMENT_UNREADABLE" }));
}
