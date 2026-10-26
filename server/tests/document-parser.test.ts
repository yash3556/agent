import { existsSync } from "node:fs";
import * as pdfjs from "pdfjs-dist/legacy/build/pdf.mjs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { extractDocumentText } from "../src/services/document-parser.js";
import { standardFontDataUrl } from "../src/services/document-parser.worker.js";

afterEach(() => {
  vi.restoreAllMocks();
});

function makePdf(): Buffer {
  const stream = "BT /F1 12 Tf 72 720 Td (Contact alice@example.test) Tj ET";
  return Buffer.from(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>
endobj
4 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>
endobj
5 0 obj
<< /Length ${Buffer.byteLength(stream)} >>
stream
${stream}
endstream
endobj
trailer
<< /Root 1 0 R >>
%%EOF`);
}

describe("PDF standard font configuration", () => {
  it("loads installed standard fonts without warnings and still extracts text", async () => {
    expect(standardFontDataUrl.endsWith("/")).toBe(true);
    expect(existsSync(`${standardFontDataUrl}LiberationSans-Regular.ttf`)).toBe(true);

    const warnings: string[] = [];
    vi.spyOn(console, "warn").mockImplementation((...args) => warnings.push(args.join(" ")));
    const loadingTask = pdfjs.getDocument({
      data: new Uint8Array(makePdf()),
      useSystemFonts: false,
      stopAtErrors: true,
      maxImageSize: 0,
      standardFontDataUrl,
    });

    try {
      const document = await loadingTask.promise;
      const page = await document.getPage(1);
      const content = await page.getTextContent();
      const extractedText = content.items
        .filter((item) => "str" in item)
        .map((item) => "str" in item ? item.str : "")
        .join(" ");

      expect(extractedText).toContain("Contact alice@example.test");
      expect(warnings.some((warning) =>
        warning.includes("Ensure that the `standardFontDataUrl` API parameter is provided."),
      )).toBe(false);
      expect(warnings.some((warning) => warning.includes("Unable to load font data"))).toBe(false);

      const workerSegments = await extractDocumentText("pdf", makePdf());
      expect(workerSegments.map((segment) => segment.text).join(" "))
        .toContain("Contact alice@example.test");
    } finally {
      await loadingTask.destroy();
    }
  });
});
