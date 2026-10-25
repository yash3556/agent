import type { FindingCategory, FindingSeverity } from "../../types.js";
export interface DetectorMatch {
  category?: FindingCategory;
  type: string;
  severity: FindingSeverity;
  confidence: number;
  ruleId: string;
  maskedSample: string;
  description: string;
  start: number;
  end: number;
}
// Flattened standard Verhoeff multiplication and position tables.
const verhoeffD = "0123456789123406789523401789563401289567401239567859876043216598710432765982104387659321049876543210";
const verhoeffP = "01234567891576283094580379614289160435279453126870428657390127938064157046913258";
function isValidAadhaar(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 12 || /^0+$/.test(digits)) return false;
  let checksum = 0;
  for (let index = 0; index < digits.length; index += 1) {
    checksum = Number(verhoeffD[checksum * 10 + Number(verhoeffP[(index % 8) * 10 + Number(digits[digits.length - 1 - index])])]);
  }
  return checksum === 0;
}
function isValidDate(value: string): boolean {
  const normalized = value.trim();
  const isoMatch = normalized.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (isoMatch) {
    const year = Number(isoMatch[1]);
    const month = Number(isoMatch[2]);
    const day = Number(isoMatch[3]);
    if (year < 1900 || year > 2100 || month < 1 || month > 12 || day < 1 || day > 31) return false;
    return true;
  }
  const slashMatch = normalized.match(/^(\d{1,2})[\/](\d{1,2})[\/](\d{2,4})$/);
  if (!slashMatch) return false;
  const month = Number(slashMatch[1]);
  const day = Number(slashMatch[2]);
  const year = Number(slashMatch[3]);
  if (year < 1900 || year > 2100 || month < 1 || month > 12 || day < 1 || day > 31) return false;
  return true;
}
export function detectIndiaIdentity(text: string): DetectorMatch[] {
  const matches: DetectorMatch[] = [];
  const add = (pattern: RegExp, type: string, ruleId: string, severity: FindingSeverity, confidence: number, description: string, getMasked: (value: string) => string, validator?: (value: string) => boolean) => {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      const value = match[1] ?? match[0];
      const rawIndex = match.index ?? 0;
      const valueIndex = match[0].indexOf(value);
      const start = rawIndex + (valueIndex >= 0 ? valueIndex : 0);
      const end = start + value.length;
      if (validator && !validator(value)) continue;
      matches.push({
        type,
        severity,
        confidence,
        ruleId,
        maskedSample: getMasked(value),
        description,
        start,
        end,
      });
    }
  };

  add(/\b(?:\d{4}[\s-]?\d{4}[\s-]?\d{4}|\d{12})\b/g, "AADHAAR", "aadhaar-v1", "HIGH", 0.97, "Aadhaar identity number detected.", (value) => `[REDACTED_AADHAAR]`, isValidAadhaar);
  add(/\b(?:pan|permanent\s+account\s+number)\s*[:=]?\s*([A-Z]{5}[0-9]{4}[A-Z])\b/gi, "PAN", "pan-v1", "HIGH", 0.96, "Permanent Account Number detected.", () => `[REDACTED_PAN]`);
  add(/\b[A-Z]{4}0[A-Z0-9]{6}\b/g, "IFSC", "ifsc-v1", "MEDIUM", 0.92, "Indian bank IFSC code detected.", () => `[REDACTED_IFSC]`);
  add(/\b(?:upi(?:\s*id)?|vpa)\s*[:=]?\s*([A-Za-z0-9._-]{3,}@(?:upi|ybl|okhdfc|okaxis|paytm|phonepe|icici|sbi|hdfc|kotak|yesbank|axl))\b/gi, "UPI_ID", "upi-v1", "MEDIUM", 0.9, "UPI virtual payment address detected.", () => `[REDACTED_UPI]`);
  add(/\b(?:dob|date\s*of\s*birth|birth\s*date)\s*[:=]?\s*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}-\d{2}-\d{2})\b/gi, "DATE_OF_BIRTH", "dob-v1", "MEDIUM", 0.94, "Date of birth detected near a relevant keyword.", () => `[REDACTED_DOB]`, isValidDate);

  return matches;
}
