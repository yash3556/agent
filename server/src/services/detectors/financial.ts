import type { DetectorMatch } from "./india.js";

function validLuhn(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (/^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  for (let i = digits.length - 1, double = false; i >= 0; i -= 1, double = !double) {
    let digit = Number(digits[i]);
    if (double) digit = digit * 2 > 9 ? digit * 2 - 9 : digit * 2;
    sum += digit;
  }
  return digits.length >= 13 && sum % 10 === 0;
}

function validIban(value: string): boolean {
  const normalized = value.replace(/\s/g, "").toUpperCase();
  const moved = normalized.slice(4) + normalized.slice(0, 4);
  let remainder = 0;
  for (const char of moved) {
    const expanded = char >= "A" ? String(char.charCodeAt(0) - 55) : char;
    for (const digit of expanded) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

export function detectFinancialData(text: string): DetectorMatch[] {
  const matches: DetectorMatch[] = [];
  const seen = new Set<string>();
  const add = (
    pattern: RegExp,
    type: string,
    ruleId: string,
    confidence: number,
    validate: (value: string) => boolean = () => true,
    hasContext: (source: string, start: number, end: number) => boolean = () => true,
  ) => {
    for (const match of text.matchAll(pattern)) {
      const value = match[1] ?? match[0];
      if (!validate(value)) continue;
      const start = (match.index ?? 0) + match[0].indexOf(value);
      if (!hasContext(text, start, start + value.length)) continue;
      const key = value.replace(/[\s-]/g, "").toUpperCase();
      if (seen.has(key)) continue;
      seen.add(key);
      matches.push({
        type, ruleId, confidence, severity: "HIGH", start, end: start + value.length,
        maskedSample: `[REDACTED_${type}]`, description: `${type.replace(/_/g, " ").toLowerCase()} detected.`,
      });
    }
  };

  add(
    /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g,
    "PAYMENT_CARD",
    "luhn-card-v1",
    0.98,
    validLuhn,
    (source, start) => {
      const context = source.slice(Math.max(0, start - 48), start);
      return /\b(?:(?:credit|debit|payment)\s+card|card)(?:\s+(?:number|no\.?))?\s*(?:[:=#]\s*|\s+)$/i.test(context)
        || /\b(?:cc|cvv|cvc)\s*(?:number|no\.?|#|:|=)\s*$/i.test(context);
    },
  );
  add(/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/gi, "IBAN", "iban-mod97-v1", 0.98, validIban);
  add(/\b(?:0[1-9]|[12]\d|3[0-8])[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/gi, "GSTIN", "gstin-format-v1", 0.9);
  add(/\b(?:bank\s+)?(?:account|acct|a\/c)(?:\s+(?:number|no\.?))?\s*[:#=-]?\s*(\d{8,18})\b/gi, "BANK_ACCOUNT", "bank-account-context-v1", 0.9);

  const headerTerms = /\b(?:salary|payroll|gross\s+pay|net\s+pay|bank\s+account|account\s+number|routing\s+number|sort\s+code|tax\s+withheld)\b/gi;
  if (/[,\t|;]/.test(text) && [...text.matchAll(headerTerms)].length >= 2 || /\b(?:payroll|payslip|salary\s+register)\b/i.test(text)) {
    matches.push({
      type: "FINANCIAL_TABLE", ruleId: "financial-table-v1", severity: "HIGH", confidence: 0.9,
      start: 0, end: text.length, maskedSample: "[REDACTED_FINANCIAL_TABLE]",
      description: "A payroll or sensitive financial table header was detected.",
    });
  }
  return matches;
}
