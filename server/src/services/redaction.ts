const privateKeyBlock = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/gi;
const obfuscatedEmail = /(?<![\w.%+-])[A-Z0-9._%+-]+\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|\bat\b)\s*[A-Z0-9-]+(?:(?:\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\bdot\b)\s*|\.)[A-Z0-9-]+)*(?:\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\bdot\b)\s*|\.)[A-Z]{2,}\b/gi;

const sensitiveValuePatterns: Array<{ expression: RegExp; replacement: string }> = [
  { expression: obfuscatedEmail, replacement: "[REDACTED_EMAIL]" },
  {
    expression: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|jdbc:[a-z]+):\/\/[^\s"'<>;,]+/gi,
    replacement: "[REDACTED_CONNECTION_STRING]",
  },
  {
    expression: /\bhttps?:\/\/[^\s"'<>;,]+/gi,
    replacement: "[REDACTED_URL]",
  },
  {
    expression: /\b(?:api[_-]?key|access[_-]?token|token|password|passwd|secret|client[_-]?secret|credential)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s"'<>;,]+)/gi,
    replacement: "[REDACTED_CREDENTIAL]",
  },
  {
    expression: /\b[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z0-9_]*\s*=\s*[^\s"'#]+/g,
    replacement: "[REDACTED_CREDENTIAL]",
  },
  {
    expression: /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    replacement: "[REDACTED_CREDENTIAL]",
  },
  {
    expression: /\b(?:key|secret|token|password)\b[^\r\n]{0,24}?[A-Za-z0-9_+\/=-]{20,}/gi,
    replacement: "[REDACTED_CREDENTIAL]",
  },
  {
    expression: /\bBearer\s+[A-Za-z0-9._~+/-]+={0,2}|\bBasic\s+[A-Za-z0-9+/]+={0,2}/gi,
    replacement: "[REDACTED_CREDENTIAL]",
  },
  {
    expression: /\b(?:ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|(?:sk|gho)-?[A-Za-z0-9_-]{12,})\b/gi,
    replacement: "[REDACTED_CREDENTIAL]",
  },
  {
    expression: /(?<![\w.:/@+-])\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    replacement: "[REDACTED_EMAIL]",
  },
  {
    expression: /(?<!\w)[A-Z]{5}\d{4}[A-Z](?!\w)/gi,
    replacement: "[REDACTED_PAN]",
  },
  {
    expression: /(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)/g,
    replacement: "[REDACTED_PHONE]",
  },
  {
    expression: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/gi,
    replacement: "[REDACTED_IBAN]",
  },
  {
    expression: /\b(?:0[1-9]|[12]\d|3[0-8])[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/gi,
    replacement: "[REDACTED_GSTIN]",
  },
  {
    expression: /\b(?:bank\s+)?(?:account|acct|a\/c)(?:\s+(?:number|no\.?))?\s*[:#=-]?\s*\d{8,18}\b/gi,
    replacement: "[REDACTED_BANK_ACCOUNT]",
  },
  {
    expression: /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g,
    replacement: "[REDACTED_PAYMENT_CARD]",
  },
  {
    expression: /^(?=.*\b(?:salary|payroll|gross\s+pay|net\s+pay|bank\s+account|account\s+number|routing\s+number|sort\s+code|tax\s+withheld)\b)(?=.*[,|\t;]).+$/gim,
    replacement: "[REDACTED_FINANCIAL_TABLE]",
  },
];

export function redactSensitiveText(value: string): string {
  const redactPrivateKey = (block: string) =>
    `[REDACTED_PRIVATE_KEY]${block.match(/\r\n|\r|\n/g)?.join("") ?? ""}`;
  return sensitiveValuePatterns.reduce(
    (safe, { expression, replacement }) => safe.replace(expression, replacement),
    value.replace(privateKeyBlock, redactPrivateKey)
      .replace(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*$/g, redactPrivateKey),
  );
}
