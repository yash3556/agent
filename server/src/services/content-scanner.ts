import { randomUUID } from "node:crypto";
export { redactSensitiveText } from "./redaction.js";
import type {
  FindingCategory,
  FindingSeverity,
  InspectionFinding,
} from "../types.js";
import { runDeterministicRegistry } from "./detectors/index.js";
import { redactSensitiveText } from "./redaction.js";

export interface TextSegment {
  text: string;
  page: number | null;
}

interface Detector {
  expression: RegExp;
  category: FindingCategory;
  type: string;
  severity: FindingSeverity;
  confidence: number;
  evidence: string;
  description: string;
  ruleId?: string;
}

const detectors: Detector[] = [
  {
    expression: /(?<![\w.:/@+-])\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    category: "PERSONAL_DATA",
    type: "EMAIL_ADDRESS",
    severity: "MEDIUM",
    confidence: 0.95,
    evidence: "[REDACTED_EMAIL]",
    description: "An email address pattern was detected.",
  },
  {
    expression: /(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)/g,
    category: "PERSONAL_DATA",
    type: "PHONE_NUMBER",
    severity: "MEDIUM",
    confidence: 0.78,
    evidence: "[REDACTED_PHONE]",
    description: "A phone-number-like pattern was detected.",
  },
  {
    expression: /\b(?:api[_-]?key|access[_-]?token|password|passwd|secret|client[_-]?secret)\s*[:=]\s*["']?[^\s"'<>]{6,}/gi,
    category: "CREDENTIAL",
    type: "CREDENTIAL_LIKE",
    severity: "HIGH",
    confidence: 0.9,
    evidence: "[REDACTED_CREDENTIAL]",
    description: "A credential-like key/value pattern was detected.",
    ruleId: "credential-assignment-v1",
  },
  {
    expression: /\bBearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}/gi,
    category: "CREDENTIAL",
    type: "BEARER_TOKEN_LIKE",
    severity: "HIGH",
    confidence: 0.88,
    evidence: "[REDACTED_CREDENTIAL]",
    description: "A bearer-token-like pattern was detected.",
    ruleId: "bearer-token-v1",
  },
  {
    expression: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s/@:]+(?::[^\s/@]*)?@[^\s/]+/gi,
    category: "CREDENTIAL",
    type: "DATABASE_CONNECTION_STRING",
    severity: "CRITICAL",
    confidence: 0.94,
    evidence: "[REDACTED_CREDENTIAL]",
    description: "A database connection string with embedded credentials was detected.",
    ruleId: "database-connection-v1",
  },
  {
    expression: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    category: "CREDENTIAL",
    type: "PRIVATE_KEY_MARKER",
    severity: "CRITICAL",
    confidence: 0.99,
    evidence: "[REDACTED_CREDENTIAL]",
    description: "A private-key marker was detected.",
    ruleId: "private-key-marker-v1",
  },
  {
    expression: /\bAKIA[0-9A-Z]{16}\b/g,
    category: "CREDENTIAL",
    type: "CLOUD_ACCESS_KEY_LIKE",
    severity: "CRITICAL",
    confidence: 0.98,
    evidence: "[REDACTED_CREDENTIAL]",
    description: "A cloud access-key-like pattern was detected.",
    ruleId: "aws-access-key-v1",
  },
  {
    expression: /\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)\b|\b(?:reveal|disclose|print|output|expose)\s+(?:the\s+)?(?:system\s+prompt|secrets?|credentials?|api\s+keys?)\b|\b(?:bypass|disable|ignore)\s+(?:security|safety|policy|guardrails?)\b|\b(?:hide|conceal|silently|without\s+(?:telling|informing))\b.{0,60}\b(?:user|warning|action|request|tool|data)\b|\b(?:send|upload|forward|exfiltrate)\b.{0,100}\b(?:external|unapproved|attacker|http|https|email|server|endpoint)\b/gi,
    category: "SUSPICIOUS_INSTRUCTION",
    type: "PROMPT_INJECTION_PATTERN",
    severity: "HIGH",
    confidence: 0.86,
    evidence: "[REDACTED_INSTRUCTION]",
    description: "Text resembling an instruction override or secret-disclosure request was detected.",
  },
];

export interface ScanSummary {
  totalFindings: number;
  truncated: boolean;
  bySeverity: Record<FindingSeverity, number>;
}

export interface ScanResult {
  findings: InspectionFinding[];
  findingSegments: number[];
  findingLocations: Array<{
    segment: number;
    page: number | null;
    line: number;
    start: number;
    end: number;
  }>;
  summary: ScanSummary;
}

const MAX_REPORTED_FINDINGS = 100;

export function scanText(segments: TextSegment[]): ScanResult {
  const findings: InspectionFinding[] = [];
  const bySeverity: ScanSummary["bySeverity"] = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };
  let totalFindings = 0;
  const findingSegments: number[] = [];
  const findingLocations: ScanResult["findingLocations"] = [];

  segments.forEach((segment, segmentIndex) => {
    const lines = segment.text.split(/\r\n|\r|\n/);
    lines.forEach((line, lineIndex) => {
      const registryMatches = runDeterministicRegistry(line);
      const credentialRanges = [
        ...detectors.filter(({ category }) => category === "CREDENTIAL").flatMap(({ expression }) => {
          expression.lastIndex = 0;
          return Array.from(line.matchAll(expression), (match) => ({
            start: match.index ?? 0,
            end: (match.index ?? 0) + match[0].length,
          }));
        }),
        ...registryMatches.filter(({ category }) => category === "CREDENTIAL"),
      ];
      for (const detector of detectors) {
        detector.expression.lastIndex = 0;
        const match = detector.expression.exec(line);
        if (!match) continue;
        if (detector.type === "PHONE_NUMBER" && credentialRanges.some(
          ({ start, end }) => start < match.index + match[0].length && end > match.index,
        )) continue;
        if (detector.category === "CREDENTIAL" && detector.type !== "DATABASE_CONNECTION_STRING" && registryMatches.some(
          ({ category, start, end }) => category === "CREDENTIAL" && start < match.index + match[0].length && end > match.index,
        )) continue;
        totalFindings += 1;
        bySeverity[detector.severity] += 1;
        if (findings.length < MAX_REPORTED_FINDINGS) {
          findings.push({
            id: `finding_${randomUUID()}`,
            category: detector.category,
            type: detector.type,
            severity: detector.severity,
            confidence: detector.confidence,
            location: {
              page: segment.page,
              line: lineIndex + 1,
            },
            evidence: detector.evidence,
            description: detector.description,
            ...(detector.ruleId ? { ruleId: detector.ruleId, maskedSample: detector.evidence } : {}),
          });
          findingSegments.push(segmentIndex);
          findingLocations.push({
            segment: segmentIndex,
            page: segment.page,
            line: lineIndex + 1,
            start: match.index,
            end: match.index + match[0].length,
          });
        }
      }

      for (const registryMatch of registryMatches) {
        totalFindings += 1;
        bySeverity[registryMatch.severity] += 1;
        if (findings.length < MAX_REPORTED_FINDINGS) {
          findings.push({
            id: `finding_${randomUUID()}`,
            category: registryMatch.category ?? "PERSONAL_DATA",
            type: registryMatch.type,
            severity: registryMatch.severity,
            confidence: registryMatch.confidence,
            location: {
              page: segment.page,
              line: lineIndex + 1,
            },
            evidence: registryMatch.maskedSample,
            description: registryMatch.description,
            ruleId: registryMatch.ruleId,
            maskedSample: registryMatch.maskedSample,
          });
          findingSegments.push(segmentIndex);
          findingLocations.push({
            segment: segmentIndex,
            page: segment.page,
            line: lineIndex + 1,
            start: registryMatch.start,
            end: registryMatch.end,
          });
        }
      }
    });
  });

  return {
    findings,
    findingSegments,
    findingLocations,
    summary: {
      totalFindings,
      truncated: totalFindings > MAX_REPORTED_FINDINGS,
      bySeverity,
    },
  };
}
