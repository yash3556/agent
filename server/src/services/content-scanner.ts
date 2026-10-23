import { randomUUID } from "node:crypto";
import type {
  FindingCategory,
  FindingSeverity,
  InspectionFinding,
} from "../types.js";
import { redact } from "./audit.service.js";

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
}

const detectors: Detector[] = [
  {
    expression: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
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
  },
  {
    expression: /\bAKIA[0-9A-Z]{16}\b/g,
    category: "CREDENTIAL",
    type: "CLOUD_ACCESS_KEY_LIKE",
    severity: "CRITICAL",
    confidence: 0.98,
    evidence: "[REDACTED_CREDENTIAL]",
    description: "A cloud access-key-like pattern was detected.",
  },
  {
    expression: /\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)\b|\b(?:reveal|disclose|print|output|expose)\s+(?:the\s+)?(?:system\s+prompt|secrets?|credentials?|api\s+keys?)\b|\b(?:bypass|disable|ignore)\s+(?:security|safety|policy|guardrails?)\b/gi,
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
  summary: ScanSummary;
}

const MAX_REPORTED_FINDINGS = 100;

export function redactSensitiveText(text: string): string {
  return detectors.reduce((safe, detector) => {
    if (detector.category === "SUSPICIOUS_INSTRUCTION") return safe;
    const expression = new RegExp(detector.expression.source, detector.expression.flags);
    return safe.replace(expression, detector.evidence);
  }, redact(text));
}

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

  segments.forEach((segment, segmentIndex) => {
    const lines = segment.text.split(/\r\n|\r|\n/);
    lines.forEach((line, lineIndex) => {
      for (const detector of detectors) {
        detector.expression.lastIndex = 0;
        if (!detector.expression.test(line)) continue;
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
          });
          findingSegments.push(segmentIndex);
        }
      }
    });
  });

  return {
    findings,
    findingSegments,
    summary: {
      totalFindings,
      truncated: totalFindings > MAX_REPORTED_FINDINGS,
      bySeverity,
    },
  };
}
