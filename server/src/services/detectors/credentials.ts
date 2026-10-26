import type { DetectorMatch } from "./india.js";

function highEntropy(value: string): boolean {
  if (value.length < 20) return false;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  const entropy = [...counts.values()].reduce((sum, count) => {
    const probability = count / value.length;
    return sum - probability * Math.log2(probability);
  }, 0);
  return entropy >= 3.5;
}

export function detectCredentialSecrets(text: string): DetectorMatch[] {
  const matches: DetectorMatch[] = [];
  const seen = new Set<string>();
  const emit = (value: string, start: number, type: string, ruleId: string, confidence: number) => {
    const end = start + value.length;
    if (matches.some((item) => start < item.end && end > item.start)) return;
    const key = `${start}:${end}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({
      category: "CREDENTIAL", type, severity: "HIGH", confidence, ruleId, start, end,
      maskedSample: "[REDACTED_CREDENTIAL]", description: "A credential-like value was detected; format does not establish validity.",
    });
  };
  const add = (pattern: RegExp, type: string, ruleId: string, confidence: number) => {
    for (const match of text.matchAll(pattern)) {
      const value = match[1] ?? match[0];
      emit(value, (match.index ?? 0) + match[0].indexOf(value), type, ruleId, confidence);
    }
  };

  add(/\bASIA[0-9A-Z]{16}\b/g, "AWS_SESSION_KEY_LIKE", "aws-session-key-v1", 0.98);
  add(/\bAIza[0-9A-Za-z_-]{35}\b/g, "GOOGLE_API_KEY_LIKE", "google-api-key-v1", 0.97);
  add(/\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b/g, "GITHUB_TOKEN_LIKE", "github-token-v1", 0.98);
  add(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "SLACK_TOKEN_LIKE", "slack-token-v1", 0.97);
  add(/\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g, "STRIPE_SECRET_LIKE", "stripe-secret-v1", 0.97);
  add(/\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "JWT_SHAPED", "jwt-shape-v1", 0.94);
  for (const match of text.matchAll(/\b[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z0-9_]*\s*=\s*([^\s"'#]{6,})/g)) {
    const value = match[1];
    if (/^\$\{[A-Z][A-Z0-9_]*\}$/.test(value) || /^<YOUR_[A-Z0-9_]+>$/.test(value)) continue;
    emit(value, (match.index ?? 0) + match[0].lastIndexOf(value), "ENV_SECRET", "env-secret-v1", 0.94);
  }
  for (const match of text.matchAll(/\b(?:key|secret|token|password)\b[^\r\n]{0,24}?([A-Za-z0-9_+\/=-]{20,})/gi)) {
    const value = match[1];
    if (highEntropy(value)) emit(value, (match.index ?? 0) + match[0].lastIndexOf(value), "HIGH_ENTROPY_SECRET", "entropy-secret-v1", 0.85);
  }
  return matches;
}
