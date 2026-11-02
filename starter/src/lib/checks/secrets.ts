/**
 * Deterministic secret detection. Provider-specific formats are near-certain and block; the generic
 * "something named like a secret, assigned a high-entropy string" rule is a strong lead that a person checks.
 * Evidence is always redacted: a reviewer that pastes your key into a PR comment has leaked it twice.
 */
import { fingerprint, type Finding } from "../findings";
import type { SourceFile } from "../files";

interface Rule {
  id: string;
  title: string;
  re: RegExp;
  /** Capture group holding the secret value (0 = whole match). */
  group?: number;
}

const PROVIDER_RULES: Rule[] = [
  { id: "aws-access-key", title: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: "github-token", title: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/ },
  { id: "slack-token", title: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/ },
  { id: "stripe-live-key", title: "Stripe live secret key", re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/ },
  { id: "google-api-key", title: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "anthropic-key", title: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
  { id: "openai-key", title: "OpenAI API key", re: /\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b/ },
  { id: "npm-token", title: "npm access token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: "sendgrid-key", title: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
];

const PEM_HEADER = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/;
const KEY_MATERIAL = /^[A-Za-z0-9+/=]{40,}$/;

/**
 * A header alone is not a key: placeholders ("-----BEGIN PRIVATE KEY-----\n...") and code that strips headers
 * both contain one. Require base64 key material after the header, on the same line (an escaped "\n" in an env
 * file) or on the next line.
 */
export function privateKeyAt(lines: { text: string }[], i: number): boolean {
  const text = lines[i].text;
  const m = text.match(PEM_HEADER);
  if (!m) return false;
  const after = text.slice((m.index ?? 0) + m[0].length).replace(/^(\\n|\\r|\s|["'`])+/, "");
  const sameLine = after.match(/^[A-Za-z0-9+/=]{40,}/);
  const nextLine = lines[i + 1]?.text.trim() ?? "";
  return Boolean(sameLine) || KEY_MATERIAL.test(nextLine);
}

const GENERIC = {
  id: "generic-secret-assignment",
  title: "Hardcoded secret-like value",
  re: /\b([A-Za-z0-9_]*(?:secret|token|api[_-]?key|apikey|password|passwd|private[_-]?key|client[_-]?secret|auth)[A-Za-z0-9_]*)["']?\s*[:=]\s*["'`]([^"'`\s]{16,200})["'`]/i,
};

const PLACEHOLDER = /(example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxx|\*\*\*|<|>|\$\{|\{\{|process\.env|env\.|redacted|test|fake|todo|null|undefined|localhost)/i;

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** First four characters and the length. Enough to find it, useless to anyone reading the comment. */
export function redact(secret: string): string {
  return `${secret.slice(0, 4)}... (${secret.length} chars, redacted)`;
}

export async function findSecrets(files: SourceFile[]): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const file of files) {
    for (const [i, { line, text }] of file.lines.entries()) {
      if (privateKeyAt(file.lines, i)) {
        out.push({
          id: await fingerprint("secrets", file.path, "private-key"),
          title: "Private key committed",
          category: "secrets",
          severity: "critical",
          source: "deterministic",
          file: file.path,
          line,
          rule: "private-key",
          evidence: "PEM private key header followed by key material (redacted)",
          fix: "Treat the key as compromised: revoke it, issue a new one, and store it as a secret (for example `wrangler secret put`).",
          confidence: 1,
          blocking: true,
        });
        continue;
      }
      if (text.length > 2000) continue; // minified or data blobs
      let matched = false;
      for (const rule of PROVIDER_RULES) {
        const m = text.match(rule.re);
        if (!m) continue;
        matched = true;
        out.push({
          id: await fingerprint("secrets", file.path, rule.id),
          title: rule.title,
          category: "secrets",
          severity: "critical",
          source: "deterministic",
          file: file.path,
          line,
          rule: rule.id,
          evidence: redact(m[rule.group ?? 0]),
          fix: "Revoke and rotate this credential now (git history keeps it even after you delete the line), then load it from a secret store such as `wrangler secret put`.",
          confidence: 1,
          blocking: true,
        });
      }
      if (matched) continue;
      const g = text.match(GENERIC.re);
      if (g && !PLACEHOLDER.test(g[2]) && entropy(g[2]) >= 3.5) {
        out.push({
          id: await fingerprint("secrets", file.path, `${GENERIC.id}:${g[1]}`),
          title: `${GENERIC.title} (${g[1]})`,
          category: "secrets",
          severity: "high",
          source: "deterministic",
          file: file.path,
          line,
          rule: GENERIC.id,
          evidence: redact(g[2]),
          fix: "If this is a real credential, rotate it and read it from the environment instead. If it is test data, use an obvious placeholder.",
          confidence: 0.7,
          blocking: false,
        });
      }
    }
  }
  return out;
}
