/**
 * The one shape every check and every model pass produces. Deterministic facts and model judgments share it, but the
 * `source` field keeps them apart: a model can never clear a deterministic blocker, it can only add or drop its own.
 */

export type Severity = "critical" | "high" | "medium" | "low";
export type Source = "deterministic" | "model";

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export interface Finding {
  /** Stable 8-hex id: the same issue keeps its id across pushes (no line numbers in it), so waivers stick. */
  id: string;
  title: string;
  category: string;
  severity: Severity;
  source: Source;
  file: string;
  line?: number;
  /** Rule that fired (deterministic) or "model". */
  rule: string;
  /** Where untrusted input comes from and how it reaches the problem. Required for model findings. */
  reachability?: string;
  /** Redacted evidence. Never a full secret. */
  evidence?: string;
  fix?: string;
  /** 0..1. Deterministic provider-specific matches are 1. */
  confidence: number;
  /** Set by the policy: does this finding fail the review? */
  blocking: boolean;
  specialist?: string;
}

export interface Dismissed {
  title: string;
  file: string;
  reason: string;
}

async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Normalised so small wording changes from the model do not mint a new id. */
function normaliseTitle(t: string): string {
  return t.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().split(" ").slice(0, 6).join(" ");
}

export async function fingerprint(category: string, file: string, ruleOrTitle: string): Promise<string> {
  return (await sha256Hex(`${category}|${file}|${normaliseTitle(ruleOrTitle)}`)).slice(0, 8);
}

export function isSeverity(s: unknown): s is Severity {
  return s === "critical" || s === "high" || s === "medium" || s === "low";
}

/** Keep one finding per id; deterministic beats model, then higher severity, then higher confidence. */
export function dedupe(findings: Finding[]): Finding[] {
  const best = new Map<string, Finding>();
  for (const f of findings) {
    const cur = best.get(f.id);
    if (!cur || better(f, cur)) best.set(f.id, f);
  }
  return [...best.values()];
}

function better(a: Finding, b: Finding): boolean {
  if (a.source !== b.source) return a.source === "deterministic";
  if (a.severity !== b.severity) return SEVERITY_RANK[a.severity] > SEVERITY_RANK[b.severity];
  return a.confidence > b.confidence;
}

/** Blocking first, then severity, then confidence, then file order. */
export function rank(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      Number(b.blocking) - Number(a.blocking) ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      b.confidence - a.confidence ||
      a.file.localeCompare(b.file) ||
      (a.line ?? 0) - (b.line ?? 0),
  );
}
