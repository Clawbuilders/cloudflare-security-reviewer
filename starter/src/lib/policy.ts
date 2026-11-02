/**
 * What fails a review is a policy decision, kept apart from the code that finds things. The Starter uses the default;
 * the Advanced track stores versioned policies per repository and lets you change them without redeploying.
 *
 * One rule is not configurable: a provider-format credential (private key, GitHub/AWS/Stripe/... token) always blocks.
 */
import { SEVERITY_RANK, type Finding, type Severity } from "./findings";

export interface Policy {
  version: string;
  /** Model findings at or above this severity block, if confident enough. */
  block_model_at: Severity;
  block_model_min_confidence: number;
  /** Deterministic pattern findings at or above this severity block. */
  block_rules_at: Severity;
  /** Known-vulnerable dependencies at or above this severity block. */
  block_dependencies_at: Severity;
  include_dev_dependencies: boolean;
  /** Findings below this confidence are not reported at all. */
  report_min_confidence: number;
  /** Path prefixes never reviewed (generated code, fixtures you accept). */
  ignore_paths: string[];
}

export const DEFAULT_POLICY: Policy = {
  version: "default-1",
  block_model_at: "high",
  block_model_min_confidence: 0.8,
  block_rules_at: "high",
  block_dependencies_at: "high",
  include_dev_dependencies: false,
  report_min_confidence: 0.6,
  ignore_paths: [],
};

const HARD_RAIL_RULES = new Set([
  "private-key",
  "aws-access-key",
  "github-token",
  "slack-token",
  "stripe-live-key",
  "google-api-key",
  "anthropic-key",
  "openai-key",
  "npm-token",
  "sendgrid-key",
]);

export function isHardRail(f: Finding): boolean {
  return f.source === "deterministic" && HARD_RAIL_RULES.has(f.rule);
}

const atLeast = (s: Severity, floor: Severity) => SEVERITY_RANK[s] >= SEVERITY_RANK[floor];

export function isIgnored(path: string, policy: Policy): boolean {
  return policy.ignore_paths.some((p) => p && path.startsWith(p));
}

/** Apply the policy: drop ignored and low-confidence findings, then mark what blocks. Pure. */
export function applyPolicy(findings: Finding[], policy: Policy): Finding[] {
  const out: Finding[] = [];
  for (const f of findings) {
    if (isHardRail(f)) {
      out.push({ ...f, blocking: true });
      continue;
    }
    if (isIgnored(f.file, policy) || f.confidence < policy.report_min_confidence) continue;
    if (f.category === "dependencies" && !policy.include_dev_dependencies && f.evidence?.includes("(dev dependency)")) continue;
    let blocking = false;
    if (f.category === "dependencies") blocking = f.rule !== "osv-unavailable" && atLeast(f.severity, policy.block_dependencies_at);
    else if (f.source === "deterministic") blocking = atLeast(f.severity, policy.block_rules_at) && f.confidence >= 0.9;
    else blocking = atLeast(f.severity, policy.block_model_at) && f.confidence >= policy.block_model_min_confidence;
    out.push({ ...f, blocking });
  }
  return out;
}

/** Validate a policy someone submitted. Unknown keys are rejected so a typo cannot silently weaken it. */
export function parsePolicy(input: unknown): Policy {
  if (!input || typeof input !== "object") throw new Error("policy must be a JSON object");
  const { specialists: _ignored, ...rest } = input as Partial<Policy> & { specialists?: unknown };
  const p: Policy = { ...DEFAULT_POLICY, ...rest };
  const known = new Set(Object.keys(DEFAULT_POLICY));
  for (const k of Object.keys(input as object)) if (!known.has(k) && k !== "specialists") throw new Error(`unknown policy key "${k}"`);
  const sev = ["critical", "high", "medium", "low"];
  for (const k of ["block_model_at", "block_rules_at", "block_dependencies_at"] as const) if (!sev.includes(p[k])) throw new Error(`${k} must be one of ${sev.join(", ")}`);
  for (const k of ["block_model_min_confidence", "report_min_confidence"] as const) if (typeof p[k] !== "number" || p[k] < 0 || p[k] > 1) throw new Error(`${k} must be between 0 and 1`);
  if (typeof p.include_dev_dependencies !== "boolean") throw new Error("include_dev_dependencies must be true or false");
  if (!Array.isArray(p.ignore_paths) || p.ignore_paths.some((x) => typeof x !== "string")) throw new Error("ignore_paths must be a list of path prefixes");
  if (typeof p.version !== "string" || !/^[\w.-]{1,40}$/.test(p.version)) throw new Error("version must be a short label like 2026-11-02 or v3");
  return p;
}
