/**
 * The review, as four plain functions the Workflow runs as durable steps:
 *   collect  -> what changed, with full-file context and the dependency diff
 *   checks   -> deterministic facts: secrets, known-vulnerable dependencies (with EPSS and CISA KEV), the health of
 *               newly added packages (deps.dev), risky-pattern signals, and alerts from scanners in GitHub Actions
 *   review   -> triage, then one model pass that proposes findings; known low-signal findings are excluded by rule,
 *               and a second model verifies the rest together with the scanner alerts
 *   decide   -> apply the policy and render one comment
 *
 * Free-plan budget: a Workers Free invocation gets 50 subrequests, so the collector fetches at most
 * MAX_CONTEXT_FILES full files, and the checks step makes at most about 27 requests: OSV (1 + 8 advisory details),
 * EPSS and KEV (2, only when a CVE was found) and deps.dev (3 for each of up to 5 newly added packages).
 */
import { npmDependencies, pypiDependencies, findVulnerableDependencies, type Dependency } from "./checks/deps";
import { findSecrets } from "./checks/secrets";
import { findSignals, PATTERN_RULES, standaloneFindings, type Signal } from "./checks/patterns";
import { enrichExploitation } from "./checks/exploitation";
import { findPackageHealth } from "./checks/package-health";
import { scannerAlerts, scannerCandidates, type ScannerAlert } from "./checks/code-scanning";
import { dedupe, type Dismissed, type Finding } from "./findings";
import { addedLines, isDocs, isReviewable, isScannable, priority, type SourceFile } from "./files";
import { fetchFileAtRef, getPullRequest, listCodeScanningAlerts, listPrFiles } from "./github";
import { GENERALIST, hunt, verify, type AiBinding, type Candidate, type Focus, type ModelOptions } from "./model";
import { applyPolicy, isIgnored, type Policy } from "./policy";
import type { Report } from "./report";

export interface PrRef {
  repo: string;
  number: number;
  sha: string;
  installationId?: number;
}

export interface Collected {
  sha: string;
  baseSha: string;
  ref: string;
  files: SourceFile[];
  /** Dependencies added or changed by this PR. */
  newDeps: Dependency[];
  totalChanged: number;
  /** Open alerts from code-scanning tools on lines this PR added; null = code scanning not readable. */
  alerts: ScannerAlert[] | null;
}

export interface CollectOptions {
  maxContextFiles: number;
  /** Read code-scanning alerts (zizmor, CodeQL, osv-scanner...) uploaded by GitHub Actions. */
  codeScanning: boolean;
}

const MAX_FILE_CHARS = 30_000;

/** Dependencies in a manifest at a commit, resolved with the sibling lockfile when there is one. */
async function depsAt(repo: string, manifest: string, sha: string, token: string | null, f: typeof fetch): Promise<Dependency[]> {
  const text = await fetchFileAtRef(repo, manifest, sha, token, f);
  if (!text) return [];
  if (manifest.endsWith("package.json")) {
    const dir = manifest.slice(0, manifest.length - "package.json".length);
    const lock = await fetchFileAtRef(repo, `${dir}package-lock.json`, sha, token, f).catch(() => null);
    return npmDependencies(manifest, text, lock);
  }
  return pypiDependencies(manifest, text);
}

export async function collect(p: PrRef, token: string | null, policy: Policy, o: CollectOptions, f: typeof fetch = fetch): Promise<Collected> {
  const maxContextFiles = o.maxContextFiles;
  const pr = await getPullRequest(p.repo, p.number, token, f);
  const changed = await listPrFiles(p.repo, p.number, token, 300, f);
  const live = changed.filter((c) => c.status !== "removed" && isScannable(c.filename) && !isIgnored(c.filename, policy));

  const files: SourceFile[] = live.map((c) => ({ path: c.filename, lines: addedLines(c.patch), patch: c.patch?.slice(0, MAX_FILE_CHARS) }));

  // Full-file context for the highest-priority reviewable files; the rest are judged on their diff alone.
  const forContext = files.filter((x) => isReviewable(x.path) && x.lines.length > 0).sort((a, b) => priority(b.path) - priority(a.path)).slice(0, maxContextFiles);
  await Promise.all(
    forContext.map(async (x) => {
      const content = await fetchFileAtRef(p.repo, x.path, pr.head.sha, token, f).catch(() => null);
      if (content) x.content = content.slice(0, MAX_FILE_CHARS);
    }),
  );

  // Dependency diff: what the head declares that the base did not (name@version).
  const manifests = new Set<string>();
  for (const c of changed) {
    if (/(^|\/)package(-lock)?\.json$/.test(c.filename)) manifests.add(c.filename.replace(/package-lock\.json$/, "package.json"));
    if (/(^|\/)requirements[^/]*\.txt$/.test(c.filename)) manifests.add(c.filename);
  }
  const newDeps: Dependency[] = [];
  for (const m of [...manifests].slice(0, 3)) {
    const [head, base] = await Promise.all([depsAt(p.repo, m, pr.head.sha, token, f), depsAt(p.repo, m, pr.base.sha, token, f)]);
    const before = new Set(base.map((d) => `${d.name}@${d.version}`));
    const names = new Set(base.map((d) => d.name));
    newDeps.push(...head.filter((d) => !before.has(`${d.name}@${d.version}`)).map((d) => ({ ...d, added: !names.has(d.name) })));
  }

  const alerts = o.codeScanning ? await listCodeScanningAlerts(p.repo, p.number, token, f) : null;
  return { sha: pr.head.sha, baseSha: pr.base.sha, ref: pr.head.ref, files, newDeps, totalChanged: changed.length, alerts: alerts ? scannerAlerts(alerts, files) : null };
}

/** Signals cross a step boundary as plain data; the rule is looked up again by id. */
export interface SignalData {
  ruleId: string;
  file: string;
  line: number;
  text: string;
}

export function toSignalData(s: Signal[]): SignalData[] {
  return s.map((x) => ({ ruleId: x.rule.id, file: x.file, line: x.line, text: x.text }));
}

export function fromSignalData(s: SignalData[]): Signal[] {
  return s.flatMap((x) => {
    const rule = PATTERN_RULES.find((r) => r.id === x.ruleId);
    return rule ? [{ rule, file: x.file, line: x.line, text: x.text }] : [];
  });
}

export interface Checked {
  findings: Finding[];
  signals: SignalData[];
  /** Scanner alerts, as candidates for the verifier. */
  scanner: Candidate[];
}

export async function checks(c: Collected, f: typeof fetch = fetch): Promise<Checked> {
  const signals = findSignals(c.files);
  const [vulnerable, health] = await Promise.all([
    findVulnerableDependencies(c.newDeps, f, 8).then((x) => enrichExploitation(x, f)),
    findPackageHealth(c.newDeps, f, 5),
  ]);
  const findings = [...(await findSecrets(c.files)), ...(await standaloneFindings(signals)), ...vulnerable, ...health];
  return { findings, signals: toSignalData(signals.filter((s) => !s.rule.standalone)), scanner: scannerCandidates(c.alerts ?? []) };
}

export interface Reviewed {
  findings: Finding[];
  dismissed: Dismissed[];
  reviewedByModel: number;
  omitted: string[];
  skippedModel?: string;
  /** Skill domains loaded by the model pass. */
  skills: string[];
}

/**
 * The triage gate is deterministic here: a PR with no reviewable code (docs, images, lockfiles only) skips the model.
 * Deterministic findings were already produced, so skipping never hides a secret or a vulnerable dependency.
 */
export function triage(c: Collected): { run: boolean; why?: string } {
  const code = c.files.filter((x) => isReviewable(x.path) && !isDocs(x.path) && x.lines.length > 0);
  if (code.length === 0) return { run: false, why: "no code or configuration lines added (docs, assets or deletions only)" };
  return { run: true };
}

export async function review(
  ai: AiBinding,
  opts: ModelOptions,
  c: Collected,
  checked: Pick<Checked, "signals" | "scanner">,
  policy: Pick<Policy, "model_exclusions">,
  focus: Focus = GENERALIST,
): Promise<Reviewed> {
  const gate = triage(c);
  if (!gate.run) return { findings: [], dismissed: [], reviewedByModel: 0, omitted: [], skippedModel: gate.why, skills: [] };
  const files = c.files.filter((x) => isReviewable(x.path) && x.lines.length > 0).sort((a, b) => priority(b.path) - priority(a.path));
  try {
    const { candidates, omitted, skills } = await hunt(ai, opts, focus, files, fromSignalData(checked.signals));
    const { kept, dismissed } = await verify(ai, opts, [...candidates, ...checked.scanner], files, skills, policy.model_exclusions);
    return { findings: kept, dismissed, reviewedByModel: files.length - omitted.length, omitted, skills };
  } catch (e) {
    return { findings: [], dismissed: [], reviewedByModel: 0, omitted: [], skippedModel: `model unavailable (${String(e).slice(0, 120)}); rules and dependency checks still ran`, skills: [] };
  }
}

export function decide(p: PrRef, c: Collected, checked: Checked, reviewed: Reviewed, policy: Policy, model: string): Report {
  const findings = applyPolicy(dedupe([...checked.findings, ...reviewed.findings]), policy);
  return {
    repo: p.repo,
    number: p.number,
    ref: c.ref,
    sha: c.sha,
    policyVersion: policy.version,
    model,
    findings,
    dismissed: reviewed.dismissed,
    stats: {
      files: c.files.length,
      reviewedByModel: reviewed.reviewedByModel,
      omitted: reviewed.omitted,
      skippedModel: reviewed.skippedModel,
      skills: reviewed.skills,
      scanners: scannerSummary(c.alerts),
    },
  };
}

/** One line for the report: which scanners' alerts were read, or why none were. */
export function scannerSummary(alerts: ScannerAlert[] | null): string {
  if (alerts === null) return "not read (code scanning off, not permitted, or no token)";
  if (alerts.length === 0) return "no open alerts on changed lines";
  const by = new Map<string, number>();
  for (const a of alerts) by.set(a.tool, (by.get(a.tool) ?? 0) + 1);
  return [...by].map(([t, n]) => `${t}: ${n}`).join(", ");
}
