/**
 * The review, as four plain functions the Workflow runs as durable steps:
 *   collect  -> what changed, with full-file context and the dependency diff
 *   checks   -> deterministic facts: secrets, known-vulnerable dependencies, risky-pattern signals
 *   review   -> triage, then one model pass that proposes findings and a second that verifies them
 *   decide   -> apply the policy and render one comment
 *
 * Free-plan budget: a Workers Free invocation gets 50 subrequests, so the collector fetches at most
 * MAX_CONTEXT_FILES full files and the OSV lookup fetches details for at most 8 advisories.
 */
import { npmDependencies, pypiDependencies, findVulnerableDependencies, type Dependency } from "./checks/deps";
import { findSecrets } from "./checks/secrets";
import { findSignals, PATTERN_RULES, standaloneFindings, type Signal } from "./checks/patterns";
import { dedupe, type Dismissed, type Finding } from "./findings";
import { addedLines, isDocs, isReviewable, isScannable, priority, type SourceFile } from "./files";
import { fetchFileAtRef, getPullRequest, listPrFiles } from "./github";
import { GENERALIST, hunt, verify, type AiBinding, type Focus, type ModelOptions } from "./model";
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

export async function collect(p: PrRef, token: string | null, policy: Policy, maxContextFiles: number, f: typeof fetch = fetch): Promise<Collected> {
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
    newDeps.push(...head.filter((d) => !before.has(`${d.name}@${d.version}`)));
  }

  return { sha: pr.head.sha, baseSha: pr.base.sha, ref: pr.head.ref, files, newDeps, totalChanged: changed.length };
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
}

export async function checks(c: Collected, f: typeof fetch = fetch): Promise<Checked> {
  const signals = findSignals(c.files);
  const findings = [
    ...(await findSecrets(c.files)),
    ...(await standaloneFindings(signals)),
    ...(await findVulnerableDependencies(c.newDeps, f, 8)),
  ];
  return { findings, signals: toSignalData(signals.filter((s) => !s.rule.standalone)) };
}

export interface Reviewed {
  findings: Finding[];
  dismissed: Dismissed[];
  reviewedByModel: number;
  omitted: string[];
  skippedModel?: string;
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

export async function review(ai: AiBinding, opts: ModelOptions, c: Collected, signals: SignalData[], focus: Focus = GENERALIST): Promise<Reviewed> {
  const gate = triage(c);
  if (!gate.run) return { findings: [], dismissed: [], reviewedByModel: 0, omitted: [], skippedModel: gate.why };
  const files = c.files.filter((x) => isReviewable(x.path) && x.lines.length > 0).sort((a, b) => priority(b.path) - priority(a.path));
  try {
    const { candidates, omitted } = await hunt(ai, opts, focus, files, fromSignalData(signals));
    const { kept, dismissed } = await verify(ai, opts, candidates, files);
    return { findings: kept, dismissed, reviewedByModel: files.length - omitted.length, omitted };
  } catch (e) {
    return { findings: [], dismissed: [], reviewedByModel: 0, omitted: [], skippedModel: `model unavailable (${String(e).slice(0, 120)}); rules and dependency checks still ran` };
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
    stats: { files: c.files.length, reviewedByModel: reviewed.reviewedByModel, omitted: reviewed.omitted, skippedModel: reviewed.skippedModel },
  };
}
