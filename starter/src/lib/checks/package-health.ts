/**
 * Health of packages this pull request adds for the first time, from deps.dev (Google's Open Source Insights, free and
 * keyless): https://docs.deps.dev/api/v3/
 *
 * A known CVE is OSV's job. This catches the other supply-chain risks a reviewer would notice: a package published
 * days ago (typosquats and malicious packages are usually brand new), a deprecated version, no linked source
 * repository, or a low OpenSSF Scorecard. Deterministic, never blocking by default, and limited to `max` packages
 * (three requests each) to stay inside the Workers Free subrequest budget.
 */
import { fingerprint, SEVERITY_RANK, type Finding, type Severity } from "../findings";
import type { Dependency } from "./deps";

const API = "https://api.deps.dev/v3";
const DAY = 86_400_000;
export const NEW_PACKAGE_DAYS = 30;
export const LOW_SCORECARD = 4;

export interface PackageFacts {
  dep: Dependency;
  /** Earliest publish time of any version, if known. */
  firstPublished?: number;
  versionCount?: number;
  deprecated?: string | null;
  sourceRepo?: string | null;
  scorecard?: number | null;
}

const system = (d: Dependency) => (d.ecosystem === "npm" ? "npm" : "pypi");

async function getJson<T>(url: string, f: typeof fetch): Promise<T | null> {
  try {
    const res = await f(url);
    return res.ok ? ((await res.json()) as T) : null;
  } catch {
    return null;
  }
}

export async function packageFacts(dep: Dependency, f: typeof fetch = fetch): Promise<PackageFacts> {
  const name = encodeURIComponent(dep.name);
  const [pkg, ver] = await Promise.all([
    getJson<{ versions?: { publishedAt?: string }[] }>(`${API}/systems/${system(dep)}/packages/${name}`, f),
    getJson<{ isDeprecated?: boolean; deprecatedReason?: string; relatedProjects?: { projectKey?: { id?: string }; relationType?: string }[] }>(
      `${API}/systems/${system(dep)}/packages/${name}/versions/${encodeURIComponent(dep.version)}`,
      f,
    ),
  ]);
  const facts: PackageFacts = { dep };
  if (pkg?.versions) {
    const times = pkg.versions.map((v) => Date.parse(v.publishedAt ?? "")).filter(Number.isFinite);
    facts.versionCount = pkg.versions.length;
    if (times.length) facts.firstPublished = Math.min(...times);
  }
  if (ver) {
    facts.deprecated = ver.isDeprecated ? ver.deprecatedReason || "deprecated" : null;
    facts.sourceRepo = ver.relatedProjects?.find((p) => p.relationType === "SOURCE_REPO")?.projectKey?.id ?? null;
    if (facts.sourceRepo) {
      const proj = await getJson<{ scorecard?: { overallScore?: number } }>(`${API}/projects/${encodeURIComponent(facts.sourceRepo)}`, f);
      facts.scorecard = typeof proj?.scorecard?.overallScore === "number" ? proj.scorecard.overallScore : null;
    }
  }
  return facts;
}

/** Turn facts into at most one finding per package. Pure, so it is tested without the network. */
export async function healthFinding(x: PackageFacts, now = Date.now()): Promise<Finding | null> {
  const reasons: string[] = [];
  let severity: Severity = "low";
  const bump = (s: Severity) => {
    if (SEVERITY_RANK[s] > SEVERITY_RANK[severity]) severity = s;
  };
  if (x.firstPublished !== undefined && now - x.firstPublished < NEW_PACKAGE_DAYS * DAY) {
    reasons.push(`first published ${Math.max(0, Math.floor((now - x.firstPublished) / DAY))} day(s) ago (${x.versionCount ?? "?"} version(s))`);
    bump("medium");
  }
  if (x.deprecated) reasons.push(`this version is deprecated: ${x.deprecated.slice(0, 120)}`);
  if (x.sourceRepo === null) reasons.push("no source repository linked");
  if (typeof x.scorecard === "number" && x.scorecard < LOW_SCORECARD) reasons.push(`OpenSSF Scorecard ${x.scorecard.toFixed(1)}/10`);
  if (reasons.length === 0) return null;
  const d = x.dep;
  return {
    id: await fingerprint("supply-chain", d.manifest, `package health ${d.name}`),
    title: `New dependency ${d.name}@${d.version} needs a closer look`,
    category: "supply-chain",
    severity,
    source: "deterministic",
    file: d.manifest,
    rule: "package-health",
    evidence: `deps.dev: ${reasons.join("; ")}${d.dev ? " (dev dependency)" : ""}`,
    fix: `Confirm ${d.name} is the package you meant (check the spelling against the popular one), who publishes it, and that a maintained alternative does not exist.`,
    confidence: 0.9,
    blocking: false,
  };
}

/** Check packages added by name in this PR (not version bumps), up to `max`. */
export async function findPackageHealth(deps: Dependency[], f: typeof fetch = fetch, max = 5): Promise<Finding[]> {
  const added = deps.filter((d) => d.added).slice(0, max);
  const facts = await Promise.all(added.map((d) => packageFacts(d, f)));
  const out = await Promise.all(facts.map((x) => healthFinding(x)));
  return out.filter((x): x is Finding => x !== null);
}
