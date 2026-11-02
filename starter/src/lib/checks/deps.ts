/**
 * Known-vulnerable dependencies, looked up live in OSV.dev (the open database behind GitHub advisories, PyPA, RustSec
 * and more). Deterministic: the answer comes from a public database, not a model.
 *
 * Covers npm (package.json, with exact versions from package-lock.json when present) and PyPI (pinned
 * requirements*.txt). A range like "^4.17.0" without a lockfile is resolved to its lower bound and labelled approximate.
 */
import { fingerprint, isSeverity, type Finding, type Severity } from "../findings";

export interface Dependency {
  name: string;
  version: string;
  ecosystem: "npm" | "PyPI";
  manifest: string;
  dev: boolean;
  approximate: boolean;
  /** Set by the collector: the package name is new in this PR (not a version bump). */
  added?: boolean;
}

const OSV = "https://api.osv.dev/v1";

function lowerBound(range: string): string | null {
  const m = range.match(/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/) ?? range.match(/(\d+\.\d+)/);
  if (!m) return null;
  return m[1].split(".").length === 2 ? `${m[1]}.0` : m[1];
}

/** Dependencies declared in a package.json, resolved through its lockfile when one is given. */
export function npmDependencies(manifestPath: string, manifest: string, lockfile?: string | null): Dependency[] {
  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(manifest);
  } catch {
    return [];
  }
  let locked: Record<string, { version?: string }> = {};
  if (lockfile) {
    try {
      locked = (JSON.parse(lockfile) as { packages?: Record<string, { version?: string }> }).packages ?? {};
    } catch {
      /* unreadable lockfile: fall back to ranges */
    }
  }
  const out: Dependency[] = [];
  for (const [section, dev] of [["dependencies", false], ["devDependencies", true]] as const) {
    for (const [name, range] of Object.entries(pkg[section] ?? {})) {
      if (/^(file|link|git|github|workspace|http|https|npm):/.test(range)) continue;
      const exact = locked[`node_modules/${name}`]?.version;
      const version = exact ?? lowerBound(range);
      if (!version) continue;
      out.push({ name, version, ecosystem: "npm", manifest: manifestPath, dev, approximate: !exact });
    }
  }
  return out;
}

/** Pinned (`name==1.2.3`) requirements only; unpinned lines have no version to look up. */
export function pypiDependencies(manifestPath: string, text: string): Dependency[] {
  const out: Dependency[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0].trim();
    const m = line.match(/^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([0-9][^\s;,]*)/);
    if (m) out.push({ name: m[1].replace(/\[.*\]$/, ""), version: m[2], ecosystem: "PyPI", manifest: manifestPath, dev: false, approximate: false });
  }
  return out;
}

interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: { package?: { name?: string; ecosystem?: string }; ranges?: { events?: { fixed?: string }[] }[] }[];
}

function severityOf(v: OsvVuln): Severity {
  const s = (v.database_specific?.severity ?? "").toLowerCase();
  if (s === "moderate") return "medium";
  return isSeverity(s) ? s : "medium";
}

function fixedVersion(v: OsvVuln, dep: Dependency): string | null {
  for (const a of v.affected ?? []) {
    if (a.package?.name !== dep.name) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) return e.fixed;
  }
  return null;
}

/**
 * Batch-query OSV, then fetch details (severity, fix) for at most `maxDetails` advisories. An OSV outage returns a
 * single low-severity "lookup unavailable" note instead of silently reporting "no vulnerabilities".
 */
export async function findVulnerableDependencies(deps: Dependency[], f: typeof fetch = fetch, maxDetails = 25): Promise<Finding[]> {
  if (deps.length === 0) return [];
  const batch = deps.slice(0, 1000);
  let results: { vulns?: { id: string }[] }[];
  try {
    const res = await f(`${OSV}/querybatch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: batch.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) }),
    });
    if (!res.ok) throw new Error(`OSV ${res.status}`);
    results = ((await res.json()) as { results: { vulns?: { id: string }[] }[] }).results;
  } catch (e) {
    return [
      {
        id: await fingerprint("dependencies", "osv", "lookup unavailable"),
        title: "Dependency vulnerability lookup unavailable",
        category: "dependencies",
        severity: "low",
        source: "deterministic",
        file: batch[0].manifest,
        rule: "osv-unavailable",
        evidence: String(e).slice(0, 120),
        fix: "Re-run the review; dependencies were not checked this time.",
        confidence: 1,
        blocking: false,
      },
    ];
  }

  const hits: { dep: Dependency; id: string }[] = [];
  results.forEach((r, i) => r.vulns?.forEach((v) => hits.push({ dep: batch[i], id: v.id })));

  const out: Finding[] = [];
  for (const [n, hit] of hits.entries()) {
    let v: OsvVuln = { id: hit.id };
    if (n < maxDetails) {
      try {
        const res = await f(`${OSV}/vulns/${encodeURIComponent(hit.id)}`);
        if (res.ok) v = (await res.json()) as OsvVuln;
      } catch {
        /* keep the bare id */
      }
    }
    const cve = v.aliases?.find((a) => a.startsWith("CVE-"));
    const fixed = fixedVersion(v, hit.dep);
    const label = `${hit.dep.name}@${hit.dep.version}${hit.dep.approximate ? " (from range)" : ""}`;
    out.push({
      id: await fingerprint("dependencies", hit.dep.manifest, `${hit.dep.name} ${hit.id}`),
      title: `${label}: ${v.summary ?? "known vulnerability"}`.slice(0, 160),
      category: "dependencies",
      severity: n < maxDetails ? severityOf(v) : "medium",
      source: "deterministic",
      file: hit.dep.manifest,
      rule: hit.id,
      evidence: `${hit.id}${cve ? ` / ${cve}` : ""}${hit.dep.dev ? " (dev dependency)" : ""}`,
      fix: fixed ? `Upgrade ${hit.dep.name} to ${fixed} or later.` : `No fixed version listed; check https://osv.dev/vulnerability/${hit.id} for a workaround.`,
      confidence: hit.dep.approximate ? 0.8 : 1,
      blocking: false, // the policy decides
    });
  }
  return out;
}
