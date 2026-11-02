import { describe, expect, it } from "vitest";
import { applyExclusions, exclusionReason, PRECEDENTS } from "../starter/src/lib/exclusions";
import { applyExploitation, cveOf, enrichExploitation, knownExploited } from "../starter/src/lib/checks/exploitation";
import { findPackageHealth, healthFinding } from "../starter/src/lib/checks/package-health";
import { scannerAlerts, scannerCandidates } from "../starter/src/lib/checks/code-scanning";
import { applyPolicy, DEFAULT_POLICY, parsePolicy } from "../starter/src/lib/policy";
import { verify, type AiBinding, type Candidate } from "../starter/src/lib/model";
import { scannerSummary } from "../starter/src/lib/pipeline";
import type { Finding } from "../starter/src/lib/findings";
import type { Dependency } from "../starter/src/lib/checks/deps";
import { codeguardRules, codeguardText } from "../src/codeguard";
import { CODEGUARD_RULES } from "../src/codeguard.generated";
import { isScannerWorkflow } from "../src/scanners";

const cand = (over: Partial<Candidate>): Candidate => ({
  title: "t",
  category: "injection",
  severity: "high",
  file: "src/api.ts",
  untrusted_input: "request body",
  flow: "body.q -> db.query",
  fix: "parameterise",
  confidence: 0.9,
  specialist: "appsec",
  ...over,
});

const depFinding = (over: Partial<Finding>): Finding => ({
  id: "abcd1234",
  title: "lodash@4.17.0: prototype pollution",
  category: "dependencies",
  severity: "medium",
  source: "deterministic",
  file: "package.json",
  rule: "GHSA-xxxx",
  evidence: "GHSA-xxxx / CVE-2021-44228",
  confidence: 1,
  blocking: false,
  ...over,
});

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("false-positive exclusions (ported from anthropics/claude-code-security-review)", () => {
  it("drops generic DoS, rate-limit and memory-safety-outside-C findings", () => {
    expect(exclusionReason(cand({ title: "Denial of service via large payload" }))).toMatch(/denial-of-service/);
    expect(exclusionReason(cand({ title: "Missing rate limit on search endpoint" }))).toMatch(/rate-limiting/);
    expect(exclusionReason(cand({ title: "Buffer overflow in parser", file: "src/parse.ts" }))).toMatch(/Memory-safety/);
    expect(exclusionReason(cand({ title: "Buffer overflow in parser", file: "src/parse.c" }))).toBeNull();
  });

  it("keeps the cases this reviewer cares about", () => {
    expect(exclusionReason(cand({ title: "Missing rate limit on login allows password brute force" }))).toBeNull();
    expect(exclusionReason(cand({ title: "Open redirect leaks OAuth code via redirect_uri" }))).toBeNull();
    expect(exclusionReason(cand({ title: "Open redirect on /go" }))).toMatch(/Open redirect/);
    expect(exclusionReason(cand({ title: "Unbounded agent loop with no spend limit" }))).toBeNull();
    expect(exclusionReason(cand({ title: "Ignore previous instructions", category: "prompt-injection", file: "README.md" }))).toBeNull();
    expect(exclusionReason(cand({ title: "SQL injection in search" }))).toBeNull();
  });

  it("drops SSRF in client-side files and anything in tests", () => {
    expect(exclusionReason(cand({ title: "SSRF via fetch(url)", file: "src/components/Preview.tsx" }))).toMatch(/client-side/);
    expect(exclusionReason(cand({ title: "SSRF via fetch(url)", file: "src/worker.ts" }))).toBeNull();
    expect(exclusionReason(cand({ title: "SQL injection", file: "test/db.test.ts" }))).toMatch(/test-only/);
  });

  it("keeps credentials in URLs as findings (a live dry run caught the upstream precedent hiding one)", () => {
    expect(PRECEDENTS).toMatch(/credential in a URL/);
    expect(PRECEDENTS).not.toMatch(/Logging URLs is assumed safe/);
  });

  it("respects the policy's list of enabled exclusions", () => {
    const c = cand({ title: "Open redirect on /go" });
    expect(applyExclusions([c]).excluded).toHaveLength(1);
    expect(applyExclusions([c], ["dos"]).kept).toHaveLength(1);
  });

  it("verify() reports excluded candidates as dismissed without calling the model for them", async () => {
    const calls: unknown[] = [];
    const ai: AiBinding = { run: async (_m, input) => (calls.push(input), { response: JSON.stringify({ verdicts: [{ index: 0, verdict: "keep", confidence: 0.9 }] }) }) };
    const opts = { model: "m", verifyModel: "v", maxChars: 10000, minConfidence: 0.6 };
    const files = [{ path: "src/api.ts", lines: [{ line: 1, text: "x" }], content: "x" }];
    const r = await verify(ai, opts, [cand({ title: "Missing rate limit on search" }), cand({ title: "SQL injection in search" })], files);
    expect(r.dismissed[0].reason).toMatch(/excluded by rule/);
    expect(r.kept.map((k) => k.title)).toEqual(["SQL injection in search"]);
    expect(JSON.stringify(calls[0])).toContain("False-positive precedents");
    const none = await verify(ai, opts, [cand({ title: "Potential memory leak" })], files);
    expect(none.kept).toHaveLength(0);
    expect(calls).toHaveLength(1);
  });
});

describe("EPSS and CISA KEV", () => {
  it("finds the CVE in OSV evidence", () => {
    expect(cveOf(depFinding({}))).toBe("CVE-2021-44228");
    expect(cveOf(depFinding({ evidence: "GHSA-only" }))).toBeNull();
  });

  it("raises severity for KEV and high EPSS, and the policy blocks KEV", () => {
    const [kev] = applyExploitation([depFinding({})], new Map([["CVE-2021-44228", 0.97]]), new Set(["CVE-2021-44228"]));
    expect(kev.severity).toBe("critical");
    expect(kev.knownExploited).toBe(true);
    expect(kev.evidence).toMatch(/CISA KEV.*EPSS 97\.0%/);
    const [epss] = applyExploitation([depFinding({ severity: "low" })], new Map([["CVE-2021-44228", 0.2]]), new Set());
    expect(epss.severity).toBe("high");
    const [low] = applyExploitation([depFinding({ severity: "low" })], new Map([["CVE-2021-44228", 0.001]]), new Set());
    expect(low.severity).toBe("low");
    expect(low.evidence).toContain("EPSS 0.10%");

    const kevMedium = { ...depFinding({ severity: "medium" }), knownExploited: true };
    expect(applyPolicy([kevMedium], { ...DEFAULT_POLICY, block_dependencies_at: "critical" })[0].blocking).toBe(true);
    expect(applyPolicy([kevMedium], { ...DEFAULT_POLICY, block_dependencies_at: "critical", block_known_exploited: false })[0].blocking).toBe(false);
  });

  it("searches the KEV feed as text and makes no requests without a CVE", async () => {
    const urls: string[] = [];
    const f = (async (url: string) => {
      urls.push(String(url));
      if (String(url).includes("epss")) return json({ data: [{ cve: "CVE-2021-44228", epss: "0.9" }] });
      return new Response('{"vulnerabilities":[{"cveID": "CVE-2021-44228"}]}');
    }) as typeof fetch;
    expect(await knownExploited(["CVE-2021-44228", "CVE-2020-0001"], f)).toEqual(new Set(["CVE-2021-44228"]));
    urls.length = 0;
    const out = await enrichExploitation([depFinding({}), depFinding({ id: "2", evidence: "GHSA-only" })], f);
    expect(urls).toHaveLength(2);
    expect(out[0].knownExploited).toBe(true);
    expect(out[1].evidence).toBe("GHSA-only");
    urls.length = 0;
    await enrichExploitation([depFinding({ evidence: "GHSA-only" })], f);
    expect(urls).toHaveLength(0);
  });

  it("leaves findings unchanged when both sources are down", async () => {
    const down = (async () => new Response("no", { status: 503 })) as unknown as typeof fetch;
    const [x] = await enrichExploitation([depFinding({})], down);
    expect(x.severity).toBe("medium");
    expect(x.knownExploited).toBeUndefined();
  });
});

describe("deps.dev package health", () => {
  const dep: Dependency = { name: "expresss", version: "1.0.0", ecosystem: "npm", manifest: "package.json", dev: false, approximate: false, added: true };
  const now = Date.parse("2026-11-02T00:00:00Z");

  it("flags a brand-new package as medium and quiet facts as nothing", async () => {
    const f = await healthFinding({ dep, firstPublished: now - 3 * 86_400_000, versionCount: 1, sourceRepo: null }, now);
    expect(f?.severity).toBe("medium");
    expect(f?.evidence).toMatch(/3 day\(s\) ago.*no source repository/);
    expect(f?.blocking).toBe(false);
    expect(await healthFinding({ dep, firstPublished: now - 900 * 86_400_000, sourceRepo: "github.com/a/b", scorecard: 7.5, deprecated: null }, now)).toBeNull();
    const old = await healthFinding({ dep, firstPublished: now - 900 * 86_400_000, sourceRepo: "github.com/a/b", scorecard: 2.1, deprecated: "use x" }, now);
    expect(old?.severity).toBe("low");
    expect(old?.evidence).toMatch(/deprecated: use x.*Scorecard 2\.1/);
  });

  it("only checks packages added by name, and caps the requests", async () => {
    const urls: string[] = [];
    const f = (async (url: string) => {
      urls.push(String(url));
      if (String(url).includes("/versions/")) return json({ isDeprecated: false, relatedProjects: [{ projectKey: { id: "github.com/x/y" }, relationType: "SOURCE_REPO" }] });
      if (String(url).includes("/projects/")) return json({ scorecard: { overallScore: 8 } });
      return json({ versions: [{ publishedAt: "2015-01-01T00:00:00Z" }] });
    }) as typeof fetch;
    const deps = [dep, { ...dep, name: "bumped", added: false }, ...Array.from({ length: 8 }, (_, i) => ({ ...dep, name: `p${i}` }))];
    expect(await findPackageHealth(deps, f, 5)).toEqual([]);
    expect(urls.length).toBe(15);
    expect(urls.some((u) => u.includes("bumped"))).toBe(false);
  });
});

describe("code-scanning alerts", () => {
  const files = [{ path: ".github/workflows/ci.yml", lines: [{ line: 12, text: "run: echo ${{ github.event.issue.title }}" }] }];
  const alert = (line: number, path = ".github/workflows/ci.yml") => ({
    number: 1,
    html_url: "https://github.com/o/r/security/code-scanning/1",
    tool: { name: "zizmor" },
    rule: { id: "template-injection", description: "code injection via template expansion", security_severity_level: "high" },
    most_recent_instance: { message: { text: "attacker-controlled title expanded in run" }, location: { path, start_line: line } },
  });

  it("keeps only alerts on added lines and turns them into verifier candidates", () => {
    const kept = scannerAlerts([alert(12), alert(40), alert(12, "other.yml")], files);
    expect(kept).toHaveLength(1);
    const [c] = scannerCandidates(kept);
    expect(c.category).toBe("ci-cd");
    expect(c.severity).toBe("high");
    expect(c.specialist).toBe("scanner:zizmor");
    expect(c.fix).toContain("code-scanning/1");
    expect(scannerAlerts(null, files)).toEqual([]);
  });

  it("summarises what was read", () => {
    expect(scannerSummary(null)).toMatch(/not read/);
    expect(scannerSummary([])).toMatch(/no open alerts/);
    expect(scannerSummary(scannerAlerts([alert(12)], files))).toBe("zizmor: 1");
  });

  it("re-reviews only for configured scanner workflows", () => {
    expect(isScannerWorkflow("CodeQL")).toBe(true);
    expect(isScannerWorkflow("zizmor ")).toBe(true);
    expect(isScannerWorkflow("tests")).toBe(false);
    expect(isScannerWorkflow("semgrep", "semgrep, zizmor")).toBe(true);
  });
});

describe("policy settings for the new checks", () => {
  it("validates model_exclusions and block_known_exploited", () => {
    expect(parsePolicy({ version: "v2", model_exclusions: ["dos"] }).model_exclusions).toEqual(["dos"]);
    expect(() => parsePolicy({ version: "v2", model_exclusions: ["made-up"] })).toThrow(/model_exclusions/);
    expect(() => parsePolicy({ version: "v2", block_known_exploited: "yes" })).toThrow(/block_known_exploited/);
    expect(parsePolicy({ version: "v2" }).block_known_exploited).toBe(true);
  });
});

describe("CodeGuard rules for /security fix", () => {
  it("routes findings to the right rules and stays in budget", () => {
    expect(codeguardRules({ category: "injection", title: "SQL injection in search" })).toEqual(["input-validation-injection"]);
    expect(codeguardRules({ category: "secrets", title: "Hardcoded API key" })[0]).toBe("hardcoded-credentials");
    expect(codeguardRules({ category: "ci-cd", title: "Workflow script injection" })).toContain("devops-ci-cd-containers");
    expect(codeguardRules({ category: "prompt-injection", title: "Model output picks the issue to comment on" })).toContain("mcp-security");
    for (const id of ["input-validation-injection", "hardcoded-credentials", "mcp-security"]) expect(CODEGUARD_RULES[id]).toBeDefined();
    const t = codeguardText(["input-validation-injection", "client-side-web-security"], 3000);
    expect(t.length).toBeLessThanOrEqual(3000);
    expect(t).toContain("CodeGuard");
    expect(codeguardText([], 3000)).toBe("");
  });
});
