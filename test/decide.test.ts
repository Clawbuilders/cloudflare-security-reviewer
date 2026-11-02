import { describe, expect, it } from "vitest";
import type { Finding } from "../starter/src/lib/findings";
import { dedupe, rank } from "../starter/src/lib/findings";
import { applyPolicy, DEFAULT_POLICY, parsePolicy } from "../starter/src/lib/policy";
import { parseJsonObject, toCandidates } from "../starter/src/lib/model";
import { clean, MARKER, renderReport } from "../starter/src/lib/report";

const base = (o: Partial<Finding>): Finding => ({
  id: "00000000", title: "t", category: "injection", severity: "high", source: "model", file: "src/a.ts", rule: "model", confidence: 0.9, blocking: false, ...o,
});

describe("policy", () => {
  it("always blocks a committed credential, even under a lenient policy", () => {
    const lenient = { ...DEFAULT_POLICY, block_rules_at: "critical" as const, report_min_confidence: 1, ignore_paths: ["src/"] };
    const [f] = applyPolicy([base({ source: "deterministic", rule: "aws-access-key", category: "secrets", severity: "critical", confidence: 1 })], lenient);
    expect(f.blocking).toBe(true);
  });

  it("blocks confident high model findings, keeps medium ones as review, hides dev-dependency advisories", () => {
    const out = applyPolicy(
      [
        base({ id: "a" }),
        base({ id: "b", severity: "medium" }),
        base({ id: "c", category: "dependencies", source: "deterministic", rule: "GHSA-1", evidence: "GHSA-1 (dev dependency)", confidence: 1 }),
      ],
      DEFAULT_POLICY,
    );
    expect(out.map((f) => [f.id, f.blocking])).toEqual([["a", true], ["b", false]]);
  });

  it("rejects unknown keys so a typo cannot weaken a policy", () => {
    expect(() => parsePolicy({ version: "v2", block_model_att: "low" })).toThrow(/unknown policy key/);
    expect(parsePolicy({ version: "v2", block_model_at: "medium" }).block_model_at).toBe("medium");
  });
});

describe("findings", () => {
  it("keeps the deterministic copy of a duplicate and ranks blocking first", () => {
    const d = dedupe([base({ id: "x", source: "model" }), base({ id: "x", source: "deterministic", rule: "r" })]);
    expect(d).toHaveLength(1);
    expect(d[0].source).toBe("deterministic");
    expect(rank([base({ id: "1", severity: "critical" }), base({ id: "2", blocking: true, severity: "medium" })]).map((f) => f.id)).toEqual(["2", "1"]);
  });
});

describe("model output validation", () => {
  it("parses JSON wrapped in a code fence", () => {
    expect(parseJsonObject('Here:\n```json\n{"findings":[]}\n```')).toEqual({ findings: [] });
  });

  it("drops findings without a path from untrusted input, or pointing at files not sent", () => {
    const c = toCandidates(
      {
        findings: [
          { title: "SQLi", category: "Injection", severity: "high", file: "src/a.ts", line: 3, untrusted_input: "query string", flow: "into db.prepare", fix: "bind", confidence: 0.9 },
          { title: "Vague worry", file: "src/a.ts", untrusted_input: "", flow: "" },
          { title: "Elsewhere", file: "src/other.ts", untrusted_input: "x", flow: "y" },
          { title: "Comment tells AI reviewers to approve", category: "prompt-injection", file: "src/a.ts" },
        ],
      },
      ["src/a.ts"],
      "security",
    );
    expect(c.map((x) => x.title)).toEqual(["SQLi", "Comment tells AI reviewers to approve"]);
    expect(c[0].category).toBe("injection");
  });
});

describe("report", () => {
  it("strips HTML and defuses @mentions in model text", () => {
    expect(clean("<img src=x onerror=alert(1)> ping @octocat")).toBe("ping @​octocat");
  });

  it("renders one comment with the marker and the policy version", () => {
    const body = renderReport({
      repo: "o/r", number: 1, ref: "b", sha: "abcdef0123", policyVersion: "v7", model: "m", dismissed: [],
      findings: [base({ blocking: true, reachability: "query -> sql" })],
      stats: { files: 2, reviewedByModel: 1, omitted: [] },
    });
    expect(body.startsWith(MARKER)).toBe(true);
    expect(body).toContain("1 blocking, 0 to review");
    expect(body).toContain("policy `v7`");
  });
});
