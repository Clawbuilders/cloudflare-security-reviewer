import { describe, expect, it } from "vitest";
import { allowed, decideApproval, decideRejection, isActive, parseCommand, waivable, type Waiver } from "../src/commands";
import { BUILT_IN, filesFor, forcedBy, parseCustomSpecialists, toSpecialist } from "../src/specialists";
import { triage } from "../src/triage";

const waiver = (o: Partial<Waiver> = {}): Waiver => ({
  finding_id: "1a2b3c4d", reason: "sandbox only", requested_by: "alice", approved_by: null, status: "pending", days: 30, created_at: 0, expires_at: null, policy_version: "v1", ...o,
});

describe("commands", () => {
  it("parses a waiver with an expiry and ignores quoted or fenced text", () => {
    expect(parseCommand("/waive 1A2B3C4D 14d vendor sandbox only")).toEqual({ cmd: "waive", findingId: "1a2b3c4d", reason: "vendor sandbox only", days: 14 });
    expect(parseCommand("/waive 1a2b3c4d no reason given here")?.cmd).toBe("waive");
    expect(parseCommand("> /approve 1a2b3c4d")).toBeNull();
    expect(parseCommand("```\n/approve 1a2b3c4d\n```")).toBeNull();
    expect(parseCommand("/waive 1a2b3c4d 400d too long")).toBeNull();
    expect(parseCommand("/security fix 1a2b3c4d")).toEqual({ cmd: "fix", findingId: "1a2b3c4d" });
  });

  it("enforces four eyes and write access for approval", () => {
    expect(decideApproval(waiver(), "alice", "admin")).toMatchObject({ ok: false });
    expect(decideApproval(waiver(), "bob", "triage")).toMatchObject({ ok: false });
    expect(decideApproval(waiver(), "renovate[bot]", "write")).toMatchObject({ ok: false });
    expect(decideApproval(waiver(), "bob", "write")).toEqual({ ok: true });
    expect(decideRejection(waiver(), "alice", "read")).toEqual({ ok: true });
  });

  it("lets a waiver lapse at its expiry and never waives a committed credential", () => {
    const w = waiver({ status: "approved", approved_by: "bob", expires_at: 1000 });
    expect(isActive(w, 999)).toBe(true);
    expect(isActive(w, 1000)).toBe(false);
    expect(waivable("github-token", true)).toBe(false);
    expect(allowed("fix", "carol", "triage")).toBe(false);
  });
});

describe("specialists", () => {
  it("forces specialists whose area has a deterministic signal", () => {
    expect([...forcedBy(BUILT_IN, ["ci-cd", "secrets"])].sort()).toEqual(["ci-cloud", "identity"]);
  });

  it("validates custom specialists added through the policy", () => {
    const [c] = parseCustomSpecialists([{ id: "payments", name: "Payments reviewer", question: "Does this touch payments?", instructions: "Check refunds are authorised.", paths: ["src/billing/"] }]);
    const s = toSpecialist(c);
    expect(filesFor(s, [{ path: "src/billing/refund.ts", lines: [] }, { path: "src/ui.ts", lines: [] }]).map((f) => f.path)).toEqual(["src/billing/refund.ts"]);
    expect(() => parseCustomSpecialists([{ id: "appsec", name: "x", question: "y", instructions: "z" }])).toThrow();
  });
});

describe("triage", () => {
  it("runs forced specialists even when Clef says no, and fails open when Clef is down", async () => {
    const ai = { run: async () => ({ answers: { appsec: { noul: 0.05 }, identity: { noul: 0.9 }, "ai-agent": { noul: 0.1 } } }) };
    const some = BUILT_IN.filter((s) => ["appsec", "identity", "ai-agent"].includes(s.id));
    expect((await triage(ai, "diff", some, new Set(["ai-agent"]), 0.35)).run).toEqual(["identity", "ai-agent"]);
    const down = { run: async () => { throw new Error("503"); } };
    expect((await triage(down, "diff", some, new Set(), 0.35)).tier).toBe("fail-open");
  });
});
