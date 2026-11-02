import { describe, expect, it } from "vitest";
import { DOMAINS } from "../starter/src/lib/skills.generated";
import { skillText, validationText } from "../starter/src/lib/skills";
import { GENERALIST } from "../starter/src/lib/model";
import { BUILT_IN, parseCustomSpecialists, toSpecialist } from "../src/specialists";

describe("security-audit skill wiring", () => {
  it("every domain and attack class a reviewer asks for exists in the vendored skill", () => {
    for (const s of [GENERALIST, ...BUILT_IN]) {
      expect(s.skill?.length, `${s.id} loads no skill`).toBeTruthy();
      for (const ref of s.skill ?? []) {
        const d = DOMAINS[ref.domain];
        expect(d, `${s.id}: unknown domain ${ref.domain}`).toBeDefined();
        for (const title of ref.classes ?? []) expect(d.classes.map((c) => c.title), `${s.id}: ${ref.domain} lost "${title}"`).toContain(title);
      }
    }
  });

  it("loads core discipline first and stays inside the budget", () => {
    const appsec = BUILT_IN.find((s) => s.id === "appsec")!;
    const { text, loaded } = skillText(appsec.skill!, 3000);
    expect(text.length).toBeLessThanOrEqual(3000);
    expect(text).toContain("source-only");
    expect(loaded).toContain("ATTACK-CLASSES");
    const ai = skillText([{ domain: "AI-AND-LLM" }], 7000);
    expect(ai.text.indexOf("Core discipline")).toBeLessThan(ai.text.indexOf("Tool and action attack classes"));
    expect(skillText(appsec.skill!, 0).text).toBe("");
  });

  it("gives the verifier the skill's checklist plus the involved domains' validation rules", () => {
    const v = validationText(["AI-AND-LLM", "AI-AND-LLM", "NOPE"], 8000);
    expect(v).toContain("Verify every trace");
    expect(v.match(/\[AI-AND-LLM\.md\] Validation rules/g)).toHaveLength(1);
    expect(v).not.toContain("sandbox");
  });

  it("lets a custom specialist load a skill domain, and rejects unknown ones", () => {
    const [c] = parseCustomSpecialists([{ id: "tenants", name: "Tenant reviewer", question: "Tenant data?", instructions: "Check tenant filters.", skill: ["DATA-ISOLATION-AND-LIFECYCLE"] }]);
    expect(toSpecialist(c).skill).toEqual([{ domain: "DATA-ISOLATION-AND-LIFECYCLE" }]);
    expect(() => parseCustomSpecialists([{ id: "x", name: "x", question: "y", instructions: "z", skill: ["MADE-UP"] }])).toThrow(/must list up to 3/);
  });
});
