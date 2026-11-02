/**
 * Triage with Clef, Cloudflare's decision model: one yes/no probability per specialist ("does this change need you?").
 * It returns numbers code can branch on, not prose. Triage can only ADD work beyond the deterministic floor:
 * a specialist forced by a signal runs even at probability 0, and any failure runs everyone (fail open).
 */
import type { AiBinding } from "../starter/src/lib/model";
import type { Specialist } from "./specialists";

export interface TriageResult {
  run: string[];
  skipped: string[];
  tier: "clef" | "fail-open";
  probs: Record<string, number>;
}

export function summarise(files: { path: string; lines: { text: string }[] }[], maxChars = 6000): string {
  let out = "";
  for (const f of files) {
    const head = `File ${f.path} (+${f.lines.length} lines)\n`;
    const body = f.lines.slice(0, 40).map((l) => `+ ${l.text.slice(0, 160)}`).join("\n");
    const block = `${head}${body}\n`;
    if (out.length + block.length > maxChars) {
      out += `${head}`;
      continue;
    }
    out += block;
  }
  return out.slice(0, maxChars);
}

export async function triage(ai: AiBinding, summary: string, specialists: Specialist[], forced: Set<string>, threshold: number): Promise<TriageResult> {
  const ids = specialists.map((s) => s.id);
  try {
    const questions = Object.fromEntries(specialists.map((s) => [s.id, { type: "noul", instructions: s.question }]));
    const res = (await ai.run("@cf/cloudflare/clef-flash", { model: "clef-flash", state: summary, questions })) as {
      answers?: Record<string, { noul?: number }>;
      result?: { answers?: Record<string, { noul?: number }> };
    };
    const answers = res?.answers ?? res?.result?.answers;
    if (!answers) throw new Error("Clef returned no answers");
    const probs = Object.fromEntries(ids.map((id) => [id, typeof answers[id]?.noul === "number" ? (answers[id].noul as number) : 1]));
    const run = ids.filter((id) => forced.has(id) || probs[id] >= threshold);
    return { run, skipped: ids.filter((id) => !run.includes(id)), tier: "clef", probs };
  } catch {
    return { run: ids, skipped: [], tier: "fail-open", probs: Object.fromEntries(ids.map((id) => [id, 1])) };
  }
}
