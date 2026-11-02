/**
 * One comment per pull request, edited in place on every push. Model-written text is sanitised:
 * no HTML, no @mentions (a finding must not ping people), no breaking out of the layout.
 */
import type { Dismissed, Finding } from "./findings";
import { rank } from "./findings";
import { SKILL_LABEL, SKILL_SOURCE_URL } from "./skills";

export const MARKER = "<!-- clawbuilders-security-reviewer -->";

export interface Report {
  repo: string;
  ref: string;
  sha: string;
  number: number;
  policyVersion: string;
  model: string;
  findings: Finding[];
  dismissed: Dismissed[];
  stats: { files: number; reviewedByModel: number; omitted: string[]; skippedModel?: string; skills?: string[] };
  waived?: { id: string; reason: string; approvedBy: string; expires: string }[];
}

/** Make untrusted text safe to drop into Markdown. */
export function clean(s: string | undefined, max = 400): string {
  if (!s) return "";
  return s
    .replace(/<[^>]*>/g, "")
    .replace(/@(?=[A-Za-z0-9-])/g, "@​")
    .replace(/`{3,}/g, "``")
    .replace(/\r?\n+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

const code = (s: string) => `\`${s.replace(/`/g, "'")}\``;

function where(f: Finding): string {
  return code(`${f.file}${f.line ? `:${f.line}` : ""}`);
}

function item(f: Finding, n: number): string {
  const lines = [`${n}. **[${f.severity}] ${clean(f.title, 160)}** ${where(f)} · ${f.category} · id ${code(f.id)}${f.source === "deterministic" ? " · deterministic" : ""}`];
  if (f.reachability) lines.push(`   - How it is reached: ${clean(f.reachability)}`);
  if (f.evidence) lines.push(`   - Evidence: ${code(clean(f.evidence, 200))}`);
  if (f.fix) lines.push(`   - Fix: ${clean(f.fix)}`);
  return lines.join("\n");
}

export function summaryLine(r: Report): string {
  const blocking = r.findings.filter((f) => f.blocking).length;
  const other = r.findings.length - blocking;
  if (r.findings.length === 0) return "No security findings";
  return `${blocking} blocking, ${other} to review`;
}

export function renderReport(r: Report): string {
  const ranked = rank(r.findings);
  const blocking = ranked.filter((f) => f.blocking);
  const rest = ranked.filter((f) => !f.blocking);
  const out: string[] = [MARKER, `## Security review: ${summaryLine(r)}`];
  out.push(
    `Commit ${code(r.sha.slice(0, 7))} · ${r.stats.files} file${r.stats.files === 1 ? "" : "s"} checked · ${r.stats.reviewedByModel} read by ${code(r.model.replace(/^@cf\//, ""))} · policy ${code(r.policyVersion)}`,
  );
  if (r.stats.skippedModel) out.push(`\n_Model pass skipped: ${clean(r.stats.skippedModel)}_`);
  if (r.stats.skills?.length) out.push(`\n_Methodology: [${SKILL_LABEL}](${SKILL_SOURCE_URL}) (${r.stats.skills.map((s) => clean(s, 80)).join("; ")})_`);
  if (blocking.length) out.push("\n### Blocking", ...blocking.map((f, i) => item(f, i + 1)));
  if (rest.length) out.push("\n### Review", ...rest.map((f, i) => item(f, i + 1)));
  if (r.findings.length === 0) out.push("\nNothing reachable was found in the lines under review.");
  if (r.waived?.length) {
    out.push("\n### Waived", ...r.waived.map((w) => `- ${code(w.id)}: ${clean(w.reason, 200)} (approved by ${clean(w.approvedBy, 40)}, expires ${w.expires})`));
  }
  if (r.dismissed.length) {
    out.push(
      `\n<details><summary>${r.dismissed.length} candidate finding(s) dismissed by the verifier</summary>\n`,
      ...r.dismissed.slice(0, 30).map((d) => `- ${clean(d.title, 120)} (${code(d.file)}): ${clean(d.reason, 200)}`),
      "\n</details>",
    );
  }
  if (r.stats.omitted.length) out.push(`\n_Too large for one model pass, checked by rules only: ${r.stats.omitted.slice(0, 15).map(code).join(", ")}_`);
  out.push(
    "\n---\n_Security only: no style or quality findings. Deterministic findings come from rules and the OSV.dev database; model findings were proposed by one pass and confirmed by a second. It flags risk for a person to judge and can miss things._",
  );
  return out.join("\n");
}
