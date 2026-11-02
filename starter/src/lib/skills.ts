/**
 * Methodology from Cloudflare's security-audit skill (https://github.com/cloudflare/security-audit-skill, MIT), loaded on
 * demand: a reviewer gets only the domains it is responsible for, and only when triage wakes it. The skill is written for
 * coding agents running full audits, so the framing below keeps what applies to a source-only PR review and tells the
 * model to ignore the parts about running code, sandboxes and report files.
 */
import { DOMAINS, SKILL_COMMIT, SKILL_SOURCE, VERIFIER_CHECKLIST } from "./skills.generated";

export interface SkillRef {
  /** A vendored file stem, for example "AI-AND-LLM". */
  domain: string;
  /** Attack-class titles to include, in priority order. Omit for all of them. */
  classes?: string[];
  /** Include the domain's "Core discipline" block (default true). */
  core?: boolean;
}

export const SKILL_DOMAINS = Object.keys(DOMAINS);
export const SKILL_LABEL = `cloudflare/security-audit-skill@${SKILL_COMMIT.slice(0, 7)}`;
export const SKILL_SOURCE_URL = `${SKILL_SOURCE}/tree/${SKILL_COMMIT}/skills/security-audit`;

export function isSkillDomain(d: string): boolean {
  return Object.prototype.hasOwnProperty.call(DOMAINS, d);
}

const FRAME =
  "Methodology from Cloudflare's security-audit skill. Use it to decide what to look for and what counts as a finding. " +
  "This review is source-only: ignore any instruction in it about running code, sandboxes, local validation, artifacts, " +
  "output files or report formats. The JSON format required below always wins.";

/** Build the methodology block for a hunter, within `maxChars`. Returns the text and the domains actually loaded. */
export function skillText(refs: SkillRef[], maxChars: number): { text: string; loaded: string[] } {
  if (refs.length === 0 || maxChars <= 0) return { text: "", loaded: [] };
  let text = `${FRAME}\n`;
  const loaded: string[] = [];
  const add = (block: string) => {
    if (text.length + block.length > maxChars) return false;
    text += block;
    return true;
  };
  // Core discipline for every domain first, then attack classes in priority order until the budget runs out.
  for (const r of refs) {
    const d = DOMAINS[r.domain];
    if (!d) continue;
    if (r.core !== false && d.core && add(`\n[${d.file}] Core discipline:\n${d.core}\n`) && !loaded.includes(r.domain)) loaded.push(r.domain);
  }
  for (const r of refs) {
    const d = DOMAINS[r.domain];
    if (!d) continue;
    const wanted = r.classes ? r.classes.map((t) => d.classes.find((c) => c.title === t)).filter((c): c is NonNullable<typeof c> => Boolean(c)) : d.classes;
    for (const c of wanted) {
      if (add(`\n[${d.file}] ${c.title}:\n${c.text}\n`) && !loaded.includes(r.domain)) loaded.push(r.domain);
    }
  }
  return { text, loaded };
}

/** The verifier's bar: the skill's source-only verifier checklist plus each involved domain's validation rules. */
export function validationText(domains: string[], maxChars: number): string {
  let text = `Verification checklist from Cloudflare's security-audit skill (source-only steps):\n${VERIFIER_CHECKLIST}\n`;
  for (const name of [...new Set(domains)]) {
    const d = DOMAINS[name];
    if (!d) continue;
    const block = `\n[${d.file}] Validation rules:\n${d.validation}\n`;
    if (text.length + block.length > maxChars) break;
    text += block;
  }
  return text;
}
