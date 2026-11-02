/**
 * Secure-coding rules from CoSAI's Project CodeGuard (CC-BY-4.0), used when the committee writes a fix.
 *
 * CodeGuard is written for agents that generate code ("do this when you write it"), so it belongs in /security fix,
 * not in the reviewers: its hardening checklists would turn into "missing best practice" findings, which the
 * exclusion rules deliberately drop. When writing a fix, the same checklists keep the suggestion from swapping one
 * weakness for another.
 */
import { CODEGUARD_COMMIT, CODEGUARD_RULES, CODEGUARD_SOURCE } from "./codeguard.generated";
import type { Finding } from "../starter/src/lib/findings";

export const CODEGUARD_LABEL = `cosai-oasis/project-codeguard@${CODEGUARD_COMMIT.slice(0, 7)} (CC-BY-4.0)`;
export const CODEGUARD_URL = `${CODEGUARD_SOURCE}/tree/${CODEGUARD_COMMIT}/skills/codeguard/rules`;

/** Keyword -> rule ids, checked against the finding's category and title, first match first. */
const ROUTES: [RegExp, string[]][] = [
  [/secret|credential|api.?key|hard.?coded|private.?key/, ["hardcoded-credentials"]],
  [/sql|nosql|injection|command|shell|exec|template|eval/, ["input-validation-injection"]],
  [/xss|cross.?site.?script|html|dom|csp|client/, ["client-side-web-security"]],
  [/path|traversal|file|upload/, ["file-handling-and-uploads"]],
  [/deserial|xml|xxe|pickle|yaml/, ["xml-and-serialization"]],
  [/session|cookie|csrf/, ["session-management-and-cookies"]],
  [/auth|login|jwt|token|mfa|password|oauth/, ["authentication-mfa", "session-management-and-cookies"]],
  [/access|authori[sz]|permission|idor|ownership|tenant|isolation/, ["authorization-access-control"]],
  [/crypt|hash|cipher|random|tls|signature/, ["crypto-algorithms", "additional-cryptography"]],
  [/ssrf|cors|api|webhook|graphql|redirect/, ["api-web-services"]],
  [/\bci\b|ci-cd|workflow|github.action|docker|container|pipeline/, ["devops-ci-cd-containers"]],
  [/terraform|iac|cloud|bucket|iam|config/, ["iac-security"]],
  [/prompt|agent|llm|\bmodel\b|mcp|\btool|\bai\b/, ["mcp-security"]],
  [/\blog/, ["logging"]],
  [/privacy|pii|personal|data/, ["privacy-data-protection", "data-storage"]],
  [/depend|supply|package|npm|pypi/, ["supply-chain-security"]],
];

export function codeguardRules(f: Pick<Finding, "category" | "title">): string[] {
  const text = `${f.category} ${f.title}`.toLowerCase();
  const ids: string[] = [];
  for (const [re, rules] of ROUTES) if (re.test(text)) for (const r of rules) if (!ids.includes(r) && CODEGUARD_RULES[r]) ids.push(r);
  return ids.slice(0, 2);
}

/** The rule text for a fix prompt, within `maxChars`. */
export function codeguardText(ids: string[], maxChars = 3500): string {
  if (ids.length === 0 || maxChars <= 0) return "";
  let text = "Secure-coding rules from CoSAI Project CodeGuard. Follow them in the replacement; ignore anything about other files, tools or processes.\n";
  for (const id of ids) {
    const r = CODEGUARD_RULES[id];
    if (!r) continue;
    const head = `\n[${r.file}] ${r.title}\n`;
    const room = maxChars - text.length - head.length - 6; // 6 = "\n...\n"
    if (room < 400) break;
    text += `${head}${r.text.length > room ? `${r.text.slice(0, room)}\n...` : r.text}\n`;
  }
  return text;
}
