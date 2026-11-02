/**
 * The committee. Each specialist owns one angle and gets only the files that matter to it. A specialist is just data
 * (an id, a triage question, instructions, a path filter, and the domains of Cloudflare's security-audit skill it loads),
 * so a repository can add its own through the policy API without a redeploy. The model never decides alone which specialists can be skipped: a deterministic signal in a
 * specialist's area always wakes it.
 */
import type { Focus } from "../starter/src/lib/model";
import type { SourceFile } from "../starter/src/lib/files";
import { isWorkflow } from "../starter/src/lib/files";
import type { SignalData } from "../starter/src/lib/pipeline";
import { isSkillDomain, SKILL_DOMAINS } from "../starter/src/lib/skills";

export interface Specialist extends Focus {
  /** One yes/no question for the triage model. */
  question: string;
  /** Files this specialist reads; undefined = every reviewable file. */
  paths?: (path: string) => boolean;
  /** Signal categories that force this specialist to run. */
  categories: string[];
}

const CONFIG = (p: string) =>
  isWorkflow(p) || /(^|\/)(Dockerfile|docker-compose\.ya?ml|wrangler\.(json|jsonc|toml)|_headers|_redirects|.*\.tf|nginx\.conf|vercel\.json|netlify\.toml)$/.test(p) || /(cors|headers|middleware|config|security)/i.test(p);

export const BUILT_IN: Specialist[] = [
  {
    id: "appsec",
    name: "Application security specialist",
    question: "Does this change handle requests, user input, database queries, files, HTML output, redirects or outbound requests?",
    categories: ["injection", "xss", "path-traversal", "ssrf", "open-redirect"],
    instructions:
      "Look for injection (SQL, NoSQL, shell, template, code), cross-site scripting, path traversal, server-side request forgery, " +
      "open redirects, unsafe deserialization and unsafe file upload handling. Trace each from the request, webhook or other " +
      "untrusted input to the sink.",
    skill: [
      { domain: "ATTACK-CLASSES", classes: ["Injection", "Resource and file handling", "Feature abuse and data leakage", "Chained vulnerabilities and trust boundaries", "Obvious things"] },
      { domain: "CLIENT-SIDE", core: false, classes: ["DOM and object-state attack classes", "Cross-origin messaging and network attack classes"] },
    ],
  },
  {
    id: "identity",
    name: "Authentication and access-control specialist",
    question: "Does this change touch login, sessions, tokens, API keys, permissions, roles, ownership checks or cryptography?",
    categories: ["auth", "crypto", "secrets"],
    instructions:
      "Look for missing or wrong authorization (including one user reaching another user's records by changing an id), broken " +
      "authentication, session fixation, tokens that are not verified or never expire, secrets compared without constant time, " +
      "secrets exposed in URLs or logs, weak or misused cryptography, and webhook handlers that skip signature checks.",
    skill: [
      { domain: "WEB-PROTOCOL-AND-AUTH", classes: ["Browser-session attack classes", "API-key and mTLS attack classes", "Federated-identity attack classes", "MFA, passkey, and account-transition attack classes", "Universal moves"] },
      { domain: "ATTACK-CLASSES", core: false, classes: ["Access control", "Cryptography and secrets"] },
    ],
  },
  {
    id: "supply-chain",
    name: "Supply-chain specialist",
    question: "Does this change add or update dependencies, install scripts, build steps, or code fetched at build or run time?",
    categories: ["dependencies"],
    paths: (p) => /(package\.json|requirements[^/]*\.txt|pyproject\.toml|Cargo\.toml|go\.mod|Dockerfile|\.npmrc|install|postinstall|build|\.github\/workflows\/)/i.test(p),
    instructions:
      "Look for risky dependency changes: install or postinstall scripts that fetch and run code, dependencies pulled from git URLs " +
      "or unpinned registries, packages whose names look like a typo of a popular package, and scripts or images fetched without " +
      "a pinned version or checksum.",
    skill: [{ domain: "SUPPLY-CHAIN-AND-RELEASE", classes: ["Dependency and build-input attack classes", "Release and update attack classes", "Universal moves"] }],
  },
  {
    id: "ci-cloud",
    name: "CI/CD and cloud configuration specialist",
    question: "Does this change GitHub Actions workflows, deployment, infrastructure, CORS, security headers, cookies, or Cloudflare/Wrangler configuration?",
    categories: ["ci-cd", "config"],
    paths: CONFIG,
    instructions:
      "Look for GitHub Actions script injection, pull_request_target jobs that run untrusted code, over-broad workflow permissions, " +
      "secrets exposed to forks, third-party actions not pinned to a commit, permissive CORS with credentials, missing or weakened " +
      "security headers and cookie flags, admin or internal routes exposed without an access check, and debug or dry-run modes " +
      "left on in production configuration.",
    skill: [
      { domain: "CLOUD-AND-DEPLOYMENT", classes: ["Configuration and secret lifecycle attack classes", "Managed storage, events, and edge attack classes", "Ingress, network, and control-plane attack classes", "Workload identity and IAM attack classes"] },
      { domain: "SUPPLY-CHAIN-AND-RELEASE", core: false, classes: ["CI and automation attack classes"] },
    ],
  },
  {
    id: "ai-agent",
    name: "AI and agent security specialist",
    question: "Does this change call a language model, build prompts, define agent tools, or act on model output?",
    categories: ["prompt-injection", "ai-agent"],
    instructions:
      "Use the OWASP Top 10 for Agentic Applications (2026). Look for agent goal hijack (untrusted text from pages, documents, " +
      "issues, emails or tool results placed in a prompt that can change what the agent does), tool misuse (tools with side " +
      "effects such as writes, payments, email or deploys callable without a person confirming), over-broad credentials given " +
      "to an agent, model output executed or rendered or used in queries without validation, secrets placed in prompts, and " +
      "missing limits on agent loops or spend.",
    skill: [{ domain: "AI-AND-LLM" }],
  },
  {
    id: "data-isolation",
    name: "Data isolation and lifecycle specialist",
    question: "Does this change read, write, export, delete or share records that belong to different users, teams or tenants?",
    categories: [],
    instructions:
      "Look for one user, team or tenant reaching another's records: queries missing an owner or tenant filter, ids taken from " +
      "the request without an ownership check, caches or search indexes shared across tenants, exports and backups that " +
      "include other people's data, and deletes or revocations that leave copies, sessions or derived data behind.",
    skill: [
      { domain: "DATA-ISOLATION-AND-LIFECYCLE" },
      { domain: "ATTACK-CLASSES", core: false, classes: ["Business logic"] },
    ],
  },
];

export interface CustomSpecialist {
  id: string;
  name: string;
  question: string;
  instructions: string;
  /** Path prefixes; empty = all reviewable files. */
  paths?: string[];
  /** Domains of the vendored security-audit skill to load, for example ["DATA-ISOLATION-AND-LIFECYCLE"]. */
  skill?: string[];
}

export function parseCustomSpecialists(input: unknown): CustomSpecialist[] {
  if (input === undefined) return [];
  if (!Array.isArray(input) || input.length > 5) throw new Error("specialists must be a list of at most 5");
  return input.map((raw, i) => {
    const s = raw as Partial<CustomSpecialist>;
    const str = (v: unknown, max: number, what: string) => {
      if (typeof v !== "string" || !v.trim() || v.length > max) throw new Error(`specialists[${i}].${what} must be text up to ${max} characters`);
      return v.trim();
    };
    const id = str(s.id, 30, "id");
    if (!/^[a-z0-9-]+$/.test(id) || BUILT_IN.some((b) => b.id === id)) throw new Error(`specialists[${i}].id must be lowercase-with-dashes and not a built-in id`);
    if (s.paths !== undefined && (!Array.isArray(s.paths) || s.paths.some((p) => typeof p !== "string"))) throw new Error(`specialists[${i}].paths must be a list of path prefixes`);
    if (s.skill !== undefined && (!Array.isArray(s.skill) || s.skill.length > 3 || s.skill.some((d) => typeof d !== "string" || !isSkillDomain(d)))) {
      throw new Error(`specialists[${i}].skill must list up to 3 of: ${SKILL_DOMAINS.join(", ")}`);
    }
    return { id, name: str(s.name, 60, "name"), question: str(s.question, 300, "question"), instructions: str(s.instructions, 1500, "instructions"), paths: s.paths, skill: s.skill };
  });
}

export function toSpecialist(c: CustomSpecialist): Specialist {
  return {
    id: c.id,
    name: c.name,
    question: c.question,
    instructions: c.instructions,
    categories: [],
    paths: c.paths?.length ? (p) => c.paths!.some((prefix) => p.startsWith(prefix)) : undefined,
    skill: c.skill?.map((domain) => ({ domain })),
  };
}

export function filesFor(s: Specialist, files: SourceFile[]): SourceFile[] {
  return s.paths ? files.filter((f) => s.paths!(f.path)) : files;
}

/** Specialists forced on by deterministic signals or findings in their categories. */
export function forcedBy(specialists: Specialist[], categories: string[]): Set<string> {
  return new Set(specialists.filter((s) => s.categories.some((c) => categories.includes(c))).map((s) => s.id));
}

/** Specialists with no files to read never run, whatever triage says. */
export function withFiles(specialists: Specialist[], files: SourceFile[]): Specialist[] {
  return specialists.filter((s) => filesFor(s, files).length > 0);
}

export function signalCategories(signals: SignalData[], findingCategories: string[], ruleCategory: (id: string) => string | undefined): string[] {
  return [...new Set([...findingCategories, ...signals.map((s) => ruleCategory(s.ruleId)).filter((c): c is string => Boolean(c))])];
}
