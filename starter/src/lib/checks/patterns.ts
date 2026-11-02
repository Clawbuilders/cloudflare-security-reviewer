/**
 * Risky-pattern signals: a small, readable rule set in the spirit of Semgrep, run over the lines under review.
 * A match is a lead, not a verdict: it is handed to the model, which must show how untrusted input reaches it.
 * Two kinds of rule are confident enough to report on their own (GitHub Actions script injection and disabled TLS).
 */
import { fingerprint, type Finding, type Severity } from "../findings";
import { isWorkflow, type SourceFile } from "../files";

export interface PatternRule {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  re: RegExp;
  /** Only run on files whose path matches. */
  only?: (path: string) => boolean;
  /** Confident enough to report even if the model is unavailable or disagrees. */
  standalone?: boolean;
  fix: string;
}

const JS = (p: string) => /\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|astro)$/.test(p);
const PY = (p: string) => p.endsWith(".py");

export const PATTERN_RULES: PatternRule[] = [
  {
    id: "sql-built-from-strings",
    title: "SQL built by string interpolation",
    category: "injection",
    severity: "high",
    re: /\b(query|execute|exec|prepare|raw|unsafe)\s*\(\s*(`[^`]*\$\{|["'][^"']*["']\s*\+)/i,
    fix: "Use bound parameters (`prepare(sql).bind(value)`, placeholders, or a tagged template that parameterises).",
  },
  {
    id: "python-sql-format",
    title: "SQL built with an f-string or % formatting",
    category: "injection",
    severity: "high",
    re: /\.execute\(\s*(f["']|["'][^"']*["']\s*%\s)/,
    only: PY,
    fix: "Pass values as parameters: `cursor.execute(sql, (value,))`.",
  },
  {
    id: "shell-command-interpolation",
    title: "Shell command built from interpolated input",
    category: "injection",
    severity: "high",
    re: /\b(exec|execSync|spawnSync)\s*\(\s*`[^`]*\$\{|subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(/,
    fix: "Call the program with an argument array (`execFile`, `spawn(cmd, args)`, `subprocess.run([...])`) and validate inputs.",
  },
  {
    id: "dynamic-code-eval",
    title: "Dynamic code evaluation",
    category: "injection",
    severity: "medium",
    re: /\beval\s*\(|new\s+Function\s*\(/,
    only: JS,
    fix: "Remove eval; parse data with JSON.parse or a real parser.",
  },
  {
    id: "html-injection-sink",
    title: "Raw HTML sink",
    category: "xss",
    severity: "medium",
    re: /\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML|document\.write\(|v-html=|\{@html\s/,
    fix: "Render text with textContent or framework escaping; sanitise any HTML you must render (for example DOMPurify).",
  },
  {
    id: "tls-verification-disabled",
    title: "TLS certificate verification disabled",
    category: "crypto",
    severity: "high",
    re: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|InsecureSkipVerify\s*:\s*true/,
    standalone: true,
    fix: "Keep certificate verification on; trust a private CA explicitly instead of turning checks off.",
  },
  {
    id: "weak-hash",
    title: "MD5 or SHA-1 used",
    category: "crypto",
    severity: "medium",
    re: /createHash\(\s*["'](md5|sha1)["']\)|hashlib\.(md5|sha1)\(|crypto\.subtle\.digest\(\s*["']SHA-1["']/i,
    fix: "Use SHA-256 for integrity, and a password hash (Argon2id, scrypt, bcrypt, PBKDF2) for passwords.",
  },
  {
    id: "insecure-random-for-secret",
    title: "Math.random used for a security value",
    category: "crypto",
    severity: "medium",
    re: /(token|secret|password|session|nonce|otp|salt|key)\w*\s*[:=][^;\n]*Math\.random\(\)/i,
    fix: "Use crypto.getRandomValues or crypto.randomUUID.",
  },
  {
    id: "jwt-unverified",
    title: "JWT decoded without verification or 'none' algorithm allowed",
    category: "auth",
    severity: "high",
    re: /jwt\.decode\(|algorithms\s*:\s*\[[^\]]*["']none["']|verify\s*=\s*False.*jwt|options=\{\s*["']verify_signature["']\s*:\s*False/i,
    fix: "Verify the signature with a pinned algorithm and key (jwt.verify / jose jwtVerify) before trusting any claim.",
  },
  {
    id: "cors-wildcard",
    title: "CORS allows any origin",
    category: "config",
    severity: "low",
    re: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|origin\s*:\s*["']\*["']|cors\(\s*\)/,
    fix: "Allow only the origins that need access, and never combine a wildcard with credentials.",
  },
  {
    id: "path-from-request",
    title: "File path built from request data",
    category: "path-traversal",
    severity: "medium",
    re: /(readFile|readFileSync|createReadStream|sendFile|open|unlink|writeFile)\s*\([^)]*(req\.|request\.|params|query|body|searchParams)/,
    fix: "Resolve the path, then check it stays inside an allowed base directory; prefer an allow-list of names.",
  },
  {
    id: "fetch-from-request",
    title: "Outbound request to a URL taken from the request",
    category: "ssrf",
    severity: "medium",
    re: /fetch\(\s*(req|request|params|query|body|searchParams|url\.searchParams)[\w.]*(\.get\([^)]*\))?\s*[,)]/,
    fix: "Allow-list destination hosts and schemes; block private and link-local addresses.",
  },
  {
    id: "redirect-from-request",
    title: "Redirect target taken from the request",
    category: "open-redirect",
    severity: "low",
    re: /(redirect|Response\.redirect)\(\s*(req\.|request\.|params|query|searchParams)/,
    fix: "Redirect only to relative paths or an allow-listed set of hosts.",
  },
  {
    id: "gha-script-injection",
    title: "GitHub Actions expression from untrusted event data inside run",
    category: "ci-cd",
    severity: "high",
    re: /\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|head_commit|discussion|pages)\.[\w.]*(title|body|message|name|label|ref|email)|head_ref)\s*\}\}/,
    only: isWorkflow,
    standalone: true,
    fix: "Pass the value through an env: variable and reference it as \"$VAR\" in the script.",
  },
  {
    id: "gha-pull-request-target",
    title: "pull_request_target workflow",
    category: "ci-cd",
    severity: "medium",
    re: /^\s*pull_request_target\s*:/,
    only: isWorkflow,
    fix: "Never check out or run the PR's code in a pull_request_target job; use pull_request, or split privileged steps into a workflow_run.",
  },
  {
    id: "gha-write-all",
    title: "Workflow grants write-all permissions",
    category: "ci-cd",
    severity: "medium",
    re: /permissions\s*:\s*write-all/,
    only: isWorkflow,
    fix: "Declare the minimum permissions each job needs (for example contents: read).",
  },
  {
    id: "text-addressed-to-ai-reviewers",
    title: "Text addressed to AI reviewers or agents",
    category: "prompt-injection",
    severity: "medium",
    re: /(ignore (all |any )?(previous|prior|above) instructions|(ai|llm|automated|security) (code )?(reviewer|agent|assistant)s?\b[^\n]{0,80}\b(approve|no (findings|issues)|is safe|skip|ignore))/i,
    standalone: true,
    fix: "Remove instructions aimed at automated reviewers. They are a red flag in a contribution and the reviewer ignores them.",
  },
  {
    id: "model-output-to-sink",
    title: "Model output passed to code, a shell, SQL or HTML",
    category: "ai-agent",
    severity: "medium",
    re: /(eval|exec|execSync|innerHTML\s*=|query|execute)\s*\(?[^;\n]*(completion|choices\[0\]|\.response\b|output_text|message\.content|toolCall|tool_call)/,
    fix: "Treat model output as untrusted input: validate it against a schema and never execute it directly.",
  },
];

export interface Signal {
  rule: PatternRule;
  file: string;
  line: number;
  text: string;
}

export function findSignals(files: SourceFile[], rules: PatternRule[] = PATTERN_RULES): Signal[] {
  const out: Signal[] = [];
  for (const file of files) {
    const applicable = rules.filter((r) => !r.only || r.only(file.path));
    for (const { line, text } of file.lines) {
      if (text.length > 1000) continue;
      for (const rule of applicable) if (rule.re.test(text)) out.push({ rule, file: file.path, line, text: text.trim().slice(0, 200) });
    }
  }
  return out;
}

/** Standalone signals become findings directly; the rest wait for the model. */
export async function standaloneFindings(signals: Signal[]): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const s of signals) {
    if (!s.rule.standalone) continue;
    out.push({
      id: await fingerprint(s.rule.category, s.file, s.rule.id),
      title: s.rule.title,
      category: s.rule.category,
      severity: s.rule.severity,
      source: "deterministic",
      file: s.file,
      line: s.line,
      rule: s.rule.id,
      evidence: s.text,
      fix: s.rule.fix,
      confidence: 0.9,
      blocking: false,
    });
  }
  return out;
}
