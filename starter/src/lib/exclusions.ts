/**
 * False-positive filter, ported from Anthropic's claude-code-security-review (MIT, Copyright (c) 2025 Anthropic PBC):
 *   https://github.com/anthropics/claude-code-security-review/blob/0c6a49f1fa56a1d472575da86a94dbc1edb78eda/claudecode/findings_filter.py
 *
 * Two layers, both applied to model findings only (a deterministic finding is a fact, never filtered):
 *   1. HARD_EXCLUSIONS: cheap regex rules that drop well-known low-signal findings before the verifier spends a call.
 *   2. PRECEDENTS: the same project's false-positive precedents, added to the verifier's prompt.
 *
 * Adapted for this reviewer, and marked where it differs from upstream:
 *   - A credential in a URL is a finding (upstream treats logged URLs as safe, which hides tokens in query strings).
 *   - Open redirects are kept when the redirect carries a token or sits in a login/OAuth flow (upstream drops all).
 *   - Upstream's "user content in AI prompts is not a vulnerability" is narrowed: mere inclusion is not a finding, but
 *     model output that picks a tool, a target or a write is (that is the AI-AND-LLM skill's action-binding class).
 *   - Upstream's "GitHub Actions input sanitisation" and "outdated libraries" exclusions are left to the deterministic
 *     checks, which already cover workflow script injection and OSV.dev.
 */
import type { Candidate } from "./model";

export interface Exclusion {
  id: string;
  reason: string;
  patterns: RegExp[];
  /** Only applies to files matching this (default: every file). */
  onlyFiles?: RegExp;
  /** Never applies to files matching this. */
  exceptFiles?: RegExp;
  /** The finding is kept if its text matches this. */
  unless?: RegExp;
}

const C_CPP = /\.(c|cc|cpp|cxx|h|hpp)$/i;

export const HARD_EXCLUSIONS: Exclusion[] = [
  {
    id: "dos",
    reason: "Generic denial-of-service or resource exhaustion finding (low signal)",
    patterns: [/\b(denial of service|dos attack|resource exhaustion)\b/i, /\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b/i, /\b(infinite|unbounded).*?(loop|recursion)\b/i],
    // An agent loop with no limit that spends money is an AI-AND-LLM finding, not generic DoS.
    unless: /\b(spend|cost|billing|tokens? budget|paid)\b/i,
  },
  {
    id: "rate-limit",
    reason: "Generic rate-limiting recommendation",
    patterns: [/\b(missing|lack of|no)\s+rate\s+limit/i, /\brate\s+limiting\s+(missing|required|not implemented)/i, /\b(implement|add)\s+rate\s+limit/i, /\bunlimited\s+(requests|calls|api)/i],
    unless: /\b(login|password|otp|one-time|brute.?force|credential stuffing)\b/i,
  },
  {
    id: "resource-leak",
    reason: "Resource management finding (not a security vulnerability)",
    patterns: [
      /\b(resource|memory|file)\s+leak\s+potential/i,
      /\bunclosed\s+(resource|file|connection)/i,
      /\b(close|cleanup|release)\s+(resource|file|connection)/i,
      /\bpotential\s+memory\s+leak/i,
      /\b(database|thread|socket|connection)\s+leak/i,
    ],
  },
  {
    id: "open-redirect",
    reason: "Open redirect with no token or login flow involved (low impact)",
    patterns: [/\b(open redirect|unvalidated redirect)\b/i, /\b(redirect.(attack|exploit|vulnerability))\b/i, /\b(malicious.redirect)\b/i],
    unless: /\b(oauth|oidc|redirect_uri|callback|token|code=|session|login|sso)\b/i,
  },
  {
    id: "regex-injection",
    reason: "Regex injection or ReDoS finding (not applicable)",
    patterns: [/\b(regex|regular expression)\s+injection\b/i, /\b(regex|regular expression)\s+denial of service\b/i, /\b(regex|regular expression)\s+flooding\b/i, /\bredos\b/i],
  },
  {
    id: "memory-safety",
    reason: "Memory-safety finding outside C/C++ (not applicable)",
    exceptFiles: C_CPP,
    patterns: [
      /\b(buffer overflow|stack overflow|heap overflow)\b/i,
      /\b(oob)\s+(read|write|access)\b/i,
      /\b(out.?of.?bounds?)\b/i,
      /\b(memory safety|memory corruption)\b/i,
      /\b(use.?after.?free|double.?free|null.?pointer.?dereference)\b/i,
      /\b(segmentation fault|segfault|memory violation)\b/i,
      /\b(bounds check|boundary check|array bounds)\b/i,
      /\b(integer overflow|integer underflow|integer conversion)\b/i,
      /\barbitrary.?(memory read|pointer dereference|memory address|memory pointer)\b/i,
    ],
  },
  {
    id: "ssrf-client-side",
    reason: "SSRF in client-side code (a browser cannot reach internal services for an attacker)",
    onlyFiles: /\.(html|jsx|tsx|vue|svelte)$|(^|\/)(public|static|client|frontend|components|pages)\//i,
    patterns: [/\b(ssrf|server\s*.?side\s*.?request\s*.?forgery)\b/i],
  },
  {
    id: "test-only",
    reason: "Finding in test-only code",
    onlyFiles: /(^|\/)(__tests__|tests?|spec|fixtures?)\/|\.(test|spec)\.[a-z]+$/i,
    patterns: [/./],
  },
  {
    id: "log-spoofing",
    reason: "Log spoofing or log injection without data exposure",
    patterns: [/\blog\s+(spoofing|forging|injection)\b/i, /\b(crlf|newline)\s+injection\b.*\blog/i],
    unless: /\b(password|secret|token|api.?key|credential|pii)\b/i,
  },
  {
    id: "markdown",
    reason: "Finding in a Markdown documentation file",
    onlyFiles: /\.(md|mdx|markdown)$/i,
    patterns: [/./],
  },
];

/** Why a candidate is excluded, or null if it goes on to the verifier. Prompt-injection findings are never excluded. */
export function exclusionReason(c: Pick<Candidate, "title" | "file" | "flow" | "fix" | "category">, enabled: readonly string[] = DEFAULT_EXCLUSIONS): string | null {
  if (c.category === "prompt-injection") return null;
  const text = `${c.title} ${c.flow}`;
  for (const ex of HARD_EXCLUSIONS) {
    if (!enabled.includes(ex.id)) continue;
    if (ex.onlyFiles && !ex.onlyFiles.test(c.file)) continue;
    if (ex.exceptFiles?.test(c.file)) continue;
    if (!ex.patterns.some((p) => p.test(text))) continue;
    if (ex.unless?.test(text)) continue;
    return ex.reason;
  }
  return null;
}

export const DEFAULT_EXCLUSIONS: readonly string[] = HARD_EXCLUSIONS.map((e) => e.id);

/** Split candidates into those the verifier should see and those dropped by a hard exclusion. */
export function applyExclusions<T extends Pick<Candidate, "title" | "file" | "flow" | "fix" | "category">>(
  candidates: T[],
  enabled: readonly string[] = DEFAULT_EXCLUSIONS,
): { kept: T[]; excluded: { candidate: T; reason: string }[] } {
  const kept: T[] = [];
  const excluded: { candidate: T; reason: string }[] = [];
  for (const c of candidates) {
    const reason = exclusionReason(c, enabled);
    if (reason) excluded.push({ candidate: c, reason });
    else kept.push(c);
  }
  return { kept, excluded };
}

/** Precedents for the verifier, adapted from the same project's false-positive filter prompt. */
export const PRECEDENTS = `False-positive precedents (adapted from anthropics/claude-code-security-review, MIT). Drop a finding that relies on one of these:
1. Logging high-value secrets in plain text is a vulnerability, and so is putting a credential in a URL (query strings end up in access logs, proxies and browser history). Logging request headers is assumed dangerous. Other theoretical exposures of secrets are not findings.
2. UUIDs are unguessable. A finding that needs someone to guess a UUID is not valid.
3. Missing or modifiable audit logs are not a vulnerability.
4. Environment variables, configuration files and CLI flags are trusted. An attack that needs control of them is not valid.
5. Memory or file-descriptor leaks are not findings.
6. Tabnabbing, XS-Leaks, prototype pollution and plain open redirects are not findings, unless the redirect carries a token or is part of a login flow.
7. React and similar frameworks escape output. Report XSS in components only when they use dangerouslySetInnerHTML, v-html, innerHTML or a similar raw sink.
8. Client-side code is not trusted and does not need its own permission checks; the server does. Missing authorization belongs on the server route.
9. Including untrusted text in a model prompt is not a finding by itself. It is a finding when the model's output then chooses a tool, a target, a write, a query or something that is executed or rendered without a check.
10. Shell scripts and CI steps are not exploitable unless untrusted input really reaches them; name that input.
11. SSRF needs control of the host or protocol, not only the path, and only matters in server-side code.
12. Path traversal with ../ matters when reading or writing files, not in outbound HTTP request paths.
13. A missing hardening measure (a header, a stricter cookie flag, a rate limit) is not a vulnerability unless the change removes one that was there, or a concrete attack depends on it.
14. A crash, a null value or an unhandled error is not a vulnerability unless it bypasses a security check.
15. Report a medium finding only if it is obvious and concrete.`;
