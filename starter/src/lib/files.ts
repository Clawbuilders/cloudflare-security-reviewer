/**
 * What the reviewer reads: the files a pull request changes, with their added lines and (when fetched) the full file
 * at the head commit for context.
 */

export interface Line {
  line: number;
  text: string;
}

export interface SourceFile {
  path: string;
  /** Lines added by the pull request. */
  lines: Line[];
  /** Full file at the head commit, when fetched. Gives the model context beyond the diff hunk. */
  content?: string;
  /** Unified diff for this file. */
  patch?: string;
}

/** Added lines (with their new-file line numbers) from a GitHub unified patch. */
export function addedLines(patch: string | undefined): Line[] {
  if (!patch) return [];
  const out: Line[] = [];
  let next = 0;
  for (const raw of patch.split("\n")) {
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      next = Number(hunk[1]);
      continue;
    }
    if (raw.startsWith("+") && !raw.startsWith("+++")) out.push({ line: next++, text: raw.slice(1) });
    else if (raw.startsWith("-")) continue;
    else if (!raw.startsWith("\\")) next++;
  }
  return out;
}

const SKIP_DIRS = /(^|\/)(node_modules|vendor|dist|build|out|\.next|\.wrangler|target|coverage|__snapshots__)\//;
const LOCKFILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|poetry\.lock|Gemfile\.lock|go\.sum|composer\.lock)$/;
const BINARY = /\.(png|jpe?g|gif|webp|ico|svg|pdf|zip|gz|tgz|wasm|woff2?|ttf|otf|mp4|mov|mp3|bin|exe|dll|so|dylib|class|jar)$/i;
const MINIFIED = /\.min\.(js|css)$/;
const DOCS = /\.(md|mdx|txt|rst|adoc)$/i;

const CODE =
  /\.(ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|java|kt|kts|php|cs|swift|scala|ex|exs|sql|sh|bash|ps1|vue|svelte|astro|html?)$/i;
const CONFIG =
  /(^|\/)(Dockerfile|docker-compose\.ya?ml|wrangler\.(json|jsonc|toml)|package\.json|requirements[^/]*\.txt|pyproject\.toml|Cargo\.toml|go\.mod|_headers|_redirects|nginx\.conf|\.htaccess)$|\.(tf|ya?ml|toml|ini|conf|env[^/]*)$|(^|\/)\.env/i;

/** Files worth scanning for secrets: any text file that is not generated or vendored. */
export function isScannable(path: string): boolean {
  return !SKIP_DIRS.test(path) && !LOCKFILES.test(path) && !BINARY.test(path) && !MINIFIED.test(path);
}

/** Files worth a model's attention: source code and security-relevant configuration. */
export function isReviewable(path: string): boolean {
  return isScannable(path) && (CODE.test(path) || CONFIG.test(path));
}

export function isDocs(path: string): boolean {
  return DOCS.test(path);
}

export function isWorkflow(path: string): boolean {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path);
}

/** Highest-signal files first when the model budget cannot fit everything: entry points, auth, data access, CI. */
export function priority(path: string): number {
  let p = 0;
  if (/(route|handler|controller|api|server|index|worker|app|middleware|webhook)/i.test(path)) p += 3;
  if (/(auth|login|session|token|jwt|oauth|permission|admin|crypto|secret)/i.test(path)) p += 3;
  if (/(db|sql|query|model|repo|store|upload|file|fetch|proxy|exec|shell)/i.test(path)) p += 2;
  if (/(prompt|agent|tool|llm|ai|mcp)/i.test(path)) p += 2;
  if (isWorkflow(path)) p += 2;
  if (/(test|spec|fixture|mock|example|demo)/i.test(path)) p -= 3;
  return p;
}
