/**
 * Bring in results from heavier scanners that run in GitHub Actions (zizmor for workflow files, CodeQL, osv-scanner for
 * more ecosystems than this Worker covers, or any tool that uploads SARIF). They cannot run inside a Worker, but their
 * results are one API call away.
 *
 * Scanner results are treated as proposals, not facts: only alerts on lines this pull request added are kept, they go
 * through the same exclusions and verifier as model findings, and the verifier can drop them.
 */
import type { CodeScanningAlert } from "../github";
import type { SourceFile } from "../files";
import type { Candidate } from "../model";
import { isSeverity, type Severity } from "../findings";

export interface ScannerAlert {
  tool: string;
  rule: string;
  title: string;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  url?: string;
}

function severityOf(a: CodeScanningAlert): Severity {
  const s = (a.rule?.security_severity_level ?? "").toLowerCase();
  if (isSeverity(s)) return s;
  const level = (a.rule?.severity ?? "").toLowerCase();
  return level === "error" ? "high" : level === "warning" ? "medium" : "low";
}

const CATEGORY: Record<string, string> = { zizmor: "ci-cd", codeql: "scanner", "osv-scanner": "dependencies" };

/** Keep alerts on added lines of changed files, as plain data that can cross a Workflow step. */
export function scannerAlerts(alerts: CodeScanningAlert[] | null, files: SourceFile[], max = 20): ScannerAlert[] {
  if (!alerts) return [];
  const out: ScannerAlert[] = [];
  for (const a of alerts) {
    const loc = a.most_recent_instance?.location;
    const file = files.find((f) => f.path === loc?.path);
    if (!file || !loc?.start_line) continue;
    const added = new Set(file.lines.map((l) => l.line));
    const end = loc.end_line ?? loc.start_line;
    let hit = false;
    for (let n = loc.start_line; n <= end && !hit; n++) hit = added.has(n);
    if (!hit) continue;
    out.push({
      tool: (a.tool?.name ?? "scanner").slice(0, 40),
      rule: (a.rule?.id ?? a.rule?.name ?? "rule").slice(0, 80),
      title: (a.rule?.description ?? a.rule?.name ?? a.rule?.id ?? "Scanner alert").slice(0, 140),
      severity: severityOf(a),
      message: (a.most_recent_instance?.message?.text ?? "").slice(0, 500),
      file: file.path,
      line: loc.start_line,
      url: a.html_url,
    });
    if (out.length >= max) break;
  }
  return out;
}

/** Scanner alerts as candidates for the verifier. */
export function scannerCandidates(alerts: ScannerAlert[]): Candidate[] {
  return alerts.map((a) => ({
    title: `${a.tool}: ${a.title}`.slice(0, 160),
    category: CATEGORY[a.tool.toLowerCase()] ?? "scanner",
    severity: a.severity,
    file: a.file,
    line: a.line,
    untrusted_input: `reported by ${a.tool} rule ${a.rule}; confirm which untrusted input reaches it`,
    flow: a.message || a.title,
    fix: a.url ? `See the ${a.tool} alert: ${a.url}` : `See the ${a.tool} rule ${a.rule}.`,
    confidence: 0.8,
    specialist: `scanner:${a.tool.toLowerCase()}`,
  }));
}
