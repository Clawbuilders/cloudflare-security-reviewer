/** GitHub Actions workflows whose results the committee reads (their names, as shown in the Actions tab). */
export const DEFAULT_SCANNER_WORKFLOWS = "zizmor,CodeQL,osv-scanner,OSV-Scanner";

export function isScannerWorkflow(name: string, configured?: string): boolean {
  const names = (configured || DEFAULT_SCANNER_WORKFLOWS).split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  return names.includes(name.trim().toLowerCase());
}
