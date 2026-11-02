/**
 * PR comment commands and the waiver rules. Pure functions: the agent supplies GitHub permissions and the clock.
 *
 *   /waive 1a2b3c4d 14d vendor sandbox, no real data   request a waiver (expiry optional, default 30 days, max 90)
 *   /approve 1a2b3c4d                                  a DIFFERENT person with write access approves it
 *   /reject 1a2b3c4d                                   anyone with triage access, or the requester withdrawing
 *   /security rescan                                   review the head commit again
 *   /security fix 1a2b3c4d                             post a suggested fix on the finding's line (a person applies it)
 *
 * Quoted lines and fenced code are ignored, so replying to the bot or quoting a finding never triggers anything.
 */
import type { Permission } from "../starter/src/lib/github";

export type Command =
  | { cmd: "waive"; findingId: string; reason: string; days: number }
  | { cmd: "approve" | "reject"; findingId: string }
  | { cmd: "rescan" }
  | { cmd: "fix"; findingId: string };

export const DEFAULT_WAIVER_DAYS = 30;
export const MAX_WAIVER_DAYS = 90;
const MAX_REASON = 500;

export function parseCommand(body: string): Command | null {
  let fenced = false;
  for (const raw of body.split(/\r?\n/)) {
    if (/^\s*```/.test(raw)) {
      fenced = !fenced;
      continue;
    }
    if (fenced || /^\s*>/.test(raw)) continue;
    const line = raw.trim();
    let m = line.match(/^\/waive\s+([0-9a-fA-F]{8})(?:\s+(\d{1,3})d)?\s+(.+)$/);
    if (m) {
      const reason = m[3].trim();
      if (reason.length < 3) return null;
      const days = m[2] ? Number(m[2]) : DEFAULT_WAIVER_DAYS;
      if (days < 1 || days > MAX_WAIVER_DAYS) return null;
      return { cmd: "waive", findingId: m[1].toLowerCase(), reason: reason.slice(0, MAX_REASON), days };
    }
    m = line.match(/^\/(approve|reject)\s+([0-9a-fA-F]{8})\b/);
    if (m) return { cmd: m[1] as "approve" | "reject", findingId: m[2].toLowerCase() };
    if (/^\/security\s+rescan\b/.test(line)) return { cmd: "rescan" };
    m = line.match(/^\/security\s+fix\s+([0-9a-fA-F]{8})\b/);
    if (m) return { cmd: "fix", findingId: m[1].toLowerCase() };
  }
  return null;
}

const isBot = (login: string) => /\[bot\]$/i.test(login);
const canWrite = (p: Permission) => p === "admin" || p === "maintain" || p === "write";
const canTriage = (p: Permission) => canWrite(p) || p === "triage";

/** Requesting a waiver or a rescan needs at least triage access; asking for a fix spends model calls, so it needs write. */
export function allowed(cmd: Command["cmd"], login: string, permission: Permission): boolean {
  if (isBot(login)) return false;
  if (cmd === "fix") return canWrite(permission);
  if (cmd === "approve") return canWrite(permission);
  return canTriage(permission);
}

export type WaiverStatus = "pending" | "approved" | "rejected";

export interface Waiver {
  finding_id: string;
  reason: string;
  requested_by: string;
  approved_by: string | null;
  status: WaiverStatus;
  days: number;
  created_at: number;
  /** Set when approved: approval time + days. */
  expires_at: number | null;
  policy_version: string;
}

export function decideApproval(w: Waiver | undefined, approver: string, permission: Permission): { ok: true } | { ok: false; reason: string } {
  if (!w) return { ok: false, reason: "There is no waiver request for that id. Ask for one with /waive <id> <reason>." };
  if (w.status !== "pending") return { ok: false, reason: `That waiver is already ${w.status}.` };
  if (isBot(approver)) return { ok: false, reason: "Bot accounts cannot approve waivers." };
  if (approver.toLowerCase() === w.requested_by.toLowerCase()) return { ok: false, reason: "Four-eyes rule: someone other than the requester has to approve." };
  if (!canWrite(permission)) return { ok: false, reason: "Approving a waiver needs write access to the repository." };
  return { ok: true };
}

export function decideRejection(w: Waiver | undefined, who: string, permission: Permission): { ok: true } | { ok: false; reason: string } {
  if (!w) return { ok: false, reason: "There is no waiver request for that id." };
  if (w.status === "rejected") return { ok: false, reason: "That waiver is already rejected." };
  if (who.toLowerCase() === w.requested_by.toLowerCase() || canTriage(permission)) return { ok: true };
  return { ok: false, reason: "Rejecting a waiver needs triage access, or to be the person who asked for it." };
}

/** An approved waiver hides a finding only until it expires; then the finding blocks again on the next review. */
export function isActive(w: Waiver, now: number): boolean {
  return w.status === "approved" && w.expires_at !== null && w.expires_at > now;
}

/** Hard rails (real credentials) can never be waived: rotate the key instead. */
export function waivable(rule: string, hardRail: boolean): boolean {
  return !hardRail && rule !== "osv-unavailable";
}
