/**
 * The durable committee review. Every step is checkpointed and retried on its own:
 *   collect -> checks (deterministic) -> triage (Clef) -> one step per specialist, in parallel
 *   -> verify (a second model, a different family) -> decide (policy + waivers) -> publish (comment, status, audit)
 */
import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { getAgentByName } from "agents";
import type { Env, ReviewParams } from "./env";
import { isActive, waivable } from "./commands";
import { BUILT_IN, filesFor, forcedBy, signalCategories, toSpecialist, withFiles, type Specialist } from "./specialists";
import { summarise, triage } from "./triage";
import { checks, collect, fromSignalData } from "../starter/src/lib/pipeline";
import { isDocs, isReviewable, priority } from "../starter/src/lib/files";
import { dedupe, type Finding } from "../starter/src/lib/findings";
import { resolveGitHubToken, setCommitStatus, upsertComment } from "../starter/src/lib/github";
import { DEFAULT_MODEL, DEFAULT_VERIFY_MODEL, hunt, verify, type Candidate, type ModelOptions } from "../starter/src/lib/model";
import { PATTERN_RULES } from "../starter/src/lib/checks/patterns";
import { applyPolicy, isHardRail } from "../starter/src/lib/policy";
import { MARKER, renderReport, summaryLine, type Report } from "../starter/src/lib/report";

const RETRY = { retries: { limit: 3, delay: "5 seconds", backoff: "exponential" }, timeout: "3 minutes" } as const;

async function token(env: Env, installationId?: number): Promise<string | null> {
  return (await resolveGitHubToken(env, installationId).catch(() => null)) ?? env.GITHUB_TOKEN ?? null;
}

export class ReviewWorkflow extends WorkflowEntrypoint<Env, ReviewParams> {
  async run(event: WorkflowEvent<ReviewParams>, step: WorkflowStep) {
    const p = event.payload;
    const env = this.env;
    const dry = env.DRY_RUN === "true";
    const agent = await getAgentByName(env.SECURITY_AGENT, p.repo);
    const opts: ModelOptions = {
      model: env.MODEL || DEFAULT_MODEL,
      verifyModel: env.VERIFY_MODEL || DEFAULT_VERIFY_MODEL,
      maxChars: Number(env.MAX_MODEL_CHARS || 30000),
      minConfidence: Number(env.MIN_CONFIDENCE || 0.6),
      gateway: env.AI_GATEWAY || undefined,
      skillChars: Number(env.SKILL_CHARS ?? 7000),
    };

    const stored = await step.do("load policy", RETRY, async () => {
      const s = await agent.getPolicy();
      return { policy: s.policy, specialists: s.specialists };
    });
    const policy = stored.policy;
    const committee: Specialist[] = [...BUILT_IN, ...stored.specialists.map(toSpecialist)];

    const collected = await step.do("collect", RETRY, async () => collect(p, await token(env, p.installationId), policy, Number(env.MAX_CONTEXT_FILES || 15)));
    if (!dry) {
      await step.do("status: pending", RETRY, async () =>
        setCommitStatus({ repo: p.repo, sha: collected.sha, state: "pending", description: "Security committee reviewing", token: await token(env, p.installationId) }),
      );
    }
    const checked = await step.do("checks", RETRY, async () => checks(collected));

    const reviewable = collected.files.filter((f) => isReviewable(f.path) && !isDocs(f.path) && f.lines.length > 0).sort((a, b) => priority(b.path) - priority(a.path));

    const plan = await step.do("triage", RETRY, async () => {
      if (reviewable.length === 0) return { run: [] as string[], skipped: committee.map((s) => s.id), tier: "no code changed", probs: {} as Record<string, number> };
      const eligible = withFiles(committee, reviewable);
      const cats = signalCategories(checked.signals, checked.findings.map((f) => f.category), (id) => PATTERN_RULES.find((r) => r.id === id)?.category);
      const t = await triage(env.AI, summarise(reviewable), eligible, forcedBy(eligible, cats), Number(env.TRIAGE_THRESHOLD || 0.35));
      return { ...t, skipped: committee.map((s) => s.id).filter((id) => !t.run.includes(id)) };
    });

    // One durable step per specialist, run in parallel. A failed specialist returns nothing rather than sinking the review.
    const proposals = await Promise.all(
      plan.run.map((id) =>
        step.do(`specialist: ${id}`, RETRY, async () => {
          const s = committee.find((x) => x.id === id)!;
          const files = filesFor(s, reviewable);
          const signals = fromSignalData(checked.signals).filter((x) => files.some((f) => f.path === x.file));
          try {
            const { candidates, skills } = await hunt(env.AI, opts, s, files, signals);
            return { id, candidates, skills, error: null as string | null };
          } catch (e) {
            return { id, candidates: [] as Candidate[], skills: [] as string[], error: String(e).slice(0, 160) };
          }
        }),
      ),
    );

    const verified = await step.do("verify", RETRY, async () => {
      const all = proposals.flatMap((x) => x.candidates);
      try {
        // The verifier applies the validation rules of every domain whose specialist proposed something.
        const domains = proposals.filter((x) => x.candidates.length > 0).flatMap((x) => x.skills);
        return await verify(env.AI, opts, all, reviewable, domains);
      } catch (e) {
        return { kept: [] as Finding[], dismissed: all.map((c) => ({ title: c.title, file: c.file, reason: `verifier failed: ${String(e).slice(0, 80)}` })) };
      }
    });

    const decision = await step.do("decide", RETRY, async () => {
      const waivers = await agent.getWaivers();
      const now = Date.now();
      const all = applyPolicy(dedupe([...checked.findings, ...verified.kept]), policy);
      const waived: Report["waived"] = [];
      const findings: Finding[] = [];
      for (const f of all) {
        const w = waivers.find((x) => x.finding_id === f.id);
        if (w && isActive(w, now) && waivable(f.rule, isHardRail(f))) {
          waived.push({ id: f.id, reason: w.reason, approvedBy: w.approved_by ?? "", expires: new Date(w.expires_at!).toISOString().slice(0, 10) });
        } else findings.push(f);
      }
      const failed = proposals.filter((x) => x.error).map((x) => `${x.id} (${x.error})`);
      const report: Report = {
        repo: p.repo,
        number: p.number,
        ref: collected.ref,
        sha: collected.sha,
        policyVersion: policy.version,
        model: `${opts.model.replace(/^@cf\//, "")} + ${opts.verifyModel.replace(/^@cf\//, "")}`,
        findings,
        dismissed: verified.dismissed,
        waived,
        stats: {
          files: collected.files.length,
          reviewedByModel: reviewable.length,
          omitted: [],
          skills: proposals.filter((x) => x.skills.length > 0).map((x) => `${x.id}: ${x.skills.join(" + ")}`),
          skippedModel:
            plan.run.length === 0
              ? `no specialist needed (${plan.tier})`
              : `${plan.run.length} specialist(s) ran: ${plan.run.join(", ")}${plan.skipped.length ? `; skipped by triage: ${plan.skipped.join(", ")}` : ""}${failed.length ? `; failed: ${failed.join(", ")}` : ""}`,
        },
      };
      return report;
    });

    return step.do("publish", RETRY, async () => {
      const body = renderReport(decision).replace("_Model pass skipped: ", "_Committee: ");
      const blocking = decision.findings.filter((f) => f.blocking).length;
      await agent.recordReview({ pr: p.number, sha: decision.sha, policyVersion: decision.policyVersion, models: decision.model, specialists: plan.run, findings: decision.findings });
      if (dry) return { dryRun: true, summary: summaryLine(decision), blocking, body };
      const t = await token(env, p.installationId);
      const comment = await upsertComment({ repo: p.repo, issueNumber: p.number, body, marker: MARKER, token: t });
      await setCommitStatus({ repo: p.repo, sha: decision.sha, state: blocking ? "failure" : "success", description: summaryLine(decision), targetUrl: comment.url, token: t });
      return { summary: summaryLine(decision), blocking, comment: comment.url };
    });
  }
}
