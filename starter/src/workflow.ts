import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import type { Env } from "./env";
import { resolveGitHubToken, setCommitStatus, upsertComment } from "./lib/github";
import { DEFAULT_MODEL, DEFAULT_VERIFY_MODEL, type ModelOptions } from "./lib/model";
import { checks, collect, decide, review, type PrRef } from "./lib/pipeline";
import { DEFAULT_POLICY } from "./lib/policy";
import { MARKER, renderReport, summaryLine } from "./lib/report";

const RETRY = { retries: { limit: 3, delay: "5 seconds", backoff: "exponential" }, timeout: "3 minutes" } as const;

async function token(env: Env, installationId?: number): Promise<string | null> {
  return (await resolveGitHubToken(env, installationId).catch(() => null)) ?? env.GITHUB_TOKEN ?? null;
}

/**
 * One review per pushed commit. Each step's result is saved, so a flaky GitHub or model call retries only that step.
 * The Starter uses the default policy; the Advanced track makes it configurable.
 */
export class ReviewWorkflow extends WorkflowEntrypoint<Env, PrRef> {
  async run(event: WorkflowEvent<PrRef>, step: WorkflowStep) {
    const p = event.payload;
    const env = this.env;
    const dry = env.DRY_RUN === "true";
    const policy = DEFAULT_POLICY;
    const opts: ModelOptions = {
      model: env.MODEL || DEFAULT_MODEL,
      verifyModel: env.VERIFY_MODEL || DEFAULT_VERIFY_MODEL,
      maxChars: Number(env.MAX_MODEL_CHARS || 40000),
      minConfidence: Number(env.MIN_CONFIDENCE || 0.6),
      gateway: env.AI_GATEWAY || undefined,
      skillChars: Number(env.SKILL_CHARS ?? 6000),
    };

    const collected = await step.do("collect", RETRY, async () => collect(p, await token(env, p.installationId), policy, Number(env.MAX_CONTEXT_FILES || 15)));

    if (!dry) {
      await step.do("status: pending", RETRY, async () =>
        setCommitStatus({ repo: p.repo, sha: collected.sha, state: "pending", description: "Security review running", token: await token(env, p.installationId) }),
      );
    }

    const checked = await step.do("checks", RETRY, async () => checks(collected));
    const reviewed = await step.do("review", RETRY, async () => review(env.AI, opts, collected, checked.signals));

    return step.do("publish", RETRY, async () => {
      const report = decide(p, collected, checked, reviewed, policy, opts.model);
      const body = renderReport(report);
      const blocking = report.findings.filter((f) => f.blocking).length;
      if (dry) return { dryRun: true, summary: summaryLine(report), blocking, body };
      const t = await token(env, p.installationId);
      const comment = await upsertComment({ repo: p.repo, issueNumber: p.number, body, marker: MARKER, token: t });
      await setCommitStatus({ repo: p.repo, sha: collected.sha, state: blocking ? "failure" : "success", description: summaryLine(report), targetUrl: comment.url, token: t });
      return { summary: summaryLine(report), blocking, comment: comment.url };
    });
  }
}
