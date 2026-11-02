/**
 * STARTER TRACK: a security reviewer for every pull request, on Cloudflare Workers + Workers AI (free plan).
 *
 *   GitHub pull_request webhook -> verify signature -> start one ReviewWorkflow per pushed commit
 *   ReviewWorkflow: collect -> deterministic checks -> model review (propose, then verify) -> one PR comment + status
 *
 * Security only: secrets, vulnerable dependencies, injection, auth, access control, SSRF, CI and AI-agent risks.
 * No style or quality findings.
 */
import type { Env } from "./env";
import { verifyWebhookSignature } from "./lib/github";
import type { PrRef } from "./lib/pipeline";

export { ReviewWorkflow } from "./workflow";

const REVIEW_ACTIONS = new Set(["opened", "synchronize", "reopened", "ready_for_review"]);

/** Workflow ids must be short and simple; the same commit always maps to the same id, so duplicate deliveries collapse. */
export async function instanceId(p: PrRef): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${p.repo}#${p.number}@${p.sha}`));
  return `pr-${[...new Uint8Array(d)].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return new Response("ClawBuilders security reviewer (Starter) is running. Point a GitHub pull_request webhook at POST /.\n");
    }

    // Dry-run results. Only exposed in DRY_RUN mode, since a report can describe a private repository.
    if (request.method === "GET" && url.pathname.startsWith("/reviews/")) {
      if (env.DRY_RUN !== "true") return new Response("Not found", { status: 404 });
      const id = url.pathname.slice("/reviews/".length);
      try {
        const inst = await env.REVIEW_WORKFLOW.get(id);
        return Response.json(await inst.status());
      } catch {
        return new Response("No such review", { status: 404 });
      }
    }

    if (request.method !== "POST" || url.pathname !== "/") return new Response("Not found", { status: 404 });

    // Fail closed: without a webhook secret anyone could make this Worker spend your Workers AI allowance.
    if (!env.GITHUB_WEBHOOK_SECRET) return new Response("Set GITHUB_WEBHOOK_SECRET first: npx wrangler secret put GITHUB_WEBHOOK_SECRET", { status: 503 });
    const raw = await request.text();
    if (!(await verifyWebhookSignature(env.GITHUB_WEBHOOK_SECRET, raw, request.headers.get("x-hub-signature-256")))) {
      return new Response("Invalid signature", { status: 401 });
    }
    if (request.headers.get("x-github-event") === "ping") return new Response("pong");
    if (request.headers.get("x-github-event") !== "pull_request") return new Response("Ignored event", { status: 202 });

    let payload: { action?: string; pull_request?: { number: number; draft?: boolean; head: { sha: string } }; repository?: { full_name: string }; installation?: { id: number } };
    try {
      payload = JSON.parse(raw);
    } catch {
      return new Response("Invalid JSON", { status: 400 });
    }
    const pr = payload.pull_request;
    if (!pr || !payload.repository || !REVIEW_ACTIONS.has(payload.action ?? "")) return new Response("Ignored action", { status: 202 });
    if (pr.draft) return new Response("Draft PR: reviewed when marked ready", { status: 202 });

    const ref: PrRef = { repo: payload.repository.full_name, number: pr.number, sha: pr.head.sha, installationId: payload.installation?.id };
    const id = await instanceId(ref);
    try {
      await env.REVIEW_WORKFLOW.create({ id, params: ref });
    } catch (e) {
      if (!/already exists/i.test(String(e))) throw e; // a redelivery of the same commit
    }
    return Response.json({ review: id }, { status: 202 });
  },
} satisfies ExportedHandler<Env>;
