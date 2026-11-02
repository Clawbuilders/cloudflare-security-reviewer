/**
 * ADVANCED TRACK: a security committee for every pull request, on Cloudflare (free plan).
 *
 *   POST /                         GitHub webhook: pull_request (review) and issue_comment (/waive, /approve, /security ...)
 *   GET  /api/<owner>/<repo>/policy    the active policy and its history        (Bearer ADMIN_TOKEN)
 *   PUT  /api/<owner>/<repo>/policy    publish a new policy version, no redeploy (Bearer ADMIN_TOKEN)
 *   GET  /api/<owner>/<repo>/audit     every verdict with the policy version that produced it (Bearer ADMIN_TOKEN)
 *   GET  /reviews/<id>                 dry-run results (only when DRY_RUN=true)
 */
import { getAgentByName } from "agents";
import type { Env } from "./env";
import { SecurityAgent } from "./agent";
import { ReviewWorkflow } from "./workflow";
import { verifyWebhookSignature } from "../starter/src/lib/github";

export { SecurityAgent, ReviewWorkflow };

const REVIEW_ACTIONS = new Set(["opened", "synchronize", "reopened", "ready_for_review"]);

function sameSecret(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function api(request: Request, env: Env, repo: string, what: string): Promise<Response> {
  if (!env.ADMIN_TOKEN) return new Response("The policy API is off. Turn it on with: npx wrangler secret put ADMIN_TOKEN", { status: 404 });
  const auth = request.headers.get("authorization") ?? "";
  if (!sameSecret(auth, `Bearer ${env.ADMIN_TOKEN}`)) return new Response("Unauthorized", { status: 401 });
  const agent = await getAgentByName(env.SECURITY_AGENT, repo);
  if (what === "audit" && request.method === "GET") return Response.json(await agent.getAudit(Number(new URL(request.url).searchParams.get("limit") || 50)));
  if (what === "policy" && request.method === "GET") return Response.json(await agent.getPolicy());
  if (what === "policy" && request.method === "PUT") {
    try {
      const actor = request.headers.get("x-actor")?.slice(0, 60) || "api";
      const result = await agent.setPolicy(await request.json(), actor);
      return Response.json(result, { status: "error" in result ? 400 : 201 });
    } catch (e) {
      return Response.json({ error: String(e instanceof Error ? e.message : e) }, { status: 400 });
    }
  }
  return new Response("Not found", { status: 404 });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/healthz")) {
      return Response.json({ ok: true, service: "ClawBuilders security committee (Advanced)", dryRun: env.DRY_RUN === "true", policyApi: Boolean(env.ADMIN_TOKEN) });
    }

    const apiMatch = url.pathname.match(/^\/api\/([\w.-]+)\/([\w.-]+)\/(policy|audit)$/);
    if (apiMatch) return api(request, env, `${apiMatch[1]}/${apiMatch[2]}`, apiMatch[3]);

    if (request.method === "GET" && url.pathname.startsWith("/reviews/")) {
      if (env.DRY_RUN !== "true") return new Response("Not found", { status: 404 });
      try {
        return Response.json(await (await env.REVIEW_WORKFLOW.get(url.pathname.slice("/reviews/".length))).status());
      } catch {
        return new Response("No such review", { status: 404 });
      }
    }

    if (request.method !== "POST" || (url.pathname !== "/" && url.pathname !== "/webhook")) return new Response("Not found", { status: 404 });
    if (!env.GITHUB_WEBHOOK_SECRET) return new Response("Set GITHUB_WEBHOOK_SECRET first: npx wrangler secret put GITHUB_WEBHOOK_SECRET", { status: 503 });
    const raw = await request.text();
    if (!(await verifyWebhookSignature(env.GITHUB_WEBHOOK_SECRET, raw, request.headers.get("x-hub-signature-256")))) return new Response("Invalid signature", { status: 401 });

    const event = request.headers.get("x-github-event");
    if (event === "ping") return new Response("pong");
    let payload: any;
    try {
      payload = JSON.parse(raw);
    } catch {
      return new Response("Invalid JSON", { status: 400 });
    }
    const repo: string | undefined = payload.repository?.full_name;
    if (!repo) return new Response("Ignored", { status: 202 });
    const agent = await getAgentByName(env.SECURITY_AGENT, repo);

    if (event === "pull_request" && REVIEW_ACTIONS.has(payload.action) && payload.pull_request && !payload.pull_request.draft) {
      await agent.onPullRequest({ repo, number: payload.pull_request.number, sha: payload.pull_request.head.sha, installationId: payload.installation?.id });
      return Response.json({ queued: `${repo}#${payload.pull_request.number}` }, { status: 202 });
    }
    if (event === "issue_comment" && payload.action === "created" && payload.issue?.pull_request && payload.comment) {
      await agent.onComment({
        repo,
        number: payload.issue.number,
        author: payload.comment.user?.login ?? "",
        authorType: payload.comment.user?.type ?? "",
        body: String(payload.comment.body ?? "").slice(0, 5000),
        installationId: payload.installation?.id,
      });
      return new Response("Accepted", { status: 202 });
    }
    return new Response("Ignored", { status: 202 });
  },
} satisfies ExportedHandler<Env>;
