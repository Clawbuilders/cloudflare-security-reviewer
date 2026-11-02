/**
 * GitHub helpers: token resolution (GitHub App or PAT), webhook signature check, and the few REST calls the
 * reviewer needs. Every network function takes an optional `f` (fetch) so tests can stub it.
 * Adapted from Clawbuilders/cloudflare-compliance-reviewer (MIT).
 */

export interface GitHubAppEnv {
  GITHUB_APP_ID?: string;
  GITHUB_APP_PRIVATE_KEY?: string;
}

const UA = "ClawBuilders-Security-Reviewer";
const API = "https://api.github.com";

function baseHeaders(token?: string | null, accept = "application/vnd.github+json"): Record<string, string> {
  const h: Record<string, string> = { "User-Agent": UA, Accept: accept };
  if (token) h.Authorization = `token ${token}`;
  return h;
}

async function ensureOk(res: Response, what: string): Promise<Response> {
  if (!res.ok) throw new Error(`GitHub ${what} failed: ${res.status} ${res.statusText} ${(await res.text()).slice(0, 300)}`.trim());
  return res;
}

// ---------- GitHub App authentication ----------

function base64UrlEncode(input: ArrayBuffer | string): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// GitHub generates PKCS#1 keys ("BEGIN RSA PRIVATE KEY"); Web Crypto needs PKCS#8. Convert once:
//   openssl pkcs8 -topk8 -nocrypt -in downloaded-key.pem -out pkcs8-key.pem
async function importPrivateKey(pem: string): Promise<CryptoKey> {
  if (pem.includes("BEGIN RSA PRIVATE KEY")) {
    throw new Error('GITHUB_APP_PRIVATE_KEY is PKCS#1 ("BEGIN RSA PRIVATE KEY") — convert it: openssl pkcs8 -topk8 -nocrypt -in key.pem -out pkcs8-key.pem');
  }
  const body = pem.replace(/-----BEGIN PRIVATE KEY-----/, "").replace(/-----END PRIVATE KEY-----/, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}

async function createAppJwt(appId: string, privateKeyPem: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const unsigned = `${base64UrlEncode(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${base64UrlEncode(JSON.stringify({ iat: now - 60, exp: now + 600, iss: appId }))}`;
  const key = await importPrivateKey(privateKeyPem);
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
  return `${unsigned}.${base64UrlEncode(signature)}`;
}

async function getInstallationToken(appJwt: string, installationId: number, f: typeof fetch): Promise<string> {
  const res = await f(`${API}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: { ...baseHeaders(null), Authorization: `Bearer ${appJwt}` },
  });
  await ensureOk(res, "installation token");
  return ((await res.json()) as { token: string }).token;
}

export function hasAppCredentials(env: GitHubAppEnv): boolean {
  return Boolean(env.GITHUB_APP_ID && env.GITHUB_APP_PRIVATE_KEY);
}

/** App installation token when configured (needs the webhook's installation.id), otherwise null → caller falls back to a PAT. */
export async function resolveGitHubToken(env: GitHubAppEnv, installationId: number | undefined, f: typeof fetch = fetch): Promise<string | null> {
  if (!hasAppCredentials(env) || !installationId) return null;
  return getInstallationToken(await createAppJwt(env.GITHUB_APP_ID!, env.GITHUB_APP_PRIVATE_KEY!), installationId, f);
}

/** Constant-time check of GitHub's X-Hub-Signature-256 over the raw body. No secret configured → returns true (callers decide whether that is allowed). */
export async function verifyWebhookSignature(secret: string | undefined, rawBody: string, signatureHeader: string | null): Promise<boolean> {
  if (!secret) return true;
  if (!signatureHeader) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
  const expected = "sha256=" + [...new Uint8Array(signature)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (expected.length !== signatureHeader.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) mismatch |= expected.charCodeAt(i) ^ signatureHeader.charCodeAt(i);
  return mismatch === 0;
}

// ---------- REST helpers ----------

/** File contents at a ref, or null when it does not exist. */
export async function fetchFileAtRef(repo: string, path: string, ref: string, token?: string | null, f: typeof fetch = fetch): Promise<string | null> {
  const res = await f(`${API}/repos/${repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(ref)}`, {
    headers: baseHeaders(token, "application/vnd.github.raw+json"),
  });
  if (res.status === 404) return null;
  await ensureOk(res, `file ${path}`);
  return res.text();
}

export interface UpsertArgs {
  repo: string;
  issueNumber: number;
  body: string;
  marker: string;
  token?: string | null;
}

/** Update the comment carrying `marker` if one exists, otherwise create it — a re-run edits in place instead of piling up comments. */
export async function upsertComment(a: UpsertArgs, f: typeof fetch = fetch): Promise<{ id: number; url: string; action: "created" | "updated" }> {
  let existing: number | null = null;
  for (let page = 1; page <= 5 && existing === null; page++) {
    const res = await f(`${API}/repos/${a.repo}/issues/${a.issueNumber}/comments?per_page=100&page=${page}`, { headers: baseHeaders(a.token) });
    await ensureOk(res, "list comments");
    const comments = (await res.json()) as { id: number; body?: string }[];
    existing = comments.find((c) => c.body?.includes(a.marker))?.id ?? null;
    if (comments.length < 100) break;
  }
  const headers = { ...baseHeaders(a.token), "Content-Type": "application/json" };
  const res =
    existing !== null
      ? await f(`${API}/repos/${a.repo}/issues/comments/${existing}`, { method: "PATCH", headers, body: JSON.stringify({ body: a.body }) })
      : await f(`${API}/repos/${a.repo}/issues/${a.issueNumber}/comments`, { method: "POST", headers, body: JSON.stringify({ body: a.body }) });
  await ensureOk(res, existing !== null ? "update comment" : "create comment");
  const data = (await res.json()) as { id: number; html_url?: string };
  return { id: data.id, url: data.html_url ?? "", action: existing !== null ? "updated" : "created" };
}

export type Permission = "admin" | "maintain" | "write" | "triage" | "read" | "none";

export async function getCollaboratorPermission(repo: string, user: string, token?: string | null, f: typeof fetch = fetch): Promise<Permission> {
  const res = await f(`${API}/repos/${repo}/collaborators/${encodeURIComponent(user)}/permission`, { headers: baseHeaders(token) });
  if (res.status === 404) return "none";
  await ensureOk(res, "collaborator permission");
  const data = (await res.json()) as { permission?: string; role_name?: string };
  const pick = (s?: string): Permission | null => (s && ["admin", "maintain", "write", "triage", "read", "none"].includes(s) ? (s as Permission) : null);
  return pick(data.role_name) ?? pick(data.permission) ?? "none";
}

export interface PrFile {
  filename: string;
  status: string; // added | modified | removed | renamed | ...
  patch?: string; // absent for binary or very large files
}

/** Files changed in a pull request (GitHub caps this at 3000; we stop at `max`). */
export async function listPrFiles(repo: string, number: number, token?: string | null, max = 300, f: typeof fetch = fetch): Promise<PrFile[]> {
  const out: PrFile[] = [];
  for (let page = 1; out.length < max; page++) {
    const res = await f(`${API}/repos/${repo}/pulls/${number}/files?per_page=100&page=${page}`, { headers: baseHeaders(token) });
    await ensureOk(res, `files for ${repo}#${number}`);
    const batch = (await res.json()) as PrFile[];
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out.slice(0, max);
}

export interface PullRequestInfo {
  number: number;
  head: { sha: string; ref: string };
  base: { sha: string; ref: string };
  draft?: boolean;
}

export async function getPullRequest(repo: string, number: number, token?: string | null, f: typeof fetch = fetch): Promise<PullRequestInfo> {
  const res = await f(`${API}/repos/${repo}/pulls/${number}`, { headers: baseHeaders(token) });
  await ensureOk(res, `PR ${repo}#${number}`);
  return (await res.json()) as PullRequestInfo;
}

export type StatusState = "success" | "failure" | "pending" | "error";

/** A commit status ("security-review") so branch protection can require it. Works with a PAT or an App token. */
export async function setCommitStatus(
  a: { repo: string; sha: string; state: StatusState; description: string; context?: string; targetUrl?: string; token?: string | null },
  f: typeof fetch = fetch,
): Promise<void> {
  const res = await f(`${API}/repos/${a.repo}/statuses/${a.sha}`, {
    method: "POST",
    headers: { ...baseHeaders(a.token), "Content-Type": "application/json" },
    body: JSON.stringify({ state: a.state, description: a.description.slice(0, 140), context: a.context ?? "security-review", target_url: a.targetUrl }),
  });
  await ensureOk(res, "commit status");
}

/** A pull-request review comment on one line of the head commit (used for suggested fixes). */
export async function createLineComment(
  a: { repo: string; number: number; sha: string; path: string; line: number; startLine?: number; body: string; token?: string | null },
  f: typeof fetch = fetch,
): Promise<string> {
  const res = await f(`${API}/repos/${a.repo}/pulls/${a.number}/comments`, {
    method: "POST",
    headers: { ...baseHeaders(a.token), "Content-Type": "application/json" },
    body: JSON.stringify({
      commit_id: a.sha,
      path: a.path,
      line: a.line,
      side: "RIGHT",
      ...(a.startLine ? { start_line: a.startLine, start_side: "RIGHT" } : {}),
      body: a.body,
    }),
  });
  await ensureOk(res, "line comment");
  return ((await res.json()) as { html_url: string }).html_url;
}

export async function createComment(a: { repo: string; issueNumber: number; body: string; token?: string | null }, f: typeof fetch = fetch): Promise<void> {
  const res = await f(`${API}/repos/${a.repo}/issues/${a.issueNumber}/comments`, {
    method: "POST",
    headers: { ...baseHeaders(a.token), "Content-Type": "application/json" },
    body: JSON.stringify({ body: a.body }),
  });
  await ensureOk(res, "create comment");
}
