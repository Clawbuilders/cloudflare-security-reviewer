import type { GitHubAppEnv } from "./lib/github";
import type { AiBinding } from "./lib/model";
import type { PrRef } from "./lib/pipeline";

export interface Env extends GitHubAppEnv {
  AI: AiBinding;
  REVIEW_WORKFLOW: Workflow<PrRef>;
  /** Required: the secret you typed into the GitHub webhook form. */
  GITHUB_WEBHOOK_SECRET?: string;
  /** Fine-grained PAT: Pull requests read/write, Commit statuses read/write, Contents read. Or use a GitHub App. */
  GITHUB_TOKEN?: string;
  MODEL?: string;
  VERIFY_MODEL?: string;
  MIN_CONFIDENCE?: string;
  MAX_CONTEXT_FILES?: string;
  MAX_MODEL_CHARS?: string;
  /** Optional AI Gateway id: logs, caching and rate limits for every model call. */
  AI_GATEWAY?: string;
  /** "true" = never write to GitHub; read results at GET /reviews/<id>. */
  DRY_RUN?: string;
}
