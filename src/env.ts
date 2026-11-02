import type { GitHubAppEnv } from "../starter/src/lib/github";
import type { AiBinding } from "../starter/src/lib/model";
import type { SecurityAgent } from "./agent";

export interface ReviewParams {
  repo: string;
  number: number;
  sha: string;
  installationId?: number;
}

export interface Env extends GitHubAppEnv {
  AI: AiBinding;
  SECURITY_AGENT: DurableObjectNamespace<SecurityAgent>;
  REVIEW_WORKFLOW: Workflow<ReviewParams>;
  GITHUB_WEBHOOK_SECRET?: string;
  GITHUB_TOKEN?: string;
  /** Bearer token for the policy and audit API. Unset = the API is off. */
  ADMIN_TOKEN?: string;
  MODEL?: string;
  VERIFY_MODEL?: string;
  TRIAGE_THRESHOLD?: string;
  MIN_CONFIDENCE?: string;
  MAX_CONTEXT_FILES?: string;
  MAX_MODEL_CHARS?: string;
  AI_GATEWAY?: string;
  DRY_RUN?: string;
}
