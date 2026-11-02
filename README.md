# Build a Security Reviewer Agent on Cloudflare

A ClawBuilders lab repo. A GitHub pull-request reviewer that looks at **security only** (no style or quality comments) and
is built the way you would want a security agent built: **deterministic checks first, a model second, a different model to
verify, and a policy that decides what blocks the merge.**

Both tracks run on the **Cloudflare Workers Free plan**.

| Track | What you build | Deploy |
|---|---|---|
| **Starter**: [`starter/`](starter) | One reviewer per PR: secrets, vulnerable dependencies (OSV.dev), risky patterns, then a model review that has to show how untrusted input reaches each problem, checked by a second model. One comment and a commit status. | [![Deploy Starter](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Clawbuilders/cloudflare-security-reviewer/tree/main/starter) |
| **Advanced**: this directory | A committee: Clef triage wakes five specialists (AppSec, identity, supply chain, CI and cloud config, AI-agent security) in parallel durable steps, plus your own specialists. Versioned policies you change without redeploying, four-eyes waivers that expire, an audit log, and suggested fixes a person commits. | [![Deploy Advanced](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Clawbuilders/cloudflare-security-reviewer) |

The workshop guide is [`docs/workshop-guide.md`](docs/workshop-guide.md).

## Why it is built this way

AI code scanners on their own are noisy. In Semgrep's 2025 study, Claude Code and OpenAI Codex reported mostly false
positives on real web apps, and the same prompt found different issues on different runs. So this reviewer:

1. **Runs deterministic checks first.** Secrets by provider format, known-vulnerable dependencies from the OSV.dev
   database, and a small readable rule set. These are facts. A committed credential always blocks, and no model or
   policy can turn that off.
2. **Asks the model for a path, not an opinion.** A model finding must name where untrusted input comes from (a request,
   a webhook, a model reply, a PR field) and how it reaches the problem. No path, no finding.
3. **Verifies with a second model.** A different model family re-reads each finding against the full file and drops what
   does not hold up. Dismissed findings stay visible in a collapsed list, so you can see what was filtered.
4. **Treats the code as untrusted.** A pull request can contain text written to steer an AI reviewer. The models have no
   tools, answer only in validated JSON, and a rule flags text addressed to AI reviewers.
5. **Lets a policy decide.** What blocks is configuration, not code. Every verdict records the policy version.

It flags risk for a person to judge. It does not prove that a finding is exploitable and it can miss things.

```
GitHub pull_request webhook (signature verified)
        |
        v
 Starter: ReviewWorkflow (one per pushed commit, every step checkpointed)
   collect ..... changed files, full-file context, dependency diff
   checks ...... secrets, OSV.dev, pattern signals                 (deterministic)
   review ...... skip if no code changed; propose, then verify     (gpt-oss-120b, nemotron-3-120b)
   publish ..... one comment edited in place + "security-review" commit status
```

## Starter setup

```bash
cd starter
npm install
npx wrangler secret put GITHUB_WEBHOOK_SECRET   # any long random string
npx wrangler secret put GITHUB_TOKEN            # fine-grained PAT, see below
npm run deploy
```

Token: a fine-grained personal access token limited to the repositories you want reviewed, with **Pull requests: read and
write**, **Commit statuses: read and write**, **Contents: read**. (Prefer a GitHub App? Set `GITHUB_APP_ID` and
`GITHUB_APP_PRIVATE_KEY`, PKCS#8, instead.)

Then in your repository: **Settings > Webhooks > Add webhook**. Payload URL = your Worker URL, content type
`application/json`, the same secret, and the **Pull requests** event. Open a PR and the review appears as a comment.

Make the check required: **Settings > Branches > branch protection > Require status checks > `security-review`**.

### Try it without touching GitHub

```bash
echo 'GITHUB_WEBHOOK_SECRET="local-test-secret"' >  starter/.dev.vars
echo 'DRY_RUN="true"'                           >> starter/.dev.vars
cd starter && npx wrangler dev
```

`DRY_RUN` never writes to GitHub. In a second terminal, send a signed webhook for any public PR and read the comment it
would have posted:

```bash
bash starter/send-test-webhook.sh Clawbuilders/cloudflare-web-qa-jev-agent 3
curl -s localhost:8787/reviews/<review id> | jq -r .output.body
```

Public repositories work without a token (GitHub allows 60 unauthenticated requests an hour).

## Advanced setup

```bash
npm install
npx wrangler secret put GITHUB_WEBHOOK_SECRET
npx wrangler secret put GITHUB_TOKEN     # Starter permissions plus Issues: read and write, Metadata: read
npx wrangler secret put ADMIN_TOKEN      # optional: turns on the policy and audit API
npm run deploy
```

Webhook events: **Pull requests** and **Issue comments**.

### The committee

| Specialist | Wakes when | Looks for |
|---|---|---|
| `appsec` | requests, input, queries, files, HTML, redirects | injection, XSS, path traversal, SSRF, open redirects, unsafe deserialization |
| `identity` | login, sessions, tokens, permissions, crypto | missing authorization (including reading another user's records by id), broken auth, tokens in URLs or logs, weak crypto, unsigned webhooks |
| `supply-chain` | dependency, install-script or build changes | install scripts that fetch code, git or unpinned sources, typo-named packages, unpinned downloads |
| `ci-cloud` | workflows, deploy config, CORS, headers, Wrangler | Actions script injection, `pull_request_target` misuse, broad permissions, unpinned actions, permissive CORS, exposed admin routes |
| `ai-agent` | model calls, prompts, agent tools | the OWASP Top 10 for Agentic Applications (2026): goal hijack from untrusted text, tools with side effects and no confirmation, model output executed or rendered |

Clef (`@cf/cloudflare/clef-flash`) answers one yes/no question per specialist. Triage can only add work: a deterministic
signal in a specialist's area always wakes it, and if Clef is unavailable every specialist runs.

### Policies without a redeploy

```bash
curl -X PUT https://<worker>/api/<owner>/<repo>/policy \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "x-actor: your-name" \
  -d '{
    "version": "2026-11-02",
    "block_model_at": "medium",
    "ignore_paths": ["generated/"],
    "specialists": [{
      "id": "webhooks",
      "name": "Webhook reviewer",
      "question": "Does this change add or modify a webhook or callback endpoint?",
      "instructions": "Check every webhook verifies its signature over the raw body before acting and rejects replays.",
      "paths": ["src/"]
    }]
  }'
```

Versions are immutable, unknown keys are rejected (a typo cannot silently weaken a policy), and the next review uses the
new version. `GET .../policy` shows the active policy and its history; `GET .../audit` lists every verdict with the policy
version, models and specialists that produced it.

| Key | Default | Meaning |
|---|---|---|
| `block_model_at` | `high` | model findings at or above this severity block, if `block_model_min_confidence` (0.8) is met |
| `block_rules_at` | `high` | deterministic rule findings at or above this severity block |
| `block_dependencies_at` | `high` | vulnerable dependencies at or above this severity block |
| `include_dev_dependencies` | `false` | report advisories in devDependencies |
| `report_min_confidence` | `0.6` | below this, a finding is not reported |
| `ignore_paths` | `[]` | path prefixes never reviewed |

### Comment commands

```
/waive 1a2b3c4d 14d vendor sandbox only, no real data   request a waiver (default 30 days, max 90)
/approve 1a2b3c4d                                        a DIFFERENT person with write access
/reject 1a2b3c4d
/security rescan
/security fix 1a2b3c4d                                   a suggested change on that line; a person commits it
```

A committed credential can never be waived: rotate it. An approved waiver expires and the finding blocks again on the next
review. Quoted lines and code fences are ignored, so replying to the bot never triggers anything. Bots cannot run commands.

## Free-plan notes

- **Models.** `gpt-oss-120b` proposes, `nemotron-3-120b-a12b` verifies, `clef-flash` triages. All run on Workers Free.
  The larger GLM, Kimi and DeepSeek models need Workers Paid; change `MODEL` and `VERIFY_MODEL` in `wrangler.json` if
  you have it.
- **Allowance.** Workers AI's free daily allowance covers a handful of PR reviews a day; the Advanced committee uses more
  per PR than the Starter. Add an [AI Gateway](https://developers.cloudflare.com/ai-gateway/) id as `AI_GATEWAY` for
  logs, caching and rate limits.
- **Subrequests.** A free invocation gets 50, so a review reads full context for at most `MAX_CONTEXT_FILES` (15) files
  and fetches details for at most 8 advisories. Larger files are judged on their diff.

## Develop

```bash
npm test            # unit tests: checks, policy, model-output validation, waivers, triage
npm run typecheck   # both tracks
```

## Extend it with your coding agent

Paste a prompt like this into Claude Code, Codex, Gemini CLI, Cursor, OpenCode or Hermes:

> Add a specialist to this security reviewer that checks Cloudflare D1 queries for missing tenant filters. Add it to
> `src/specialists.ts` with a triage question and a path filter, add a unit test, and run `npm test`.

## License

MIT. GitHub helpers adapted from [cloudflare-compliance-reviewer](https://github.com/Clawbuilders/cloudflare-compliance-reviewer).
