# Build a Security Reviewer Agent on Cloudflare

A ClawBuilders lab repo. A GitHub pull-request reviewer that looks at **security only** (no style or quality comments) and
is built the way you would want a security agent built: **deterministic checks first, a model second, a different model to
verify, and a policy that decides what blocks the merge.**

Both tracks run on the **Cloudflare Workers Free plan**.

| Track | What you build | Deploy |
|---|---|---|
| **Starter**: [`starter/`](starter) | One reviewer per PR: secrets, vulnerable dependencies (OSV.dev, ranked by real-world exploitation), the health of new packages, risky patterns, then a model review that has to show how untrusted input reaches each problem, checked by a second model. One comment and a commit status. | [![Deploy Starter](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Clawbuilders/cloudflare-security-reviewer/tree/main/starter) |
| **Advanced**: this directory | A committee: Clef triage wakes six specialists (AppSec, identity, supply chain, CI and cloud config, AI-agent security, data isolation) in parallel durable steps, plus your own specialists. Versioned policies you change without redeploying, four-eyes waivers that expire, an audit log, and suggested fixes a person commits. | [![Deploy Advanced](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Clawbuilders/cloudflare-security-reviewer) |

The workshop guide is [`docs/workshop-guide.md`](docs/workshop-guide.md).

## Why it is built this way

AI code scanners on their own are noisy. In Semgrep's 2025 study, Claude Code and OpenAI Codex reported mostly false
positives on real web apps, and the same prompt found different issues on different runs. So this reviewer:

1. **Runs deterministic checks first.** Secrets by provider format, known-vulnerable dependencies from the OSV.dev
   database, and a small readable rule set. These are facts. A committed credential always blocks, and no model or
   policy can turn that off.
2. **Ranks dependency risk by exploitation, not only severity.** Each CVE is looked up in
   [EPSS](https://www.first.org/epss/) (the chance it is exploited in the next 30 days) and
   [CISA's Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog. A
   KEV-listed dependency is critical and blocks; EPSS of 10% or more raises it to at least high. Packages added for the
   first time are checked on [deps.dev](https://deps.dev): published days ago, deprecated, no linked source, or a low
   OpenSSF Scorecard.
3. **Asks the model for a path, not an opinion.** A model finding must name where untrusted input comes from (a request,
   a webhook, a model reply, a PR field) and how it reaches the problem. No path, no finding.
4. **Filters known noise, then verifies with a second model.** Hard exclusion rules ported from Anthropic's
   [claude-code-security-review](https://github.com/anthropics/claude-code-security-review) (MIT) drop generic
   denial-of-service, "add rate limiting", resource leaks, memory safety outside C/C++ and similar low-signal findings
   before any model call. A different model family then re-reads each remaining finding against the full file, with the
   same project's false-positive precedents, and drops what does not hold up. Dismissed findings stay visible in a
   collapsed list with the reason.
5. **Treats the code as untrusted.** A pull request can contain text written to steer an AI reviewer. The models have no
   tools, answer only in validated JSON, and a rule flags text addressed to AI reviewers.
6. **Lets a policy decide.** What blocks is configuration, not code. Every verdict records the policy version.
7. **Borrows a real audit methodology.** Each reviewer loads the matching domain of
   [Cloudflare's security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT): its "core discipline"
   and attack classes go to the model that proposes findings, and its validation rules and verifier checklist go to the
   model that checks them. Only the domains a reviewer owns are loaded, and only when triage wakes it.
8. **Reads the heavy scanners instead of running them.** zizmor, CodeQL and osv-scanner run in GitHub Actions and upload
   results to code scanning. The reviewer reads the open alerts on lines the PR added in one request and sends them
   through the same filter and verifier as model findings.

It flags risk for a person to judge. It does not prove that a finding is exploitable and it can miss things.

```
GitHub pull_request webhook (signature verified)
        |
        v
 Starter: ReviewWorkflow (one per pushed commit, every step checkpointed)
   collect ..... changed files, full-file context, dependency diff, code-scanning alerts
   checks ...... secrets, OSV.dev + EPSS + KEV, deps.dev, pattern signals   (deterministic)
   review ...... skip if no code changed; propose, exclude noise, verify    (gpt-oss-120b, nemotron-3-120b)
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
write**, **Commit statuses: read and write**, **Contents: read**, and optionally **Code scanning alerts: read** to bring in
zizmor or CodeQL results (see below). (Prefer a GitHub App? Set `GITHUB_APP_ID` and
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

Webhook events: **Pull requests**, **Issue comments**, and **Workflow runs** (so the review runs again when a scanner
workflow finishes after it).

### Scanner results from GitHub Actions (optional, both tracks)

Some scanners are too heavy for a Worker. Run them in Actions and the reviewer picks up their alerts:

- **zizmor** for GitHub Actions workflows: copy [`examples/github-actions/zizmor.yml`](examples/github-actions/zizmor.yml)
  into the reviewed repository's `.github/workflows/`.
- **CodeQL**: **Settings > Code security > Code scanning > Set up > Default**.
- **osv-scanner** for ecosystems this Worker does not read (Go, Cargo, Maven...):
  [`examples/github-actions/osv-scanner.yml`](examples/github-actions/osv-scanner.yml).

Code scanning is free on public repositories (private ones need GitHub Advanced Security). Give the token or App
**Code scanning alerts: read**. Only alerts on lines the PR added are used, and the verifier can still drop them. The
Advanced track re-reviews when a workflow named in `SCANNER_WORKFLOWS` (default `zizmor,CodeQL,osv-scanner`) finishes;
the Starter reads whatever has finished when it runs. Set `CODE_SCANNING="false"` to turn it off. The comment says which
scanners' alerts were read, or why none were.

### The committee

| Specialist | Wakes when | Looks for |
|---|---|---|
| `appsec` | requests, input, queries, files, HTML, redirects | injection, XSS, path traversal, SSRF, open redirects, unsafe deserialization |
| `identity` | login, sessions, tokens, permissions, crypto | missing authorization (including reading another user's records by id), broken auth, tokens in URLs or logs, weak crypto, unsigned webhooks |
| `supply-chain` | dependency, install-script or build changes | install scripts that fetch code, git or unpinned sources, typo-named packages, unpinned downloads |
| `ci-cloud` | workflows, deploy config, CORS, headers, Wrangler | Actions script injection, `pull_request_target` misuse, broad permissions, unpinned actions, permissive CORS, exposed admin routes |
| `ai-agent` | model calls, prompts, agent tools | the OWASP Top 10 for Agentic Applications (2026): goal hijack from untrusted text, tools with side effects and no confirmation, model output executed or rendered |
| `data-isolation` | records of different users, teams or tenants | missing owner or tenant filters, shared caches and indexes, exports with other people's data, deletes that leave copies behind |

### Skills each specialist loads

From the vendored [`starter/skills/security-audit/`](starter/skills/security-audit) (Cloudflare, MIT, pinned commit in
`UPSTREAM.md`). The review comment lists what was loaded.

| Reviewer | Skill domains |
|---|---|
| Starter generalist | `ATTACK-CLASSES` (injection, access control, obvious things), `AI-AND-LLM` (tool and action classes) |
| `appsec` | `ATTACK-CLASSES`, `CLIENT-SIDE` |
| `identity` | `WEB-PROTOCOL-AND-AUTH`, `ATTACK-CLASSES` (access control, cryptography and secrets) |
| `supply-chain` | `SUPPLY-CHAIN-AND-RELEASE` |
| `ci-cloud` | `CLOUD-AND-DEPLOYMENT`, `SUPPLY-CHAIN-AND-RELEASE` (CI and automation) |
| `ai-agent` | `AI-AND-LLM` |
| `data-isolation` | `DATA-ISOLATION-AND-LIFECYCLE`, `ATTACK-CLASSES` (business logic) |
| verifier | the skill's source-only verifier checklist plus each involved domain's validation rules |

`SKILL_CHARS` (6000 Starter, 7000 Advanced) caps how much methodology goes into each prompt; core discipline is loaded
first, then attack classes in priority order. Set it to `0` to compare reviews with and without the skill. A custom
specialist can load a domain too: add `"skill": ["DATA-ISOLATION-AND-LIFECYCLE"]` to its policy entry. To update the
skill, copy newer files into the vendored directory and run `npm run skills:sync`; `npm test` fails if the generated
module is stale or a specialist names an attack class that no longer exists.

For a deep audit of a whole repository, run the full skill in your coding agent (Claude Code, Codex, Gemini CLI, Cursor,
OpenCode) alongside this reviewer: the skill audits occasionally and deeply, the reviewer checks every pull request.

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
      "skill": ["WEB-PROTOCOL-AND-AUTH"],
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
| `block_known_exploited` | `true` | a dependency in CISA KEV blocks whatever its severity |
| `model_exclusions` | all | exclusion rules applied to model and scanner findings: `dos`, `rate-limit`, `resource-leak`, `open-redirect`, `regex-injection`, `memory-safety`, `ssrf-client-side`, `test-only`, `log-spoofing`, `markdown` |

### Comment commands

```
/waive 1a2b3c4d 14d vendor sandbox only, no real data   request a waiver (default 30 days, max 90)
/approve 1a2b3c4d                                        a DIFFERENT person with write access
/reject 1a2b3c4d
/security rescan
/security fix 1a2b3c4d                                   a suggested change on that line; a person commits it
```

`/security fix` writes the suggestion with the matching secure-coding rules from CoSAI's
[Project CodeGuard](https://github.com/cosai-oasis/project-codeguard) (CC-BY-4.0, vendored under
[`skills/codeguard/`](skills/codeguard)), so a fix for SQL injection follows CodeGuard's input-validation rules instead of
trading one weakness for another. CodeGuard is used only for fixes: its checklists are written for code generation and
would produce "missing best practice" noise in a review.

A committed credential can never be waived: rotate it. An approved waiver expires and the finding blocks again on the next
review. Quoted lines and code fences are ignored, so replying to the bot never triggers anything. Bots cannot run commands.

## Free-plan notes

- **Models.** `gpt-oss-120b` proposes, `nemotron-3-120b-a12b` verifies, `clef-flash` triages. All run on Workers Free.
  The larger GLM, Kimi and DeepSeek models need Workers Paid; change `MODEL` and `VERIFY_MODEL` in `wrangler.json` if
  you have it.
- **Allowance.** Workers AI's free daily allowance covers a handful of PR reviews a day; the Advanced committee uses more
  per PR than the Starter. Add an [AI Gateway](https://developers.cloudflare.com/ai-gateway/) id as `AI_GATEWAY` for
  logs, caching and rate limits.
- **Subrequests.** A free invocation gets 50, so a review reads full context for at most `MAX_CONTEXT_FILES` (15) files.
  The checks step makes at most about 27 requests: OSV (1 + 8 advisory details), EPSS and KEV (2, only when a CVE is
  found; KEV is cached at the edge for six hours) and deps.dev (3 for each of up to 5 newly added packages). Larger
  files are judged on their diff.

## Develop

```bash
npm test            # skill sync check + unit tests: checks, exclusions, EPSS/KEV, deps.dev, scanners, policy, waivers, triage
npm run skills:sync # regenerate the skill modules after updating vendored files (security-audit skill, CodeGuard)
npm run typecheck   # both tracks
```

## Extend it with your coding agent

Paste a prompt like this into Claude Code, Codex, Gemini CLI, Cursor, OpenCode or Hermes:

> Add a specialist to this security reviewer that checks Cloudflare D1 queries for missing tenant filters. Add it to
> `src/specialists.ts` with a triage question and a path filter, add a unit test, and run `npm test`.

## License

MIT. See `NOTICE`: includes Cloudflare's security-audit skill (MIT), exclusion rules adapted from Anthropic's
claude-code-security-review (MIT), CoSAI Project CodeGuard rules (CC-BY-4.0, under `skills/codeguard/` only), and GitHub
helpers adapted from [cloudflare-compliance-reviewer](https://github.com/Clawbuilders/cloudflare-compliance-reviewer).

Further reading that is not vendored: Trail of Bits'
[fp-check and differential-review skills](https://github.com/trailofbits/skills) (CC-BY-SA-4.0) make a good companion
for a deeper manual review in your coding agent.
