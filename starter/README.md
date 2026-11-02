# Security reviewer: Starter track

One security reviewer for every GitHub pull request, on Cloudflare Workers + Workers AI, free plan.

1. Deploy (button in the [main README](../README.md), or `npm install && npm run deploy`).
2. Set two secrets: `npx wrangler secret put GITHUB_WEBHOOK_SECRET` and `npx wrangler secret put GITHUB_TOKEN`.
3. Add a webhook in your repository (Settings > Webhooks): your Worker URL, `application/json`, the same secret, event **Pull requests**.
4. Open a pull request. The review appears as one comment, plus a `security-review` commit status.
5. Optional: run zizmor, CodeQL or osv-scanner in GitHub Actions (examples in `../examples/github-actions/`) and add
   **Code scanning alerts: read** to the token; the reviewer verifies their alerts on the lines the PR added.

Try it locally with `DRY_RUN="true"` in `.dev.vars` and `send-test-webhook.sh`. Full explanation: [README](../README.md) and
[workshop guide](../docs/workshop-guide.md).
