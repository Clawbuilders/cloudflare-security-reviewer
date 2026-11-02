#!/usr/bin/env bash
# Send a signed pull_request webhook to a local reviewer (wrangler dev) for any public PR.
# usage: scripts/send-test-webhook.sh <owner/repo> <pr-number> [port] [secret]
# The secret must match GITHUB_WEBHOOK_SECRET in .dev.vars. Run with DRY_RUN="true" so nothing is written to GitHub.
set -euo pipefail
repo=$1; number=$2; port=${3:-8787}; secret=${4:-local-test-secret}
sha=$(curl -fsS "https://api.github.com/repos/$repo/pulls/$number" | node -pe 'JSON.parse(require("fs").readFileSync(0)).head.sha')
body=$(printf '{"action":"opened","pull_request":{"number":%s,"draft":false,"head":{"sha":"%s"}},"repository":{"full_name":"%s"}}' "$number" "$sha" "$repo")
sig=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "$secret" | awk '{print $NF}')
curl -sS -X POST "http://localhost:$port/" -H "x-github-event: pull_request" -H "x-hub-signature-256: sha256=$sig" -H "content-type: application/json" -d "$body"
echo
echo "Starter: read the result at http://localhost:$port/reviews/<review id above>"
echo "Advanced: the review starts after a 15 second debounce; its id is printed in the wrangler log."
