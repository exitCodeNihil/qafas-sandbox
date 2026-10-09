#!/usr/bin/env bash
# Branch protection for `main`: PRs only, the CI jobs must pass,
# no force pushes, no deletes. GitHub only allows this on public repos or paid plans, so it
# is a script rather than something the workflows can apply: run it once the repo is public.
#   scripts/protect-main.sh [owner/repo]
set -euo pipefail
repo="${1:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
gh api -X PUT "repos/$repo/branches/main/protection" --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["linux", "macos"] },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": true,
  "required_conversation_resolution": true
}
JSON
echo "main protected on $repo: linux, macos required; linear history; no force-push"
