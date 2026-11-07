#!/usr/bin/env bash
# Open (or comment on) one tracking issue when a scheduled workflow fails, so
# a red nightly is noticed without anyone watching the Actions tab.
#
#   GH_TOKEN=... scripts/ci/report-failure.sh "<workflow name>"
set -euo pipefail

workflow=$1
run_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
title="$workflow failed"

gh label create ci-failure --color B60205 --description "Scheduled CI failed" 2>/dev/null || true

issue=$(gh issue list --state open --label ci-failure --search "in:title \"$title\"" --json number --jq '.[0].number // empty')
if [ -n "$issue" ]; then
  gh issue comment "$issue" --body "Failed again: $run_url"
else
  gh issue create --title "$title" --label ci-failure \
    --body "The scheduled **$workflow** run failed: $run_url. Close this issue once it is green again."
fi
