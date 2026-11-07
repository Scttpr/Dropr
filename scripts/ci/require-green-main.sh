#!/usr/bin/env bash
# Release gate: the tagged commit must be on main and its CI must have passed.
# The release then reuses that run instead of testing the same commit twice.
#
# Tag a commit main's CI ran on: a push of several commits only tests the
# last one. The latest result counts, so a daily security run that finds a
# new advisory on main's tip blocks its release until fixed or re-run.
#
#   GH_TOKEN=... scripts/ci/require-green-main.sh <sha>
set -euo pipefail

sha=$1 repo=${GITHUB_REPOSITORY:?}

# The tag must point into main's history, not at an unreviewed side branch.
status=$(gh api "repos/$repo/compare/main...$sha" --jq .status)
case $status in
  behind | identical) ;;
  *) echo "$sha is not on main (compare: $status)" >&2; exit 1 ;;
esac

# Both gates (ci.yml "ci-ok", security.yml "security-ok") from push runs.
for check in ci-ok security-ok; do
  conclusion=$(gh api "repos/$repo/commits/$sha/check-runs?check_name=$check&filter=latest" \
    --jq '[.check_runs[] | select(.app.slug == "github-actions")][0].conclusion // "missing"')
  echo "$check: $conclusion"
  if [ "$conclusion" != success ]; then
    echo "$check did not pass on $sha; wait for main's CI or re-run it" >&2
    exit 1
  fi
done
