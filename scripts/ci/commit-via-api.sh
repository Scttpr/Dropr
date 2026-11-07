#!/usr/bin/env bash
# Commit every changed tracked file to a branch through the GitHub GraphQL API
# (createCommitOnBranch), so the commit is authored and signed by the GitHub
# App whose token is in GH_TOKEN. Pushes made with the workflow GITHUB_TOKEN
# never trigger CI; App-token commits do.
#
#   GH_TOKEN=... scripts/ci/commit-via-api.sh <branch> <message> [base-sha]
#
# base-sha (default: HEAD) is the commit the changes were made on. A missing
# branch is created there; an existing branch must still point at it, so a
# branch that moved meanwhile (say, a Dependabot rebase) is never overwritten
# with changes computed for an older commit. Prints the new commit's SHA, or
# nothing when there is nothing to commit.
set -euo pipefail
cd "$(dirname "$0")/../.."

branch=$1 message=$2 base=${3:-$(git rev-parse HEAD)}
repo=${GITHUB_REPOSITORY:?}

mapfile -t changed < <(git diff --name-only)
if [ "${#changed[@]}" -eq 0 ]; then
  exit 0
fi

if ! gh api "repos/$repo/git/ref/heads/$branch" --silent 2>/dev/null; then
  gh api "repos/$repo/git/refs" -f ref="refs/heads/$branch" -f sha="$base" --silent
fi

additions=$(for f in "${changed[@]}"; do
  jq -nc --arg path "$f" --arg contents "$(base64 -w0 "$f")" '{path: $path, contents: $contents}'
done | jq -sc .)

jq -n --arg repo "$repo" --arg branch "$branch" --arg head "$base" \
  --arg message "$message" --argjson additions "$additions" '{
  query: "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }",
  variables: { input: {
    branch: { repositoryNameWithOwner: $repo, branchName: $branch },
    expectedHeadOid: $head,
    message: { headline: $message },
    fileChanges: { additions: $additions }
  } }
}' | gh api graphql --input - --jq .data.createCommitOnBranch.commit.oid
