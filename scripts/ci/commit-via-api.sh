#!/usr/bin/env bash
# Commit every changed tracked file to a branch through the GitHub GraphQL API
# (createCommitOnBranch), so the commit is authored and signed by the GitHub
# App whose token is in GH_TOKEN. Pushes made with the workflow GITHUB_TOKEN
# never trigger CI; App-token commits do.
#
#   GH_TOKEN=... scripts/ci/commit-via-api.sh <branch> <message> [base-sha]
#
# The branch is created from base-sha when it does not exist yet. Prints
# nothing and exits 0 when there is nothing to commit.
set -euo pipefail
cd "$(dirname "$0")/../.."

branch=$1 message=$2 base=${3:-$(git rev-parse HEAD)}
repo=${GITHUB_REPOSITORY:?}

mapfile -t changed < <(git diff --name-only)
if [ "${#changed[@]}" -eq 0 ]; then
  exit 0
fi

if ! head=$(gh api "repos/$repo/git/ref/heads/$branch" --jq .object.sha 2>/dev/null); then
  gh api "repos/$repo/git/refs" -f ref="refs/heads/$branch" -f sha="$base" >/dev/null
  head=$base
fi

additions=$(for f in "${changed[@]}"; do
  jq -nc --arg path "$f" --arg contents "$(base64 -w0 "$f")" '{path: $path, contents: $contents}'
done | jq -sc .)

jq -n --arg repo "$repo" --arg branch "$branch" --arg head "$head" \
  --arg message "$message" --argjson additions "$additions" '{
  query: "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }",
  variables: { input: {
    branch: { repositoryNameWithOwner: $repo, branchName: $branch },
    expectedHeadOid: $head,
    message: { headline: $message },
    fileChanges: { additions: $additions }
  } }
}' | gh api graphql --input - --jq .data.createCommitOnBranch.commit.oid
