#!/usr/bin/env bash
# Run one native Go fuzz target for a while (make fuzz, nightly.yml).
#
#   scripts/fuzz.sh <package> <target> <fuzztime>
#
# When -fuzztime runs out while a worker is still executing an input, the Go
# fuzzing engine reports the cancellation as a failure: "--- FAIL: <target>"
# followed only by "context deadline exceeded", with no failing input and
# nothing written to testdata/fuzz. That one outcome is a pass (with a
# warning); every other failure, and any new file under testdata/fuzz, fails.
set -uo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 <package> <target> <fuzztime>" >&2
  exit 2
fi
pkg=$1 target=$2 fuzztime=$3

dir=$(go list -f '{{.Dir}}' "$pkg") || exit 1
corpus="$dir/testdata/fuzz/$target"
list_corpus() { find "$corpus" -type f 2>/dev/null | sort; }
before=$(list_corpus)

out=$(mktemp)
trap 'rm -f "$out"' EXIT
go test -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime" "$pkg" 2>&1 | tee "$out"
status=${PIPESTATUS[0]}
[ "$status" -eq 0 ] && exit 0

# The indented lines of the "--- FAIL: <target>" block: the failure details.
details=$(awk -v t="--- FAIL: $target " '
  index($0, t) == 1 { in_block = 1; next }
  in_block && /^[ \t]/ { sub(/^[ \t]+/, ""); print; next }
  in_block { exit }
' "$out")

if [ "$details" = "context deadline exceeded" ] &&
  [ "$(list_corpus)" = "$before" ] &&
  ! grep -qE 'Failing input written|^panic:|fatal error:' "$out"; then
  msg="$target: fuzzing stopped at the -fuzztime deadline while an input was running (Go reports it as a failure); no failing input, counted as a pass"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::warning title=Fuzz deadline::$msg"
  else
    echo "warning: $msg" >&2
  fi
  exit 0
fi
exit "$status"
