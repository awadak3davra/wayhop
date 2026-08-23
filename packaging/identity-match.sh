#!/bin/sh
# identity-match.sh — does the daemon answering on the port come from the binary we just installed?
#
# The installers' health probe asks for HTTP 200 and nothing more. A daemon left over from before the
# upgrade answers exactly the same 200: the new binary could not bind, exited without a word, and the
# install reports success while the router keeps running the old code. That is not hypothetical — the
# UI gates lost a whole session to the same shape, measuring yesterday's build because a stale process
# held the port.
#
# Usage: identity-match.sh "<wayhop --version output>" "<GET /api/health body>"
# Exit:  0 the port is serving the installed build
#        1 MISMATCH — something else is on that port
#        2 cannot judge (either side reports no commit; an unstamped build, or a daemon too old to
#          report one). Deliberately distinct from 0: an installer must not treat "no evidence" as
#          "verified", and must not fail an upgrade over it either.
set -eu

installed="${1:-}"
health="${2:-}"

# `wayhop --version` prints: wayhop <ver> (<short-commit>, <date>)[ DIRTY]
short=$(printf '%s' "$installed" | sed -n 's/^wayhop [^ ]* (\([^,)]*\).*/\1/p' | head -n1)
# /api/health carries the full commit under build.commit.
full=$(printf '%s' "$health" | sed -n 's/.*"commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)

[ -n "$short" ] && [ "$short" != "unknown" ] || exit 2
[ -n "$full" ] && [ "$full" != "unknown" ] || exit 2

# The binary prints a short commit and the daemon reports the full one, so this is a prefix test.
case "$full" in
  "$short"*) exit 0 ;;
  *) exit 1 ;;
esac
