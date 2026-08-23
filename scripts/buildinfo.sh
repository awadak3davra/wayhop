#!/bin/sh
# buildinfo.sh — print the -X flags that stamp a binary with the source it came from.
#
# Every build path used to inject only the version, so every official binary reported
# `wayhop 0.5.5 (unknown, unknown)`. A production router was then found running a dirty build from a
# commit that no longer existed, and nothing about the binary could have told anyone that.
#
# One script rather than the same four lines in the Makefile, build.yml and feed.yml: three copies of
# a rule about identity are three chances for one of them to stamp something different.
#
# The date is the COMMIT's date, not the wall clock, so two builds of the same commit produce the
# same binary. A wall-clock stamp would make every rebuild differ in bytes and defeat the embedded-
# asset comparison that scripts/check-target-fresh.mjs relies on.
#
# Usage: go build -ldflags "-s -w $(scripts/buildinfo.sh [version])" ./cmd/wayhop
set -eu

pkg=wayhop/internal/version

version="${1:-}"
if [ -z "$version" ]; then
  version=$(sed -n 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    internal/version/version.go 2>/dev/null || true)
fi
[ -n "$version" ] || version=0.0.0-dev

# Outside a repository there is no commit to report. "unknown" is the honest answer, and the release
# workflow refuses to publish a binary carrying it — a build nobody can trace is not a release.
if commit=$(git rev-parse HEAD 2>/dev/null); then
  date=$(git show -s --format=%cI HEAD 2>/dev/null || echo unknown)
  if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
    dirty=false
  else
    dirty=true
  fi
else
  commit=unknown
  date=unknown
  dirty=unknown
fi

printf -- '-X %s.Version=%s -X %s.Commit=%s -X %s.Date=%s -X %s.Dirty=%s' \
  "$pkg" "$version" "$pkg" "$commit" "$pkg" "$date" "$pkg" "$dirty"
