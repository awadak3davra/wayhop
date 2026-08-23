#!/bin/sh
# check-feed-completeness.sh — fault tests for packaging/feed/verify-apk-feed.sh.
#
# That verifier is what turns the apk feed from best-effort into a promise, so the cases that matter
# are the ones it must REFUSE: a missing architecture, an empty package, a missing index. A verifier
# that passed those would restore exactly the silence it was written to end.
set -eu

V="packaging/feed/verify-apk-feed.sh"
[ -f "$V" ] || { echo "FAIL  $V is missing — this gate has no subject"; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

map="$tmp/arch-map.txt"
cat > "$map" <<'MAP'
# comment line, must be skipped
arm64     aarch64_generic aarch64_cortex-a53   | aarch64-3.10
amd64     x86_64                               | x86-64-3.2
MAP

mkfeed() { # $1 = feed dir; creates a complete feed for the map above
  rm -rf "$1"
  for t in aarch64_generic aarch64_cortex-a53 x86_64; do
    mkdir -p "$1/apk/$t"
    echo "payload" > "$1/apk/$t/wayhop-1.0.0-r1.apk"
    echo "index" > "$1/apk/$t/packages.adb"
  done
}

fails=0
case_() { # name expected-exit feed-dir [extra-args]
  name="$1"; want="$2"; feed="$3"; shift 3
  got=0
  sh "$V" "$feed" "$map" "$@" >/dev/null 2>&1 || got=$?
  if [ "$got" = "$want" ]; then
    echo "  PASS  $name (exit $got)"
  else
    echo "  FAIL  $name: exit $got, want $want"
    fails=$((fails + 1))
  fi
}

feed="$tmp/feed"

mkfeed "$feed"
case_ 'a complete feed passes' 0 "$feed"

mkfeed "$feed"
case_ 'a complete feed passes with the index required' 0 "$feed" --require-index

# The headline case: the packer skipped and the feed shipped without an architecture it advertises.
mkfeed "$feed"
rm -rf "$feed/apk/x86_64"
case_ 'a claimed architecture with no package is refused' 1 "$feed"

mkfeed "$feed"
rm -rf "$feed/apk"
case_ 'no apk packages at all is refused' 1 "$feed"

# Half-written output installs as nothing and looks like a file.
mkfeed "$feed"
: > "$feed/apk/aarch64_generic/wayhop-1.0.0-r1.apk"
case_ 'an empty package is refused' 1 "$feed"

mkfeed "$feed"
rm -f "$feed/apk/aarch64_cortex-a53/packages.adb"
case_ 'a missing index is refused when the index is required' 1 "$feed" --require-index
case_ 'a missing index is tolerated when it is not required' 0 "$feed"

# A map that parses to nothing must not read as "everything present".
empty="$tmp/empty-map.txt"
printf '# only a comment\n\n' > "$empty"
got=0
sh "$V" "$feed" "$empty" >/dev/null 2>&1 || got=$?
if [ "$got" = 2 ]; then
  echo "  PASS  an arch map that yields no tokens is an error, not a pass (exit 2)"
else
  echo "  FAIL  an empty arch map returned $got, want 2"
  fails=$((fails + 1))
fi

got=0
sh "$V" "$tmp/nope" "$map" >/dev/null 2>&1 || got=$?
if [ "$got" = 2 ]; then
  echo "  PASS  a missing feed directory is an error (exit 2)"
else
  echo "  FAIL  a missing feed directory returned $got, want 2"
  fails=$((fails + 1))
fi

if [ "$fails" -gt 0 ]; then
  echo "$fails feed-completeness case(s) failed"
  exit 1
fi
echo "apk feed completeness: 9 cases, including 6 that must not pass"
