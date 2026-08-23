#!/bin/sh
# check-installer-identity.sh — fault tests for packaging/identity-match.sh.
#
# That script is what stops an installer reporting success while a stale daemon holds the port, so
# the case that matters is the MISMATCH: if it ever returned 0 there, the whole check would be a
# comment. Each case below is run for its exit code, including the ones that must NOT pass.
set -eu

M="packaging/identity-match.sh"
[ -f "$M" ] || { echo "FAIL  $M is missing — this gate has no subject"; exit 2; }

fails=0
case_() { # name expected version-line health-body
  name="$1"; want="$2"; ver="$3"; hp="$4"
  got=0
  sh "$M" "$ver" "$hp" || got=$?
  if [ "$got" = "$want" ]; then
    echo "  PASS  $name (exit $got)"
  else
    echo "  FAIL  $name: exit $got, want $want"
    fails=$((fails + 1))
  fi
}

FULL='961103dc9d6c2cf9a2ab6b29ac3d0368deb4090b'
OTHER='1fa030d24c3b8b0a1d2e3f4a5b6c7d8e9f001122'

case_ 'the port serves the installed build' 0 \
  "wayhop 0.5.5 (961103dc9d6c, 2026-08-08T17:34:37Z)" \
  "{\"status\":\"ok\",\"version\":\"0.5.5\",\"build\":{\"version\":\"0.5.5\",\"commit\":\"$FULL\",\"date\":\"2026-08-08T17:34:37Z\",\"dirty\":\"false\"}}"

case_ 'a stale daemon from another build holds the port' 1 \
  "wayhop 0.5.5 (961103dc9d6c, 2026-08-08T17:34:37Z)" \
  "{\"status\":\"ok\",\"version\":\"0.5.5\",\"build\":{\"commit\":\"$OTHER\",\"dirty\":\"false\"}}"

# Same version string, different code: the exact upgrade that looks successful and is not.
case_ 'same version, different commit' 1 \
  "wayhop 0.5.5 (961103dc9d6c, 2026-08-08T17:34:37Z)" \
  "{\"version\":\"0.5.5\",\"build\":{\"commit\":\"$OTHER\"}}"

case_ 'the installed binary is unstamped' 2 \
  "wayhop 0.5.5 (unknown, unknown)" \
  "{\"build\":{\"commit\":\"$FULL\"}}"

case_ 'the daemon reports no commit' 2 \
  "wayhop 0.5.5 (961103dc9d6c, 2026-08-08T17:34:37Z)" \
  "{\"status\":\"ok\",\"version\":\"0.5.5\"}"

case_ 'the daemon answered with nothing' 2 \
  "wayhop 0.5.5 (961103dc9d6c, 2026-08-08T17:34:37Z)" ""

case_ 'a dirty build still matches its own commit' 0 \
  "wayhop 0.5.5 (961103dc9d6c, 2026-08-08T17:34:37Z) DIRTY" \
  "{\"build\":{\"commit\":\"$FULL\",\"dirty\":\"true\"}}"

if [ "$fails" -gt 0 ]; then
  echo "$fails installer-identity case(s) failed"
  exit 1
fi
echo "installer identity matching: 7 cases, including 3 that must not pass"
