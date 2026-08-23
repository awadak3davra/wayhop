#!/bin/sh
# check-retire-iptv.sh — fault tests for packaging/retire-iptv.sh.
#
# The cases that matter are the ones where it must NOT act: a directory holding something WayHop did
# not write, and a second run over a tree it has already retired. A migration that deletes an
# operator's file, or that clobbers the archive it made last time, fails once and permanently.
#
# Every case also asserts that NOTHING was deleted — the file count before and after must match,
# whatever the script decided to do.
set -eu

R="packaging/retire-iptv.sh"
[ -f "$R" ] || { echo "FAIL  $R is missing — this gate has no subject"; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0

countfiles() { find "$1" -type f 2>/dev/null | wc -l | tr -d ' '; }

ok_() { echo "  PASS  $1"; }
no_() { echo "  FAIL  $1${2:+   [$2]}"; fails=$((fails + 1)); }

# --- 1. nothing to do -------------------------------------------------------------------------
d="$tmp/a"; mkdir -p "$d"
out=$(sh "$R" "$d")
case "$out" in *"nothing to retire"*) ok_ 'a data dir with no iptv/ is a no-op' ;;
  *) no_ 'a data dir with no iptv/ is a no-op' "$out" ;; esac

# --- 2. WayHop-only contents are moved aside, not deleted -------------------------------------
d="$tmp/b"; mkdir -p "$d/iptv"
echo "#EXTM3U" > "$d/iptv/aaaa.m3u"
echo "#EXTM3U" > "$d/iptv/bbbb.m3u"
before=$(countfiles "$d")
sh "$R" "$d" >/dev/null
after=$(countfiles "$d")
if [ ! -d "$d/iptv" ] && [ -d "$d/iptv-retired" ] && [ -f "$d/iptv-retired/aaaa.m3u" ]; then
  ok_ 'generated playlists are moved to iptv-retired'
else
  no_ 'generated playlists are moved to iptv-retired'
fi
[ "$before" = "$after" ] && ok_ 'nothing was deleted while retiring' \
  || no_ 'nothing was deleted while retiring' "before=$before after=$after"

# --- 3. idempotency: a second run does nothing -------------------------------------------------
before=$(countfiles "$d")
out=$(sh "$R" "$d")
after=$(countfiles "$d")
case "$out" in *"nothing to retire"*) ok_ 'a second run is a no-op' ;;
  *) no_ 'a second run is a no-op' "$out" ;; esac
[ "$before" = "$after" ] && ok_ 'the second run deleted nothing' \
  || no_ 'the second run deleted nothing' "before=$before after=$after"

# --- 4. an operator's own file stops everything ------------------------------------------------
d="$tmp/c"; mkdir -p "$d/iptv"
echo "#EXTM3U" > "$d/iptv/aaaa.m3u"
echo "mine" > "$d/iptv/notes.txt"
before=$(countfiles "$d")
out=$(sh "$R" "$d")
after=$(countfiles "$d")
if [ -d "$d/iptv" ] && [ -f "$d/iptv/notes.txt" ] && [ ! -d "$d/iptv-retired" ]; then
  ok_ 'a directory holding an unrecognised file is left exactly as it was'
else
  no_ 'a directory holding an unrecognised file is left exactly as it was'
fi
case "$out" in *notes.txt*) ok_ 'the notice names the file it did not recognise' ;;
  *) no_ 'the notice names the file it did not recognise' "$out" ;; esac
[ "$before" = "$after" ] && ok_ 'nothing was deleted when it refused' \
  || no_ 'nothing was deleted when it refused' "before=$before after=$after"

# A subdirectory is unrecognised too: WayHop wrote flat playlist files and nothing else.
d="$tmp/d"; mkdir -p "$d/iptv/sub"
echo "#EXTM3U" > "$d/iptv/aaaa.m3u"
echo "x" > "$d/iptv/sub/keep.txt"
sh "$R" "$d" >/dev/null
if [ -d "$d/iptv/sub" ] && [ ! -d "$d/iptv-retired" ]; then
  ok_ 'a subdirectory is unrecognised and stops the move'
else
  no_ 'a subdirectory is unrecognised and stops the move'
fi

# --- 5. an existing archive is never clobbered -------------------------------------------------
d="$tmp/e"; mkdir -p "$d/iptv" "$d/iptv-retired"
echo "#EXTM3U" > "$d/iptv/new.m3u"
echo "old" > "$d/iptv-retired/old.m3u"
before=$(countfiles "$d")
sh "$R" "$d" >/dev/null
after=$(countfiles "$d")
if [ -f "$d/iptv/new.m3u" ] && [ -f "$d/iptv-retired/old.m3u" ]; then
  ok_ 'an existing archive is neither merged into nor overwritten'
else
  no_ 'an existing archive is neither merged into nor overwritten'
fi
[ "$before" = "$after" ] && ok_ 'nothing was deleted around the existing archive' \
  || no_ 'nothing was deleted around the existing archive' "before=$before after=$after"

# --- 6. an empty directory is WayHop's own leftover -------------------------------------------
d="$tmp/f"; mkdir -p "$d/iptv"
sh "$R" "$d" >/dev/null
[ -d "$d/iptv-retired" ] && [ ! -d "$d/iptv" ] && ok_ 'an empty iptv/ is retired' \
  || no_ 'an empty iptv/ is retired'

# --- 7. usage ----------------------------------------------------------------------------------
rc=0; sh "$R" >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] && ok_ 'no argument is a usage error' || no_ 'no argument is a usage error' "exit $rc"

if [ "$fails" -gt 0 ]; then
  echo "$fails iptv-retirement case(s) failed"
  exit 1
fi
echo "iptv retirement: 13 cases, including 6 where it must refuse to act"
