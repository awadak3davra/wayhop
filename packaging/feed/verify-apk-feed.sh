#!/bin/sh
# verify-apk-feed.sh — every apk architecture the feed CLAIMS to support must actually be there.
#
# The apk half of the feed degraded silently in three places at once: the step carried
# continue-on-error, a runner without docker exited 0 with a warning, and a container without
# apk-tools v3 exited 0 with another. So a green feed job could publish an opkg feed and no apk
# packages at all — while the installer advertises OpenWrt 22.x-25.x with "apk|opkg" and 25.x has
# no opkg. The support matrix said one thing and the artifacts said another, and nothing compared
# them.
#
# This is that comparison. It reads the same arch-map.txt the packer reads, so the list cannot drift
# from what was built, and it fails on a token with no package, an empty package, or an index that
# was never written.
#
# Usage: verify-apk-feed.sh <feed-dir> <arch-map> [--require-index]
set -eu

FEED="${1:-}"
MAP="${2:-}"
REQUIRE_INDEX=0
[ "${3:-}" = "--require-index" ] && REQUIRE_INDEX=1

[ -n "$FEED" ] && [ -n "$MAP" ] || { echo "usage: verify-apk-feed.sh <feed-dir> <arch-map> [--require-index]" >&2; exit 2; }
[ -d "$FEED" ] || { echo "verify-apk-feed: $FEED is not a directory" >&2; exit 2; }
[ -f "$MAP" ] || { echo "verify-apk-feed: $MAP is missing — the claimed arch list is what this checks" >&2; exit 2; }

fails=0
tokens=0

while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  ow="${line%%|*}"
  # shellcheck disable=SC2086
  set -- $ow
  shift  # drop the Go name; the rest are the OpenWrt arch tokens
  for tok in "$@"; do
    tokens=$((tokens + 1))
    dir="$FEED/apk/$tok"
    pkg=""
    if [ -d "$dir" ]; then
      pkg=$(find "$dir" -maxdepth 1 -name '*.apk' -type f 2>/dev/null | head -n1)
    fi
    if [ -z "$pkg" ]; then
      echo "FAIL  $tok: no .apk in $dir — the feed claims this architecture and ships nothing for it" >&2
      fails=$((fails + 1))
      continue
    fi
    # A zero-length file is the shape a half-finished pack leaves behind, and it installs as nothing.
    if [ ! -s "$pkg" ]; then
      echo "FAIL  $tok: $pkg is empty" >&2
      fails=$((fails + 1))
      continue
    fi
    if [ "$REQUIRE_INDEX" = 1 ] && [ ! -s "$dir/packages.adb" ]; then
      echo "FAIL  $tok: no signed packages.adb — a package nobody can resolve is not published" >&2
      fails=$((fails + 1))
      continue
    fi
    echo "  ok  $tok  $(basename "$pkg")"
  done
done < "$MAP"

# A map that yielded no tokens means the parse failed, and every assertion above was skipped rather
# than passed. Reporting success there would be the empty-subject pass this whole audit is about.
if [ "$tokens" = 0 ]; then
  echo "FAIL  no architecture tokens parsed from $MAP — nothing was verified" >&2
  exit 2
fi

if [ "$fails" -gt 0 ]; then
  echo "$fails of $tokens claimed apk architecture(s) missing from the feed" >&2
  exit 1
fi
echo "apk feed complete: $tokens claimed architecture(s), all present"
