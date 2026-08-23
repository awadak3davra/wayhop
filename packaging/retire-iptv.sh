#!/bin/sh
# retire-iptv.sh — set aside the data directory of a feature that no longer ships, without deleting.
#
# The IPTV feature wrote generated playlists to <data-dir>/iptv/<token>.m3u and is no longer part of
# WayHop. An upgraded router therefore carries a directory nothing reads any more.
#
# The obvious move — delete it — is the one this must not make. WayHop generated those playlists, so
# they are its own derived data, but the directory is on a live router and nothing stops them
# having put something of their own in it. An installer that removes a directory it only PARTLY owns
# is a data-loss bug that surfaces once, for one person, permanently.
#
# So the rule is: recognise what WayHop wrote, and touch nothing else. Recognised-only contents are
# RENAMED aside, never removed, so the operator can look at them or delete them themselves. Anything
# unrecognised means the whole directory stays exactly where it is and the operator is told.
#
# NOTE: <etc>/plugins/ is NOT retired despite sharing the removal that took IPTV out of the panel.
# The engine plugins are live — plugin.Manager renders *.conf there and the installers rewrite paths
# inside them on upgrade — so moving that directory would take the running tunnels with it.
#
# Usage: retire-iptv.sh <data-dir>
# Exit:  0 nothing to do, moved, or deliberately left alone (each says which)
#        2 usage error
set -eu

DATA="${1:-}"
[ -n "$DATA" ] || { echo "usage: retire-iptv.sh <data-dir>" >&2; exit 2; }

SRC="$DATA/iptv"
DST="$DATA/iptv-retired"

[ -d "$SRC" ] || { echo "iptv: nothing to retire ($SRC is not there)"; exit 0; }

# What WayHop generated. Everything else in that directory belongs to whoever put it there.
unknown=""
n_known=0
for f in "$SRC"/* "$SRC"/.[!.]*; do
  [ -e "$f" ] || continue
  base=$(basename "$f")
  case "$base" in
    *.m3u) if [ -f "$f" ]; then n_known=$((n_known + 1)); continue; fi ;;
  esac
  unknown="$unknown $base"
done

if [ -n "$unknown" ]; then
  echo "iptv: leaving $SRC alone — it holds entries WayHop did not write:$unknown"
  echo "iptv: the IPTV feature no longer ships; move or delete that directory yourself when ready."
  exit 0
fi

if [ -e "$DST" ]; then
  # Already retired once. Merging into it would need a per-file decision, and overwriting is exactly
  # the destructive step this script exists to avoid, so both are left as they are.
  echo "iptv: $DST already exists, so $SRC is left untouched — nothing was merged or overwritten."
  exit 0
fi

mv "$SRC" "$DST"
echo "iptv: the feature no longer ships; moved $SRC to $DST ($n_known playlist(s), nothing deleted)."
echo "iptv: delete it yourself once you are sure you do not want it."
