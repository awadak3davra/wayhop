#!/bin/sh
# Repair permissions on WayHop-owned state after install/upgrade. This is intentionally a fixed
# inventory: an operator may keep unrelated files beside WayHop state, and a recursive chmod would
# silently claim ownership of them. Refuse symlinks rather than following them outside the state
# roots while running as root.
set -eu

[ "$#" = 2 ] || { echo "usage: harden-state.sh <state-root> <data-root>" >&2; exit 2; }
STATE_ROOT="$1"
DATA_ROOT="$2"

case "$STATE_ROOT:$DATA_ROOT" in
  /etc/wayhop:/var/lib/wayhop|/opt/etc/wayhop:/opt/var/wayhop) ;;
  *) echo "wayhop: refusing unexpected state roots: $STATE_ROOT $DATA_ROOT" >&2; exit 2 ;;
esac

fail() {
  echo "wayhop: state permission repair failed: $*" >&2
  exit 1
}

harden_dir() {
  _path="$1"
  [ -L "$_path" ] && fail "$_path is a symlink"
  [ ! -e "$_path" ] && return 0
  [ -d "$_path" ] || fail "$_path is not a directory"
  chmod 0700 "$_path" || fail "cannot chmod 0700 $_path"
}

harden_file() {
  _path="$1"
  [ -L "$_path" ] && fail "$_path is a symlink"
  [ ! -e "$_path" ] && return 0
  [ -f "$_path" ] || fail "$_path is not a regular file"
  chmod 0600 "$_path" || fail "cannot chmod 0600 $_path"
}

harden_dir "$STATE_ROOT"
harden_dir "$DATA_ROOT"

for _file in \
  "$STATE_ROOT/config.json" \
  "$STATE_ROOT/config.json.bak" \
  "$STATE_ROOT/profile.json" \
  "$STATE_ROOT/profile.json.bak" \
  "$STATE_ROOT/singbox.json" \
  "$STATE_ROOT/singbox.json.bak" \
  "$STATE_ROOT/singbox.json.good" \
  "$STATE_ROOT/singbox-unused.json" \
  "$STATE_ROOT/cache.db" \
  "$DATA_ROOT/profile.json" \
  "$DATA_ROOT/profile.json.bak"
do
  harden_file "$_file"
done

_plugins="$STATE_ROOT/plugins"
harden_dir "$_plugins"
for _file in "$_plugins"/*.conf; do
  harden_file "$_file"
done

_backups="$DATA_ROOT/backups"
harden_dir "$_backups"
for _file in "$_backups"/wayhop-backup-*.json; do
  harden_file "$_file"
done

exit 0
