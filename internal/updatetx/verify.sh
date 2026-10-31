#!/bin/sh
# update-verify.sh - judges a WayHop update from OUTSIDE the daemon being replaced, and undoes it when
# the new build does not come up.
#
# A daemon cannot vouch for its own replacement: the process that swapped the binary is the one the
# restart kills, and a new build that crashes on start is in no position to roll itself back. So the
# judgement runs here, in a process of its own session that outlives both: it restarts the service
# through its init (or lets the package manager do it), waits a bounded window for the NEW build to
# answer /api/health with its own commit, and otherwise stops the service, puts the rollback copy back
# (a plain or hard-linked .bak, or a .bak.gz) and starts it again. It runs once per update: the marker
# is removed before the old build is restarted, so a rollback is never itself judged and never loops.
#
# Written by the daemon (and the installers) from the copy embedded in the binary
# (`wayhop update-verifier`), next to the config, where the init script finds it at boot.
#
# Usage: sh update-verify.sh restart       the panel's self-update: restart the service, then judge
#        sh update-verify.sh boot          the init, at boot, with an update still unjudged (the power
#                                          went inside the window): judge again; a second boot
#                                          inside the window rolls back at once
#        sh update-verify.sh pm apk|opkg   the package's own upgrade, run here so the restart its
#                                          maintainer scripts do cannot kill it midway, then judged
# Input: update.pending beside this script (key=value). Output: update-result.json beside it, and a
# log on stdout (the daemon appends it to /tmp/wayhop-update.log).
set -u

ETC="$(cd "$(dirname "$0")" && pwd)"
M="$ETC/update.pending"
R="$ETC/update-result.json"
PIDF=/tmp/wayhop-update-verify.pid
MODE="${1:-}"

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$*"; }
val() { sed -n "s/^$1=//p" "$M" 2>/dev/null | head -n 1; }
jesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'; }
now() { date +%s; }

[ -f "$M" ] || { log "no update is pending"; exit 0; }
BIN="$(val bin)"; SVC="$(val init)"; CONF="$(val config)"; ROLLBACK="$(val rollback)"
WANT_COMMIT="$(val want_commit)"; WANT_VERSION="$(val want_version)"
FROM="$(val from)"; TO="$(val to)"; BY="$(val by)"; WINDOW="$(val window)"; BOOTS="$(val boots)"
case "$WINDOW" in ''|*[!0-9]*) WINDOW=90 ;; esac
case "$BOOTS" in ''|*[!0-9]*) BOOTS=0 ;; esac
if [ -z "$BIN" ] || [ -z "$SVC" ]; then log "the pending marker names no binary or init; dropping it"; rm -f "$M"; exit 1; fi
echo "$$" > "$PIDF" 2>/dev/null
trap 'rm -f "$PIDF"' EXIT

# Where the daemon answers: the config's listen address, a wildcard probed on loopback.
LISTEN="$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONF" 2>/dev/null | tail -n 1)"
PORT="${LISTEN##*:}"; case "$PORT" in ''|*[!0-9]*) PORT=8088 ;; esac
HOST=127.0.0.1
case "$LISTEN" in *:*) _h="${LISTEN%:*}"; case "$_h" in ''|0.0.0.0|'[::]'|::) ;; *) HOST="$_h" ;; esac ;; esac

result() { # <ok|rolled_back|failed> <reason>
  printf '{"result":"%s","reason":"%s","from":"%s","to":"%s","by":"%s","at":%s}\n' \
    "$1" "$(jesc "$2")" "$(jesc "$FROM")" "$(jesc "$TO")" "$(jesc "$BY")" "$(now)" > "$R.new" && mv "$R.new" "$R"
  log "result: $1 -- $2"
}
probe() {
  if command -v curl >/dev/null 2>&1; then curl -s -m 4 "http://$HOST:$PORT/api/health" 2>/dev/null
  else wget -q -O - -T 4 "http://$HOST:$PORT/api/health" 2>/dev/null; fi
}
ALIVE=0; DEAD=0; LAST="the new build did not start"
judge() { # <commit> <version>: 0 when that build answers
  if ! pidof wayhop >/dev/null 2>&1; then DEAD=$((DEAD + 1)); LAST="the new build is not running"; return 1; fi
  ALIVE=$((ALIVE + 1))
  _b="$(probe)"
  [ -n "$_b" ] || { LAST="the new build runs but does not answer on :$PORT"; return 1; }
  _c="$(printf '%s' "$_b" | sed -n 's/.*"commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  _v="$(printf '%s' "$_b" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -n "$1" ] && [ "$1" != unknown ]; then
    case "$_c" in "$1"*) return 0 ;; esac
  elif [ -n "$2" ]; then
    [ "$_v" = "$2" ] && return 0
  else
    return 0   # nothing to compare: an answer is the proof
  fi
  LAST="something else answers on :$PORT (version ${_v:-?}, commit ${_c:-?}), not the new build"
  return 1
}
verify() { # <seconds> <commit> <version>: 0 once that build answers within the window
  _end=$(( $(now) + $1 )); ALIVE=0; DEAD=0
  while :; do
    judge "$2" "$3" && return 0
    [ "$(now)" -ge "$_end" ] && break
    sleep 3
  done
  # A build procd keeps respawning is seen dead far more often than alive: it crashes on start.
  [ "$DEAD" -gt "$ALIVE" ] && LAST="the new build does not stay running (it exits or crashes on start)"
  LAST="$LAST, within ${1}s"
  return 1
}
stop_wait() {
  "$SVC" stop >/dev/null 2>&1
  _i=0
  while pidof wayhop >/dev/null 2>&1 && [ "$_i" -lt 15 ]; do sleep 1; _i=$((_i + 1)); done
  _p="$(pidof wayhop 2>/dev/null)"; [ -z "$_p" ] || kill -9 $_p 2>/dev/null
}
restore() { # the rollback copy back under the binary's name; the service is stopped
  [ -n "$ROLLBACK" ] && [ -f "$ROLLBACK" ] || return 1
  rm -f "$BIN.rb"
  case "$ROLLBACK" in
    *.gz)
      gzip -t "$ROLLBACK" 2>/dev/null || return 1
      # Unpacked in /tmp first where it fits, so the failed binary goes only once a good copy is in hand.
      _u=""; _k=$(( $(wc -c < "$ROLLBACK") * 4 / 1024 + 1024 ))
      if [ "$(df -Pk /tmp 2>/dev/null | awk 'NR == 2 { print $4 }')" -ge "$_k" ] 2>/dev/null; then
        gzip -dc "$ROLLBACK" > /tmp/wayhop-rollback.$$ 2>/dev/null && _u=/tmp/wayhop-rollback.$$
      fi
      rm -f "$BIN"
      if [ -n "$_u" ]; then cp "$_u" "$BIN.rb"; _rc=$?; rm -f "$_u"; else gzip -dc "$ROLLBACK" > "$BIN.rb"; _rc=$?; fi
      [ "$_rc" = 0 ] || { rm -f "$BIN.rb"; return 1; } ;;
    *)
      ln "$ROLLBACK" "$BIN.rb" 2>/dev/null || cp "$ROLLBACK" "$BIN.rb" || { rm -f "$BIN.rb"; return 1; } ;;
  esac
  chmod 0755 "$BIN.rb" && sync && mv "$BIN.rb" "$BIN"
}
rollback() { # <reason>
  rm -f "$M"   # first: whatever happens below happens once, and the old build is never judged
  if [ -z "$ROLLBACK" ]; then
    result failed "$1; $(val norollback)"
    return
  fi
  log "rolling back: $1"
  stop_wait
  if ! restore; then
    "$SVC" start >/dev/null 2>&1
    result failed "$1; the rollback copy $ROLLBACK could not be restored -- restore it by hand"
    return
  fi
  "$SVC" restart >/dev/null 2>&1   # a restart, so no instance of the failed build survives it
  _fc="$(printf '%s' "$FROM" | sed -n 's/^wayhop [^ ]* (\([0-9a-f]*\),.*/\1/p')"
  _fv="$(printf '%s' "$FROM" | sed -n 's/^wayhop \([^ ]*\) .*/\1/p')"
  if verify 60 "$_fc" "$_fv"; then result rolled_back "$1; the previous build ($FROM) runs again"
  else result rolled_back "$1; the previous build was restored but does not answer yet"; fi
}
# Item 3 of the space work: a plain rollback copy on a nearly full flash is compressed once the new
# build has proved itself. Below one more binary's worth (+ 2 MiB head-room) of free space the next
# binary-sized write -- an update's staging, an engine install -- cannot land, so the ~60% the copy
# gives back matters more than restoring it by link instead of by gunzip. Both stay restorable.
squash_if_tight() {
  [ -n "$ROLLBACK" ] && [ -f "$ROLLBACK" ] || return 0
  case "$ROLLBACK" in *.gz) return 0 ;; esac
  [ "$ROLLBACK" -ef "$BIN" ] && return 0
  _free="$(df -Pk "$(dirname "$BIN")" 2>/dev/null | awk 'NR == 2 { print $4 }')"
  _need=$(( ($(wc -c < "$BIN") + 1023) / 1024 + 2048 ))
  [ -n "$_free" ] && [ "$_free" -lt "$_need" ] 2>/dev/null || return 0
  _want="$(sha256sum "$ROLLBACK" | cut -d' ' -f1)"
  gzip -c "$ROLLBACK" > "$ROLLBACK.gz.new" 2>/dev/null &&
    [ "$(gzip -dc "$ROLLBACK.gz.new" | sha256sum | cut -d' ' -f1)" = "$_want" ] &&
    sync && mv "$ROLLBACK.gz.new" "$ROLLBACK.gz" && rm -f "$ROLLBACK" &&
    { log "the overlay is nearly full ($(( _free / 1024 )) MiB free): the rollback copy is kept compressed as $ROLLBACK.gz"; return 0; }
  rm -f "$ROLLBACK.gz.new"
  log "could not compress the rollback copy; kept $ROLLBACK as it is"
}
# The record goes last, so whoever reads an "ok" reads it with the flash in its final state.
proven() { rm -f "$M"; squash_if_tight; result ok "${1:-the new build answers}"; }

case "$MODE" in
  restart)
    log "restarting WayHop onto $TO (by $BY), judging it for ${WINDOW}s"
    sleep 1   # the HTTP reply that asked for this goes out first
    "$SVC" restart >/dev/null 2>&1
    if verify "$WINDOW" "$WANT_COMMIT" "$WANT_VERSION"; then proven; else rollback "$LAST"; fi ;;
  boot)
    BOOTS=$((BOOTS + 1))
    sed -i "/^boots=/d" "$M" 2>/dev/null; echo "boots=$BOOTS" >> "$M"
    if [ "$BOOTS" -ge 2 ]; then
      rollback "the router restarted again before the new build had proved itself"
    else
      log "booted with $TO not yet judged: judging it now"
      if verify $((WINDOW + 60)) "$WANT_COMMIT" "$WANT_VERSION"; then proven; else rollback "$LAST"; fi
    fi ;;
  pm)
    case "${2:-}" in
      apk) PMC="apk update && apk upgrade wayhop" ;;
      opkg) _o="$(command -v opkg 2>/dev/null || echo /opt/bin/opkg)"; PMC="$_o update && $_o upgrade wayhop" ;;
      *) log "unknown package manager '${2:-}'"; rm -f "$M"; exit 2 ;;
    esac
    log "running: $PMC"
    sh -c "$PMC" < /dev/null 2>&1
    _rc=$?
    if [ "$_rc" != 0 ]; then
      rm -f "$M"; result failed "the package manager exited $_rc: '$PMC' (see /tmp/wayhop-update.log)"; exit 0
    fi
    if [ "$("$BIN" --version 2>/dev/null | head -n 1)" = "$FROM" ]; then
      [ -n "$ROLLBACK" ] && [ "$ROLLBACK" -ef "$BIN" ] && rm -f "$ROLLBACK"   # the copy of a build still in place
      # The panel asked because the catalogue lists $TO; nothing changing means something kept it,
      # most often a pinned version (apk add wayhop=<version> writes the pin into /etc/apk/world).
      rm -f "$M"
      result failed "the package manager installed nothing new although the feed lists $TO: a pinned or held version keeps $FROM (apk: 'apk add wayhop' unpins it; opkg: see 'opkg status wayhop' for a hold flag)"
      exit 0
    fi
    # The package's maintainer scripts restarted the service; the window starts now.
    if verify "$WINDOW" "$WANT_COMMIT" "$WANT_VERSION"; then proven "the package manager installed it and the new build answers"; else rollback "$LAST"; fi ;;
  *)
    log "usage: update-verify.sh restart|boot|pm apk|opkg"; exit 2 ;;
esac
exit 0
