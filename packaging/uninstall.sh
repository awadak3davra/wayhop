#!/bin/sh
# WayHop (wayhop) uninstaller for Entware / Keenetic.
#
# Stops the service, then removes the binary, init script and the single rolling
# backup. By DEFAULT it KEEPS your config + runtime state (/opt/etc/wayhop,
# /opt/var/wayhop); pass --purge to delete those too.
#
#   sh ./uninstall.sh              # remove binary + service, keep config/data
#   sh ./uninstall.sh --purge      # also remove config + runtime state
#   sh ./uninstall.sh --keep-config  # explicitly keep config (the default)
#
# Idempotent + safe to re-run (every removal is guarded; never errors if a path
# is already gone). Only WayHop's own paths are touched -- shared deps
# (ip/ipset/iptables/sing-box) are NEVER removed. POSIX sh / busybox-safe.

# --- paths -----------------------------------------------------------------
INITD=/opt/etc/init.d
SBIN=/opt/sbin
ETC=/opt/etc/wayhop
VAR=/opt/var/wayhop
INIT="$INITD/S99wayhop"
BINARY="$SBIN/wayhop"
BACKUP="$SBIN/wayhop.bak"

# --- output helpers (colour only on a TTY) ---------------------------------
if [ -t 1 ]; then
  C_R='\033[31m'; C_G='\033[32m'; C_Y='\033[33m'; C_B='\033[36m'; C_D='\033[2m'; C_0='\033[0m'
else
  C_R=''; C_G=''; C_Y=''; C_B=''; C_D=''; C_0=''
fi
say()  { printf '%b[wayhop]%b %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '  %b+%b %s\n' "$C_G" "$C_0" "$*"; }
info() { printf '  %b·%b %s\n' "$C_D" "$C_0" "$*"; }
warn() { printf '  %b!%b %s\n' "$C_Y" "$C_0" "$*"; }
hdr()  { printf '\n%b== %s ==%b\n' "$C_B" "$*" "$C_0"; }
die()  { printf '%b[wayhop] ERROR:%b %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
WayHop uninstaller for Entware / Keenetic.

Usage: sh ./uninstall.sh [options]

Options:
      --purge        also delete config + runtime state (/opt/etc/wayhop,
                     /opt/var/wayhop) -- this removes your saved connections
      --keep-config  keep config + runtime state (this is the default)
  -y, --yes          assume "yes" to the purge confirmation (non-interactive)
  -h, --help         show this help and exit

By default config/data are KEPT so you can reinstall without losing your setup.
Shared dependencies (ip/ipset/iptables/sing-box) are never removed.
USAGE
  exit 0
}

# --- argument parsing ------------------------------------------------------
PURGE=0
ASSUME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --purge)        PURGE=1 ;;
    --keep-config)  PURGE=0 ;;
    -y|--yes)       ASSUME=yes ;;
    -h|--help)      usage ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

# confirm "question" -> 0 = yes, 1 = no (honours -y and no-TTY: default NO)
confirm() {
  q="$1"
  if [ "$ASSUME" = yes ]; then printf '%s %b[auto-yes]%b\n' "$q" "$C_D" "$C_0"; return 0; fi
  if [ ! -t 0 ]; then printf '%s %b[no TTY, default no]%b\n' "$q" "$C_D" "$C_0"; return 1; fi
  printf '%s [y/N] ' "$q"; read -r ans
  case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

say "WayHop uninstaller (Entware / Keenetic)"

# When purging interactively, confirm first so the run is predictable.
if [ "$PURGE" = 1 ]; then
  if [ -d "$ETC" ] || [ -d "$VAR" ]; then
    warn "--purge will DELETE your config + saved connections:"
    [ -d "$ETC" ] && info "$ETC"
    [ -d "$VAR" ] && info "$VAR"
    if ! confirm "Really delete config + runtime state?"; then
      PURGE=0
      info "purge cancelled -- config will be kept"
    fi
  fi
fi

# ===========================================================================
# 1. STOP the service BEFORE removing anything
# ===========================================================================
hdr "Service"
if [ -x "$INIT" ]; then
  say "stopping service"
  "$INIT" stop 2>/dev/null || true
  ok "service stopped"
else
  info "no init script at $INIT (already removed?)"
fi

# ===========================================================================
# 1b. NETWORK RULES: tear down ONLY WayHop's own kernel routing (its nft table
#     + its fwmark ip rules). Never touches a foreign table/rule. Idempotent.
#     (The daemon normally tears its plane down on a clean stop; this is the
#     backstop for a crashed daemon or a leftover plane.)
# ===========================================================================
hdr "Network rules"
CLEANED=0
if command -v nft >/dev/null 2>&1 && nft list table inet wayhop_pbr >/dev/null 2>&1; then
  if nft delete table inet wayhop_pbr 2>/dev/null; then ok "removed nft table inet wayhop_pbr"; CLEANED=1; fi
fi
if command -v ip >/dev/null 2>&1; then
  # WayHop marks its traffic with fwmark <N>/0x00ff0000 — one mark PER egress, so a multi-tunnel
  # failover setup has several (0x10000, 0x20000, 0x30000, …), each routed via its OWN table. The
  # 0xff0000 mask is WayHop's signature: remove EVERY rule carrying it (not just 0x20000) and flush
  # the tables those rules pointed at, so no orphaned routes survive. Parse-act one at a time, with
  # a guard cap against any loop.
  _tables=""; _n=0
  while [ "$_n" -lt 64 ]; do
    _line="$(ip rule show 2>/dev/null | grep -m1 '/0xff0000')"
    [ -z "$_line" ] && break
    _mark="$(printf '%s\n' "$_line" | grep -oE '0x[0-9a-f]+/0xff0000' | head -n1)"
    [ -z "$_mark" ] && break
    _tbl="$(printf '%s\n' "$_line" | grep -oE 'lookup [0-9]+' | grep -oE '[0-9]+' | head -n1)"
    ip rule del fwmark "$_mark" 2>/dev/null || break
    CLEANED=1; _n=$((_n+1))
    case " $_tables " in *" $_tbl "*) ;; *) [ -n "$_tbl" ] && _tables="$_tables $_tbl" ;; esac
  done
  for _t in $_tables; do
    ip route flush table "$_t" 2>/dev/null && CLEANED=1
  done
fi
if [ "$CLEANED" = 1 ]; then ok "WayHop routing rules cleared"; else info "no WayHop routing rules present (already clean)"; fi

# ===========================================================================
# 2. REMOVE binary, init script (the 'S' autostart entry = the boot hook on
#    Entware) and the single rolling backup. Each removal is guarded.
# ===========================================================================
hdr "Remove"
REMOVED=""
for f in "$INIT" "$BINARY" "$BACKUP"; do
  if [ -e "$f" ]; then
    if rm -f "$f"; then ok "removed $f"; REMOVED="$REMOVED $f"
    else warn "could not remove $f"; fi
  else
    info "$f already absent"
  fi
done
# stray staging artifact from an interrupted install
if [ -e "$SBIN/wayhop.new" ]; then
  rm -f "$SBIN/wayhop.new" && ok "removed $SBIN/wayhop.new (stale staging file)"
fi
[ -z "$REMOVED" ] && info "nothing to remove (WayHop binary/service not present)"

# ===========================================================================
# 3. CONFIG + DATA: purge on request, otherwise keep
# ===========================================================================
hdr "Config + data"
if [ "$PURGE" = 1 ]; then
  for d in "$ETC" "$VAR"; do
    if [ -e "$d" ]; then
      if rm -rf "$d"; then ok "purged $d"
      else warn "could not purge $d"; fi
    else
      info "$d already absent"
    fi
  done
else
  KEPT=0
  for d in "$ETC" "$VAR"; do
    if [ -d "$d" ]; then ok "kept $d"; KEPT=1; fi
  done
  [ "$KEPT" = 1 ] && info "(re-run with --purge to delete config + saved connections)"
fi

# ===========================================================================
# 4. SUMMARY
# ===========================================================================
hdr "Done"
if [ "$PURGE" = 1 ]; then
  say "WayHop fully removed (binary, service, config + data)."
else
  say "WayHop binary + service removed; config kept (use --purge to delete it)."
fi
info "shared dependencies (ip/ipset/iptables/sing-box) were left untouched."
