#!/bin/sh
# WayHop (wayhop) installer for Entware / Keenetic.
#
# What it does, in order:
#   1. Detects the platform (Keenetic vs plain Entware) and CPU arch.
#   2. Pre-flight checks: router/system info, free flash space, RAM, clock/NTP,
#      internet reachability, and the routing dependencies (ip / ipset / iptables).
#   3. Scans for CONFLICTS and offers to resolve each one interactively:
#        - whatever already listens on the UI port (commonly lighttpd on stock
#          Keenetic firmware), keen-pbr, a stray sing-box, a previous install.
#   4. Installs the binary (atomic swap + single rolling backup), the init
#      script, and a default config; then starts + health-checks the UI.
#
# Idempotent: re-running upgrades in place. POSIX sh / busybox-safe (no bashisms,
# no `pkill -f`/`pgrep` assumption, no base64, no `od -A`). See --help for flags.

VERSION="0.5.0"

# ---------------------------------------------------------------------------
# Output helpers (colour only on a TTY)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_R='\033[31m'; C_G='\033[32m'; C_Y='\033[33m'; C_B='\033[36m'; C_DIM='\033[2m'; C_0='\033[0m'
else
  C_R=''; C_G=''; C_Y=''; C_B=''; C_DIM=''; C_0=''
fi
say()  { printf '%b[wayhop]%b %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '  %b+%b %s\n' "$C_G" "$C_0" "$*"; }
info() { printf '  %b·%b %s\n' "$C_DIM" "$C_0" "$*"; }
warn() { printf '  %b!%b %s\n' "$C_Y" "$C_0" "$*"; }
hdr()  { printf '\n%b== %s ==%b\n' "$C_B" "$*" "$C_0"; }
die()  { printf '%b[wayhop] ERROR:%b %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
WayHop installer for Entware / Keenetic.

Usage: sh ./install.sh [options] [arch]

Options:
  -y, --yes        assume "yes" to every prompt (non-interactive; auto-resolve)
  -n, --no         assume "no"  to every prompt (report only, change nothing risky)
      --port N     UI port to use (default 8088) -- handy if :8088 is occupied
      --arch A     force arch: mipsle | mips | arm | arm64 | amd64
      --no-start   install everything but do not start the service
      --dry-run    run every check and print what WOULD change; make NO changes
  -h, --help       show this help and exit

arch is auto-detected when omitted. Idempotent: re-running upgrades in place.
USAGE
  exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
ASSUME=""           # "", "yes", "no"
DRY_RUN=0
NO_START=0
PORT=8088
FORCE_ARCH=""

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)    ASSUME=yes ;;
    -n|--no)     ASSUME=no ;;
    --port)      shift; PORT="$1"; PORT_EXPLICIT=1 ;;
    --port=*)    PORT="${1#*=}"; PORT_EXPLICIT=1 ;;
    --arch)      shift; FORCE_ARCH="$1" ;;
    --arch=*)    FORCE_ARCH="${1#*=}" ;;
    --no-start)  NO_START=1 ;;
    --dry-run)   DRY_RUN=1 ;;
    -h|--help)   usage ;;
    mipsle|mips|arm|arm64|amd64) FORCE_ARCH="$1" ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done
case "$PORT" in ''|*[!0-9]*) die "invalid --port: '$PORT'" ;; esac
{ [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; } || die "--port out of range 1-65535: $PORT"

# ask "question" [default y|n]  -> 0 = yes, 1 = no  (honours -y/-n and no-TTY)
ask() {
  q="$1"; def="${2:-n}"
  if [ "$ASSUME" = yes ]; then printf '%s %b[auto-yes]%b\n' "$q" "$C_DIM" "$C_0"; return 0; fi
  if [ "$ASSUME" = no  ]; then printf '%s %b[auto-no]%b\n'  "$q" "$C_DIM" "$C_0"; return 1; fi
  if [ ! -t 0 ]; then
    printf '%s %b[no TTY, default %s]%b\n' "$q" "$C_DIM" "$def" "$C_0"
    [ "$def" = y ]; return $?
  fi
  if [ "$def" = y ]; then prompt="[Y/n]"; else prompt="[y/N]"; fi
  printf '%s %s ' "$q" "$prompt"; read -r ans
  case "$ans" in
    [Yy]*) return 0 ;;
    [Nn]*) return 1 ;;
    "")    [ "$def" = y ]; return $? ;;
    *)     return 1 ;;
  esac
}

# run a mutating command, or just describe it under --dry-run
run() {
  if [ "$DRY_RUN" = 1 ]; then printf '  %b(dry-run)%b would: %s\n' "$C_DIM" "$C_0" "$*"; return 0; fi
  "$@"
}

# pgrep -f <fixed-string>, with a busybox fallback (pgrep/procps-ng is often
# absent on minimal Entware). Echoes matching PIDs, one per line.
pgrep_f() {
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -f "$1" 2>/dev/null
  else
    { ps w 2>/dev/null || ps 2>/dev/null; } | grep -F "$1" | grep -v grep \
      | awk -v me="$$" '($1+0)>0 && $1!=me {print $1}'
  fi
}
proc_running() { [ -n "$(pgrep_f "$1")" ]; }

# guess_lan_ip: the address a LAN browser reaches the panel on. Prefer the LAN bridge
# (br-lan/br0/lan), then any RFC1918 address, then the hostname. NOT `ip route get 1`,
# whose src is the WAN-facing IP -- useless for opening the UI from the LAN.
guess_lan_ip() {
  for i in br-lan br0 lan br-local; do
    a="$(ip -4 addr show "$i" 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}')"
    [ -n "$a" ] && { echo "$a"; return; }
  done
  ip -4 addr show 2>/dev/null | awk '/inet /{x=$2; sub(/\/.*/,"",x); if(x!~/^127\./ && (x~/^192\.168\./||x~/^10\./||x~/^172\.(1[6-9]|2[0-9]|3[01])\./)){print x; exit}}'
}

# Advisory-only: report which native VPN engines the kernel/userland can carry,
# and recommend an opkg package for any that are absent. DETECT + RECOMMEND ONLY
# -- this never installs anything. POSIX/busybox-safe; no-op if probes are missing.
native_have() {
  # $1 = lsmod module name(s, space-sep), $2 = userland cmd, $3..= candidate proto .sh files
  mod="$1"; cmd="$2"; shift 2
  for m in $mod; do
    lsmod 2>/dev/null | grep -q "^$m" && return 0
  done
  [ -n "$cmd" ] && command -v "$cmd" >/dev/null 2>&1 && return 0
  for f in "$@"; do [ -f "$f" ] && return 0; done
  return 1
}

native_summary() {
  hdr "Native VPN support"
  present=""
  # AmneziaWG (kernel module 'amneziawg', userland 'awg', or a netifd proto handler)
  if native_have amneziawg awg /lib/netifd/proto/amneziawg.sh /opt/lib/netifd/proto/amneziawg.sh; then
    present="$present amneziawg"
  else
    info "for native amneziawg: opkg install amneziawg-go  (or kmod-amneziawg + amneziawg-tools)"
  fi
  # WireGuard (kernel module 'wireguard', userland 'wg', or a netifd proto handler)
  if native_have wireguard wg /lib/netifd/proto/wireguard.sh /opt/lib/netifd/proto/wireguard.sh; then
    present="$present wireguard"
  else
    info "for native wireguard: opkg install wireguard-tools  (+ kmod-wireguard)"
  fi
  if [ -n "$present" ]; then ok "native:$present"
  else info "native: none detected -- WayHop will tunnel these via sing-box instead"; fi
  info "(advisory only -- nothing was installed; WayHop carries non-native protocols via sing-box)"
}

SRC="$(cd "$(dirname "$0")" && pwd)"
say "WayHop installer $VERSION"
[ "$DRY_RUN" = 1 ] && warn "DRY-RUN: no changes will be made"

# ===========================================================================
# 1. PLATFORM + ARCHITECTURE
# ===========================================================================
hdr "System"

[ -d /opt ] || die "Entware /opt not found. Install Entware first (or use the -openwrt build on OpenWrt)."

if [ -f /etc/openwrt_release ] && [ ! -f /bin/ndmc ]; then
  warn "this looks like OpenWrt -- you probably want the '*-openwrt.tar.gz' build (native procd)."
  ask "Continue with the Entware (/opt) installer anyway?" n || die "aborted -- grab the -openwrt tarball."
fi

if [ -f /bin/ndmc ] || grep -qiE 'keenetic|-ndm-' /proc/version 2>/dev/null; then
  PLATFORM=keenetic
else
  PLATFORM=entware
fi

detect_arch() {
  case "$(uname -m)" in
    armv7l|armv7)                     echo arm ;;            # the published 'arm' build is GOARM=7
    armv6l|armv6|armv5l|armv5|armv4l) echo armv6-unsupported ;;  # would SIGILL on the ARMv7 build
    arm)                              echo arm-ambiguous ;;  # bare 'arm' — can't tell v6 from v7
    aarch64|arm64)                    echo arm64 ;;
    x86_64|amd64)                     echo amd64 ;;
    mips|mips64)
      # endianness from the ELF EI_DATA byte (offset 5: 1=LE, 2=BE) of busybox.
      # busybox has no `od -A`; `od -t u1 | head -n1` keeps the address column,
      # so field 2 is the byte (same approach as the OpenWrt installer).
      bb="$(command -v busybox 2>/dev/null || echo /bin/busybox)"
      d="$(dd if="$bb" bs=1 skip=5 count=1 2>/dev/null | od -t u1 | head -n1 | tr -s ' ' | cut -d' ' -f2)"
      # d=1 LE, d=2 BE; default to the more common little-endian (mipsle) when busybox is unreadable.
      [ "$d" = 2 ] && echo mips || echo mipsle ;;
    *) echo unknown ;;
  esac
}
ARCH="${FORCE_ARCH:-$(detect_arch)}"
case "$ARCH" in
  armv6-unsupported) die "ARMv6/ARMv5 CPU ($(uname -m)) is not supported -- the published 'arm' build is ARMv7 and would crash (illegal instruction). No armv6 build is shipped." ;;
  arm-ambiguous)     die "uname reports a bare 'arm' -- cannot tell ARMv6 from ARMv7. If this CPU is genuinely ARMv7, re-run with: sh ./install.sh arm" ;;
  unknown)           die "could not detect arch (uname -m=$(uname -m)); pass one explicitly, e.g. 'sh ./install.sh mipsle'" ;;
esac

BIN="$SRC/wayhop-$ARCH"
[ -f "$BIN" ] || BIN="$SRC/wayhop"
[ -f "$BIN" ] || die "binary not found -- expected $SRC/wayhop-$ARCH (wrong arch tarball?)"

ok "platform: $PLATFORM"
ok "arch:     $ARCH  ($(uname -m))   binary: $(basename "$BIN")"
info "kernel:   $(uname -r 2>/dev/null)"
if [ "$PLATFORM" = keenetic ] && [ -x /bin/ndmc ]; then
  model="$(ndmc -c 'show version' 2>/dev/null | grep -iE 'model|device' | head -n1 | sed 's/^ *//')"
  [ -n "$model" ] && info "router:   $model"
fi
case "$ARCH" in mips|mipsle)
  info "note:     MIPS builds are softfloat; if the daemon crashes on start, re-run with the other MIPS arch."
  info "          → to force little-endian: sh install.sh mipsle   (big-endian: sh install.sh mips)"
;; esac

# ===========================================================================
# 2. ROUTER STATUS (non-blocking)
# ===========================================================================
hdr "Router status"

avail_kb="$(df /opt 2>/dev/null | awk 'NR>1{print $4; exit}')"
if [ -n "$avail_kb" ] && [ "$avail_kb" -gt 0 ] 2>/dev/null; then
  if [ "$avail_kb" -lt 20000 ]; then warn "free space on /opt: $((avail_kb/1024)) MB -- LOW (need ~20 MB; an upgrade could fail mid-write)"
  else ok "free space on /opt: $((avail_kb/1024)) MB"; fi
else info "free space: could not read df /opt"; fi

mem_kb="$(awk '/MemTotal/{print $2; exit}' /proc/meminfo 2>/dev/null)"
[ -n "$mem_kb" ] && info "RAM: $((mem_kb/1024)) MB total"

up="$(awk '{print int($1)}' /proc/uptime 2>/dev/null)"
[ -n "$up" ] && info "uptime: $((up/3600))h $(((up%3600)/60))m"

if ping -c1 -W3 1.1.1.1 >/dev/null 2>&1; then ok "internet: reachable"
else warn "internet: 1.1.1.1 unreachable (fine if you're offline; needed later to pull rule-sets)"; fi

# clock / NTP (Reality/TLS break on skew). Check known daemon names individually
# (pgrep_f matches a fixed string, so no regex alternation).
if proc_running ntpd || proc_running chronyd || proc_running timesyncd || proc_running ntpdate; then
  ok "clock: an NTP service is running"
elif [ -n "$up" ] && [ "$up" -lt 120 ]; then
  warn "clock: router rebooted <2 min ago -- time may not be synced yet (Reality/TLS need an accurate clock)"
else
  info "clock: no NTP daemon detected (ok if KeeneticOS syncs time itself)"
fi

# ===========================================================================
# 3. DEPENDENCIES (non-blocking warnings)
# ===========================================================================
hdr "Dependencies"

if command -v opkg >/dev/null 2>&1; then ok "opkg present"; else warn "opkg not found (unusual for Entware)"; fi
MISSING=""
for c in ip ipset iptables; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c present"; else warn "$c not found (needed for list-based / kernel routing)"; MISSING="$MISSING $c"; fi
done
if [ -n "$MISSING" ] && command -v opkg >/dev/null 2>&1; then
  pkgs=""
  for c in $MISSING; do case "$c" in ip) pkgs="$pkgs ip-full";; ipset) pkgs="$pkgs ipset";; iptables) pkgs="$pkgs iptables";; esac; done
  if ask "Install missing routing packages via opkg (${pkgs# }) ?" n; then
    run sh -c "opkg update && opkg install ${pkgs# }" || warn "opkg install failed -- install ${pkgs# } manually later"
  fi
fi

# nftables: needed for the hybrid kernel PBR mode (optional — sing-box TUN mode works without it).
if command -v nft >/dev/null 2>&1; then
  ok "nft:      $(nft --version 2>/dev/null | head -1)"
elif [ "$PLATFORM" = keenetic ]; then
  info "nft:      not present -- expected on KeeneticOS (its kernel ships no nftables; WayHop routes via the iptables/ipset plane here)"
else
  info "nft:      not found (install nftables for hybrid PBR mode; sing-box TUN mode works without it)"
fi

# sing-box (UI works without it; Apply needs it). $SB always holds a path.
SB="/opt/sbin/sing-box"
if [ -x "$SB" ]; then ok "sing-box: $SB"
elif command -v sing-box >/dev/null 2>&1; then SB="$(command -v sing-box)"; ok "sing-box: $SB"
else warn "sing-box not found -- the UI will start, but you cannot Apply a proxy config until it exists at $SB (opkg install sing-box, or drop the $ARCH build from github.com/SagerNet/sing-box/releases)"; fi
# Version compatibility: WayHop supports sing-box 1.12.x-1.13.x (CI validates every protocol on
# both). Older than 1.12 lacks features WayHop generates; 1.14+ is untested and may change the schema.
if [ -x "$SB" ]; then
  SB_VER="$("$SB" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)"
  SB_MAJOR="$(echo "$SB_VER" | cut -d. -f1)"
  SB_MINOR="$(echo "$SB_VER" | cut -d. -f2)"
  if [ -n "$SB_MAJOR" ] && [ "$SB_MAJOR" -eq 1 ] 2>/dev/null && [ "$SB_MINOR" -lt 12 ] 2>/dev/null; then
    warn "sing-box $SB_VER is older than the supported 1.12.x-1.13.x — upgrade it (opkg install sing-box, or a 1.13.x build from github.com/SagerNet/sing-box/releases)"
  elif { [ -n "$SB_MAJOR" ] && [ "$SB_MAJOR" -gt 1 ] 2>/dev/null; } || { [ "$SB_MAJOR" -eq 1 ] && [ "$SB_MINOR" -ge 14 ] 2>/dev/null; }; then
    warn "sing-box $SB_VER is newer than the tested 1.12.x-1.13.x — it may work, but if Apply fails, install a 1.13.x build from github.com/SagerNet/sing-box/releases"
  fi
fi

# ===========================================================================
# 4. CONFLICTS  (detect, then offer to resolve each one)
# ===========================================================================
hdr "Conflicts"

INITD="/opt/etc/init.d"
ETC="/opt/etc/wayhop"

# best-effort: who listens on tcp :$1  -> echoes a short "prog/pid" string for display
port_listener() {
  { netstat -tlnp 2>/dev/null || ss -ltnp 2>/dev/null; } \
    | grep -E "[:.]$1[[:space:]]" | head -n1 \
    | grep -oE '[0-9]+/[A-Za-z._-]+|pid=[0-9]+|"[A-Za-z._-]+"' | tr '\n' ' '
}
port_busy() { { netstat -tln 2>/dev/null || ss -ltn 2>/dev/null; } | grep -qE "[:.]$1[[:space:]]"; }

# busybox-safe kill-by-name. Dry-run pure (returns without sleeping/killing).
# $pids below is a deliberate whitespace-separated PID list from pgrep_f (POSIX sh
# has no arrays); the word-split on `kill $pids` is intended, so SC2086 is expected.
# shellcheck disable=SC2086
kill_by_name() {
  pat="$1"
  if [ "$DRY_RUN" = 1 ]; then printf '  %b(dry-run)%b would stop processes matching: %s\n' "$C_DIM" "$C_0" "$pat"; return 0; fi
  pids="$(pgrep_f "$pat")"
  [ -z "$pids" ] && return 0
  kill $pids 2>/dev/null
  sleep 1
  pids="$(pgrep_f "$pat")"
  [ -n "$pids" ] && kill -9 $pids 2>/dev/null
  return 0
}

# pick a free port from a small list (used in non-interactive mode)
first_free_port() { for p in 8089 8090 8091 8099 18088; do port_busy "$p" || { echo "$p"; return; }; done; echo 8089; }

# read + validate a new UI port into $PORT, honouring -y/-n/no-TTY
choose_new_port() {
  if [ "$ASSUME" = yes ] || [ "$ASSUME" = no ] || [ ! -t 0 ]; then
    PORT="$(first_free_port)"; ok "WayHop UI will use :$PORT (auto-picked)"; return
  fi
  while :; do
    printf '  new UI port [8089]: '; read -r np
    [ -z "$np" ] && np=8089
    case "$np" in *[!0-9]*) warn "  not a number"; continue;; esac
    if [ "$np" -lt 1 ] || [ "$np" -gt 65535 ]; then warn "  out of range 1-65535"; continue; fi
    if port_busy "$np"; then warn "  :$np is also in use, pick another"; continue; fi
    break
  done
  PORT="$np"; ok "WayHop UI will use :$PORT"
}

UNRESOLVED=0

# 4a. Previous WayHop install -> graceful upgrade (informational)
UPGRADE=0
if [ -x "$INITD/S99wayhop" ] || [ -x /opt/sbin/wayhop ]; then
  UPGRADE=1
  ok "existing WayHop install detected -- this will upgrade it in place"
fi

# 4a'. Port persistence: adopt the port the existing config already listens on UNLESS the user
# passed --port explicitly. Without this an upgrade run with no --port defaults to 8088 and would
# (a) health-check the WRONG port -> a needless rollback of a perfectly good upgrade, and (b) offer
# to rewrite a previously-relocated listen port back to 8088. Runs BEFORE the port-occupant checks.
if [ "${PORT_EXPLICIT:-0}" != 1 ] && [ -f "$ETC/config.json" ]; then
  _cfg_port="$(grep -oE '"listen"[[:space:]]*:[[:space:]]*":[0-9]+"' "$ETC/config.json" 2>/dev/null | grep -oE '[0-9]+' | tail -n1)"
  if [ -n "$_cfg_port" ] && [ "$_cfg_port" != "$PORT" ]; then
    PORT="$_cfg_port"; ok "keeping the configured UI port :$PORT (pass --port to change it)"
  fi
fi

# 4b. UI port occupant
listener="$(port_listener "$PORT")"
case "$listener" in
  *wayhop*|*velinx*|*wakeroute*) info "port :$PORT held by WayHop itself (upgrade) -- will restart it" ;;
  *lighttpd*)
    UNRESOLVED=$((UNRESOLVED+1))
    warn "port :$PORT is held by lighttpd (stock firmware web server: $listener)"
    echo "      WayHop's UI cannot bind :$PORT while lighttpd holds it."
    if ask "  Stop and disable lighttpd so WayHop can use :$PORT?" n; then
      kill_by_name lighttpd
      for s in /opt/etc/init.d/S*lighttpd; do [ -f "$s" ] && [ -x "$s" ] && { info "disabling $s"; run chmod -x "$s"; }; done
      ok "lighttpd stopped/disabled"
      info "(if stock firmware respawns lighttpd after a reboot, re-run with --port <free-port>)"
      UNRESOLVED=$((UNRESOLVED-1))
    elif ask "  Use a different UI port instead?" y; then
      choose_new_port; UNRESOLVED=$((UNRESOLVED-1))
    else
      die "port :$PORT is occupied; re-run with --port <free-port> or free lighttpd"
    fi ;;
  ?*)
    # On an upgrade, busybox netstat may fail to NAME the listener, dropping us here even though
    # it's the running WayHop being replaced -- don't offer to relocate the port then.
    if [ "$UPGRADE" = 1 ]; then
      info "port :$PORT in use ($listener) -- assuming it's the WayHop being upgraded; keeping :$PORT"
    else
      UNRESOLVED=$((UNRESOLVED+1))
      warn "port :$PORT is already in use ($listener)"
      if ask "  Use a different UI port?" y; then choose_new_port; UNRESOLVED=$((UNRESOLVED-1))
      else warn "  continuing -- WayHop may fail to bind :$PORT"; fi
    fi ;;
  *) ok "UI port :$PORT is free" ;;
esac

# 4c. secondary ports (configurable; warn only, never blocking)
for p in 9090 5353 7890; do
  port_busy "$p" && warn "port :$p in use ($(port_listener "$p")) -- adjust \"ports\" in config.json if WayHop needs it"
done

# 4d. keen-pbr (selective routing -- can coexist)
KEENPBR=""
for s in /opt/etc/init.d/S*keen-pbr; do [ -x "$s" ] && KEENPBR="$s"; done
if [ -n "$KEENPBR" ]; then
  warn "keen-pbr is active ($KEENPBR)"
  echo "      WayHop can coexist with keen-pbr (each uses its own fwmark + routing table),"
  echo "      but if BOTH route the same destinations the result is ambiguous."
  if ask "  Disable keen-pbr so WayHop owns routing? (No = keep both, recommended)" n; then
    run "$KEENPBR" stop 2>/dev/null
    run chmod -x "$KEENPBR"
    ok "keen-pbr stopped/disabled (re-enable: chmod +x $KEENPBR && $KEENPBR start)"
  else info "keeping keen-pbr -- WayHop will route only the traffic it marks"; fi
fi

# 4e. stray sing-box not managed by WayHop (only relevant once we have a config)
if proc_running '/opt/sbin/sing-box'; then
  if [ -f "$ETC/config.json" ] && grep -q '/opt/sbin/sing-box' "$ETC/config.json" 2>/dev/null; then
    info "sing-box is running and already managed by WayHop -- ok"
  elif [ -f "$ETC/config.json" ]; then
    warn "sing-box is running but is NOT referenced by WayHop's config"
    if ask "  Stop the independent sing-box (WayHop will manage its own)?" n; then
      kill_by_name '/opt/sbin/sing-box'; ok "stray sing-box stopped"
    else info "leaving it running -- watch for port/route clashes"; fi
  else
    info "a sing-box is already running -- WayHop will manage its own once you Apply"
  fi
fi

# 4f. our routing table already populated (old install residue)
if command -v ip >/dev/null 2>&1 && ip route show table 2025 2>/dev/null | grep -q .; then
  info "routing table 2025 already has routes (old WayHop run); they will be reclaimed on Apply"
fi

if [ "$UNRESOLVED" -gt 0 ]; then warn "$UNRESOLVED conflict(s) left as-is -- continuing anyway"
else ok "no blocking conflicts"; fi

# ---------------------------------------------------------------------------
# Under --dry-run we stop here, before any change.
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" = 1 ]; then
  hdr "Dry-run complete"
  say "checks finished; no changes made. Re-run without --dry-run to install."
  exit 0
fi

# ===========================================================================
# 5. INSTALL
# ===========================================================================
hdr "Install"

SBIN="/opt/sbin"
VAR="/opt/var/wayhop"
if [ -x "$SBIN/wayhop" ]; then
  PREV_VER="$("$SBIN/wayhop" --version 2>/dev/null | head -1)"
  [ -n "$PREV_VER" ] && info "upgrading from: $PREV_VER"
fi
# --- one-time migration from a previous "wakeroute"/"velinx"-named install --
# Preserves saved connections/config across the rename(s). Field devices run
# either the older "wakeroute" name or the newer "velinx" name; both migrate to
# "wayhop". Runs before mkdir so the "move only if the new dir is absent" guard
# holds. "velinx" is tried first (newer/more common); its dir wins if both exist.
for _OLD in velinx wakeroute; do
  OLD_INITD="$INITD/S99$_OLD"; OLD_ETC="/opt/etc/$_OLD"; OLD_VAR="/opt/var/$_OLD"; OLD_BIN="$SBIN/$_OLD"
  [ -x "$OLD_INITD" ] || [ -d "$OLD_ETC" ] || [ -x "$OLD_BIN" ] || continue
  say "migrating previous '$_OLD' install -> wayhop (your config is preserved)"
  if [ -x "$OLD_INITD" ]; then
    "$OLD_INITD" stop 2>/dev/null || true
    rm -f "$OLD_INITD"
  fi
  if [ -d "$OLD_ETC" ] && [ ! -d "$ETC" ]; then
    mv "$OLD_ETC" "$ETC" 2>/dev/null || { cp -a "$OLD_ETC" "$ETC" && rm -rf "$OLD_ETC"; } || warn "could not move $OLD_ETC -> $ETC"
    ok "moved config $OLD_ETC -> $ETC"
  elif [ -d "$OLD_ETC" ]; then warn "both $OLD_ETC and $ETC exist -- keeping $ETC"; fi
  if [ -d "$OLD_VAR" ] && [ ! -d "$VAR" ]; then
    mv "$OLD_VAR" "$VAR" 2>/dev/null || { cp -a "$OLD_VAR" "$VAR" && rm -rf "$OLD_VAR"; } || warn "could not move $OLD_VAR -> $VAR"
    ok "moved runtime state $OLD_VAR -> $VAR"
  fi
  # The dir moved, but the GENERATED sing-box config (singbox.json + its .bak/.good) still embeds the
  # OLD experimental.cache_file.path (/opt/etc/$_OLD/cache.db) -- the daemon loads singbox.json
  # as-is, so a stale path there crash-loops sing-box on "initialize cache-file: ... no such file".
  # Rewrite paths in EVERY text config; NEVER sed cache.db (binary bbolt -- sed would corrupt it).
  for _f in "$ETC"/config.json "$ETC"/singbox.json "$ETC"/singbox.json.bak "$ETC"/singbox.json.good "$ETC"/plugins/*.conf; do
    [ -f "$_f" ] && sed -i "s#/opt/etc/$_OLD#/opt/etc/wayhop#g; s#/opt/var/$_OLD#/opt/var/wayhop#g" "$_f" 2>/dev/null
  done
  ok "rewrote old '$_OLD' paths in config + sing-box + plugin configs"
  rm -f "$OLD_BIN" "$OLD_BIN.bak"
  # Flush the OLD kernel-PBR nft table (renamed ${_OLD}_pbr -> wayhop_pbr; the daemon never
  # tears the old-named table down). No-op where nft is absent (Keenetic NDM-native). Best-effort.
  if command -v nft >/dev/null 2>&1; then nft delete table inet "${_OLD}_pbr" 2>/dev/null || true; fi
done
# Reap a sing-box orphaned by a prior WAYHOP crash, matched by OUR config path (the same match the
# daemon's own ReapStrays uses) — so a PassWall/HomeProxy/other sing-box running ITS own config is
# never touched. (Was `sing-box run`, which killed every sing-box on the box.)
for _p in $(pgrep_f "$ETC/singbox.json" 2>/dev/null); do kill "$_p" 2>/dev/null || true; done
mkdir -p "$SBIN" "$INITD" "$ETC" "$VAR" || die "could not create install directories"

if [ -x "$INITD/S99wayhop" ]; then
  say "stopping existing service"
  "$INITD/S99wayhop" stop 2>/dev/null || true
  sleep 1
fi

# binary: stage -> back up previous -> atomic rename
say "installing binary -> $SBIN/wayhop"
cp "$BIN" "$SBIN/wayhop.new" || die "failed to copy binary"
chmod 0755 "$SBIN/wayhop.new" || die "failed to chmod binary"
[ -f "$SBIN/wayhop" ] && { cp "$SBIN/wayhop" "$SBIN/wayhop.bak" || warn "could not create backup (rollback with wayhop.bak unavailable)"; }
mv "$SBIN/wayhop.new" "$SBIN/wayhop" || die "failed to install binary"
ok "binary installed ($(wc -c < "$SBIN/wayhop" 2>/dev/null) bytes)"

# init script (bundled in the tarball)
HAVE_INIT=0
if [ -f "$SRC/S99wayhop" ]; then
  say "installing init script -> $INITD/S99wayhop"
  if cp "$SRC/S99wayhop" "$INITD/S99wayhop" && chmod 0755 "$INITD/S99wayhop"; then HAVE_INIT=1; ok "init script installed"
  else warn "could not install init script -- service won't auto-start on boot"; fi
else
  warn "S99wayhop not found next to the installer (incomplete tarball?) -- no boot auto-start; will start the daemon directly"
fi

# Persist the uninstaller next to the config so removal works long after the tmpfs-extracted
# tarball is gone (the "how do I remove this months later" trap -- /tmp/wr vanishes on reboot).
if [ -f "$SRC/uninstall.sh" ]; then
  cp "$SRC/uninstall.sh" "$ETC/uninstall.sh" 2>/dev/null && chmod 0755 "$ETC/uninstall.sh" 2>/dev/null && ok "uninstaller saved -> $ETC/uninstall.sh"
fi

# config: seed only if absent (never clobber an existing one)
if [ ! -f "$ETC/config.json" ]; then
  say "writing default config -> $ETC/config.json  (UI port :$PORT)"
  cat > "$ETC/config.json" <<JSON
{
  "listen": ":$PORT",
  "data_dir": "$VAR",
  "demo": false,
  "ports": { "ui": $PORT, "clash": 9090, "dns": 5353, "mixed": 7890 },
  "clash": { "controller": "127.0.0.1:9090", "secret": "" },
  "singbox": { "bin": "$SB", "config": "$ETC/singbox.json" },
  "failsafe": { "target": "1.1.1.1", "auto_reboot": false }
}
JSON
  chmod 0600 "$ETC/config.json" || warn "could not chmod 0600 the config (it may hold secrets later)"
  ok "config written"
else
  ok "keeping existing config $ETC/config.json"
  # if the selected port differs from what the existing config pins, offer to update it
  cur="$(grep -oE '"listen"[[:space:]]*:[[:space:]]*":[0-9]+"' "$ETC/config.json" 2>/dev/null | grep -oE '[0-9]+' | tail -n1)"
  if [ -n "$cur" ] && [ "$cur" != "$PORT" ]; then
    warn "existing config listens on :$cur but you selected :$PORT"
    if ask "  update the config's listen port to :$PORT?" y; then
      if sed -i "s|\"listen\"[^,]*|\"listen\": \":$PORT\"|" "$ETC/config.json" && \
         grep -q "\"listen\": \":$PORT\"" "$ETC/config.json"; then ok "config now listens on :$PORT"
      else warn "could not update config; change \"listen\" to \":$PORT\" by hand"; PORT="$cur"; fi
    else PORT="$cur"; info "keeping the configured port :$cur"; fi
  fi
fi

# ===========================================================================
# 6. START + HEALTH CHECK
# ===========================================================================
if [ "$NO_START" = 1 ]; then
  hdr "Done (not started)"
  say "installed but not started (--no-start). Start later: $INITD/S99wayhop start"
  native_summary
  exit 0
fi

hdr "Start"
if [ "$HAVE_INIT" = 1 ]; then
  say "starting service"
  "$INITD/S99wayhop" start 2>/dev/null || warn "start returned non-zero -- check: $INITD/S99wayhop start"
else
  warn "no init script -- starting the daemon directly (it will NOT survive a reboot)"
  ( "$SBIN/wayhop" --config "$ETC/config.json" >/dev/null 2>&1 & )
fi
sleep 2

# health check the UI (curl preferred; busybox wget fallback)
# Detect the probe tool once so the inner loop doesn't re-run command -v on every attempt.
PROBE_TOOL=""
if command -v curl >/dev/null 2>&1; then PROBE_TOOL=curl
elif command -v wget >/dev/null 2>&1; then PROBE_TOOL=wget; fi
# HEALTH_CHECKED distinguishes "probed and failed" from "could not probe (no curl/wget)". Only the
# former justifies a rollback — rolling back a good upgrade just because the router lacks an HTTP
# client is worse than trusting it (the daemon's own fail-safe + watchdog cover runtime failures).
HEALTH_CHECKED=0
[ -n "$PROBE_TOOL" ] && HEALTH_CHECKED=1
HEALTHY=0
i=0
while [ "$i" -lt 5 ]; do
  case "$PROBE_TOOL" in
    curl) code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PORT/" 2>/dev/null)"
          [ "$code" = 200 ] && { HEALTHY=1; break; } ;;
    wget) wget -q -O /dev/null --timeout=3 "http://127.0.0.1:$PORT/" 2>/dev/null && { HEALTHY=1; break; } ;;
    *)    break ;;
  esac
  i=$((i+1)); sleep 1
done

# --- transactional rollback: if this was an UPGRADE and the new binary failed its health check,
#     restore the previous binary and restart it, so a bad update never strands the router. The
#     preserved config is untouched (upgrades never rewrite it), so only the binary is reverted. ---
ROLLED_BACK=0
if [ "$HEALTHY" != 1 ] && [ "${HEALTH_CHECKED:-0}" = 1 ] && [ "$UPGRADE" = 1 ] && [ -f "$SBIN/wayhop.bak" ]; then
  warn "new version did not answer on :$PORT within the timeout -- rolling back to the previous binary"
  [ "$HAVE_INIT" = 1 ] && "$INITD/S99wayhop" stop 2>/dev/null
  for _p in $(pgrep_f "$ETC/singbox.json" 2>/dev/null); do kill "$_p" 2>/dev/null || true; done
  sleep 1
  if cp "$SBIN/wayhop.bak" "$SBIN/wayhop"; then
    ok "restored the previous binary from $SBIN/wayhop.bak"
    if [ "$HAVE_INIT" = 1 ]; then "$INITD/S99wayhop" start 2>/dev/null || true
    else ( "$SBIN/wayhop" --config "$ETC/config.json" >/dev/null 2>&1 & ); fi
    sleep 2
    ROLLED_BACK=1
    i=0
    while [ "$i" -lt 5 ]; do
      case "$PROBE_TOOL" in
        curl) [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PORT/" 2>/dev/null)" = 200 ] && { HEALTHY=1; break; } ;;
        wget) wget -q -O /dev/null --timeout=3 "http://127.0.0.1:$PORT/" 2>/dev/null && { HEALTHY=1; break; } ;;
        *) break ;;
      esac
      i=$((i+1)); sleep 1
    done
    if [ "$HEALTHY" = 1 ]; then warn "rolled back -- the PREVIOUS version is running on :$PORT; the update did NOT apply. Check the logs, then retry."
    else warn "rolled back, but the previous version is not answering on :$PORT either -- check: logread 2>/dev/null | grep wayhop"; fi
  else
    die "ROLLBACK FAILED: could not restore $SBIN/wayhop.bak. Restore by hand: cp $SBIN/wayhop.bak $SBIN/wayhop && $INITD/S99wayhop restart"
  fi
fi

IP="$(guess_lan_ip)"
[ -z "$IP" ] && IP="$(uname -n 2>/dev/null)"

INSTALLED_VER="$("$SBIN/wayhop" --version 2>/dev/null | head -1)"
hdr "Done"
[ -n "$INSTALLED_VER" ] && ok "version:  $INSTALLED_VER"
if [ "$HEALTHY" = 1 ]; then ok "UI is up (HTTP 200 on :$PORT)"
elif [ "${HEALTH_CHECKED:-0}" = 1 ]; then warn "UI not answering yet on :$PORT -- give it a few seconds, then check: logread 2>/dev/null | grep wayhop"
else info "UI health not verified (no curl/wget on this router) -- open the URL below to confirm"; fi
say "open  ->  http://${IP:-<router-ip>}:$PORT"
native_summary
echo ""
echo "  next steps:"
[ -x "$SB" ] || echo "    1. install sing-box   (opkg install sing-box) so you can Apply configs"
echo "    2. add a connection in the UI (paste a vless:// / hysteria2:// link or a .conf)"
echo "    3. create a Failover group and hit Apply (it auto-reverts if connectivity drops)"
if [ -f "$ETC/uninstall.sh" ]; then echo "    uninstall:  sh $ETC/uninstall.sh   (add --purge to also delete config)"
else echo "    uninstall:  sh ./uninstall.sh   (add --purge to also delete config; re-extract the tarball if it's gone)"; fi

# Exit status reflects the real outcome so the bootstrap / automation can tell success from failure.
if [ "${ROLLED_BACK:-0}" = 1 ]; then
  warn "UPDATE FAILED -- rolled back to the previous version (running on :$PORT). Nothing else changed."
  exit 1
fi
if [ "$UPGRADE" = 1 ] && [ "$HEALTHY" != 1 ] && [ "${HEALTH_CHECKED:-0}" = 1 ]; then
  warn "UPGRADE did not come up on :$PORT and no rollback was possible -- check: logread 2>/dev/null | grep wayhop"
  exit 1
fi
exit 0
