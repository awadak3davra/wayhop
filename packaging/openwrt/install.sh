#!/bin/sh
# WakeRoute (wakeroute) installer for OpenWrt 22.x-25.x (procd / fw4 / apk|opkg).
#
# Pre-flights the router (arch, free space, deps, UI-port conflict), then installs
# the static binary (atomic swap + rolling backup), registers the procd service,
# seeds a config, enables boot-start and starts it -- with a UI health check.
#
# Usage:  sh ./install.sh [options] [arch]
#   -y, --yes        assume "yes" to every prompt (non-interactive)
#       --port N     UI port to use (default 8088)
#       --arch A     force arch: mipsle | mips | arm | arm64 | amd64
#       --no-start   install but do not start the service
#       --dry-run    run every check and print what WOULD change; change nothing
#   -h, --help       show this help and exit
#
# Idempotent: re-running upgrades in place. POSIX sh / busybox-safe.

VERSION="0.3.0"

# --- native OpenWrt paths --------------------------------------------------
SBIN=/usr/sbin
INITD=/etc/init.d
ETC=/etc/wakeroute
VAR=/var/lib/wakeroute
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ -t 1 ]; then C_R='\033[31m'; C_G='\033[32m'; C_Y='\033[33m'; C_B='\033[36m'; C_D='\033[2m'; C_0='\033[0m'
else C_R=''; C_G=''; C_Y=''; C_B=''; C_D=''; C_0=''; fi
say()  { printf '%b[wakeroute]%b %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '  %b+%b %s\n' "$C_G" "$C_0" "$*"; }
info() { printf '  %b·%b %s\n' "$C_D" "$C_0" "$*"; }
warn() { printf '  %b!%b %s\n' "$C_Y" "$C_0" "$*"; }
hdr()  { printf '\n%b== %s ==%b\n' "$C_B" "$*" "$C_0"; }
die()  { printf '%b[wakeroute] ERROR:%b %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
usage() {
  cat <<'USAGE'
WakeRoute installer for OpenWrt (procd).

Usage: sh ./install.sh [options] [arch]
  -y, --yes      assume "yes" to every prompt (non-interactive)
      --port N   UI port to use (default 8088)
      --arch A   force arch: mipsle | mips | arm | arm64 | amd64
      --no-start install but do not start the service
      --dry-run  run all checks, print what WOULD change, change nothing
  -h, --help     show this help
USAGE
  exit 0
}

ASSUME=""; DRY_RUN=0; NO_START=0; PORT=8088; FORCE_ARCH=""
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) ASSUME=yes ;;
    --port) shift; PORT="$1" ;; --port=*) PORT="${1#*=}" ;;
    --arch) shift; FORCE_ARCH="$1" ;; --arch=*) FORCE_ARCH="${1#*=}" ;;
    --no-start) NO_START=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage ;;
    mipsle|mips|arm|arm64|amd64) FORCE_ARCH="$1" ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done
case "$PORT" in ''|*[!0-9]*) die "invalid --port: '$PORT'" ;; esac
{ [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; } || die "--port out of range 1-65535: $PORT"

ask() {
  q="$1"; def="${2:-n}"
  if [ "$ASSUME" = yes ]; then printf '%s %b[auto-yes]%b\n' "$q" "$C_D" "$C_0"; return 0; fi
  if [ ! -t 0 ]; then printf '%s %b[no TTY, default %s]%b\n' "$q" "$C_D" "$def" "$C_0"; [ "$def" = y ]; return $?; fi
  if [ "$def" = y ]; then p="[Y/n]"; else p="[y/N]"; fi
  printf '%s %s ' "$q" "$p"; read -r a
  case "$a" in [Yy]*) return 0;; [Nn]*) return 1;; "") [ "$def" = y ]; return $?;; *) return 1;; esac
}
run() { if [ "$DRY_RUN" = 1 ]; then printf '  %b(dry-run)%b would: %s\n' "$C_D" "$C_0" "$*"; return 0; fi; "$@"; }
port_busy() { { netstat -tln 2>/dev/null || ss -ltn 2>/dev/null; } | grep -qE "[:.]$1[[:space:]]"; }
port_listener() { { netstat -tlnp 2>/dev/null || ss -ltnp 2>/dev/null; } | grep -E "[:.]$1[[:space:]]" | head -n1 | grep -oE '[0-9]+/[A-Za-z._-]+|"[A-Za-z._-]+"' | tr '\n' ' '; }
first_free_port() { for p in 8089 8090 8091 8099 18088; do port_busy "$p" || { echo "$p"; return; }; done; echo 8089; }

say "WakeRoute (OpenWrt) installer $VERSION"
[ "$DRY_RUN" = 1 ] && warn "DRY-RUN: no changes will be made"

# ===========================================================================
# System
# ===========================================================================
hdr "System"
[ -f /etc/rc.common ] || die "/etc/rc.common not found -- this installer is for OpenWrt (procd). On Entware/Keenetic use the non-openwrt tarball."
if [ -f /bin/ndmc ]; then
  warn "Keenetic detected -- you probably want the Entware build (the non-'-openwrt' tarball)."
  ask "Continue with the OpenWrt installer anyway?" n || die "aborted."
fi

detect_arch() {
  case "$(uname -m)" in
    armv7l|armv6l|arm) echo arm ;;
    aarch64|arm64)     echo arm64 ;;
    x86_64|amd64)      echo amd64 ;;
    mips|mips64)
      bb="$(command -v busybox 2>/dev/null || echo /bin/busybox)"
      d="$(dd if="$bb" bs=1 skip=5 count=1 2>/dev/null | od -t u1 | head -n1 | tr -s ' ' | cut -d' ' -f2)"
      [ "$d" = 1 ] && echo mipsle || echo mips ;;
    *) echo unknown ;;
  esac
}
ARCH="${FORCE_ARCH:-$(detect_arch)}"
[ "$ARCH" = unknown ] && die "could not detect arch (uname -m=$(uname -m)); pass one explicitly"
BIN="$SRC/wakeroute-$ARCH"
[ -f "$BIN" ] || BIN="$SRC/wakeroute"
[ -f "$BIN" ] || die "binary not found -- expected $SRC/wakeroute-$ARCH (wrong arch tarball?)"
ok "arch: $ARCH ($(uname -m))   binary: $(basename "$BIN")"
[ -f /etc/openwrt_release ] && info "$(. /etc/openwrt_release; echo "$DISTRIB_DESCRIPTION")"
case "$ARCH" in mips|mipsle) info "MIPS builds are softfloat; if the daemon crashes on start, re-run with the other MIPS arch.";; esac

# ===========================================================================
# Router status
# ===========================================================================
hdr "Router status"
avail_kb="$(df / 2>/dev/null | awk 'NR>1{print $4; exit}')"
if [ -n "$avail_kb" ] && [ "$avail_kb" -gt 0 ] 2>/dev/null; then
  if [ "$avail_kb" -lt 16000 ]; then warn "free overlay space: $((avail_kb/1024)) MB -- LOW (the binary is ~9 MB; an upgrade could fail mid-write)"
  else ok "free overlay space: $((avail_kb/1024)) MB"; fi
fi
mem_kb="$(awk '/MemTotal/{print $2; exit}' /proc/meminfo 2>/dev/null)"; [ -n "$mem_kb" ] && info "RAM: $((mem_kb/1024)) MB"
if ping -c1 -W3 1.1.1.1 >/dev/null 2>&1; then ok "internet: reachable"; else warn "internet: 1.1.1.1 unreachable (ok offline; needed later to pull rule-sets)"; fi

# ===========================================================================
# Dependencies
# ===========================================================================
hdr "Dependencies"
PKG=""; command -v apk >/dev/null 2>&1 && PKG=apk; [ -z "$PKG" ] && command -v opkg >/dev/null 2>&1 && PKG=opkg
[ -n "$PKG" ] && ok "package manager: $PKG" || warn "no apk/opkg found"
MISSING=""
for c in ip nft; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c present"; else warn "$c not found"; MISSING="$MISSING $c"; fi
done
command -v ipset >/dev/null 2>&1 && ok "ipset present" || info "ipset not present (only needed for some kernel-routing modes)"
if [ -n "$MISSING" ] && [ -n "$PKG" ]; then
  pkgs=""; for c in $MISSING; do case "$c" in ip) pkgs="$pkgs ip-full";; nft) pkgs="$pkgs nftables";; esac; done
  if ask "Install missing packages via $PKG (${pkgs# }) ?" n; then
    if [ "$PKG" = apk ]; then run sh -c "apk update && apk add ${pkgs# }" || warn "install failed"
    else run sh -c "opkg update && opkg install ${pkgs# }" || warn "install failed"; fi
  fi
fi
SB="/usr/bin/sing-box"
if [ -x "$SB" ]; then ok "sing-box: $SB"
elif command -v sing-box >/dev/null 2>&1; then SB="$(command -v sing-box)"; ok "sing-box: $SB"
else warn "sing-box not found -- the UI starts, but you cannot Apply a proxy config until it exists at $SB ($PKG add sing-box, or drop the $ARCH build from github.com/SagerNet/sing-box/releases)"; fi

# ===========================================================================
# Conflicts
# ===========================================================================
hdr "Conflicts"
[ -x "$INITD/wakeroute" ] && ok "existing WakeRoute install detected -- upgrading in place"
listener="$(port_listener "$PORT")"
case "$listener" in
  *wakeroute*) info "port :$PORT held by WakeRoute itself (upgrade) -- will restart it" ;;
  ?*)
    warn "port :$PORT is already in use ($listener)"
    if ask "  Use a different UI port?" y; then
      if [ "$ASSUME" = yes ] || [ ! -t 0 ]; then PORT="$(first_free_port)"; ok "UI will use :$PORT (auto)"
      else
        while :; do printf '  new UI port [8089]: '; read -r np; [ -z "$np" ] && np=8089
          case "$np" in *[!0-9]*) warn "  not a number"; continue;; esac
          { [ "$np" -ge 1 ] && [ "$np" -le 65535 ]; } || { warn "  out of range"; continue; }
          port_busy "$np" && { warn "  :$np also in use"; continue; }; break; done
        PORT="$np"; ok "UI will use :$PORT"
      fi
    else warn "  continuing -- WakeRoute may fail to bind :$PORT"; fi ;;
  *) ok "UI port :$PORT is free" ;;
esac
for p in 9090 5353 7890; do port_busy "$p" && warn "port :$p in use ($(port_listener "$p")) -- adjust \"ports\" in config.json if needed"; done

if [ "$DRY_RUN" = 1 ]; then hdr "Dry-run complete"; say "no changes made. Re-run without --dry-run to install."; exit 0; fi

# ===========================================================================
# Install
# ===========================================================================
hdr "Install"
mkdir -p "$ETC" "$VAR" || die "could not create directories"
if [ -x "$INITD/wakeroute" ]; then say "stopping existing service"; "$INITD/wakeroute" stop 2>/dev/null || true; sleep 1; fi

say "installing binary -> $SBIN/wakeroute"
cp "$BIN" "$SBIN/wakeroute.new" || die "failed to copy binary"
chmod 0755 "$SBIN/wakeroute.new" || die "failed to chmod binary"
[ -f "$SBIN/wakeroute" ] && cp "$SBIN/wakeroute" "$SBIN/wakeroute.bak"
mv "$SBIN/wakeroute.new" "$SBIN/wakeroute" || die "failed to install binary"
ok "binary installed"

[ -f "$SRC/wakeroute.init" ] || die "wakeroute.init not found next to this installer"
say "installing procd init -> $INITD/wakeroute"
cp "$SRC/wakeroute.init" "$INITD/wakeroute.new" && chmod 0755 "$INITD/wakeroute.new" && mv "$INITD/wakeroute.new" "$INITD/wakeroute" || die "failed to install init"

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
  chmod 0600 "$ETC/config.json" || warn "could not chmod 0600 the config"
  ok "config written"
else
  ok "keeping existing config $ETC/config.json"
  cur="$(grep -oE '"listen"[[:space:]]*:[[:space:]]*":[0-9]+"' "$ETC/config.json" 2>/dev/null | grep -oE '[0-9]+' | tail -n1)"
  if [ -n "$cur" ] && [ "$cur" != "$PORT" ]; then
    warn "existing config listens on :$cur but you selected :$PORT"
    if ask "  update the config's listen port to :$PORT?" y; then
      sed -i "s|\"listen\"[^,]*|\"listen\": \":$PORT\"|" "$ETC/config.json" && ok "updated to :$PORT" || { warn "edit by hand"; PORT="$cur"; }
    else PORT="$cur"; info "keeping :$cur"; fi
  fi
fi

say "enabling service (boot start)"
"$INITD/wakeroute" enable 2>/dev/null || warn "enable returned non-zero -- check: $INITD/wakeroute enable"

# ===========================================================================
# Start + health check
# ===========================================================================
if [ "$NO_START" = 1 ]; then hdr "Done (not started)"; say "start later: $INITD/wakeroute start"; exit 0; fi
hdr "Start"
say "starting service"
"$INITD/wakeroute" start 2>/dev/null || warn "start returned non-zero -- check: logread -e wakeroute"
sleep 2
HEALTHY=0
if command -v curl >/dev/null 2>&1; then
  i=0; while [ "$i" -lt 5 ]; do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PORT/" 2>/dev/null)" = 200 ] && { HEALTHY=1; break; }
    i=$((i+1)); sleep 1
  done
fi
IP="$(ip route get 1 2>/dev/null | awk '{print $7; exit}')"; [ -z "$IP" ] && IP="$(uname -n 2>/dev/null)"
hdr "Done"
if [ "$HEALTHY" = 1 ]; then ok "UI is up (HTTP 200 on :$PORT)"; else warn "UI not answering yet on :$PORT -- check: logread -e wakeroute"; fi
say "open  ->  http://${IP:-<router-ip>}:$PORT"
echo ""
echo "  status: $INITD/wakeroute status   |   logs: logread -e wakeroute"
[ -x "$SB" ] || echo "  install sing-box ($PKG add sing-box) so you can Apply configs"
echo "  uninstall: sh ./uninstall.sh  (add --purge to also delete config)"
