#!/bin/sh
# WayHop (wayhop) installer for OpenWrt 22.x-25.x (procd / fw4 / apk|opkg).
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

VERSION="0.5.0"

# --- native OpenWrt paths --------------------------------------------------
SBIN=/usr/sbin
INITD=/etc/init.d
ETC=/etc/wayhop
VAR=/var/lib/wayhop
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ -t 1 ]; then C_R='\033[31m'; C_G='\033[32m'; C_Y='\033[33m'; C_B='\033[36m'; C_D='\033[2m'; C_0='\033[0m'
else C_R=''; C_G=''; C_Y=''; C_B=''; C_D=''; C_0=''; fi
say()  { printf '%b[wayhop]%b %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '  %b+%b %s\n' "$C_G" "$C_0" "$*"; }
info() { printf '  %b·%b %s\n' "$C_D" "$C_0" "$*"; }
warn() { printf '  %b!%b %s\n' "$C_Y" "$C_0" "$*"; }
hdr()  { printf '\n%b== %s ==%b\n' "$C_B" "$*" "$C_0"; }
die()  { printf '%b[wayhop] ERROR:%b %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
usage() {
  cat <<'USAGE'
WayHop installer for OpenWrt (procd).

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
first_free_port() { for p in 8089 8090 8091 8099 18088; do port_busy "$p" || { echo "$p"; return; }; done; echo 18089; }
# guess_lan_ip: the address a LAN browser reaches the panel on. Prefer the LAN bridge, then any
# RFC1918 address. NOT `ip route get 1` (whose src is the WAN IP -- wrong for opening the UI).
guess_lan_ip() {
  for i in br-lan br0 lan; do
    a="$(ip -4 addr show "$i" 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}')"
    [ -n "$a" ] && { echo "$a"; return; }
  done
  ip -4 addr show 2>/dev/null | awk '/inet /{x=$2; sub(/\/.*/,"",x); if(x!~/^127\./ && (x~/^192\.168\./||x~/^10\./||x~/^172\.(1[6-9]|2[0-9]|3[01])\./)){print x; exit}}'
}

# Advisory-only: report which native VPN engines this OpenWrt box can carry, and
# recommend a package for any that are absent. DETECT + RECOMMEND ONLY -- never
# installs anything. POSIX/busybox-safe; no-op if the probes are missing.
native_have() {
  mod="$1"; cmd="$2"; shift 2
  for m in $mod; do lsmod 2>/dev/null | grep -q "^$m" && return 0; done
  [ -n "$cmd" ] && command -v "$cmd" >/dev/null 2>&1 && return 0
  for f in "$@"; do [ -f "$f" ] && return 0; done
  return 1
}
native_summary() {
  hdr "Native VPN support"
  present=""
  if native_have amneziawg awg /lib/netifd/proto/amneziawg.sh; then present="$present amneziawg"
  else info "for native amneziawg: $PMINST kmod-amneziawg amneziawg-tools  (proto handler: luci-proto-amneziawg)"; fi
  if native_have wireguard wg /lib/netifd/proto/wireguard.sh; then present="$present wireguard"
  else info "for native wireguard: $PMINST kmod-wireguard wireguard-tools"; fi
  if [ -n "$present" ]; then ok "native:$present"
  else info "native: none detected -- WayHop will tunnel these via sing-box instead"; fi
  info "(advisory only -- nothing was installed; WayHop carries non-native protocols via sing-box)"
}

say "WayHop (OpenWrt) installer $VERSION"
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
      if [ "$d" -eq 1 ] 2>/dev/null; then echo mipsle; else echo mips; fi ;;
    *) echo unknown ;;
  esac
}
ARCH="${FORCE_ARCH:-$(detect_arch)}"
[ "$ARCH" = unknown ] && die "could not detect arch (uname -m=$(uname -m)); pass one explicitly"
BIN="$SRC/wayhop-$ARCH"
[ -f "$BIN" ] || BIN="$SRC/wayhop"
[ -f "$BIN" ] || die "binary not found -- expected $SRC/wayhop-$ARCH or $SRC/wayhop (wrong arch tarball?)"
ok "arch: $ARCH ($(uname -m))   binary: $(basename "$BIN")"
# shellcheck disable=SC1091  # /etc/openwrt_release exists only on the target device, not at lint time
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
mem_kb="$(awk '/MemTotal/{print $2; exit}' /proc/meminfo 2>/dev/null)"; [ -n "$mem_kb" ] && [ "$mem_kb" -gt 0 ] 2>/dev/null && info "RAM: $((mem_kb/1024)) MB"
if ping -c1 -W3 1.1.1.1 >/dev/null 2>&1; then ok "internet: reachable"; else warn "internet: 1.1.1.1 unreachable (ok offline; needed later to pull rule-sets)"; fi

# ===========================================================================
# Dependencies
# ===========================================================================
hdr "Dependencies"
PKG=""; command -v apk >/dev/null 2>&1 && PKG=apk; [ -z "$PKG" ] && command -v opkg >/dev/null 2>&1 && PKG=opkg
# apk uses "apk add"; opkg uses "opkg install" — keep this distinct from $PKG add which is wrong for opkg
PMINST="opkg install"; [ "$PKG" = apk ] && PMINST="apk add"
if [ -n "$PKG" ]; then ok "package manager: $PKG"; else warn "no apk/opkg found"; fi
MISSING=""
for c in ip nft; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c present"; else warn "$c not found"; MISSING="$MISSING $c"; fi
done
if command -v ipset >/dev/null 2>&1; then ok "ipset present"; else info "ipset not present (only needed for some kernel-routing modes)"; fi
if [ -n "$MISSING" ] && [ -n "$PKG" ]; then
  pkgs=""; for c in $MISSING; do case "$c" in ip) pkgs="$pkgs $([ "$PKG" = apk ] && echo ip || echo ip-full)";; nft) pkgs="$pkgs nftables";; esac; done
  if ask "Install missing packages via $PKG (${pkgs# }) ?" n; then
    if [ "$PKG" = apk ]; then run sh -c "apk update && apk add ${pkgs# }" || warn "install failed"
    else run sh -c "opkg update && opkg install ${pkgs# }" || warn "install failed"; fi
  fi
fi
SB="/usr/bin/sing-box"
if [ -x "$SB" ]; then ok "sing-box: $SB"
elif command -v sing-box >/dev/null 2>&1; then SB="$(command -v sing-box)"; ok "sing-box: $SB"
else warn "sing-box not found -- the UI starts, but you cannot Apply a proxy config until it exists at $SB ($PMINST sing-box, or drop the $ARCH build from github.com/SagerNet/sing-box/releases)"; fi
# Version compatibility: WayHop supports sing-box 1.12.x-1.13.x (CI validates every protocol on
# both). Older than 1.12 lacks features WayHop generates; 1.14+ is untested and may change the schema.
if [ -x "$SB" ]; then
  SB_VER="$("$SB" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)"
  SB_MAJOR="$(echo "$SB_VER" | cut -d. -f1)"
  SB_MINOR="$(echo "$SB_VER" | cut -d. -f2)"
  if [ -n "$SB_MAJOR" ] && [ "$SB_MAJOR" -eq 1 ] 2>/dev/null && [ "$SB_MINOR" -lt 12 ] 2>/dev/null; then
    warn "sing-box $SB_VER is older than the supported 1.12.x-1.13.x — upgrade it ($PMINST sing-box, or a 1.13.x build from github.com/SagerNet/sing-box/releases)"
  elif { [ -n "$SB_MAJOR" ] && [ "$SB_MAJOR" -gt 1 ] 2>/dev/null; } || { [ "$SB_MAJOR" -eq 1 ] && [ "$SB_MINOR" -ge 14 ] 2>/dev/null; }; then
    warn "sing-box $SB_VER is newer than the tested 1.12.x-1.13.x — it may work, but if Apply fails, install a 1.13.x build from github.com/SagerNet/sing-box/releases"
  fi
fi

# ===========================================================================
# Conflicts
# ===========================================================================
hdr "Conflicts"
UPGRADE=0
[ -x "$INITD/wayhop" ] && { UPGRADE=1; ok "existing WayHop install detected -- upgrading in place"; }
listener="$(port_listener "$PORT")"
case "$listener" in
  *wayhop*|*velinx*|*wakeroute*) info "port :$PORT held by WayHop itself (upgrade) -- will restart it" ;;
  ?*)
    # On an upgrade, busybox netstat may fail to NAME the listener, dropping us here even though
    # it's the running WayHop being replaced. Don't offer to relocate the port in that case --
    # the install stops the old service and restarts on the same port.
    if [ "$UPGRADE" = 1 ]; then info "port :$PORT in use ($listener) -- assuming it's the WayHop being upgraded; keeping :$PORT"; else
    warn "port :$PORT is already in use ($listener)"
    if ask "  Use a different UI port?" y; then
      if [ "$ASSUME" = yes ] || [ ! -t 0 ]; then PORT="$(first_free_port)"; ok "UI will use :$PORT (auto)"
      else
        while :; do printf '  new UI port [8089]: '; read -r np || { np="$(first_free_port)"; break; }; [ -z "$np" ] && np=8089
          case "$np" in *[!0-9]*) warn "  not a number"; continue;; esac
          { [ "$np" -ge 1 ] && [ "$np" -le 65535 ]; } || { warn "  out of range"; continue; }
          port_busy "$np" && { warn "  :$np also in use"; continue; }; break; done
        PORT="$np"; ok "UI will use :$PORT"
      fi
    else warn "  continuing -- WayHop may fail to bind :$PORT"; fi
    fi ;;
  *) ok "UI port :$PORT is free" ;;
esac
for p in 9090 5353 7890; do port_busy "$p" && warn "port :$p in use ($(port_listener "$p")) -- adjust \"ports\" in config.json if needed"; done

if [ "$DRY_RUN" = 1 ]; then hdr "Dry-run complete"; say "no changes made. Re-run without --dry-run to install."; exit 0; fi

# ===========================================================================
# Install
# ===========================================================================
hdr "Install"
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
  OLD_INITD="$INITD/$_OLD"; OLD_ETC="/etc/$_OLD"; OLD_VAR="/var/lib/$_OLD"; OLD_BIN="$SBIN/$_OLD"
  [ -x "$OLD_INITD" ] || [ -d "$OLD_ETC" ] || [ -x "$OLD_BIN" ] || continue
  say "migrating previous '$_OLD' install -> wayhop (your config is preserved)"
  if [ -x "$OLD_INITD" ]; then
    "$OLD_INITD" stop 2>/dev/null || true
    "$OLD_INITD" disable 2>/dev/null || true
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
  # OLD experimental.cache_file.path (/etc/$_OLD/cache.db) -- the daemon loads singbox.json as-is,
  # so a stale path there crash-loops sing-box on "initialize cache-file: ... no such file". Rewrite
  # paths in EVERY text config; NEVER sed cache.db (binary bbolt -- sed would corrupt it).
  for _f in "$ETC"/config.json "$ETC"/singbox.json "$ETC"/singbox.json.bak "$ETC"/singbox.json.good "$ETC"/plugins/*.conf; do
    [ -f "$_f" ] && sed -i "s#/etc/$_OLD#/etc/wayhop#g; s#/var/lib/$_OLD#/var/lib/wayhop#g" "$_f" 2>/dev/null
  done
  ok "rewrote old '$_OLD' paths in config + sing-box + plugin configs"
  rm -f "$OLD_BIN" "$OLD_BIN.bak"
  # Flush the OLD kernel-PBR nft table: the daemon renamed ${_OLD}_pbr -> wayhop_pbr and never
  # tears the old-named table down, and the old daemon doesn't tear its PBR plane down on stop.
  # Without this, BOTH the stale ${_OLD}_pbr and the new wayhop_pbr prerouting-mangle chains
  # mark packets on a live (un-rebooted) cutover -> double-marking / mis-routing. Best-effort.
  command -v nft >/dev/null 2>&1 && nft delete table inet "${_OLD}_pbr" 2>/dev/null || true
done
# Reap a sing-box orphaned by a prior crash (holds the cache.db lock + clash/TUN
# ports) so the new core starts clean. The wayhop daemon's ReapStrays covers this too.
# Reap only WayHop's own orphaned sing-box (matched by OUR config path), never a
# PassWall/HomeProxy/other sing-box running its own config. (Was `sing-box run` = killed them all.)
for _p in $(pgrep -f "$ETC/singbox.json" 2>/dev/null); do kill "$_p" 2>/dev/null || true; done
mkdir -p "$ETC" "$VAR" || die "could not create directories"
if [ -x "$INITD/wayhop" ]; then
  info "note: tunneled traffic pauses for a few seconds while the binary is swapped"
  say "stopping existing service"; "$INITD/wayhop" stop 2>/dev/null || true; sleep 1
fi

say "installing binary -> $SBIN/wayhop"
cp "$BIN" "$SBIN/wayhop.new" || die "failed to copy binary"
chmod 0755 "$SBIN/wayhop.new" || die "failed to chmod binary"
[ -f "$SBIN/wayhop" ] && { cp "$SBIN/wayhop" "$SBIN/wayhop.bak" || warn "could not create backup (rollback with wayhop.bak unavailable)"; }
mv "$SBIN/wayhop.new" "$SBIN/wayhop" || die "failed to install binary"
ok "binary installed"

[ -f "$SRC/wayhop.init" ] || die "wayhop.init not found next to this installer"
say "installing procd init -> $INITD/wayhop"
cp "$SRC/wayhop.init" "$INITD/wayhop.new" || die "failed to install init"
chmod 0755 "$INITD/wayhop.new" || die "failed to install init"
mv "$INITD/wayhop.new" "$INITD/wayhop" || die "failed to install init"

# Persist the uninstaller next to the config so removal works long after the tmpfs-extracted
# tarball is gone (the "how do I remove this months later" trap -- /tmp/wr vanishes on reboot).
if [ -f "$SRC/uninstall.sh" ]; then
  cp "$SRC/uninstall.sh" "$ETC/uninstall.sh" 2>/dev/null && chmod 0755 "$ETC/uninstall.sh" 2>/dev/null && ok "uninstaller saved -> $ETC/uninstall.sh"
fi

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
      if sed -i "s|\"listen\"[^,]*|\"listen\": \":$PORT\"|" "$ETC/config.json" && \
         grep -q "\"listen\": \":$PORT\"" "$ETC/config.json"; then ok "updated to :$PORT"
      else warn "could not update config; change \"listen\" to \":$PORT\" by hand"; PORT="$cur"; fi
    else PORT="$cur"; info "keeping :$cur"; fi
  fi
fi

say "enabling service (boot start)"
"$INITD/wayhop" enable 2>/dev/null || warn "enable returned non-zero -- check: $INITD/wayhop enable"

# ===========================================================================
# Start + health check
# ===========================================================================
if [ "$NO_START" = 1 ]; then hdr "Done (not started)"; say "start later: $INITD/wayhop start"; native_summary; exit 0; fi
hdr "Start"
say "starting service"
"$INITD/wayhop" start 2>/dev/null || warn "start returned non-zero -- check: logread -e wayhop"
sleep 2
PROBE_TOOL=""
if command -v curl >/dev/null 2>&1; then PROBE_TOOL=curl
elif command -v wget >/dev/null 2>&1; then PROBE_TOOL=wget; fi
HEALTHY=0
i=0
while [ "$i" -lt 5 ]; do
  case "$PROBE_TOOL" in
    curl) [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PORT/" 2>/dev/null)" = 200 ] && { HEALTHY=1; break; } ;;
    wget) wget -q -O /dev/null --timeout=3 "http://127.0.0.1:$PORT/" 2>/dev/null && { HEALTHY=1; break; } ;;
    *)    break ;;
  esac
  i=$((i+1)); sleep 1
done
INSTALLED_VER="$("$SBIN/wayhop" --version 2>/dev/null | head -1)"
IP="$(guess_lan_ip)"; [ -z "$IP" ] && IP="$(uname -n 2>/dev/null)"
hdr "Done"
[ -n "$INSTALLED_VER" ] && ok "version:  $INSTALLED_VER"
if [ "$HEALTHY" = 1 ]; then ok "UI is up (HTTP 200 on :$PORT)"
elif [ -z "$PROBE_TOOL" ]; then info "no curl or wget found -- health probe skipped; open http://${IP:-<router-ip>}:$PORT to verify"
else warn "UI not answering yet on :$PORT -- check: logread -e wayhop"; fi
say "open  ->  http://${IP:-<router-ip>}:$PORT"
native_summary
echo ""
echo "  status: $INITD/wayhop status   |   logs: logread -e wayhop"
[ -x "$SB" ] || echo "  install sing-box ($PMINST sing-box) so you can Apply configs"
if [ -f "$ETC/uninstall.sh" ]; then echo "  uninstall: sh $ETC/uninstall.sh   (add --purge to also delete config)"
elif [ -f "$SRC/uninstall.sh" ]; then echo "  uninstall: sh ./uninstall.sh   (add --purge to also delete config)"
else warn "uninstall.sh not found -- re-download the tarball to remove WayHop later"; fi
