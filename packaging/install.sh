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
      --with-awg[=auto|kmod|userspace]
                   then install AmneziaWG 3.1 with install-awg.sh (exit 2 if it is refused)
      --cleanup    only reclaim space: remove what earlier installs and updates left behind,
                   keep one rollback copy (compressed); with --dry-run, list it and change nothing
      --drop-rollback  with --cleanup: remove the rollback copy too
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
CLEANUP=0; DROP_ROLLBACK=0
NO_START=0
PORT=8088
FORCE_ARCH=""
WITH_AWG=0; AWG_MODE=auto

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)    ASSUME=yes ;;
    --with-awg)  WITH_AWG=1 ;;
    --with-awg=*) WITH_AWG=1; AWG_MODE="${1#*=}" ;;
    -n|--no)     ASSUME=no ;;
    --port)      shift; PORT="$1"; PORT_EXPLICIT=1 ;;
    --port=*)    PORT="${1#*=}"; PORT_EXPLICIT=1 ;;
    --arch)      shift; FORCE_ARCH="$1" ;;
    --arch=*)    FORCE_ARCH="${1#*=}" ;;
    --no-start)  NO_START=1 ;;
    --dry-run)   DRY_RUN=1 ;;
    --cleanup)   CLEANUP=1 ;;
    --drop-rollback) DROP_ROLLBACK=1 ;;
    -h|--help)   usage ;;
    mipsle|mips|arm|arm64|amd64) FORCE_ARCH="$1" ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done
[ "$DROP_ROLLBACK" = 1 ] && [ "$CLEANUP" != 1 ] && die "--drop-rollback only goes with --cleanup"
case "$PORT" in ''|*[!0-9]*) die "invalid --port: '$PORT'" ;; esac
{ [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; } || die "--port out of range 1-65535: $PORT"
case "$AWG_MODE" in auto|kmod|userspace) ;; *) die "invalid --with-awg mode '$AWG_MODE' (want auto, kmod or userspace)" ;; esac

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

# >>> with-awg hook (packaging/awg/install-awg.sh; tests: packaging/awg/test/hooks.sh)
# --with-awg: AmneziaWG 3.1 through install-awg.sh, once WayHop itself is in place. Uses the
# install-awg.sh beside this script (the tarball's own copy); without one it is downloaded from the
# WayHop release (latest, or WAYHOP_VERSION) and checked against that release's SHA256SUMS.txt the way
# bootstrap.sh checks a tarball: the manifest signature wherever usign/signify exists, then SHA-256.
# Release manifest key: the same as bootstrap.sh's; scripts/check-awg-installer-keys.sh guards drift.
RELEASE_PUBKEY="untrusted comment: WayHop package feed
RWRPIiBbFocxjpgLjnQqmDCLsl6UIxNQbLKar75vb/65X5BEh5lnqbxL"
awg_fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 20 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -q -T 20 -O "$2" "$1"
  else return 1; fi
}
awg_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | sed 's/.*= *//'; fi
}
awg_installer() { # tmpdir -> sets AWG_SH to a verified install-awg.sh; 1 when there is none
  AWG_SH=""
  if [ -f "$SRC/install-awg.sh" ]; then AWG_SH="$SRC/install-awg.sh"; return 0; fi
  _ab="https://github.com/awadak3davra/wayhop/releases/latest/download"
  if [ -n "${WAYHOP_VERSION:-}" ]; then
    case "$WAYHOP_VERSION" in v*) _at="$WAYHOP_VERSION" ;; *) _at="v$WAYHOP_VERSION" ;; esac
    _ab="https://github.com/awadak3davra/wayhop/releases/download/$_at"
  fi
  info "install-awg.sh is not beside install.sh -- fetching it from $_ab"
  awg_fetch "$_ab/SHA256SUMS.txt" "$1/SHA256SUMS.txt" || { warn "could not download the release's SHA256SUMS.txt"; return 1; }
  _av=""
  command -v signify >/dev/null 2>&1 && _av=signify
  [ -z "$_av" ] && command -v usign >/dev/null 2>&1 && _av=usign
  if [ -n "$_av" ]; then
    awg_fetch "$_ab/SHA256SUMS.txt.sig" "$1/SHA256SUMS.txt.sig" ||
      { warn "the release ships no SHA256SUMS.txt.sig -- refusing an unsigned manifest on a device that can verify one"; return 1; }
    printf '%s\n' "$RELEASE_PUBKEY" > "$1/release.pub"
    "$_av" -V -q -p "$1/release.pub" -x "$1/SHA256SUMS.txt.sig" -m "$1/SHA256SUMS.txt" 2>/dev/null ||
      { warn "manifest SIGNATURE verification FAILED -- refusing install-awg.sh"; return 1; }
    ok "release manifest signature verified ($_av)"
  else
    warn "no usign/signify here: the manifest signature is not checked; SHA-256 over HTTPS still is"
  fi
  _am="$(awk '{ n = $2; sub(/^\*/, "", n); if (n == "install-awg.sh") print $1 }' "$1/SHA256SUMS.txt")"
  { [ -n "$_am" ] && [ "$(printf '%s\n' "$_am" | wc -l | tr -d ' ')" = 1 ] && [ "${#_am}" = 64 ]; } ||
    { warn "install-awg.sh is not listed exactly once, with a SHA-256, in the release's SHA256SUMS.txt"; return 1; }
  _am="$(printf '%s' "$_am" | tr 'A-F' 'a-f')"
  awg_fetch "$_ab/install-awg.sh" "$1/install-awg.sh" || { warn "could not download install-awg.sh"; return 1; }
  [ "$(awg_sha256 "$1/install-awg.sh")" = "$_am" ] || { warn "SHA-256 MISMATCH for install-awg.sh -- refusing to run it"; return 1; }
  ok "install-awg.sh sha256 verified"
  AWG_SH="$1/install-awg.sh"
}
with_awg() { # extra install-awg.sh args... -> 0 done, 1 failed, 2 refused
  hdr "AmneziaWG 3.1 (--with-awg)"
  _ad="$(mktemp -d 2>/dev/null)" || _ad=""
  [ -n "$_ad" ] || { _ad="/tmp/wayhop-awg.$$"; (umask 077; mkdir -p "$_ad"); }
  if ! awg_installer "$_ad"; then
    rm -rf "$_ad"; warn "AmneziaWG NOT installed: no verified install-awg.sh (WayHop itself is fine)"; return 1
  fi
  _ay="--yes"; [ "$ASSUME" = no ] && _ay="--dry-run"   # -n: report only
  sh "$AWG_SH" --mode "$AWG_MODE" "$_ay" "$@"
  _arc=$?
  rm -rf "$_ad"
  case "$_arc" in
    0) ok "AmneziaWG step done" ;;
    2) warn "AmneziaWG NOT installed: refused, see above (WayHop itself is fine)" ;;
    *) warn "AmneziaWG NOT installed: install-awg.sh exited $_arc (WayHop itself is fine)"; _arc=1 ;;
  esac
  return "$_arc"
}
# <<< with-awg hook

# >>> space + leftovers (tests: packaging/test/openwrt_upgrade_harness.sh)
# The overlay is the one resource an upgrade can run out of: 60 MiB on the test router with a fifth of it
# free, against a ~14 MiB binary. The upgrade used to need room for TWO more binaries (the new one,
# and a fresh copy of the old one as the rollback) while the previous rollback copy still sat beside
# them: ~30 MiB on a box with 13-20 free. It then failed half-way, with the service already stopped
# and a partial wayhop.new holding what little room there had been.
#
# Now: (1) what WayHop itself left behind is removed first (staging files of an interrupted install
# or panel update, builds under the project's old names, duplicate copies, orphaned temp dirs);
# (2) the rollback copy is a HARD LINK to the current binary, so writing it costs nothing: when the
# new binary is renamed over the old name, the old inode stays behind under the .bak name; (3) where
# even the new binary alone does not fit, the rollback copy is kept gzip-compressed (~40%), verified
# against the binary's digest, and the old binary is removed only after that and with the service
# stopped (the init script restores from it if power is lost before the new binary lands); (4) only
# when none of that fits does it refuse, before anything is stopped, with the exact MiB to free.
# Older copies of WayHop builds go only when the upgrade needs their room, or on --cleanup. Never
# touched: the running binary, the config, and anything not provably WayHop's.
MARGIN_KB=2048          # head-room left free after every step (flash file systems need some)
STAGE_AGE_MIN=10        # a staging file younger than this may be a panel update still writing it
TMP_AGE_MIN=30          # an installer temp dir younger than this may belong to a run in progress
ENGINES="sing-box mihomo xray hysteria dnscrypt-proxy amneziawg-go olcrtc"   # the updater's BinNames, plus olcrtc, which earlier builds installed
UPG="/tmp/wayhop-upgrade.$$"
LEFT="$UPG/leftovers"
GZ_STAGED=""
trap 'rm -rf "$UPG" 2>/dev/null' EXIT
upg_dir() { [ -d "$UPG" ] || (umask 077; mkdir -p "$UPG") || die "could not create $UPG"; }
kib_of() { [ -f "$1" ] || { echo 0; return; }; _b="$(wc -c < "$1" 2>/dev/null | tr -d ' ')"; echo $(( (${_b:-0} + 1023) / 1024 )); }
mib_of() { echo $(( ($1 + 1023) / 1024 )); }
avail_kib() { df -Pk "$1" 2>/dev/null | awk 'NR == 2 && $4 ~ /^[0-9]+$/ { print $4 }'; }
mount_of() { df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print $6 }'; }
# What deleting this name gives back: a directory's usage; nothing for a file another name still holds.
freed_kib() {
  if [ -d "$1" ]; then du -sk "$1" 2>/dev/null | awk '{ print $1; exit }'; return; fi
  [ -f "$1" ] || { echo 0; return; }
  # shellcheck disable=SC2012  # the link count: OpenWrt's busybox has no stat
  _l="$(ls -ld "$1" 2>/dev/null | awk '{ print $2 }')"
  if [ "${_l:-1}" -gt 1 ] 2>/dev/null; then echo 0; return; fi
  du -k "$1" 2>/dev/null | awk '{ print $1; exit }'
}
sha_of() { [ -f "$1" ] && sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
# "Provably WayHop's": an ELF executable carrying a WayHop build's own package paths (the project was
# called velinx and wakeroute before). A file that merely has a matching name is left alone.
is_wayhop_build() {
  { [ -f "$1" ] && [ ! -h "$1" ]; } || return 1
  [ "$(dd if="$1" bs=1 skip=1 count=3 2>/dev/null)" = ELF ] || return 1
  grep -q -e 'wayhop/internal/' -e 'velinx/internal/' -e 'wakeroute/internal/' "$1" 2>/dev/null
}
recent() { [ -n "$(find "$1" -maxdepth 0 -mmin "-$2" 2>/dev/null)" ]; }
left_add() { printf '%s\t%s\t%s\t%s\n' "$1" "${2:-0}" "$3" "$4" >> "$LEFT"; }   # tier KiB path why

# scan_leftovers upgrade|cleanup -> $LEFT, one line per item: tier, KiB it frees, path, reason.
#   dead      always safe: nothing can use it (an upgrade removes these before it measures)
#   ram       the same, but in /tmp, which is RAM: it is not overlay space, it is memory
#   obsolete  an older WayHop build kept beside the binary: removed on --cleanup, or when the upgrade
#             needs its room (the upgrade writes a fresh rollback copy of the current binary anyway)
#   rollback  the one rollback copy --cleanup keeps (removed only with --drop-rollback)
scan_leftovers() {
  upg_dir; : > "$LEFT"; : > "$UPG/older"
  _busy=0; pidof wayhop >/dev/null 2>&1 && _busy=1
  # Staging files of an interrupted install (this script's names) or panel self-update (the daemon's).
  for _f in "$SBIN/wayhop.new" "$SBIN/wayhop.bak.new" "$SBIN/wayhop.bak.gz.new" "$SBIN/wayhop.rb" \
            "$SBIN/wayhop.bak.tmp" "$SBIN/.wayhop.new" "$SVC.new" /lib/upgrade/keep.d/wayhop.new; do
    [ -f "$_f" ] || continue
    if [ "$_busy" = 1 ] && recent "$_f" "$STAGE_AGE_MIN"; then
      info "keeping $_f: written in the last $STAGE_AGE_MIN min while WayHop runs (an update in progress?)"; continue
    fi
    left_add dead "$(freed_kib "$_f")" "$_f" "unfinished install or update"
  done
  # Builds under the project's earlier names. While their service exists the migration below moves it;
  # once it is gone nothing runs them, and the config paths they were built for no longer exist.
  for _o in velinx wakeroute; do
    [ -x "$INITD/${INIT_PREFIX}$_o" ] && continue
    for _f in "$SBIN/$_o" "$SBIN/$_o.bak" "$SBIN/$_o".bak-*; do
      is_wayhop_build "$_f" && left_add dead "$(freed_kib "$_f")" "$_f" "a build under the old '$_o' name; nothing runs it"
    done
    for _f in "$SBIN/$_o.new" "$SBIN/.$_o.new" "$SBIN/$_o.bak.new" "$SBIN/$_o.bak.tmp"; do
      [ -f "$_f" ] && left_add dead "$(freed_kib "$_f")" "$_f" "unfinished install under the old '$_o' name"
    done
  done
  # Copies of WayHop builds beside the binary, as hand deploys kept them (wayhop.bak-<commit>). One
  # identical to the binary or to the rollback copy is a duplicate; any other is an older build.
  _cur="$(sha_of "$SBIN/wayhop")"; _bak="$(sha_of "$SBIN/wayhop.bak")"
  for _f in "$SBIN"/wayhop.bak-*; do
    is_wayhop_build "$_f" || continue
    _s="$(sha_of "$_f")"
    if [ -n "$_s" ] && [ "$_s" = "$_cur" ]; then left_add dead "$(freed_kib "$_f")" "$_f" "a duplicate of the installed binary"
    elif [ -n "$_s" ] && [ "$_s" = "$_bak" ]; then left_add dead "$(freed_kib "$_f")" "$_f" "a duplicate of the rollback copy"
    else printf '%s\n' "$_f" >> "$UPG/older"; fi
  done
  # An apk install up to 0.5.8 published the package's binary as a second, identical copy; on
  # --cleanup the live name becomes a hard link of the package file (freed when the daemon restarts).
  _pk=/usr/libexec/wayhop/wayhop
  if [ "$1" = cleanup ] && [ -f "$_pk" ] && [ -f "$SBIN/wayhop" ] && [ ! "$_pk" -ef "$SBIN/wayhop" ] &&
     [ -n "$_cur" ] && [ "$(sha_of "$_pk")" = "$_cur" ]; then
    left_add relink "$(freed_kib "$SBIN/wayhop")" "$SBIN/wayhop" "a second copy of the package's $_pk; now a hard link of it (the room frees when WayHop next restarts)"
  fi
  # The rolling rollback copy is wayhop.bak or wayhop.bak.gz; with both, the older one is obsolete.
  _rb=""
  if [ -f "$SBIN/wayhop.bak" ] && [ -f "$SBIN/wayhop.bak.gz" ]; then
    if [ "$SBIN/wayhop.bak.gz" -nt "$SBIN/wayhop.bak" ]; then
      _rb="$SBIN/wayhop.bak.gz"; left_add obsolete "$(freed_kib "$SBIN/wayhop.bak")" "$SBIN/wayhop.bak" "older than the compressed rollback copy"
    else
      _rb="$SBIN/wayhop.bak"; left_add obsolete "$(freed_kib "$SBIN/wayhop.bak.gz")" "$SBIN/wayhop.bak.gz" "older than the plain rollback copy"
    fi
  elif [ -f "$SBIN/wayhop.bak" ]; then _rb="$SBIN/wayhop.bak"
  elif [ -f "$SBIN/wayhop.bak.gz" ]; then _rb="$SBIN/wayhop.bak.gz"; fi
  # With no rolling copy, --cleanup keeps the newest older build as the rollback copy instead.
  if [ -z "$_rb" ] && [ "$1" = cleanup ]; then
    while IFS= read -r _f; do { [ -z "$_rb" ] || [ "$_f" -nt "$_rb" ]; } && _rb="$_f"; done < "$UPG/older"
  fi
  while IFS= read -r _f; do
    [ "$_f" = "$_rb" ] || left_add obsolete "$(freed_kib "$_f")" "$_f" "an older WayHop build"
  done < "$UPG/older"
  [ "$1" = cleanup ] && [ -n "$_rb" ] && left_add rollback "$(freed_kib "$_rb")" "$_rb" "the rollback copy"
  # Engines the panel installs beside the configured sing-box: their staging files, and an
  # amneziawg-go gzip superseded by the plain binary its version record now describes.
  _sb="$(sed -n 's/.*"bin"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ETC/config.json" 2>/dev/null | head -n1)"
  _sd=/usr/bin; case "$_sb" in /*/*) _sd="${_sb%/*}" ;; esac
  for _e in $ENGINES; do
    for _f in "$_sd/$_e.new" "$_sd/$_e.new.zip" "$_sd/$_e.gz.new" "$_sd/.$_e.version.new"; do
      [ -f "$_f" ] || continue
      if [ "$_busy" = 1 ] && recent "$_f" "$STAGE_AGE_MIN"; then continue; fi
      left_add dead "$(freed_kib "$_f")" "$_f" "unfinished panel install of $_e"
    done
  done
  _r="$(awk 'NR == 1 { print $2, $3 }' "$_sd/.amneziawg-go.version" 2>/dev/null)"
  if [ -f "$_sd/amneziawg-go.gz" ] && [ -f "$_sd/amneziawg-go" ] && [ "$_r" = "0 $(wc -c < "$_sd/amneziawg-go" | tr -d ' ')" ]; then
    left_add dead "$(freed_kib "$_sd/amneziawg-go.gz")" "$_sd/amneziawg-go.gz" "a compressed amneziawg-go the installed binary superseded"
  fi
  # Temp dirs of installer runs and panel self-updates that never finished (bootstrap, this script,
  # install-awg.sh, the daemon's RAM staging). Never this run's own, never one whose process is
  # alive, never a recent one.
  for _d in /tmp/wayhop-boot.* /tmp/wayhop-awg.* /tmp/install-awg.* /tmp/wayhop-upgrade.* /tmp/wayhop-selfupdate.* /tmp/tmp.*; do
    [ -d "$_d" ] && [ "$_d" != "$UPG" ] || continue
    case "$SRC/" in "$_d"/*) continue ;; esac
    case "$_d" in /tmp/tmp.*) { [ -f "$_d/SHA256SUMS.txt" ] && [ -f "$_d/x/install.sh" ]; } || continue ;; esac
    _p="${_d##*.}"; case "$_p" in ''|*[!0-9]*) ;; *) [ -d "/proc/$_p" ] && continue ;; esac
    recent "$_d" "$TMP_AGE_MIN" && continue
    left_add ram "$(freed_kib "$_d")" "$_d" "temp dir of an installer run that did not finish (RAM, not flash)"
  done
}
sum_leftovers() { # tiers... -> KiB they free
  [ -s "$LEFT" ] || { echo 0; return; }
  awk -F '\t' -v t=" $* " 'index(t, " " $1 " ") { s += $2 } END { print s + 0 }' "$LEFT"
}
list_leftovers() { # verb tiers...
  _v="$1"; shift
  [ -s "$LEFT" ] || return 0
  while IFS="$(printf '\t')" read -r _t _k _f _w; do
    case " $* " in *" $_t "*) ;; *) continue ;; esac
    if [ "$_t" = relink ]; then info "${_v%% *} link $_f ($(mib_of "$_k") MiB) -- $_w"
    else info "$_v $_f ($(mib_of "$_k") MiB) -- $_w"; fi
  done < "$LEFT"
}
remove_leftovers() { # tiers... -> removes them; RECLAIMED_KB is what that freed
  RECLAIMED_KB=0
  [ -s "$LEFT" ] || return 0
  while IFS="$(printf '\t')" read -r _t _k _f _w; do
    case " $* " in *" $_t "*) ;; *) continue ;; esac
    if [ "$_t" = relink ]; then   # replaced by a link of the identical package file, never removed
      rm -f "$_f.rb"
      if ln /usr/libexec/wayhop/wayhop "$_f.rb" 2>/dev/null && mv "$_f.rb" "$_f"; then
        RECLAIMED_KB=$((RECLAIMED_KB + _k)); info "linked $_f ($(mib_of "$_k") MiB) -- $_w"
      else rm -f "$_f.rb"; warn "could not link $_f to the package file -- left as it was"; fi
      continue
    fi
    if [ -d "$_f" ]; then rm -rf "$_f"; else rm -f "$_f"; fi
    if [ -e "$_f" ]; then warn "could not remove $_f"; continue; fi
    RECLAIMED_KB=$((RECLAIMED_KB + _k)); info "removed $_f ($(mib_of "$_k") MiB) -- $_w"
  done < "$LEFT"
}
biggest_files() { # the largest files on the overlay, so the refusal names where the room went
  [ -d /overlay/upper ] || return 0
  find /overlay/upper -xdev -type f -size +1024k 2>/dev/null | while IFS= read -r _f; do
    printf '%s\t%s\n' "$(du -k "$_f" 2>/dev/null | cut -f1)" "${_f#/overlay/upper}"
  done | sort -rn | head -n 5 | while IFS="$(printf '\t')" read -r _k _f; do info "  $(mib_of "$_k") MiB  $_f"; done
}

# gz_rollback SRC: SRC gzip-compressed to $SBIN/wayhop.bak.gz and checked against SRC's own digest
# before it replaces anything. Prepared in /tmp (RAM) when there is room, so the overlay never holds
# a half-written copy. 0 on success; on failure nothing is left behind and the existing copies stand.
gz_rollback() {
  _want="$(sha_of "$1")"; [ -n "$_want" ] || return 1
  rm -f "$SBIN/wayhop.bak.gz.new"
  _st="$GZ_STAGED"
  if [ -z "$_st" ] && [ "$(avail_kib /tmp)" -ge $(( $(kib_of "$1") + 1024 )) ] 2>/dev/null; then
    upg_dir; gzip -c "$1" > "$UPG/rollback.gz" 2>/dev/null && _st="$UPG/rollback.gz"
  fi
  if [ -n "$_st" ]; then cp "$_st" "$SBIN/wayhop.bak.gz.new" 2>/dev/null
  else gzip -c "$1" > "$SBIN/wayhop.bak.gz.new" 2>/dev/null; fi || { rm -f "$SBIN/wayhop.bak.gz.new"; return 1; }
  [ "$(gzip -dc "$SBIN/wayhop.bak.gz.new" 2>/dev/null | sha256sum | cut -d' ' -f1)" = "$_want" ] ||
    { rm -f "$SBIN/wayhop.bak.gz.new"; return 1; }
  sync
  mv "$SBIN/wayhop.bak.gz.new" "$SBIN/wayhop.bak.gz" || { rm -f "$SBIN/wayhop.bak.gz.new"; return 1; }
}

# plan_space [extra KiB] -> PLAN: fresh | raw | gz | none | unknown, with the numbers the messages use.
# extra is what a --dry-run would have reclaimed first. raw: the new binary alone must fit, after the
# superseded rollback copy goes (the new rollback copy is a hard link). gz: the compressed copy of the
# current binary must fit, and then the new binary in the room the removed old one leaves.
plan_space() {
  NEW_KB="$(kib_of "$BIN")"; AV_KB="$(avail_kib "$SBIN")"; PLAN=unknown
  [ -n "$AV_KB" ] || return 0
  AV_KB=$((AV_KB + ${1:-0}))
  if [ ! -f "$SBIN/wayhop" ]; then
    NEED_KB=$((NEW_KB + MARGIN_KB)); ROOM_KB=$AV_KB; PLAN=fresh
    [ "$ROOM_KB" -ge "$NEED_KB" ] || PLAN=none
    return 0
  fi
  OLD_KB="$(freed_kib "$SBIN/wayhop")"     # 0 while another name (a package's copy) holds the inode
  BAK_KB=0
  if [ -f "$SBIN/wayhop.bak" ] && [ ! "$SBIN/wayhop.bak" -ef "$SBIN/wayhop" ]; then BAK_KB=$(freed_kib "$SBIN/wayhop.bak"); fi
  [ -f "$SBIN/wayhop.bak.gz" ] && BAK_KB=$((BAK_KB + $(freed_kib "$SBIN/wayhop.bak.gz")))
  ROOM_KB=$((AV_KB + BAK_KB))
  RAW_NEED_KB=$((NEW_KB + MARGIN_KB))
  if [ "$ROOM_KB" -ge "$RAW_NEED_KB" ]; then PLAN=raw; NEED_KB=$RAW_NEED_KB; return 0; fi
  NEED_KB=$RAW_NEED_KB; PLAN=none
  [ "${OLD_KB:-0}" -gt 0 ] 2>/dev/null || return 0     # removing the old binary would free nothing
  if [ -z "$GZ_STAGED" ] && [ "$DRY_RUN" != 1 ] && [ "$(avail_kib /tmp)" -ge $(( $(kib_of "$SBIN/wayhop") + 1024 )) ] 2>/dev/null; then
    upg_dir
    if gzip -c "$SBIN/wayhop" > "$UPG/rollback.gz" 2>/dev/null; then GZ_STAGED="$UPG/rollback.gz"; else rm -f "$UPG/rollback.gz"; fi
  fi
  if [ -n "$GZ_STAGED" ]; then GZ_KB="$(kib_of "$GZ_STAGED")"; else GZ_KB=$(( $(kib_of "$SBIN/wayhop") * 55 / 100 )); fi
  GZ_NEED_KB=$((GZ_KB + MARGIN_KB))
  [ "$NEW_KB" -gt "$OLD_KB" ] && GZ_NEED_KB=$((GZ_NEED_KB + NEW_KB - OLD_KB))
  [ "$GZ_NEED_KB" -lt "$NEED_KB" ] && NEED_KB=$GZ_NEED_KB
  [ "$ROOM_KB" -ge "$GZ_NEED_KB" ] && PLAN=gz
  return 0
}

# --cleanup: reclaim space without installing anything. The running binary, the config and the one
# rollback copy stay (that copy is compressed where it is plain; --drop-rollback removes it).
# shellcheck disable=SC2086  # $_tiers is a list of tier words, split on purpose
cleanup_main() {
  hdr "Cleanup"
  _fs="$(mount_of "$SBIN")"; _a0="$(avail_kib "$SBIN")"
  [ -n "$_a0" ] && info "free on ${_fs:-$SBIN}: $(mib_of "$_a0") MiB"
  scan_leftovers cleanup
  _tiers="dead ram obsolete relink"; [ "$DROP_ROLLBACK" = 1 ] && _tiers="$_tiers rollback"
  _rbf="$(awk -F '\t' '$1 == "rollback" { print $3 }' "$LEFT")"
  _squash=0
  if [ "$DROP_ROLLBACK" != 1 ] && [ "$_rbf" != "${_rbf%.gz}" ]; then :
  elif [ "$DROP_ROLLBACK" != 1 ] && [ -n "$_rbf" ] && [ ! "$_rbf" -ef "$SBIN/wayhop" ]; then _squash=1; fi
  _sum="$(sum_leftovers $_tiers)"
  if [ "$_sum" -eq 0 ] && [ "$_squash" = 0 ]; then
    ok "nothing to reclaim: no leftovers of earlier WayHop installs or updates"
    [ -n "$_rbf" ] && info "kept: $_rbf (the rollback copy; --drop-rollback removes it)"
    return 0
  fi
  if [ "$DRY_RUN" = 1 ]; then
    list_leftovers "would remove" $_tiers
    [ "$_squash" = 1 ] && info "would compress $_rbf to $SBIN/wayhop.bak.gz (about 40% of its $(mib_of "$(kib_of "$_rbf")") MiB)"
    [ "$DROP_ROLLBACK" != 1 ] && [ -n "$_rbf" ] && info "would keep: $_rbf (the rollback copy)"
    say "dry-run: about $(mib_of "$_sum") MiB would be freed$([ "$_squash" = 1 ] && echo ', more with the compressed rollback copy'); nothing was changed"
    return 0
  fi
  remove_leftovers $_tiers
  if [ "$_squash" = 1 ]; then
    if gz_rollback "$_rbf"; then
      rm -f "$_rbf"; ok "rollback copy compressed: $SBIN/wayhop.bak.gz ($(mib_of "$(kib_of "$SBIN/wayhop.bak.gz")") MiB)"
    else
      warn "could not compress the rollback copy -- kept $_rbf as it was"
    fi
  fi
  _a1="$(avail_kib "$SBIN")"
  if [ -n "$_a0" ] && [ -n "$_a1" ]; then
    ok "reclaimed $(mib_of $((_a1 > _a0 ? _a1 - _a0 : 0))) MiB on ${_fs:-$SBIN} (free now: $(mib_of "$_a1") MiB)"
  else
    ok "reclaimed about $(mib_of "$RECLAIMED_KB") MiB"
  fi
  [ "$DROP_ROLLBACK" != 1 ] && [ -f "$SBIN/wayhop.bak.gz" ] && info "kept: $SBIN/wayhop.bak.gz (the rollback copy; --drop-rollback removes it)"
  [ "$DROP_ROLLBACK" != 1 ] && [ -f "$SBIN/wayhop.bak" ] && info "kept: $SBIN/wayhop.bak (the rollback copy; --drop-rollback removes it)"
  return 0
}
# restore_rollback: the rollback copy back under the binary's name -- a link of the plain copy, or
# the compressed one unpacked and checked against the digest it was taken with. The service is
# stopped. Unpacked in /tmp first where there is room, so the failed binary goes only once a good
# copy is in hand.
restore_rollback() {
  rm -f "$SBIN/wayhop.rb"
  if [ -f "$SBIN/wayhop.bak" ]; then
    ln "$SBIN/wayhop.bak" "$SBIN/wayhop.rb" 2>/dev/null || cp "$SBIN/wayhop.bak" "$SBIN/wayhop.rb" || { rm -f "$SBIN/wayhop.rb"; return 1; }
    RESTORED_FROM="$SBIN/wayhop.bak"
  elif [ -f "$SBIN/wayhop.bak.gz" ]; then
    _u=""
    if [ "$(avail_kib /tmp)" -ge $(( $(kib_of "$SBIN/wayhop.bak.gz") * 4 + 1024 )) ] 2>/dev/null; then
      upg_dir; gzip -dc "$SBIN/wayhop.bak.gz" > "$UPG/restore" 2>/dev/null && _u="$UPG/restore"
      [ -z "$_u" ] || [ -z "${OLD_SHA:-}" ] || [ "$(sha_of "$_u")" = "$OLD_SHA" ] || return 1
    fi
    rm -f "$SBIN/wayhop"   # the failed binary: its room is what the unpacked copy needs
    if [ -n "$_u" ]; then cp "$_u" "$SBIN/wayhop.rb" 2>/dev/null
    else gzip -dc "$SBIN/wayhop.bak.gz" > "$SBIN/wayhop.rb" 2>/dev/null; fi || { rm -f "$SBIN/wayhop.rb"; return 1; }
    [ -z "${OLD_SHA:-}" ] || [ "$(sha_of "$SBIN/wayhop.rb")" = "$OLD_SHA" ] || { rm -f "$SBIN/wayhop.rb"; return 1; }
    RESTORED_FROM="$SBIN/wayhop.bak.gz"
  else
    return 1
  fi
  chmod 0755 "$SBIN/wayhop.rb" && sync && mv "$SBIN/wayhop.rb" "$SBIN/wayhop"
}
# swap_fail MSG: the new binary did not land. Put the old one back if it had been removed, start the
# service again if this run stopped it, and only then stop with the message.
swap_fail() {
  rm -f "$SBIN/wayhop.new" "$SBIN/wayhop.bak.new" "$SBIN/wayhop.bak.gz.new"
  if [ ! -f "$SBIN/wayhop" ]; then
    restore_rollback || warn "could not restore the previous binary -- by hand: gzip -dc $SBIN/wayhop.bak.gz > $SBIN/wayhop && chmod 0755 $SBIN/wayhop"
  fi
  [ "${STOPPED:-0}" = 1 ] && { "$SVC" start 2>/dev/null || true; }
  die "$1"
}
wait_stopped() { _i=0; while pidof wayhop >/dev/null 2>&1; do [ "$_i" -ge 10 ] && return 1; sleep 1; _i=$((_i + 1)); done; }

# The update as the supervisor sees it (internal/updatetx/verify.sh, written beside the config as
# update-verify.sh): the marker is written just before the new binary takes the name and removed once
# this run has judged the result itself; a power cut in between leaves it for the init to finish at
# boot. The result is what the panel and the bot report afterwards.
tx_mark() { # <rollback copy>
  _nl="$("$BIN" --version 2>/dev/null | head -n 1)"
  _nv="$(printf '%s' "$_nl" | sed -n 's/^wayhop \([^ ]*\) .*/\1/p')"
  _nc="$(printf '%s' "$_nl" | sed -n 's/^wayhop [^ ]* (\([0-9a-f]*\),.*/\1/p')"
  TX_TO="$_nl"   # for tx_done, which runs after a rollback too, when "$SBIN/wayhop" is the old build again
  printf 'bin=%s\ninit=%s\nconfig=%s\nrollback=%s\nnorollback=\nwant_commit=%s\nwant_version=%s\nfrom=%s\nto=%s\nby=installer\nwindow=90\nboots=0\n' \
    "$SBIN/wayhop" "$SVC" "$ETC/config.json" "$1" "$_nc" "$_nv" "${PREV_VER:-}" "$_nv" > "$ETC/update.pending.new" &&
    mv "$ETC/update.pending.new" "$ETC/update.pending" &&
    sync   # the sync before tx_mark covers the binary, not this file: a power cut could keep the rename
           # and lose the data, and verify.sh drops an empty marker at boot, so a broken build stays
}
tx_done() { # <ok|rolled_back|failed> <reason>
  [ -f "$ETC/update.pending" ] || return 0
  rm -f "$ETC/update.pending"
  _je() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'; }
  printf '{"result":"%s","reason":"%s","from":"%s","to":"%s","by":"installer","at":%s}\n' "$1" "$(_je "$2")" \
    "$(_je "${PREV_VER:-}")" "$(_je "${TX_TO:-$("$SBIN/wayhop" --version 2>/dev/null | head -n 1)}")" "$(date +%s)" > "$ETC/update-result.json.new" &&
    mv "$ETC/update-result.json.new" "$ETC/update-result.json"
}
# The supervisor itself, from the binary being installed (a build that predates it prints no script).
install_verifier() {
  "$BIN" update-verifier > "$ETC/update-verify.sh.new" 2>/dev/null
  if [ "$(head -n 1 "$ETC/update-verify.sh.new" 2>/dev/null)" = '#!/bin/sh' ]; then
    chmod 0755 "$ETC/update-verify.sh.new" && mv "$ETC/update-verify.sh.new" "$ETC/update-verify.sh"
  else
    rm -f "$ETC/update-verify.sh.new"
  fi
}
# Once the new build has proved itself: a plain rollback copy on a nearly full flash is compressed.
# Below one more binary's worth (+ head-room) free, the next binary-sized write -- an update's staging,
# an engine -- cannot land, so the ~60% the copy gives back matters more than restoring it by link.
squash_if_tight() {
  { [ -f "$SBIN/wayhop.bak" ] && [ ! "$SBIN/wayhop.bak" -ef "$SBIN/wayhop" ]; } || return 0
  _sf="$(avail_kib "$SBIN")"; _sn=$(( $(kib_of "$SBIN/wayhop") + MARGIN_KB ))
  { [ -n "$_sf" ] && [ "$_sf" -lt "$_sn" ]; } || return 0
  if gz_rollback "$SBIN/wayhop.bak"; then
    rm -f "$SBIN/wayhop.bak"
    ok "the overlay is nearly full ($(mib_of "$_sf") MiB free): the rollback copy is kept compressed -> $SBIN/wayhop.bak.gz"
  fi
}
# <<< space + leftovers

SRC="$(cd "$(dirname "$0")" && pwd)"
# Entware paths, here because the shared space block below reads them.
SBIN=/opt/sbin
INITD=/opt/etc/init.d
ETC=/opt/etc/wayhop
VAR=/opt/var/wayhop
INIT_PREFIX=S99          # the init is $INITD/${INIT_PREFIX}wayhop (OpenWrt: none)
SVC="$INITD/${INIT_PREFIX}wayhop"
# Banner version read from the bundled binary (the tarball ships one wayhop-<arch> for this router's
# CPU), so it can never drift from what is actually installed. Falls back quietly if it won't run.
VERSION=""
for _b in "$SRC"/wayhop-*; do
  [ -x "$_b" ] || continue
  VERSION="$("$_b" --version 2>/dev/null | head -1)"
  [ -n "$VERSION" ] && break
done
say "WayHop installer ${VERSION:-(from tarball)}"
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
if [ "$CLEANUP" = 1 ]; then cleanup_main; exit 0; fi

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
  # Default YES, which is what the no-TTY path takes: this is a router that cannot route without
  # these, reached by someone who just asked for an install. Declining leaves a panel that renders
  # rules it can never write. Still overridable with -n, and a failed opkg only warns.
  if ask "Install missing routing packages via opkg (${pkgs# }) ?" y; then
    run sh -c "opkg update && opkg install ${pkgs# }" || warn "opkg install failed -- install ${pkgs# } manually later"
  fi
fi

# nftables: needed for the hybrid kernel PBR mode (optional — sing-box TUN mode works without it).
if command -v nft >/dev/null 2>&1; then
  ok "nft:      $(nft --version 2>/dev/null | head -1)"
elif [ "$PLATFORM" = keenetic ]; then
  info "nft:      not present -- expected on KeeneticOS (Fast/Hybrid modes need nftables; use native Mixed mode or the optional sing-box TUN compatibility mode)"
else
  info "nft:      not found (install nftables for hybrid PBR mode; sing-box TUN mode works without it)"
fi

# sing-box (UI works without it; Apply needs it). $SB always holds a path.
SB="/opt/sbin/sing-box"
if [ -x "$SB" ]; then ok "sing-box: $SB"
elif command -v sing-box >/dev/null 2>&1; then SB="$(command -v sing-box)"; ok "sing-box: $SB"
else
  # sing-box carries every protocol the router itself cannot (VLESS, Hysteria2, Trojan, ...), so on
  # anything but a purely native WireGuard datapath an install without it produces a panel that
  # cannot Apply. Entware lives on USB storage, so the space that argues against this on a small
  # OpenWrt flash does not apply here. Non-fatal either way: a router with a native-only setup is
  # perfectly usable without it.
  if command -v opkg >/dev/null 2>&1 && ask "Install sing-box via opkg (needed to Apply proxy configs) ?" y; then
    run sh -c "opkg update && opkg install sing-box" || warn "opkg install sing-box failed -- install it later"
    if [ -x "$SB" ]; then ok "sing-box: $SB"
    elif command -v sing-box >/dev/null 2>&1; then SB="$(command -v sing-box)"; ok "sing-box: $SB"; fi
  fi
  [ -x "$SB" ] || warn "sing-box not found -- the UI will start, but you cannot Apply a proxy config until it exists at $SB (opkg install sing-box, or drop the $ARCH build from github.com/SagerNet/sing-box/releases)"
fi
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


# best-effort: who listens on tcp :$1  -> echoes a short "prog/pid" string for display
port_listener() {
  { netstat -tlnp 2>/dev/null || ss -ltnp 2>/dev/null; } \
    | grep -E "[:.]$1[[:space:]]" | head -n1 \
    | grep -oE '[0-9]+/[A-Za-z._-]+|pid=[0-9]+|"[A-Za-z._-]+"' | tr '\n' ' '
}
port_busy() { { netstat -tln 2>/dev/null || ss -ltn 2>/dev/null; } | grep -qE "[:.]$1[[:space:]]"; }

# --- config "listen" parsing. The value may bind ALL interfaces (":8088") or a SPECIFIC address
# ("192.168.50.1:8088", "127.0.0.1:8088", "[::]:8088"). listen_port/listen_host split it so an
# upgrade adopts the real port AND the health check probes the address the daemon actually binds
# (a specific-IP bind won't answer on 127.0.0.1). POSIX/busybox-safe; a missing/absent listen
# yields empty (callers fall back to :$PORT bind-all / a loopback probe).
_listen_value() { sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | tail -n1; }
listen_port() {
  _lv="$(_listen_value "$1")"; [ -n "$_lv" ] || return 1
  _p="${_lv##*:}"; case "$_p" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s\n' "$_p"
}
listen_host() { _lv="$(_listen_value "$1")"; case "$_lv" in *:*) printf '%s\n' "${_lv%:*}" ;; *) printf '\n' ;; esac; }
# probe_host HOST -> the address to health-check; a bind-all/empty host maps to loopback.
probe_host() { case "$1" in ''|0.0.0.0|'[::]'|'::') printf '127.0.0.1\n' ;; *) printf '%s\n' "$1" ;; esac; }

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
  _cfg_port="$(listen_port "$ETC/config.json")"
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

# ===========================================================================
# Space
# ===========================================================================
# Decided here, before anything is stopped: a refusal leaves the running WayHop exactly as it was.
hdr "Space"
scan_leftovers upgrade
DEAD_KB="$(sum_leftovers dead)"; OBS_KB="$(sum_leftovers obsolete)"
FS="$(mount_of "$SBIN")"; FS="${FS:-$SBIN}"
if [ "$DRY_RUN" = 1 ]; then
  list_leftovers "would remove" dead ram
  plan_space "$DEAD_KB"
  if [ "$PLAN" = none ] && [ "$OBS_KB" -gt 0 ]; then
    list_leftovers "would remove (the upgrade needs its room)" obsolete
    plan_space $((DEAD_KB + OBS_KB))
  fi
else
  remove_leftovers dead ram
  [ "$RECLAIMED_KB" -gt 0 ] && ok "reclaimed $(mib_of "$RECLAIMED_KB") MiB that earlier installs and updates left behind"
  plan_space
  if [ "$PLAN" = none ] && [ "$OBS_KB" -gt 0 ]; then
    info "older WayHop builds beside the binary are in the way -- removing them (the upgrade keeps a fresh rollback copy of the current binary)"
    remove_leftovers obsolete
    plan_space
  fi
fi
case "$PLAN" in
  fresh) ok "free on $FS: $(mib_of "$AV_KB") MiB; the binary needs $(mib_of "$NEED_KB") MiB" ;;
  raw)   ok "free on $FS: $(mib_of "$ROOM_KB") MiB; the upgrade needs $(mib_of "$NEED_KB") MiB (the rollback copy is a hard link: it costs no space)" ;;
  gz)    warn "free on $FS: $(mib_of "$ROOM_KB") MiB -- not enough for the new binary beside the old one ($(mib_of "$RAW_NEED_KB") MiB)"
         info "the old binary is kept as a compressed rollback copy (~$(mib_of "$GZ_KB") MiB) and removed, with the service stopped, before the new one is written ($(mib_of "$NEED_KB") MiB needed)" ;;
  none)
    warn "not enough free space on $FS to install this safely"
    warn "  free: $(mib_of "$ROOM_KB") MiB, after removing what earlier WayHop installs and updates left behind"
    if [ -f "$SBIN/wayhop" ] && [ "${OLD_KB:-0}" -gt 0 ] 2>/dev/null; then
      warn "  needed: $(mib_of "$NEED_KB") MiB -- the new binary ($(mib_of "$NEW_KB") MiB) in the room the old one leaves, the old one kept compressed (~$(mib_of "$GZ_KB") MiB) as the rollback copy, and $(mib_of "$MARGIN_KB") MiB head-room"
    else
      warn "  needed: $(mib_of "$NEED_KB") MiB -- the binary ($(mib_of "$NEW_KB") MiB) and $(mib_of "$MARGIN_KB") MiB head-room"
    fi
    if [ -d /overlay/upper ]; then warn "  the largest files on the overlay:"; biggest_files; fi
    die "free at least $(mib_of $((NEED_KB - ROOM_KB))) MiB more on $FS (remove packages or files you no longer need), then re-run. Nothing was changed$([ "$UPGRADE" = 1 ] && echo '; the running WayHop was not stopped')."
    ;;
  *)     warn "could not measure the free space on $SBIN -- continuing; every write below still fails closed" ;;
esac

# ---------------------------------------------------------------------------
# Under --dry-run we stop here, before any change.
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" = 1 ]; then
  hdr "Dry-run complete"
  say "checks finished; no changes made. Re-run without --dry-run to install."
  if [ "$WITH_AWG" = 1 ]; then with_awg --dry-run; exit $?; fi
  exit 0
fi

# An upgrade over any earlier installation is safe without a ritual: on first start the daemon
# imports whatever applied state it finds (a previous-generation apply ledger, or the pre-ledger
# applied snapshot) into its own record, and a router it knows nothing about is one it owns nothing
# on until the next Apply.
# ===========================================================================
# 5. INSTALL
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

# The init script goes in before the binary is touched: it is what puts the binary back from the
# rollback copy should the power fail inside the window the compressed-copy swap below opens.
HAVE_INIT=0
if [ -f "$SRC/S99wayhop" ]; then
  say "installing init script -> $SVC"
  if cp "$SRC/S99wayhop" "$SVC.new" && chmod 0755 "$SVC.new" && mv "$SVC.new" "$SVC"; then HAVE_INIT=1; ok "init script installed"
  else rm -f "$SVC.new"; warn "could not install init script -- service won't auto-start on boot"; fi
else
  warn "S99wayhop not found next to the installer (incomplete tarball?) -- no boot auto-start; will start the daemon directly"
fi
install_verifier

STOPPED=0
if [ "$UPGRADE" = 1 ] && [ -x "$SVC" ]; then
  say "stopping existing service"; "$SVC" stop 2>/dev/null || true; sleep 1; STOPPED=1
fi

say "installing binary -> $SBIN/wayhop"
OLD_SHA=""
if [ -f "$SBIN/wayhop" ]; then
  OLD_SHA="$(sha_of "$SBIN/wayhop")"
  if [ "$PLAN" = gz ]; then
    say "keeping the old binary as a compressed rollback copy -> $SBIN/wayhop.bak.gz"
    # The superseded plain copy goes first only when the compressed one does not fit beside it.
    gz_rollback "$SBIN/wayhop" || { [ -f "$SBIN/wayhop.bak" ] && rm -f "$SBIN/wayhop.bak" && gz_rollback "$SBIN/wayhop"; } ||
      swap_fail "could not write a verified compressed rollback copy; the existing binary was not replaced"
    rm -f "$SBIN/wayhop.bak"
    wait_stopped || swap_fail "the running WayHop did not stop; the existing binary was not replaced"
    rm -f "$SBIN/wayhop"   # its bytes live on in wayhop.bak.gz, checked against its digest above
    ok "rollback copy: $SBIN/wayhop.bak.gz ($(mib_of "$(kib_of "$SBIN/wayhop.bak.gz")") MiB, verified)"
  else
    rm -f "$SBIN/wayhop.bak.new"
    # A hard link: when the new binary is renamed over the old name the old inode stays behind under
    # the .bak name, so the rollback copy takes no space. A file system without links gets a copy.
    ln "$SBIN/wayhop" "$SBIN/wayhop.bak.new" 2>/dev/null || cp "$SBIN/wayhop" "$SBIN/wayhop.bak.new" ||
      swap_fail "could not create the rollback backup; the existing binary was not replaced"
    [ "$SBIN/wayhop.bak.new" -ef "$SBIN/wayhop" ] || cmp -s "$SBIN/wayhop" "$SBIN/wayhop.bak.new" ||
      swap_fail "rollback backup verification failed; the existing binary was not replaced"
    mv "$SBIN/wayhop.bak.new" "$SBIN/wayhop.bak" ||
      swap_fail "could not publish the rollback backup; the existing binary was not replaced"
    rm -f "$SBIN/wayhop.bak.gz"   # superseded by the plain copy of the current binary
  fi
fi
cp "$BIN" "$SBIN/wayhop.new" || swap_fail "could not write the new binary (out of space?); the existing binary was not replaced"
cmp -s "$BIN" "$SBIN/wayhop.new" || swap_fail "the written binary does not match the package; the existing binary was not replaced"
chmod 0755 "$SBIN/wayhop.new" || swap_fail "failed to chmod binary"
sync
# Recorded just before the name changes hands (see tx_mark); a fresh install has nothing to roll back to.
if [ -n "$OLD_SHA" ]; then
  if [ "$PLAN" = gz ]; then tx_mark "$SBIN/wayhop.bak.gz"; else tx_mark "$SBIN/wayhop.bak"; fi
fi
mv "$SBIN/wayhop.new" "$SBIN/wayhop" || { tx_done failed "the new binary could not take the name"; swap_fail "failed to install binary"; }
ok "binary installed"

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
  cur="$(listen_port "$ETC/config.json")"
  if [ -n "$cur" ] && [ "$cur" != "$PORT" ]; then
    warn "existing config listens on :$cur but you selected :$PORT"
    if ask "  update the config's listen port to :$PORT?" y; then
      if sed -i "s|\"listen\"[^,]*|\"listen\": \":$PORT\"|" "$ETC/config.json" && \
         grep -q "\"listen\": \":$PORT\"" "$ETC/config.json"; then ok "config now listens on :$PORT"
      else warn "could not update config; change \"listen\" to \":$PORT\" by hand"; PORT="$cur"; fi
    else PORT="$cur"; info "keeping the configured port :$cur"; fi
  fi
fi

[ -f "$SRC/harden-state.sh" ] || die "harden-state.sh is missing from the package"
sh "$SRC/harden-state.sh" "$ETC" "$VAR" || die "could not protect WayHop state permissions"
ok "file modes checked"

# A feature that no longer ships leaves its data directory behind. Set it aside rather than delete
# it: WayHop generated those playlists, but the directory sits on a live router and an
# installer that removes something it only partly owns is a data-loss bug that surfaces once and
# permanently. The script refuses to touch anything it does not recognise and never deletes.
if [ -f "$SRC/retire-iptv.sh" ]; then
  sh "$SRC/retire-iptv.sh" "$VAR" || warn "could not check the retired IPTV directory"
fi

# ===========================================================================
# 6. START + HEALTH CHECK
# ===========================================================================
if [ "$NO_START" = 1 ]; then
  tx_done ok "installed by the installer; not started (--no-start), so not judged"
  hdr "Done (not started)"
  say "installed but not started (--no-start). Start later: $INITD/S99wayhop start"
  native_summary
  if [ "$WITH_AWG" = 1 ]; then with_awg; exit $?; fi
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
# Probe the address the daemon actually binds: a config that binds a SPECIFIC LAN IP won't
# answer on 127.0.0.1, so a loopback-only probe would false-negative and needlessly roll back.
PROBE_HOST="$(probe_host "$(listen_host "$ETC/config.json")")"
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
    curl) code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$PROBE_HOST:$PORT/" 2>/dev/null)"
          [ "$code" = 200 ] && { HEALTHY=1; break; } ;;
    wget) wget -q -O /dev/null --timeout=3 "http://$PROBE_HOST:$PORT/" 2>/dev/null && { HEALTHY=1; break; } ;;
    *)    break ;;
  esac
  i=$((i+1)); sleep 1
done

# The probe above proves only that SOMETHING answered on that port. A daemon left over from before
# the upgrade answers the same 200 -- the new binary could not bind, exited without a word, and the
# install reports success while the router keeps running the old code. Compare the identity the port
# reports against the binary that was just placed.
#
# Exit 2 from the matcher means neither side could be identified (an unstamped build, or a daemon too
# old to report one). That is reported, not treated as verified and not treated as a failure: an
# absent answer is not evidence either way.
if [ "$HEALTHY" = 1 ] && [ -n "$PROBE_TOOL" ] && [ -f "$SRC/identity-match.sh" ]; then
  case "$PROBE_TOOL" in
    curl) _hb="$(curl -s --max-time 3 "http://$PROBE_HOST:$PORT/api/health" 2>/dev/null || true)" ;;
    wget) _hb="$(wget -q -O - --timeout=3 "http://$PROBE_HOST:$PORT/api/health" 2>/dev/null || true)" ;;
    *)    _hb="" ;;
  esac
  _iv="$("$SBIN/wayhop" --version 2>/dev/null || true)"
  _sc="$(printf '%s' "$_hb" | sed -n 's/.*"commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  _rc=0
  sh "$SRC/identity-match.sh" "$_iv" "$_hb" || _rc=$?
  case "$_rc" in
    0) ok "the port is serving the build just installed" ;;
    1) HEALTHY=0
       warn "something else is answering on :$PORT -- it is NOT the build just installed."
       warn "A previous daemon is most likely still holding the port; the new one could not bind."
       warn "installed: ${_iv:-unknown};  answering commit: ${_sc:-unknown}" ;;
    *) info "build identity could not be compared (unstamped binary or older daemon) -- health probe only" ;;
  esac
elif [ "$HEALTHY" = 1 ] && [ ! -f "$SRC/identity-match.sh" ]; then
  info "identity-match.sh not bundled -- the port answered, but which build answered was not checked"
fi

# --- transactional rollback: if this was an UPGRADE and the new binary failed its health check,
#     restore the previous binary and restart it, so a bad update never strands the router. The
#     preserved config is untouched (upgrades never rewrite it), so only the binary is reverted. ---
ROLLED_BACK=0
if [ "$HEALTHY" != 1 ] && [ "${HEALTH_CHECKED:-0}" = 1 ] && [ "$UPGRADE" = 1 ] && { [ -f "$SBIN/wayhop.bak" ] || [ -f "$SBIN/wayhop.bak.gz" ]; }; then
  warn "new version did not answer on :$PORT within the timeout -- rolling back to the previous binary"
  [ "$HAVE_INIT" = 1 ] && "$SVC" stop 2>/dev/null
  for _p in $(pgrep_f "$ETC/singbox.json" 2>/dev/null); do kill "$_p" 2>/dev/null || true; done
  sleep 1
  wait_stopped || { _wp="$(pidof wayhop 2>/dev/null)"; [ -z "$_wp" ] || kill -9 $_wp 2>/dev/null; }
  if restore_rollback; then
    ok "restored the previous binary from $RESTORED_FROM"
    tx_done rolled_back "the new build did not answer on :$PORT after the installer started it"
    if [ "$HAVE_INIT" = 1 ]; then "$INITD/S99wayhop" start 2>/dev/null || true
    else ( "$SBIN/wayhop" --config "$ETC/config.json" >/dev/null 2>&1 & ); fi
    sleep 2
    ROLLED_BACK=1
    i=0
    while [ "$i" -lt 5 ]; do
      case "$PROBE_TOOL" in
        curl) [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$PROBE_HOST:$PORT/" 2>/dev/null)" = 200 ] && { HEALTHY=1; break; } ;;
        wget) wget -q -O /dev/null --timeout=3 "http://$PROBE_HOST:$PORT/" 2>/dev/null && { HEALTHY=1; break; } ;;
        *) break ;;
      esac
      i=$((i+1)); sleep 1
    done
    if [ "$HEALTHY" = 1 ]; then warn "rolled back -- the PREVIOUS version is running on :$PORT; the update did NOT apply. Check the logs, then retry."
    else warn "rolled back, but the previous version is not answering on :$PORT either -- check: logread 2>/dev/null | grep wayhop"; fi
  else
    if [ -f "$SBIN/wayhop.bak" ]; then
      die "ROLLBACK FAILED: could not restore $SBIN/wayhop.bak. Restore by hand: cp $SBIN/wayhop.bak $SBIN/wayhop && $SVC restart"
    fi
    die "ROLLBACK FAILED: could not restore $SBIN/wayhop.bak.gz. Restore by hand: gzip -dc $SBIN/wayhop.bak.gz > $SBIN/wayhop && chmod 0755 $SBIN/wayhop && $SVC restart"
  fi
fi

IP="$(guess_lan_ip)"
[ -z "$IP" ] && IP="$(uname -n 2>/dev/null)"

if [ "${ROLLED_BACK:-0}" != 1 ]; then
  if [ "$HEALTHY" = 1 ]; then tx_done ok "installed by the installer and answering on :$PORT"; squash_if_tight
  elif [ "${HEALTH_CHECKED:-0}" != 1 ]; then tx_done ok "installed by the installer; not judged (no curl or wget here)"
  else tx_done failed "the new build did not answer on :$PORT and there was no rollback copy to restore"; fi
fi
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
[ -x "$SB" ] || echo "    1. install sing-box   (opkg install sing-box) -- only needed for proxy protocols; a native WireGuard setup does not use it"
echo "    2. add a connection in the UI (paste a vless:// / hysteria2:// link or a .conf)"
echo "    3. create a Failover group and hit Apply (it auto-reverts if connectivity drops)"
if [ -f "$ETC/uninstall.sh" ]; then echo "    uninstall:  sh $ETC/uninstall.sh   (add --purge to also delete config)"
else echo "    uninstall:  sh ./uninstall.sh   (add --purge to also delete config; re-extract the tarball if it's gone)"; fi

if [ "$WITH_AWG" = 1 ]; then
  if [ "${ROLLED_BACK:-0}" = 1 ] || { [ "$HEALTHY" != 1 ] && [ "${HEALTH_CHECKED:-0}" = 1 ]; }; then
    warn "AmneziaWG (--with-awg) skipped: WayHop itself did not come up"
  else
    with_awg || exit $?
  fi
fi

# Exit status reflects the real outcome so the bootstrap / automation can tell success from failure.
if [ "${ROLLED_BACK:-0}" = 1 ]; then
  warn "UPDATE FAILED -- rolled back to the previous version (running on :$PORT). Nothing else changed."
  exit 1
fi
# A probed-but-unhealthy UI means the install/upgrade did not actually come up. Fail so the
# bootstrap / automation sees it -- a FRESH install used to fall through to exit 0 (false success).
# HEALTH_CHECKED gates this: a router with no curl/wget cannot be judged, so it is trusted (exit 0).
if [ "$HEALTHY" != 1 ] && [ "${HEALTH_CHECKED:-0}" = 1 ]; then
  if [ "$UPGRADE" = 1 ]; then warn "UPGRADE did not come up on :$PORT and no rollback was possible -- check: logread 2>/dev/null | grep wayhop"
  else warn "INSTALL did not come up on :$PORT -- check: logread 2>/dev/null | grep wayhop"; fi
  exit 1
fi
exit 0
