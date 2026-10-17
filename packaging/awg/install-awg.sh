#!/bin/sh
# install-awg.sh -- install AmneziaWG 3.1 from WayHop's own package feed.
#
# On OpenWrt it installs the kernel module (kmod-amneziawg + amneziawg-tools, plus the LuCI page when
# LuCI is installed) when the feed carries one built for this router's exact kernel; otherwise, and on
# Entware/Keenetic, the userspace amneziawg-go. It adds WayHop's feed and signing key when missing
# (the keys are embedded below), checks flash and RAM against the policy in
# docs/AWG_FULL_INSTALL.md (development repository), verifies the result, and rolls back what this
# run changed when the verification fails.
# POSIX sh, busybox-ash compatible. Nothing is ever installed with --allow-untrusted or
# --force-signature.
#
# Usage: install-awg.sh [--mode auto|kmod|userspace] [--feed URL] [--dry-run] [--yes] [--json]
#                       [--uninstall] [--keep-feed] [--restart-network]
#   --mode MODE   auto (default): the kernel module when a matching one exists, else userspace.
#                 kmod / userspace: exactly that path, never the other one; refused (exit 2) when
#                 it cannot be installed here.
#   --feed URL    feed root (default https://awadak3davra.github.io/wayhop-feed); http(s)://,
#                 file:// or an absolute directory.
#   --dry-run     print the plan and change nothing.
#   --yes         do not ask for confirmation (asked only when stdin is a terminal).
#   --json        print one JSON object as the last line of stdout; human lines go to stderr.
#   --uninstall   stop what runs on AmneziaWG (ifdown every proto-amneziawg interface -- their
#                 configuration is kept --, delete leftover amneziawg links, stop amneziawg-go
#                 processes running the packaged binary), remove the AmneziaWG packages and the
#                 dependencies this script's installs pulled in (never a package that was there
#                 before, or one something else still needs), unload the module when nothing uses
#                 it, and remove the feed lines and keys this script added.
#   --keep-feed   leave WayHop's feed lines and keys in place (on --uninstall and on a rollback).
#   --restart-network  restart netifd (/etc/init.d/network restart) when this run added, changed
#                 or removed its amneziawg protocol handler. netifd reads handlers only when it
#                 starts; without this flag the script only says so (connections drop briefly).
#
# Exit codes: 0 installed, already current, dry-run or removed; 1 failed (rolled back);
#             2 refused (does not fit, unsupported, or the --mode path is unavailable); 3 usage.
# JSON: {"result":"installed|current|refused|failed|dry-run|removed","path":"kmod|userspace",
#        "packages":[...],"reason":"...","generation":"3.1|older|none","flash_free_kib":N,
#        "mem_total_kib":N,"profile":"normal|lowmem","advice":"compressed-store",
#        "netifd_restart_needed":true|false,"network_restarted":true|false}
#   "advice" is empty unless userspace does not fit raw but fits WayHop's compressed store.
#   --uninstall reports "removed" with the packages it removed (an empty list when there was
#   nothing to remove). "generation" always describes the system after the run: after a removal it
#   is "none" unless an AmneziaWG module stays loaded (then the generation that was installed).
#   "netifd_restart_needed" is true when /lib/netifd/proto/amneziawg.sh was added, changed or
#   removed and netifd has not been restarted since (in a dry run: when it would be).
#
# Interrupting a run (SIGTERM/SIGINT/SIGHUP) rolls back what it changed. Configuration files are
# replaced atomically (temp file + mv); every feed line or key is recorded in the state file before
# it is written, and the package list from before an install is kept beside it until the install
# has recorded which packages it added, so even a run killed outright leaves nothing half-written
# and a re-run (or --uninstall) picks up where it stopped.
#
# Test hooks -- never set these on a router:
#   AWG_INSTALL_ROOT         prefix for every file read or written (/etc, /opt, /proc, /sys, ...)
#   AWG_INSTALL_PKG          package-manager command used instead of apk / opkg
#   AWG_INSTALL_TEST_KEYS    TEST ONLY: a directory holding wayhop.pub, wayhop.pub.fingerprint and
#                            wayhop-apk.pem.pub that replace the embedded production keys
#   AWG_INSTALL_TEST_VERIFY  TEST ONLY: a shell command run instead of the post-install verification
#                            (a container cannot load a kernel module)

AWG_FEED_DEFAULT="https://awadak3davra.github.io/wayhop-feed"

# Trust roots: the same values as packaging/feed/keys/wayhop.pub and wayhop-apk.pem.pub.
# scripts/check-awg-installer-keys.sh fails the build when they drift apart.
AWG_USIGN_PUBKEY="untrusted comment: WayHop package feed
RWRPIiBbFocxjpgLjnQqmDCLsl6UIxNQbLKar75vb/65X5BEh5lnqbxL"
AWG_USIGN_FINGERPRINT="4f22205b1687318e"
AWG_APK_PUBKEY="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE23fTWhefAmKj/2hBQI/toMNb0NK6
Fbrq7qv87e9Ge+RLd5mUVSBiP7N/dbifJm66REO1f41eTUEBb6eyn55Bsw==
-----END PUBLIC KEY-----"

# Policy, all in KiB: docs/AWG_FULL_INSTALL.md (development repository), "Small-RAM / small-flash
# policy".
MIN_MEM_USERSPACE_KIB=49152   # userspace is refused below 48 MiB MemTotal
LOWMEM_BELOW_KIB=262144       # the lowmem profile is reported below 256 MiB MemTotal
RAW_USERSPACE_KIB=4096        # raw amneziawg-go needs 4 MiB free on the install filesystem
TMPFS_USERSPACE_KIB=4096      # the compressed store unpacks into /tmp
GZ_HEADROOM_KIB=256           # flash headroom next to the compressed binary
KMOD_HEADROOM_KIB=256         # kmod dependencies from the official feeds + filesystem slack
KMOD_FALLBACK_KIB=300         # kmod path size when the index carries no sizes
DOWNLOAD_HEADROOM_KIB=256     # /tmp headroom next to the downloaded packages

# Every package this script can install, in a safe removal order.
AWG_PKGS_ALL="luci-i18n-amneziawg-ru luci-proto-amneziawg amneziawg-tools kmod-amneziawg amneziawg-go"

TAB="$(printf '\t')"
R="${AWG_INSTALL_ROOT:-}"
R="${R%/}"

MODE=auto; FEED=""; DRY=0; YES=0; JSON=0; UNINSTALL=0; KEEP_FEED=0; RESTART_NET=0
SEL_PATH=""; PLAN_PKGS=""; ADVICE=""; GEN="none"; NETIFD_NEEDED=false; NET_RESTARTED=false
FLASH_FREE=0; MEM_TOTAL=0; PROFILE=normal
TMPD=""; LOCK=""; APPLYING=0; LOG=/dev/null

for _a in "$@"; do [ "$_a" = --json ] && JSON=1; done

# --- output ------------------------------------------------------------------------------------
msg() {
  if [ "$JSON" = 1 ]; then printf 'install-awg: %s\n' "$*" >&2; else printf 'install-awg: %s\n' "$*"; fi
}
warn() { msg "WARNING: $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

json_str() {
  printf '%s' "$1" | tr '\n\r\t' '   ' | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

json_line() { # result reason
  jl_pk=""
  for jl_p in $PLAN_PKGS; do jl_pk="$jl_pk${jl_pk:+,}\"$(json_str "$jl_p")\""; done
  printf '{"result":"%s","path":"%s","packages":[%s],"reason":"%s","generation":"%s","flash_free_kib":%s,"mem_total_kib":%s,"profile":"%s","advice":"%s","netifd_restart_needed":%s,"network_restarted":%s}\n' \
    "$1" "$SEL_PATH" "$jl_pk" "$(json_str "$2")" "$GEN" "${FLASH_FREE:-0}" "${MEM_TOTAL:-0}" "$PROFILE" "$ADVICE" \
    "$NETIFD_NEEDED" "$NET_RESTARTED"
}

cleanup() {
  [ -n "$TMPD" ] && rm -rf "$TMPD" 2>/dev/null
  [ -n "$LOCK" ] && rm -rf "$LOCK" 2>/dev/null
  TMPD=""; LOCK=""
}

finish() { # rc result reason
  case "$2" in
    installed)   msg "done: AmneziaWG $GEN installed ($SEL_PATH: $PLAN_PKGS)${3:+ -- $3}" ;;
    current)     msg "done: AmneziaWG $GEN is already installed and current ($SEL_PATH: $PLAN_PKGS)" ;;
    dry-run)
      if [ "$UNINSTALL" = 1 ]; then msg "dry run: would remove ${PLAN_PKGS:-nothing}; nothing was changed"
      else msg "dry run: would install ($SEL_PATH) $PLAN_PKGS; nothing was changed"; fi ;;
    removed)     msg "done: removed ${PLAN_PKGS:-nothing (no AmneziaWG package was installed)}${3:+ -- $3}"
                 msg "AmneziaWG now: $GEN" ;;
    refused)     msg "not installed: $3" ;;
    *)           msg "FAILED: $3" ;;
  esac
  [ "$JSON" = 1 ] && json_line "$2" "$3"
  cleanup
  exit "$1"
}

usage() {
  if [ -f "$0" ]; then sed -n '2,/^# Test hooks/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
  else echo "usage: install-awg.sh [--mode auto|kmod|userspace] [--feed URL] [--dry-run] [--yes] [--json] [--uninstall] [--keep-feed] [--restart-network]"; fi
}
usage_err() { msg "$1 (see --help)"; [ "$JSON" = 1 ] && json_line failed "usage: $1"; exit 3; }

# --- arguments ---------------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --mode)      [ $# -ge 2 ] || usage_err "--mode needs a value"; MODE="$2"; shift ;;
    --mode=*)    MODE="${1#*=}" ;;
    --feed)      [ $# -ge 2 ] || usage_err "--feed needs a value"; FEED="$2"; shift ;;
    --feed=*)    FEED="${1#*=}" ;;
    --dry-run)   DRY=1 ;;
    -y|--yes)    YES=1 ;;
    --json)      JSON=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --keep-feed) KEEP_FEED=1 ;;
    --restart-network) RESTART_NET=1 ;;
    -h|--help)   usage; exit 0 ;;
    *)           usage_err "unknown option: $1" ;;
  esac
  shift
done
case "$MODE" in auto|kmod|userspace) ;; *) usage_err "invalid --mode '$MODE' (want auto, kmod or userspace)" ;; esac
[ -n "$FEED" ] || FEED="$AWG_FEED_DEFAULT"
while :; do case "$FEED" in */) FEED="${FEED%/}" ;; *) break ;; esac; done
case "$FEED" in
  http://*|https://*|file:///*|/*) ;;
  *) usage_err "invalid --feed '$FEED' (want http(s)://, file:// or an absolute path)" ;;
esac
case "$FEED" in *[[:space:]]*) usage_err "--feed must not contain whitespace" ;; esac

if [ -z "$R" ] && [ "$DRY" != 1 ] && [ "$(id -u 2>/dev/null || echo 0)" != 0 ]; then
  usage_err "must run as root (or use --dry-run)"
fi

if [ -n "${AWG_INSTALL_TEST_KEYS:-}" ]; then
  _k="$AWG_INSTALL_TEST_KEYS"
  [ -s "$_k/wayhop.pub" ] && [ -s "$_k/wayhop.pub.fingerprint" ] && [ -s "$_k/wayhop-apk.pem.pub" ] ||
    usage_err "AWG_INSTALL_TEST_KEYS=$_k lacks wayhop.pub, wayhop.pub.fingerprint or wayhop-apk.pem.pub"
  AWG_USIGN_PUBKEY="$(cat "$_k/wayhop.pub")"
  AWG_USIGN_FINGERPRINT="$(tr -d ' \n\r' < "$_k/wayhop.pub.fingerprint")"
  AWG_APK_PUBKEY="$(cat "$_k/wayhop-apk.pem.pub")"
  warn "TEST KEYS from $_k replace the embedded WayHop feed keys (AWG_INSTALL_TEST_KEYS is for tests only)"
fi

trap cleanup EXIT
trap 'on_signal' INT TERM HUP

# --- files and package manager -----------------------------------------------------------------
rp() { printf '%s%s' "$R" "$1"; }   # a system path under the test root

release_val() { # KEY -> value from /etc/openwrt_release
  sed -n "s/^$1=[\"']\{0,1\}\([^\"']*\)[\"']\{0,1\}[[:space:]]*\$/\1/p" "$(rp /etc/openwrt_release)" 2>/dev/null | head -n1
}

pm() { "$PM_CMD" "$@"; }

pm_installed_ver() { # name -> installed version, empty when not installed
  case "$PMK" in
    apk)  pm list --manifest -I "$1" 2>/dev/null | awk -v n="$1" '$1 == n { print $2; exit }' ;;
    opkg) pm status "$1" 2>/dev/null |
            awk '/^Version:/ { v = $2 } /^Status:/ && / installed/ { i = 1 } END { if (i && v != "") print v }' ;;
  esac
}

pm_ver_ge() { # a b -> 0 when version a >= b
  case "$PMK" in
    apk)  pvg="$(pm version -t "$1" "$2" 2>/dev/null)"; [ "$pvg" = ">" ] || [ "$pvg" = "=" ] ;;
    opkg) pm compare-versions "$1" '>=' "$2" >/dev/null 2>&1 ;;
  esac
}

# The changing calls log into $LOG themselves. A redirection on a function CALL would redirect this
# shell's own output while the package manager runs, and a signal trap firing then would print the
# verdict into the log instead of stdout.
pm_update() { "$PM_CMD" update >> "$LOG" 2>&1; }
pm_install() { # pkgs...: install or upgrade
  case "$PMK" in
    apk)  "$PM_CMD" add -u "$@" >> "$LOG" 2>&1 ;;
    opkg) "$PM_CMD" install "$@" >> "$LOG" 2>&1 ;;
  esac
}
pm_remove() {
  case "$PMK" in
    apk)  "$PM_CMD" del "$@" >> "$LOG" 2>&1 ;;
    opkg) "$PM_CMD" remove "$@" >> "$LOG" 2>&1 ;;
  esac
}
pm_snapshot() { # file <- "name version" per installed package, redirected inside (see above)
  case "$PMK" in
    apk)  "$PM_CMD" list --manifest -I > "$1" 2>/dev/null ;;
    opkg) "$PM_CMD" list-installed 2>/dev/null | awk 'NF >= 3 { print $1, $3 }' > "$1" ;;
  esac
}

# --- facts -------------------------------------------------------------------------------------
PLATFORM=unsupported; KEENETIC=0; PMK=""; PM_CMD=""; PKGARCH=""; KERNEL_PKG_VER=""; KREL=""
OW_RELEASE=""; OW_TARGET=""; OW_SUBTARGET=""; OPKG_ETC=""; STATE=""; FS_PATH=/; TMP_FREE=0; MEM_AVAIL=0
HAS_LUCI=0; HAS_LUCI_RU=0

[ -e "$(rp /bin/ndmc)" ] && KEENETIC=1
if [ -f "$(rp /etc/openwrt_release)" ] && [ "$KEENETIC" = 0 ]; then
  PLATFORM=openwrt
  OW_RELEASE="$(release_val DISTRIB_RELEASE)"
  _t="$(release_val DISTRIB_TARGET)"
  OW_TARGET="${_t%%/*}"; OW_SUBTARGET="${_t#*/}"
  [ "$OW_SUBTARGET" = "$_t" ] && OW_SUBTARGET=""
  if [ -d "$(rp /etc/apk)" ]; then PMK=apk; PM_CMD="${AWG_INSTALL_PKG:-apk}"
  else PMK=opkg; PM_CMD="${AWG_INSTALL_PKG:-opkg}"; OPKG_ETC=/etc; fi
  STATE=/etc/wayhop-awg.state
  [ -d "$(rp /overlay)" ] && FS_PATH=/overlay
elif [ -e "$(rp /opt/bin/opkg)" ]; then
  PLATFORM=entware; PMK=opkg; PM_CMD="${AWG_INSTALL_PKG:-/opt/bin/opkg}"; OPKG_ETC=/opt/etc
  STATE=/opt/etc/wayhop-awg.state; FS_PATH=/opt
  PATH="/opt/bin:/opt/sbin:$PATH"; export PATH
fi

MEM_TOTAL="$(awk '/^MemTotal:/ { print $2; exit }' "$(rp /proc/meminfo)" 2>/dev/null)"
MEM_AVAIL="$(awk '/^MemAvailable:/ { print $2; exit }' "$(rp /proc/meminfo)" 2>/dev/null)"
case "$MEM_TOTAL" in ''|*[!0-9]*) MEM_TOTAL=0 ;; esac
case "$MEM_AVAIL" in ''|*[!0-9]*) MEM_AVAIL=0 ;; esac
[ "$MEM_TOTAL" -gt 0 ] && [ "$MEM_TOTAL" -lt "$LOWMEM_BELOW_KIB" ] && PROFILE=lowmem
KREL="$(awk '{ print $3; exit }' "$(rp /proc/version)" 2>/dev/null)"

df_free() { # path -> available KiB (POSIX df when the busybox build has it, plain df otherwise)
  dff="$( { df -Pk "$1" 2>/dev/null || df -k "$1" 2>/dev/null; } |
    awk 'NR > 1 && NF >= 4 { a = $(NF - 2) } END { if (a != "") print a }')"
  case "$dff" in ''|*[!0-9]*) echo 0 ;; *) echo "$dff" ;; esac
}
FLASH_FREE="$(df_free "$FS_PATH")"
TMP_FREE="$(df_free /tmp)"

if [ "$PLATFORM" = unsupported ]; then
  msg "no OpenWrt (/etc/openwrt_release) and no Entware (/opt/bin/opkg) found"
  finish 2 refused "unsupported platform: AmneziaWG is installed on OpenWrt or Entware (Keenetic) only"
fi
have "$PM_CMD" || finish 2 refused "package manager '$PM_CMD' not found"

if [ "$PMK" = apk ]; then
  PKGARCH="$(head -n1 "$(rp /etc/apk/arch)" 2>/dev/null | tr -d ' \r')"
else
  PKGARCH="$(pm print-architecture 2>/dev/null |
    awk '$1 == "arch" && $2 != "all" && $2 != "noarch" { print $2; exit }')"
  if [ -z "$PKGARCH" ] && [ "$PLATFORM" = entware ]; then
    PKGARCH="$(awk '$1 == "arch" && $2 != "all" && $2 != "noarch" { print $2; exit }' "$(rp /opt/etc/opkg.conf)" 2>/dev/null)"
    [ -n "$PKGARCH" ] || PKGARCH="$(awk '$1 == "src/gz" && $3 ~ /entware/ { n = split($3, a, "/"); print a[n]; exit }' "$(rp /opt/etc/opkg.conf)" 2>/dev/null)"
  fi
fi
[ -z "$PKGARCH" ] && [ "$PLATFORM" = openwrt ] && PKGARCH="$(release_val DISTRIB_ARCH)"
[ -n "$PKGARCH" ] || finish 2 refused "cannot tell the package architecture of this system"

if [ "$PLATFORM" = openwrt ]; then
  KERNEL_PKG_VER="$(pm_installed_ver kernel)"
  [ -n "$(pm_installed_ver luci-base)" ] && HAS_LUCI=1
  [ -n "$(pm_installed_ver luci-i18n-base-ru)" ] && HAS_LUCI_RU=1
fi

detect_generation() { # -> 3.1 | <major.minor> of a newer generation | older | none
  dg=none
  for dg_p in kmod-amneziawg amneziawg-go amneziawg-tools; do
    dg_v="$(pm_installed_ver "$dg_p")"
    [ -n "$dg_v" ] || continue
    # kmod versions are <kernel x.y.z>.<module version>: drop the kernel part first.
    [ "$dg_p" = kmod-amneziawg ] && dg_v="$(printf '%s' "$dg_v" | cut -d. -f4-)"
    dg_mm="$(printf '%s' "$dg_v" | awk -F'[.~-]' '{ print $1 "." $2 }')"
    case "$dg_mm" in
      3.1) echo 3.1; return ;;
      [3-9].[0-9]*|[1-9][0-9].[0-9]*) echo "$dg_mm"; return ;;
    esac
    dg=older
  done
  [ "$dg" = none ] && [ -d "$(rp /sys/module/amneziawg)" ] && dg=older
  echo "$dg"
}
GEN="$(detect_generation)"

if [ "$PLATFORM" = openwrt ]; then
  msg "OpenWrt ${OW_RELEASE:-?} ${OW_TARGET:-?}/${OW_SUBTARGET:-?} ($PMK, $PKGARCH), kernel ${KERNEL_PKG_VER:-${KREL:-unknown}}"
else
  msg "Entware ($PKGARCH)$( [ "$KEENETIC" = 1 ] && printf ' on KeeneticOS: kernel modules are not built for Keenetic kernels, userspace only')"
fi
msg "RAM $((MEM_TOTAL / 1024)) MiB total, $((MEM_AVAIL / 1024)) MiB available (profile $PROFILE); free: $FLASH_FREE KiB on $FS_PATH, $TMP_FREE KiB on /tmp; AmneziaWG now: $GEN"

# --- lock + temp -------------------------------------------------------------------------------
take_lock() {
  LOCK="${TMPDIR:-/tmp}/install-awg.lock"
  if ! mkdir "$LOCK" 2>/dev/null; then
    tl_pid="$(cat "$LOCK/pid" 2>/dev/null)"
    if [ -n "$tl_pid" ] && kill -0 "$tl_pid" 2>/dev/null; then
      LOCK=""; finish 1 failed "another install-awg.sh (pid $tl_pid) is running"
    fi
    rm -rf "$LOCK"
    mkdir "$LOCK" 2>/dev/null || { LOCK=""; finish 1 failed "cannot take the lock ${TMPDIR:-/tmp}/install-awg.lock"; }
  fi
  echo $$ > "$LOCK/pid"
}
TMPD="$(mktemp -d "${TMPDIR:-/tmp}/install-awg.XXXXXX" 2>/dev/null)" || TMPD=""
[ -n "$TMPD" ] && [ -d "$TMPD" ] || finish 1 failed "cannot create a temp directory in ${TMPDIR:-/tmp}"
LOG="$TMPD/pm.log"; : > "$LOG"
JOURNAL="$TMPD/journal"; : > "$JOURNAL"

log_tail() { [ -s "$LOG" ] && tail -n 8 "$LOG" | while IFS= read -r lt_l; do msg "  | $lt_l"; done; }

# --- feed configuration ------------------------------------------------------------------------
fetch() { # url dest
  rm -f "$2"
  case "$1" in
    file://*) cp "${1#file://}" "$2" 2>/dev/null ;;
    /*)       cp "$1" "$2" 2>/dev/null ;;
    *)
      if have curl; then curl -fsSL --connect-timeout 20 --max-time 300 -o "$2" "$1" 2>/dev/null
      elif have wget; then wget -q -T 20 -O "$2" "$1" 2>/dev/null
      elif have uclient-fetch; then uclient-fetch -q -T 20 -O "$2" "$1" 2>/dev/null
      else return 9; fi ;;
  esac || { rm -f "$2"; return 1; }
  [ -s "$2" ] || { rm -f "$2"; return 1; }
}

opkg_conf_files() {
  for ocf in "$(rp "$OPKG_ETC/opkg.conf")" "$(rp "$OPKG_ETC")"/opkg/*.conf; do [ -f "$ocf" ] && printf '%s\n' "$ocf"; done
}

opkg_feed_present() { # dir url -> 0 when any src line points at it
  ofp_u="$1"
  opkg_conf_files | while IFS= read -r ofp_f; do
    U="$ofp_u" awk '($1 == "src/gz" || $1 == "src") { x = $3; sub(/\/+$/, "", x); if (x == ENVIRON["U"]) f = 1 } END { exit !f }' "$ofp_f" && { echo yes; break; }
  done | grep -q yes
}

opkg_free_name() { # base -> a source name no other line uses
  ofn_n="$1"; ofn_i=1
  while opkg_conf_files | while IFS= read -r ofn_f; do
      N="$ofn_n" awk '($1 == "src/gz" || $1 == "src") && $2 == ENVIRON["N"] { f = 1 } END { exit !f }' "$ofn_f" && { echo yes; break; }
    done | grep -q yes; do
    ofn_i=$((ofn_i + 1)); ofn_n="${1}_$ofn_i"
  done
  printf '%s' "$ofn_n"
}

apk_repo_present() { # url -> 0 when a repositories line names it
  for arp_f in "$(rp /etc/apk/repositories)" "$(rp /etc/apk/repositories.d)"/*.list; do
    [ -f "$arp_f" ] || continue
    U="$1" awk '{ sub(/#.*/, "") } NF { x = $NF; sub(/\/+$/, "", x); if (x == ENVIRON["U"]) f = 1 } END { exit !f }' "$arp_f" && return 0
  done
  return 1
}

# atomic_write PATH < content: a temp file beside PATH (keeping PATH's mode), then mv over it, so an
# interrupted run leaves the old file or the new one, never half of either.
atomic_write() {
  aw_t="$1.awgtmp.$$"
  if [ -f "$1" ]; then cp -p "$1" "$aw_t" 2>/dev/null || :; fi
  if cat > "$aw_t" && mv -f "$aw_t" "$1"; then return 0; fi
  rm -f "$aw_t"
  return 1
}

# Every feed line, key, file and directory this script creates is recorded twice BEFORE it is
# created: in this run's journal (for a rollback) and in the state file (for --uninstall, and for a
# re-run after a run that was killed outright). Recording first means a kill between the two steps
# leaves an entry for something absent, which undoing skips, never something unrecorded.
journal() {
  printf '%s\n' "$*" >> "$JOURNAL"
  case "$1" in line"$TAB"*|newfile"$TAB"*|key"$TAB"*|dir"$TAB"*) state_add "$*" ;; esac
}
state_add() {
  sa_f="$(rp "$STATE")"
  { if [ -f "$sa_f" ]; then cat "$sa_f"; else echo "# install-awg.sh: feed lines and keys it added (read by --uninstall)"; fi
    printf '%s\n' "$1"; } | atomic_write "$sa_f"
}

add_line() { # file line -> appends, journals what it changed
  al_f="$(rp "$1")"
  if [ ! -e "$al_f" ]; then
    al_d="${al_f%/*}"
    if [ ! -d "$al_d" ]; then journal "dir$TAB${1%/*}"; mkdir -p "$al_d" || return 1; fi
    journal "newfile$TAB$1"
    journal "line$TAB$1$TAB$2"
    printf '%s\n' "$2" | atomic_write "$al_f"
    return
  fi
  journal "line$TAB$1$TAB$2"
  { cat "$al_f"
    if [ -s "$al_f" ] && [ -n "$(tail -c 1 "$al_f" 2>/dev/null)" ]; then printf '\n'; fi
    printf '%s\n' "$2"; } | atomic_write "$al_f"
}

remove_line() { # file line -> removes one exact occurrence
  rl_f="$(rp "$1")"
  [ -f "$rl_f" ] || return 0
  grep -qxF "$2" "$rl_f" || return 0
  L="$2" awk '!d && $0 == ENVIRON["L"] { d = 1; next } { print }' "$rl_f" | atomic_write "$rl_f"
}

clean_stale_temps() { # temp files a killed run may have left beside the files it writes
  for cst_d in /etc/apk/repositories.d /etc/apk/keys "$OPKG_ETC/opkg" "$OPKG_ETC/opkg/keys" "${STATE%/*}"; do
    [ -n "$cst_d" ] && [ -d "$(rp "$cst_d")" ] || continue
    for cst_f in "$(rp "$cst_d")"/*.awgtmp.*; do [ -f "$cst_f" ] && rm -f "$cst_f"; done
  done
}

# netifd reads its protocol handlers only when it starts, so a handler this run added, changed or
# removed is not live until netifd restarts. Snapshot it before a change, compare after.
NETIFD_PROTO=/lib/netifd/proto/amneziawg.sh
netifd_snapshot() {
  rm -f "$TMPD/proto.before"
  [ -f "$(rp "$NETIFD_PROTO")" ] && cp "$(rp "$NETIFD_PROTO")" "$TMPD/proto.before"
  : > "$TMPD/proto.snap"
}
netifd_check() { # -> sets NETIFD_NEEDED true when the handler differs from the snapshot
  [ "$PLATFORM" = openwrt ] && [ -f "$TMPD/proto.snap" ] || return 0
  nc_now="$(rp "$NETIFD_PROTO")"
  if [ -f "$TMPD/proto.before" ] && [ -f "$nc_now" ]; then
    [ "$(cat "$TMPD/proto.before")" = "$(cat "$nc_now")" ] || NETIFD_NEEDED=true
  elif [ -f "$TMPD/proto.before" ] || [ -f "$nc_now" ]; then
    NETIFD_NEEDED=true
  fi
}
netifd_apply() { # restart netifd when needed and --restart-network was given; otherwise say so
  [ "$NETIFD_NEEDED" = true ] || return 0
  if [ "$RESTART_NET" = 1 ]; then
    msg "restarting the network so netifd loads the changed amneziawg protocol handler"
    if "$(rp /etc/init.d/network)" restart >> "$LOG" 2>&1; then
      NET_RESTARTED=true; NETIFD_NEEDED=false
    else
      warn "/etc/init.d/network restart failed; restart the network or reboot before using amneziawg interfaces"
    fi
  else
    msg "note: netifd loads protocol handlers only at start: run /etc/init.d/network restart (drops connections briefly) or reboot before configuring amneziawg interfaces, or re-run with --restart-network"
  fi
}

file_is_empty_conf() { # file -> 0 when only blank lines or comments remain
  ! grep -q '^[[:space:]]*[^#[:space:]]' "$(rp "$1")" 2>/dev/null
}

drop_opkg_list() { # "src/gz NAME URL" line -> remove the downloaded list of that source
  case "$1" in src/gz\ *|src\ *) ;; *) return 0 ;; esac
  dol_n="$(printf '%s' "$1" | awk '{ print $2 }')"
  dol_d="$(awk '$1 == "lists_dir" { print $3; exit }' "$(rp "$OPKG_ETC/opkg.conf")" 2>/dev/null)"
  [ -n "$dol_d" ] || dol_d=/var/opkg-lists
  [ -n "$dol_n" ] && rm -f "$(rp "$dol_d/$dol_n")" "$(rp "$dol_d/$dol_n.sig")" 2>/dev/null
  return 0
}

# Undo journal entries (newest first). $1 = 1 to keep feed lines and keys (--keep-feed).
undo_entries() { # file keepfeed
  awk '{ a[NR] = $0 } END { for (i = NR; i > 0; i--) print a[i] }' "$1" > "$TMPD/undo"
  while IFS="$TAB" read -r ue_t ue_f ue_l; do
    case "$ue_t" in
      line)    [ "$2" = 1 ] && continue; remove_line "$ue_f" "$ue_l"; drop_opkg_list "$ue_l" ;;
      newfile) [ "$2" = 1 ] && continue; file_is_empty_conf "$ue_f" && rm -f "$(rp "$ue_f")" ;;
      key)     [ "$2" = 1 ] && continue; rm -f "$(rp "$ue_f")" ;;
      dir)     [ "$2" = 1 ] && continue; rmdir "$(rp "$ue_f")" 2>/dev/null ;;
    esac
  done < "$TMPD/undo"
}

feed_line_for() { # dir namebase -> sets FL_FILE / FL_LINE, returns 1 when already configured
  case "$PMK" in
    apk)
      apk_repo_present "$1/packages.adb" && return 1
      FL_FILE=/etc/apk/repositories.d/wayhop.list; FL_LINE="$1/packages.adb" ;;
    opkg)
      opkg_feed_present "$1" && return 1
      FL_FILE="$OPKG_ETC/opkg/customfeeds.conf"; FL_LINE="src/gz $(opkg_free_name "$2") $1" ;;
  esac
  return 0
}

ensure_feed() { # dir namebase
  if ! feed_line_for "$(pm_repo "$1")" "$2"; then msg "feed already configured: $1"; return 0; fi
  if [ "$DRY" = 1 ]; then msg "would add to $FL_FILE: $FL_LINE"; return 0; fi
  add_line "$FL_FILE" "$FL_LINE" || return 1
  msg "added to $FL_FILE: $FL_LINE"
}

key_plan() { # -> sets KEY_FILE / KEY_BODY; 1 = already trusted, 3 = this opkg checks no signatures
  case "$PMK" in
    apk)
      KEY_BODY="$AWG_APK_PUBKEY"; KEY_FILE=/etc/apk/keys/wayhop.pem
      for kp_f in "$(rp /etc/apk/keys)"/*; do
        [ -f "$kp_f" ] && [ "$(cat "$kp_f")" = "$KEY_BODY" ] && return 1
      done ;;
    opkg)
      KEY_BODY="$AWG_USIGN_PUBKEY"; KEY_FILE="$OPKG_ETC/opkg/keys/$AWG_USIGN_FINGERPRINT"
      # Entware's opkg checks no signatures unless told to; its key directory is then unused.
      if [ "$PLATFORM" = entware ] &&
         ! grep -q '^[[:space:]]*option[[:space:]][[:space:]]*check_signature' "$(rp /opt/etc/opkg.conf)" 2>/dev/null; then
        return 3
      fi
      [ -f "$(rp "$KEY_FILE")" ] && [ "$(cat "$(rp "$KEY_FILE")")" = "$KEY_BODY" ] && return 1 ;;
  esac
  return 0
}

ensure_key() {
  key_plan; ek_rc=$?
  [ "$ek_rc" = 1 ] && { msg "feed key already trusted"; return 0; }
  [ "$ek_rc" = 3 ] && { msg "this opkg checks no package signatures (no check_signature); no key to add"; return 0; }
  if [ -e "$(rp "$KEY_FILE")" ]; then
    msg "$KEY_FILE exists with different contents; not replacing a key this script did not write"
    return 2
  fi
  if [ "$DRY" = 1 ]; then msg "would add the WayHop feed key as $KEY_FILE"; return 0; fi
  ek_d="$(rp "${KEY_FILE%/*}")"
  if [ ! -d "$ek_d" ]; then journal "dir$TAB${KEY_FILE%/*}"; mkdir -p "$ek_d" || return 1; fi
  journal "key$TAB$KEY_FILE"
  printf '%s\n' "$KEY_BODY" | atomic_write "$(rp "$KEY_FILE")" || return 1
  chmod 0644 "$(rp "$KEY_FILE")" 2>/dev/null
  msg "added the WayHop feed key as $KEY_FILE"
}

# --- indexes -----------------------------------------------------------------------------------
# Normalised index table: "name version installed-size size kernel-dep" (bytes; "-" when absent).
parse_ipk_index() {
  awk '
    function flush() {
      if (n != "") printf "%s %s %s %s %s\n", n, (v == "" ? "-" : v), (is == "" ? 0 : is), (sz == "" ? 0 : sz), (kd == "" ? "-" : kd)
      n = ""; v = ""; is = ""; sz = ""; kd = ""
    }
    /^Package:/        { flush(); n = $2; next }
    /^Version:/        { v = $2; next }
    /^Installed-Size:/ { is = $2; next }
    /^Size:/           { sz = $2; next }
    /^Depends:/ {
      d = substr($0, 9); gsub(/[ \t]/, "", d)
      m = split(d, a, ",")
      for (i = 1; i <= m; i++) if (a[i] ~ /^kernel\(=/) { k = a[i]; sub(/^kernel\(=/, "", k); sub(/\)$/, "", k); kd = k }
      next
    }
    /^[ \t]*$/ { flush() }
    END { flush() }'
}

parse_apk_dump() { # `apk adbdump packages.adb` text
  awk '
    function flush() {
      if (n != "") printf "%s %s %s %s %s\n", n, (v == "" ? "-" : v), (is == "" ? 0 : is), (sz == "" ? 0 : sz), (kd == "" ? "-" : kd)
      n = ""; v = ""; is = ""; sz = ""; kd = ""; key = ""
    }
    /^  - name: /           { flush(); n = $3; next }
    /^    version: /        { v = $2; next }
    /^    installed-size: / { is = $2; next }
    /^    file-size: /      { sz = $2; next }
    /^    [a-z-]+:/         { key = $1; next }
    /^      - / { if (key == "depends:" && $2 ~ /^kernel=/) { kd = $2; sub(/^kernel=/, "", kd) } next }
    END { flush() }'
}

load_index() { # dir tablefile -> 0 when the index was fetched and parsed
  case "$PMK" in
    apk)
      fetch "$1/packages.adb" "$2.adb" || return 1
      pm adbdump "$2.adb" 2>/dev/null | parse_apk_dump > "$2" ;;
    opkg)
      fetch "$1/Packages.gz" "$2.gz" || return 1
      gzip -dc < "$2.gz" 2>/dev/null | parse_ipk_index > "$2" ;;
  esac
  [ -s "$2" ]
}

pm_repo() { # feed dir -> the form the package manager takes in its configuration
  case "$PMK:$1" in
    apk:file://*) printf '%s' "${1#file://}" ;;   # apk takes a plain local path
    opkg:/*)      printf 'file://%s' "$1" ;;      # opkg needs a URL
    *)            printf '%s' "$1" ;;
  esac
}

row() { # table name -> "name version isize size kdep" of the first matching row
  [ -n "$1" ] && [ -s "$1" ] || return 1
  awk -v n="$2" '$1 == n { print; f = 1; exit } END { exit !f }' "$1"
}
field() { printf '%s\n' "$1" | awk -v f="$2" '{ print $f }'; }
kib() { echo $((($1 + 1023) / 1024)); }

PT_DIR=""; PT_TBL=""; PA_DIR=""; PA_TBL=""
if [ "$PLATFORM" = openwrt ]; then
  PT_DIR="$FEED/awg/openwrt/$OW_RELEASE/$OW_TARGET/$OW_SUBTARGET"
  [ "$PMK" = apk ] && PA_DIR="$FEED/apk/$PKGARCH" || PA_DIR="$FEED/ipk/$PKGARCH"
else
  PA_DIR="$FEED/entware/$PKGARCH"
fi

# --- packages an install pulled in -------------------------------------------------------------
# While an install runs, the package list from before it is kept beside the state file; when the
# install ends, every package that appeared is recorded as a "pkg" entry, so --uninstall removes
# exactly those (opkg leaves a dependency behind on its own; apk removes it itself). A run killed
# before that step leaves the list behind, and the next run, install or uninstall, records it.
pending_before() { printf '%s.pkgs-before' "$(rp "$STATE")"; }
record_new_pkgs() { # before-snapshot -> a pkg entry per package installed since then
  pm_snapshot "$TMPD/now"
  awk 'NR == FNR { b[$1] = 1; next } !($1 in b) { print $1 }' "$1" "$TMPD/now" > "$TMPD/new"
  while read -r rn_p; do
    [ -n "$rn_p" ] || continue
    grep -qxF "pkg$TAB$rn_p" "$(rp "$STATE")" 2>/dev/null || state_add "pkg$TAB$rn_p"
  done < "$TMPD/new"
}
finish_pending() { # a run killed mid-install left its starting package list: record what it added
  [ -f "$(pending_before)" ] || return 0
  record_new_pkgs "$(pending_before)"
  rm -f "$(pending_before)"
}

# --- what runs on AmneziaWG ----------------------------------------------------------------------
# Removing amneziawg-tools takes netifd's handler away, after which netifd can no longer tear an
# amneziawg interface down, and a removed amneziawg-go keeps running from its deleted binary. So
# before the packages go: every proto-amneziawg interface is brought down (its configuration is not
# touched, WayHop's wr_* ones included), amneziawg links that remain are deleted, and amneziawg-go
# processes running the PACKAGED binary are stopped (WayHop stops its own copy before it calls
# --uninstall; a binary elsewhere is not ours to stop).
stop_runtime() {
  if [ "$PLATFORM" = openwrt ] && have uci; then
    for sr_i in $(uci -q show network 2>/dev/null |
        sed -n "s/^network\.\([^.=]*\)\.proto='\{0,1\}amneziawg'\{0,1\}\$/\1/p"); do
      if [ "$DRY" = 1 ]; then msg "would bring down interface $sr_i (its configuration is kept)"; continue; fi
      msg "bringing down interface $sr_i (its configuration is kept)"
      if have ifdown; then ifdown "$sr_i" >> "$LOG" 2>&1 || warn "ifdown $sr_i failed"; fi
    done
  fi
  for sr_d in "$(rp /sys/class/net)"/*; do
    grep -q '^DEVTYPE=amneziawg$' "$sr_d/uevent" 2>/dev/null || continue
    sr_n="${sr_d##*/}"
    if [ "$DRY" = 1 ]; then msg "would delete the amneziawg link $sr_n"; continue; fi
    msg "deleting the amneziawg link $sr_n"
    ip link del dev "$sr_n" >> "$LOG" 2>&1 || warn "could not delete $sr_n"
  done
  for sr_e in "$(rp /proc)"/[0-9]*/exe; do
    sr_t="$(readlink "$sr_e" 2>/dev/null)" || continue
    case "$sr_t" in /usr/bin/amneziawg-go|/usr/bin/amneziawg-go\ *|/opt/sbin/amneziawg-go|/opt/sbin/amneziawg-go\ *) ;; *) continue ;; esac
    sr_p="${sr_e%/exe}"; sr_p="${sr_p##*/}"
    if [ "$DRY" = 1 ]; then msg "would stop amneziawg-go (pid $sr_p)"; continue; fi
    msg "stopping amneziawg-go (pid $sr_p)"
    kill -TERM "$sr_p" 2>/dev/null
    sr_w=0
    while sr_alive "$sr_p" && [ "$sr_w" -lt 5 ]; do sleep 1; sr_w=$((sr_w + 1)); done
    if sr_alive "$sr_p"; then kill -KILL "$sr_p" 2>/dev/null; fi
  done
}
sr_alive() { # pid -> 0 while it runs (a zombie waiting for its parent has stopped)
  kill -0 "$1" 2>/dev/null && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
}

# --- uninstall ---------------------------------------------------------------------------------
do_uninstall() {
  SEL_PATH=""
  PLAN_PKGS=""
  for du_p in $AWG_PKGS_ALL; do [ -n "$(pm_installed_ver "$du_p")" ] && PLAN_PKGS="$PLAN_PKGS${PLAN_PKGS:+ }$du_p"; done
  du_state="$(rp "$STATE")"
  du_shared=0
  [ -n "$(pm_installed_ver wayhop)" ] && du_shared=1
  GEN_BEFORE="$GEN"
  if [ "$DRY" = 1 ]; then
    [ -n "$PLAN_PKGS" ] && stop_runtime
    [ -n "$PLAN_PKGS" ] && msg "would remove: $PLAN_PKGS"
    if [ "$PMK" = opkg ] && [ -f "$du_state" ]; then
      du_deps=""
      while IFS="$TAB" read -r du_t du_f _; do
        [ "$du_t" = pkg ] && [ -n "$(pm_installed_ver "$du_f")" ] && du_deps="$du_deps $du_f"
      done < "$du_state"
      [ -n "$du_deps" ] && msg "would remove the dependencies its installs pulled in, unless something else needs them:$du_deps"
    fi
    if [ -f "$du_state" ] && [ "$KEEP_FEED" != 1 ]; then
      while IFS="$TAB" read -r du_t du_f du_l; do
        case "$du_t" in line) msg "would remove from $du_f: $du_l" ;; key) msg "would remove $du_f" ;; esac
      done < "$du_state"
    fi
    if [ "$PLATFORM" = openwrt ] && [ -f "$(rp "$NETIFD_PROTO")" ] && [ -n "$(pm_installed_ver amneziawg-tools)" ]; then
      NETIFD_NEEDED=true
    fi
    finish 0 dry-run ""
  fi
  take_lock
  clean_stale_temps
  finish_pending
  netifd_snapshot
  du_note=""
  if [ -n "$PLAN_PKGS" ]; then
    stop_runtime
    msg "removing $PLAN_PKGS"
    # shellcheck disable=SC2086
    if ! pm_remove $PLAN_PKGS; then
      log_tail
      finish 1 failed "the package manager could not remove $PLAN_PKGS"
    fi
  fi
  # opkg: the dependencies this script's installs pulled in, one by one, retried while any goes
  # (a dependency of another goes after it); opkg itself refuses one that something still needs.
  if [ "$PMK" = opkg ] && [ -f "$du_state" ]; then
    du_deps=""
    while IFS="$TAB" read -r du_t du_f _; do
      [ "$du_t" = pkg ] || continue
      case " $AWG_PKGS_ALL " in *" $du_f "*) continue ;; esac
      [ -n "$(pm_installed_ver "$du_f")" ] && du_deps="$du_deps $du_f"
    done < "$du_state"
    du_gone=""; du_pass=0
    while [ -n "$du_deps" ] && [ "$du_pass" -lt 6 ]; do
      du_left=""
      for du_p in $du_deps; do
        if pm_remove "$du_p" && [ -z "$(pm_installed_ver "$du_p")" ]; then du_gone="$du_gone $du_p"
        else du_left="$du_left $du_p"; fi
      done
      [ "$du_left" = "$du_deps" ] && break
      du_deps="$du_left"; du_pass=$((du_pass + 1))
    done
    if [ -n "$du_gone" ]; then
      msg "removed the dependencies its installs pulled in:$du_gone"
      PLAN_PKGS="$PLAN_PKGS$du_gone"
    fi
    [ -n "$du_deps" ] && du_note="kept dependencies other packages still need:$du_deps"
  fi
  if [ -d "$(rp /sys/module/amneziawg)" ]; then
    if rmmod amneziawg >> "$LOG" 2>&1 && [ ! -d "$(rp /sys/module/amneziawg)" ]; then
      msg "unloaded the amneziawg module"
    else
      du_note="${du_note:+$du_note; }the amneziawg module is still in use and stays loaded until reboot"
    fi
  fi
  if [ -f "$du_state" ] && [ "$KEEP_FEED" != 1 ]; then
    : > "$TMPD/keep"; : > "$TMPD/drop"
    while IFS="$TAB" read -r du_t du_f du_l; do
      case "$du_t" in ''|\#*) continue ;; esac
      du_keep=0
      # A recorded dependency that is still installed stays recorded, for a later --uninstall.
      if [ "$du_t" = pkg ]; then
        [ "$PMK" = opkg ] && [ -n "$(pm_installed_ver "$du_f")" ] && printf 'pkg\t%s\n' "$du_f" >> "$TMPD/keep"
        continue
      fi
      if [ "$du_shared" = 1 ]; then
        case "$du_t:$du_l" in
          key:*) du_keep=1 ;;
          line:*/awg/openwrt/*) ;;
          line:*) du_keep=1 ;;
        esac
      fi
      if [ "$du_keep" = 1 ]; then printf '%s\t%s\t%s\n' "$du_t" "$du_f" "$du_l" >> "$TMPD/keep"
      else printf '%s\t%s\t%s\n' "$du_t" "$du_f" "$du_l" >> "$TMPD/drop"; fi
    done < "$du_state"
    undo_entries "$TMPD/drop" 0
    if [ -s "$TMPD/keep" ]; then
      { echo "# install-awg.sh: feed lines and keys it added (read by --uninstall)"; cat "$TMPD/keep"; } | atomic_write "$du_state"
      grep -q '^line' "$TMPD/keep" &&
        du_note="${du_note:+$du_note; }kept WayHop's own feed line and key: the wayhop package is installed from them"
    else
      rm -f "$du_state"
    fi
  elif [ -f "$du_state" ]; then
    du_note="${du_note:+$du_note; }kept the feed lines and keys (--keep-feed)"
  fi
  netifd_check
  netifd_apply
  # The generation after the run: none once the packages are gone, unless the module is still
  # loaded, which is then still the generation that was installed.
  GEN="$(detect_generation)"
  if [ -d "$(rp /sys/module/amneziawg)" ] && [ "$GEN_BEFORE" != none ]; then GEN="$GEN_BEFORE"; fi
  finish 0 removed "$du_note"
}
[ "$UNINSTALL" = 1 ] && do_uninstall

# --- decide ------------------------------------------------------------------------------------
KMOD_WHY=""
if [ "$PLATFORM" = openwrt ]; then
  if [ "$MODE" = userspace ]; then
    KMOD_WHY="userspace was requested"
  elif [ -z "$OW_RELEASE" ] || [ -z "$OW_TARGET" ] || [ -z "$OW_SUBTARGET" ]; then
    KMOD_WHY="/etc/openwrt_release names no release/target/subtarget"
  elif ! load_index "$PT_DIR" "$TMPD/pt.tbl"; then
    KMOD_WHY="the feed has no kernel-module build for OpenWrt $OW_RELEASE $OW_TARGET/$OW_SUBTARGET"
  else
    PT_TBL="$TMPD/pt.tbl"
    if [ -z "$KERNEL_PKG_VER" ]; then
      KMOD_WHY="the installed kernel package version is unknown"
    elif ! row "$PT_TBL" kmod-amneziawg >/dev/null; then
      KMOD_WHY="the feed's $OW_RELEASE $OW_TARGET/$OW_SUBTARGET index has no kmod-amneziawg"
    elif ! awk -v k="$KERNEL_PKG_VER" '$1 == "kmod-amneziawg" && $5 == k { f = 1 } END { exit !f }' "$PT_TBL"; then
      KMOD_WHY="kmod-amneziawg in the feed is built for kernel $(field "$(row "$PT_TBL" kmod-amneziawg)" 5), this router runs $KERNEL_PKG_VER"
    fi
  fi
  # A per-target index can still serve amneziawg-tools to the userspace path.
  if [ -z "$PT_TBL" ] && [ "$MODE" = userspace ] && [ -n "$OW_SUBTARGET" ] && load_index "$PT_DIR" "$TMPD/pt.tbl"; then
    PT_TBL="$TMPD/pt.tbl"
  fi
else
  KMOD_WHY="kernel modules are built for OpenWrt only (no Keenetic/Entware kernel SDK)"
fi

[ -z "$KMOD_WHY" ] && SEL_PATH=kmod || SEL_PATH=userspace
if [ "$MODE" = kmod ] && [ "$SEL_PATH" != kmod ]; then
  SEL_PATH=kmod
  finish 2 refused "no kernel module for this router: $KMOD_WHY"
fi
[ "$SEL_PATH" = userspace ] && [ "$MODE" = auto ] && msg "kernel module not used: $KMOD_WHY"

# plan_add name table -> appends to the plan, or returns 1 when the table lacks the package
PLAN_ROWS="$TMPD/plan"; : > "$PLAN_ROWS"
plan_add() {
  if [ "$1" = kmod-amneziawg ]; then   # the build for this kernel, when the index carries several
    pa_r="$(awk -v k="$KERNEL_PKG_VER" '$1 == "kmod-amneziawg" && $5 == k { print; f = 1; exit } END { exit !f }' "$2")" || return 1
  else
    pa_r="$(row "$2" "$1")" || return 1
  fi
  PLAN_PKGS="$PLAN_PKGS${PLAN_PKGS:+ }$1"
  printf '%s %s\n' "$pa_r" "$2" >> "$PLAN_ROWS"
}

if [ "$SEL_PATH" = kmod ]; then
  plan_add kmod-amneziawg "$PT_TBL"
  plan_add amneziawg-tools "$PT_TBL" || finish 2 refused "the feed's $OW_RELEASE $OW_TARGET/$OW_SUBTARGET index has kmod-amneziawg but no amneziawg-tools"
else
  if [ "$MEM_TOTAL" -gt 0 ] && [ "$MEM_TOTAL" -lt "$MIN_MEM_USERSPACE_KIB" ]; then
    finish 2 refused "userspace amneziawg-go needs at least 48 MiB of RAM, this system has $((MEM_TOTAL / 1024)) MiB${KMOD_WHY:+ (and no kernel module: $KMOD_WHY)}"
  fi
  if load_index "$PA_DIR" "$TMPD/pa.tbl"; then PA_TBL="$TMPD/pa.tbl"; fi
  if ! plan_add amneziawg-go "$PA_TBL"; then
    if [ -n "$PA_TBL" ]; then finish 2 refused "the feed's ${PA_DIR#"$FEED"/} index has no amneziawg-go"; fi
    if fetch "$FEED/wayhop.pub" "$TMPD/probe"; then
      finish 2 refused "the feed has no packages for $PKGARCH (${PA_DIR#"$FEED"/})"
    fi
    finish 1 failed "the feed $FEED is unreachable"
  fi
  plan_add amneziawg-tools "$PA_TBL" || plan_add amneziawg-tools "$PT_TBL" ||
    msg "no amneziawg-tools for this system in the feed; amneziawg-go alone is configured over its UAPI socket"
fi

# What is already there, and what this run would change.
NEW_KIB=0; DL_KIB=0; NOT_CURRENT=""
plan_sizes() {
  NEW_KIB=0; DL_KIB=0; NOT_CURRENT=""
  while read -r ps_n ps_v ps_is ps_sz _ _; do
    ps_iv="$(pm_installed_ver "$ps_n")"
    if [ -n "$ps_iv" ] && pm_ver_ge "$ps_iv" "$ps_v"; then continue; fi
    NOT_CURRENT="$NOT_CURRENT${NOT_CURRENT:+ }$ps_n"
    NEW_KIB=$((NEW_KIB + $(kib "$ps_is")))
    DL_KIB=$((DL_KIB + $(kib "$ps_sz")))
  done < "$PLAN_ROWS"
}

# LuCI page: kmod path only (netifd's amneziawg proto needs the module), and only when it fits.
if [ "$SEL_PATH" = kmod ] && [ "$HAS_LUCI" = 1 ]; then
  plan_sizes
  lu_r="$(row "$PT_TBL" luci-proto-amneziawg)" && {
    lu_need=$((NEW_KIB + KMOD_HEADROOM_KIB + $(kib "$(field "$lu_r" 3)") + 64))
    if [ "$FLASH_FREE" -ge "$lu_need" ]; then
      plan_add luci-proto-amneziawg "$PT_TBL"
      [ "$HAS_LUCI_RU" = 1 ] && plan_add luci-i18n-amneziawg-ru "$PT_TBL"
    else
      msg "LuCI is installed but $FLASH_FREE KiB free is too little for luci-proto-amneziawg too; skipping it"
    fi
  }
fi
plan_sizes

if [ -z "$NOT_CURRENT" ]; then
  # Current, possibly because a killed run got this far: record what that run installed.
  if [ "$DRY" != 1 ] && [ -f "$(pending_before)" ]; then take_lock; finish_pending; fi
  GEN="$(detect_generation)"
  finish 0 current ""
fi

# Space and RAM policy.
if [ "$SEL_PATH" = kmod ]; then
  km_need=$((NEW_KIB + KMOD_HEADROOM_KIB))
  [ "$NEW_KIB" -eq 0 ] && km_need=$((KMOD_FALLBACK_KIB + KMOD_HEADROOM_KIB))
  [ "$FLASH_FREE" -ge "$km_need" ] ||
    finish 2 refused "the kernel-module path needs about $km_need KiB free on $FS_PATH, $FLASH_FREE KiB is free"
else
  us_go="$(awk '$1 == "amneziawg-go" { print; exit }' "$PLAN_ROWS")"
  us_go_is="$(kib "$(field "$us_go" 3)")"; us_go_sz="$(kib "$(field "$us_go" 4)")"
  gz_need=$((us_go_sz + GZ_HEADROOM_KIB))
  case " $NOT_CURRENT " in
    *" amneziawg-go "*)
      us_need=$RAW_USERSPACE_KIB
      [ $((us_go_is + 512)) -gt "$us_need" ] && us_need=$((us_go_is + 512))
      us_need=$((us_need + NEW_KIB - us_go_is)) ;;
    *) us_need=$((NEW_KIB + KMOD_HEADROOM_KIB)) ;;   # amneziawg-go is current, only the tools
  esac
  if [ "$FLASH_FREE" -lt "$us_need" ]; then
    case " $NOT_CURRENT " in
      *" amneziawg-go "*) ;;
      *) finish 2 refused "$NOT_CURRENT needs about $us_need KiB free on $FS_PATH, $FLASH_FREE KiB is free" ;;
    esac
    if [ "$FLASH_FREE" -ge "$gz_need" ] && [ "$TMP_FREE" -ge "$TMPFS_USERSPACE_KIB" ]; then
      ADVICE=compressed-store
      finish 2 refused "amneziawg-go needs $us_need KiB free on $FS_PATH, $FLASH_FREE KiB is free: use WayHop's compressed store (about $gz_need KiB on flash, unpacked to /tmp at start)"
    fi
    finish 2 refused "amneziawg-go does not fit: $FLASH_FREE KiB free on $FS_PATH (raw needs $us_need KiB, compressed $gz_need KiB) and $TMP_FREE KiB on /tmp (needs $TMPFS_USERSPACE_KIB KiB)"
  fi
fi
if [ "$TMP_FREE" -gt 0 ] && [ "$TMP_FREE" -lt $((DL_KIB + DOWNLOAD_HEADROOM_KIB)) ]; then
  finish 2 refused "/tmp has $TMP_FREE KiB free, the download needs about $((DL_KIB + DOWNLOAD_HEADROOM_KIB)) KiB"
fi

NEED_PT=0; NEED_PA=0
while read -r _n _v _is _sz _kd _t; do
  [ "$_t" = "$PT_TBL" ] && NEED_PT=1
  [ "$_t" = "$PA_TBL" ] && NEED_PA=1
done < "$PLAN_ROWS"

msg "plan ($SEL_PATH, profile $PROFILE): install $NOT_CURRENT (about $NEW_KIB KiB on $FS_PATH)"
if [ "$DRY" = 1 ]; then
  ensure_key; [ $? -eq 2 ] && finish 2 refused "a different key already exists at $KEY_FILE"
  [ "$NEED_PA" = 1 ] && ensure_feed "$PA_DIR" wayhop
  [ "$NEED_PT" = 1 ] && ensure_feed "$PT_DIR" wayhop_awg
  # amneziawg-tools carries netifd's amneziawg protocol handler: installing or upgrading it changes
  # the handler (predicted, not compared, in a dry run).
  if [ "$PLATFORM" = openwrt ]; then
    case " $NOT_CURRENT " in *" amneziawg-tools "*) NETIFD_NEEDED=true ;; esac
  fi
  finish 0 dry-run ""
fi

if [ "$YES" != 1 ] && [ "$JSON" != 1 ] && [ -t 0 ]; then
  printf 'install-awg: install %s now? [y/N] ' "$NOT_CURRENT"
  read -r _ans
  case "$_ans" in [Yy]*) ;; *) finish 2 refused "cancelled by the operator" ;; esac
fi

# --- apply -------------------------------------------------------------------------------------
take_lock
clean_stale_temps

remove_new_packages() { # removes every package installed since $TMPD/before, AWG packages first
  rnp_list="$(awk 'NR == FNR { b[$1] = 1; next } !($1 in b) { print $1 }' "$TMPD/before" "$TMPD/after_now")"
  rnp_order=""
  for rnp_p in $AWG_PKGS_ALL; do
    printf '%s\n' "$rnp_list" | grep -qx "$rnp_p" && rnp_order="$rnp_order $rnp_p"
  done
  for rnp_p in $rnp_list; do
    case " $AWG_PKGS_ALL " in *" $rnp_p "*) ;; *) rnp_order="$rnp_order $rnp_p" ;; esac
  done
  # Dependencies may refuse to go before their dependents; retry until nothing changes.
  rnp_pass=0
  while [ -n "$rnp_order" ] && [ "$rnp_pass" -lt 4 ]; do
    rnp_left=""
    for rnp_p in $rnp_order; do
      [ -n "$(pm_installed_ver "$rnp_p")" ] || continue
      pm_remove "$rnp_p" || rnp_left="$rnp_left $rnp_p"
    done
    [ "$rnp_left" = "$rnp_order" ] && break
    rnp_order="$rnp_left"; rnp_pass=$((rnp_pass + 1))
  done
  RB_LEFT=""
  for rnp_p in $rnp_list; do [ -n "$(pm_installed_ver "$rnp_p")" ] && RB_LEFT="$RB_LEFT $rnp_p"; done
}

rollback() { # reason
  trap '' INT TERM HUP   # a rollback is not interrupted by a second signal
  APPLYING=0
  msg "rolling back: $1"
  pm_snapshot "$TMPD/after_now"
  remove_new_packages
  [ -n "$rnp_list" ] && msg "removed what this run installed: $(printf '%s' "$rnp_list" | tr '\n' ' ')"
  if grep -q "^mod$TAB" "$JOURNAL" 2>/dev/null; then
    rmmod amneziawg >> "$LOG" 2>&1 || warn "could not unload the amneziawg module this run loaded"
  fi
  undo_entries "$JOURNAL" "$KEEP_FEED"
  if grep -qE "^(line|key)$TAB" "$JOURNAL" 2>/dev/null; then
    if [ "$KEEP_FEED" = 1 ]; then msg "kept the feed lines and key this run added (--keep-feed)"
    else msg "reverted the feed lines and key this run added"; fi
  fi
  # The state file got this run's entries before each change; put it back as it was (with
  # --keep-feed the entries stay: the lines and keys they describe stay too).
  if [ "$KEEP_FEED" != 1 ]; then
    if [ -f "$TMPD/state.before" ]; then atomic_write "$(rp "$STATE")" < "$TMPD/state.before"
    else rm -f "$(rp "$STATE")"; fi
  fi
  # Whatever this run (or a killed one before it) installed and could not remove stays recorded.
  for rb_p in $RB_LEFT; do
    grep -qxF "pkg$TAB$rb_p" "$(rp "$STATE")" 2>/dev/null || state_add "pkg$TAB$rb_p"
  done
  rm -f "$(pending_before)"
  netifd_check
  rb_note=""
  [ -n "$RB_LEFT" ] && rb_note="; still installed after the rollback:$RB_LEFT"
  rb_up="$(awk 'NR == FNR { b[$1] = $2; next } ($1 in b) && b[$1] != $2 { printf " %s (%s -> %s)", $1, b[$1], $2 }' "$TMPD/before" "$TMPD/after_now")"
  [ -n "$rb_up" ] && rb_note="$rb_note; upgraded in place, the old build is not in the feed to go back to:$rb_up"
  GEN="$(detect_generation)"
  finish 1 failed "$1$rb_note"
}

# shellcheck disable=SC2329  # invoked by the INT/TERM/HUP trap
on_signal() {
  if [ "$APPLYING" = 1 ]; then rollback "interrupted"; fi
  finish 1 failed "interrupted"
}

verify() { # -> 0 when the installed path works; VERIFY_WHY says why not
  VERIFY_WHY=""
  if [ -n "${AWG_INSTALL_TEST_VERIFY:-}" ]; then
    warn "TEST ONLY: verification replaced by AWG_INSTALL_TEST_VERIFY"
    sh -c "$AWG_INSTALL_TEST_VERIFY" >> "$LOG" 2>&1 || { VERIFY_WHY="the test verification failed"; return 1; }
    return 0
  fi
  vf_out=""
  if [ "$SEL_PATH" = kmod ]; then
    if [ ! -d "$(rp /sys/module/amneziawg)" ]; then
      if have modprobe; then modprobe amneziawg >> "$LOG" 2>&1; else insmod amneziawg >> "$LOG" 2>&1; fi
      [ -d "$(rp /sys/module/amneziawg)" ] && journal "mod${TAB}amneziawg"
    elif [ -n "$(awk '$1 == "kmod-amneziawg" { print }' "$TMPD/before")" ]; then
      KMOD_NOTE="the previous amneziawg module stays loaded until its interfaces are restarted or the router reboots"
    fi
    [ -d "$(rp /sys/module/amneziawg)" ] || { VERIFY_WHY="the amneziawg kernel module did not load"; return 1; }
    vf_st="$(cat "$(rp /sys/module/amneziawg/initstate)" 2>/dev/null)"
    [ -z "$vf_st" ] || [ "$vf_st" = live ] || { VERIFY_WHY="the amneziawg module is $vf_st, not live"; return 1; }
  else
    vf_out="$(amneziawg-go --version 2>&1)" || { VERIFY_WHY="amneziawg-go --version failed: $(printf '%s' "$vf_out" | head -n1)"; return 1; }
  fi
  if printf ' %s ' "$PLAN_PKGS" | grep -q ' amneziawg-tools '; then
    vf_awg="$(awg --version 2>&1)" || { VERIFY_WHY="awg --version failed: $(printf '%s' "$vf_awg" | head -n1)"; return 1; }
    vf_out="$vf_out $vf_awg"
  fi
  # Generation 3.1: the binaries say so, or the packages that were just installed do.
  case " $vf_out " in *3.1.*|*v3.1*) return 0 ;; esac
  [ "$(detect_generation)" = 3.1 ] && return 0
  VERIFY_WHY="the installed AmneziaWG does not report generation 3.1"
  return 1
}

pm_snapshot "$TMPD/before"
[ -f "$(rp "$STATE")" ] && cp "$(rp "$STATE")" "$TMPD/state.before"
# The package list from before the install, kept until the install records what it added. One left
# by a killed run is the real starting point, so it wins.
if [ -f "$(pending_before)" ]; then cp "$(pending_before)" "$TMPD/before"
else atomic_write "$(pending_before)" < "$TMPD/before"; fi
netifd_snapshot
APPLYING=1
ensure_key; _rc=$?
[ "$_rc" = 2 ] && { APPLYING=0; finish 2 refused "a different key already exists at $KEY_FILE"; }
[ "$_rc" = 0 ] || rollback "could not write the feed key"
if [ "$NEED_PA" = 1 ]; then ensure_feed "$PA_DIR" wayhop || rollback "could not write the feed configuration"; fi
if [ "$NEED_PT" = 1 ]; then ensure_feed "$PT_DIR" wayhop_awg || rollback "could not write the feed configuration"; fi

msg "updating package lists"
if ! pm_update; then
  warn "the package-list update reported errors (another feed may be unreachable); continuing"
fi
msg "installing $PLAN_PKGS"
# shellcheck disable=SC2086
if ! pm_install $PLAN_PKGS; then
  log_tail
  rollback "the package manager could not install $PLAN_PKGS"
fi
KMOD_NOTE=""
if ! verify; then
  log_tail
  rollback "verification failed: $VERIFY_WHY"
fi
record_new_pkgs "$TMPD/before"
rm -f "$(pending_before)"
APPLYING=0
netifd_check
netifd_apply
GEN="$(detect_generation)"
[ "$GEN" = none ] && GEN=3.1
finish 0 installed "$KMOD_NOTE"
