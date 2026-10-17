#!/bin/sh
# test-userspace.sh - run the userspace AmneziaWG artifacts instead of reading them:
#
#   1. every amneziawg-go and awg in <distdir>/userspace answers --version on its own CPU, under
#      qemu-user (each qemu-<arch>-static called by name: nothing is registered with binfmt_misc);
#   2. the packages install and remove with the real package managers: the OpenWrt .ipk and both
#      Entware .ipk with opkg in OpenWrt 24.10 (the Entware architecture added for the run, as
#      Entware's own opkg lists it), the OpenWrt .apk with apk in OpenWrt 25.12. The installed
#      binaries are run, the files each package owns are listed, and nothing but the binary may
#      be left behind or carry a maintainer script.
#
# The x86_64 packages are the ones installed (the containers are x86_64); the other tokens carry
# the same payload under another Architecture, which pack-userspace.sh writes from one tree.
#
# --allow-untrusted is used for the local .apk files only because they are not in a signed index
# here; the feed signs its indexes (feed.yml), and nothing on a router may use this flag.
# kmod-tun, the OpenWrt packages' one dependency, comes from the official feeds the rootfs images
# carry, so this needs the network.
#
# Usage: scripts/awg/test-userspace.sh [distdir]     (default: dist/awg)
#   AWG_DOCKER_PREFIX=<p>   container name prefix (default: wayhop)
#   AWG_QEMU_IMAGE, AWG_OPKG_IMAGE, AWG_APK_TARGET_IMAGE   other images than the pinned defaults
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=packaging/awg/VERSIONS
. "$repo/packaging/awg/VERSIONS"
QEMU_IMAGE="${AWG_QEMU_IMAGE:-debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931}"
OPKG_IMAGE="${AWG_OPKG_IMAGE:-openwrt/rootfs:x86-64-24.10.4@sha256:1310ccbd24f30b3df6e210a48dbd0fb902445ee80e21ffc8b8e882b94987a411}"
APK_TARGET_IMAGE="${AWG_APK_TARGET_IMAGE:-openwrt/rootfs:x86-64-25.12.0@sha256:1a7f3e9c66e6b77d4014b7e37ffbee7edf114275dc6f1811314a572e11a8e636}"
GO_VER="${AWG_GO_TAG#v}-r${AWG_PKG_RELEASE}"
TOOLS_VER="${AWG_TOOLS_TAG#v}-r${AWG_PKG_RELEASE}"

DIST="$(cd "${1:-dist/awg}" && pwd)"
command -v docker >/dev/null 2>&1 || { echo "test-userspace: no docker - nothing was exercised" >&2; exit 3; }
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi; }
mnt="$(hostpath "$DIST"):/d:ro"
prefix="${AWG_DOCKER_PREFIX:-wayhop}-awg-test-$$"
export MSYS_NO_PATHCONV=1

# Each check script prints "PASS ..." / "FAIL ..." lines; wrap makes it fail when any check failed.
wrap() {
  printf '%s\n' 'fail=0' \
    'ok() { echo "  PASS  $1"; }' \
    'no() { echo "  FAIL  $1"; fail=$((fail + 1)); }' \
    "$1" \
    '[ "$fail" = 0 ]'
}
total=0
# report <name> <exit status> <output>
report() {
  echo "$3"
  [ "$2" = 0 ] || { echo "test-userspace: $1 failed" >&2; exit 1; }
  total=$((total + $(echo "$3" | grep -c '  PASS ')))
}

QEMU_CHECKS='
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends qemu-user-static >/dev/null 2>&1
  for pair in amd64:x86_64 arm64:aarch64 arm:arm mips:mips mipsle:mipsel; do
    tok=${pair%%:*} q=qemu-${pair#*:}-static
    v=$($q /d/userspace/$tok/amneziawg-go --version 2>&1) && [ "${v%% *}" = amneziawg-go ] \
      && ok "$tok amneziawg-go: $(echo "$v" | head -n1)" || no "$tok amneziawg-go --version: $v"
    v=$($q /d/userspace/$tok/awg --version 2>&1) && case "$v" in *"amneziawg-tools v${TOOLS_VER%-r*} "*) true ;; *) false ;; esac \
      && ok "$tok awg: $v" || no "$tok awg --version: $v"
  done'

OPKG_CHECKS='
  mkdir -p /var/lock /var/run
  opkg update >/dev/null 2>&1 || no "opkg update (the feeds kmod-tun comes from)"
  # OpenWrt package
  log=$(opkg install /d/ipk/x86_64/amneziawg-go_${GO_VER}_x86_64.ipk 2>&1) && ok "OpenWrt amneziawg-go installs" || no "install: $log"
  v=$(/usr/bin/amneziawg-go --version 2>&1) && ok "/usr/bin/amneziawg-go runs: $(echo "$v" | head -n1)" || no "/usr/bin/amneziawg-go: $v"
  opkg status amneziawg-go | grep -qx "Version: $GO_VER" && ok "status shows $GO_VER" || no "status: $(opkg status amneziawg-go)"
  opkg list-installed | grep -q "^kmod-tun " && ok "kmod-tun came in as the dependency" || no "kmod-tun was not installed"
  files=$(opkg files amneziawg-go | grep -v "^Package ")
  [ "$files" = /usr/bin/amneziawg-go ] && ok "the package owns /usr/bin/amneziawg-go only" || no "owns: $files"
  extra=$(ls /usr/lib/opkg/info/amneziawg-go.* | grep -v -e "\.control$" -e "\.list$" || true)
  [ -z "$extra" ] && ok "no maintainer scripts" || no "maintainer scripts: $extra"
  opkg remove amneziawg-go >/dev/null 2>&1 && [ ! -e /usr/bin/amneziawg-go ] && ok "remove takes the binary" || no "remove left /usr/bin/amneziawg-go"
  # Entware packages
  A="--add-arch x86-64-3.2:200"
  log=$(opkg $A install /d/entware/x86-64-3.2/amneziawg-go_${GO_VER}_x86-64-3.2.ipk /d/entware/x86-64-3.2/amneziawg-tools_${TOOLS_VER}_x86-64-3.2.ipk 2>&1) \
    && ok "Entware amneziawg-go and amneziawg-tools install" || no "install: $log"
  v=$(/opt/sbin/amneziawg-go --version 2>&1) && ok "/opt/sbin/amneziawg-go runs: $(echo "$v" | head -n1)" || no "/opt/sbin/amneziawg-go: $v"
  v=$(/opt/bin/awg --version 2>&1) && ok "/opt/bin/awg runs: $v" || no "/opt/bin/awg: $v"
  [ "$(opkg $A files amneziawg-go | grep -v "^Package ")" = /opt/sbin/amneziawg-go ] && ok "Entware amneziawg-go owns /opt/sbin/amneziawg-go only" || no "owns: $(opkg $A files amneziawg-go)"
  [ "$(opkg $A files amneziawg-tools | grep -v "^Package ")" = /opt/bin/awg ] && ok "amneziawg-tools owns /opt/bin/awg only" || no "owns: $(opkg $A files amneziawg-tools)"
  extra=$(ls /usr/lib/opkg/info/amneziawg-*.* | grep -v -e "\.control$" -e "\.list$" || true)
  [ -z "$extra" ] && ok "no maintainer scripts" || no "maintainer scripts: $extra"
  opkg $A remove amneziawg-tools amneziawg-go >/dev/null 2>&1 && [ ! -e /opt/sbin/amneziawg-go ] && [ ! -e /opt/bin/awg ] \
    && ok "remove takes both binaries" || no "remove left files in /opt"'

APK_CHECKS='
  apk update >/dev/null 2>&1 || no "apk update (the feeds kmod-tun comes from)"
  log=$(apk add --allow-untrusted /d/apk/x86_64/amneziawg-go-$GO_VER.apk 2>&1) && ok "OpenWrt amneziawg-go installs" || no "add: $log"
  v=$(/usr/bin/amneziawg-go --version 2>&1) && ok "/usr/bin/amneziawg-go runs: $(echo "$v" | head -n1)" || no "/usr/bin/amneziawg-go: $v"
  apk info -e kmod-tun >/dev/null && ok "kmod-tun came in as the dependency" || no "kmod-tun was not installed"
  [ "$(apk list -I amneziawg-go 2>/dev/null | cut -d" " -f1)" = "amneziawg-go-$GO_VER" ] && ok "installed as amneziawg-go-$GO_VER" || no "listed as: $(apk list -I amneziawg-go)"
  files=$(apk info -L amneziawg-go 2>/dev/null | grep -v -e "contains:" -e "^$")
  [ "$files" = usr/bin/amneziawg-go ] && ok "the package owns usr/bin/amneziawg-go only" || no "owns: $files"
  apk del amneziawg-go >/dev/null 2>&1 && [ ! -e /usr/bin/amneziawg-go ] && ok "del takes the binary" || no "del left /usr/bin/amneziawg-go"'

echo "--version of every binary under qemu-user ($QEMU_IMAGE)"
rc=0
out="$(docker run --rm --name "$prefix-qemu" -v "$mnt" -e GO_VER="$GO_VER" -e TOOLS_VER="$TOOLS_VER" \
  "$QEMU_IMAGE" sh -euc "$(wrap "$QEMU_CHECKS")")" || rc=$?
report qemu "$rc" "$out"

echo "opkg install/remove on $OPKG_IMAGE"
rc=0
out="$(docker run --rm --name "$prefix-opkg" -v "$mnt" -e GO_VER="$GO_VER" -e TOOLS_VER="$TOOLS_VER" \
  "$OPKG_IMAGE" sh -euc "$(wrap "$OPKG_CHECKS")")" || rc=$?
report opkg "$rc" "$out"

echo "apk add/del on $APK_TARGET_IMAGE"
rc=0
out="$(docker run --rm --name "$prefix-apk" -v "$mnt" -e GO_VER="$GO_VER" -e TOOLS_VER="$TOOLS_VER" \
  "$APK_TARGET_IMAGE" sh -euc "$(wrap "$APK_CHECKS")")" || rc=$?
report apk "$rc" "$out"

echo "userspace: $total checks passed (qemu --version, opkg, apk)"
