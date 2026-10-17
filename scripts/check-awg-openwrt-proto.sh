#!/bin/sh
# check-awg-openwrt-proto.sh -- the amneziawg netifd protocol handler (package amneziawg-tools,
# packaging/awg/openwrt/amneziawg-tools/files/amneziawg.sh) in the OpenWrt root filesystems of both
# package formats: 25.12 (apk) and 24.10 (opkg). The checks are scripts/awg/check-openwrt-proto.sh;
# this runs it in each image and counts what it proved.
#
# Stub mode, always: awg, ip, modprobe and amneziawg-go are stubs, and the check compares the exact
# configuration handed to `awg setconf`, the calls reported to netifd and the engine choice (kernel
# module, userspace fallback, neither). It runs with --network none.
#
# Real mode, when a directory with x86_64 `awg` and `amneziawg-go` is given (dist/awg/userspace/amd64
# after the userspace build): a real userspace interface in each image (NET_ADMIN, /dev/net/tun),
# every AmneziaWG 3.1 key read back with `awg showconf`, renew and teardown. The handler needs the
# real ip(8), which neither image ships (24.10 has busybox ip only), so real mode installs ip-tiny
# from the release's official feed and needs the network.
#
# Needs Docker. Without it this exits 3 and says so: a handler nobody ran must not report as passing.
#
# Usage: sh scripts/check-awg-openwrt-proto.sh [bindir]     (from the repository root)
set -u

BINDIR="${1:-}"
# docker -v reads a relative path as a volume NAME, not a directory: make it absolute.
if [ -n "$BINDIR" ]; then
  BINDIR="$(cd "$BINDIR" 2>/dev/null && pwd)" || { echo "no such directory: $1" >&2; exit 2; }
fi
APK_IMAGE="${AWG_PROTO_APK_IMAGE:-openwrt/rootfs:x86-64-25.12.0@sha256:1a7f3e9c66e6b77d4014b7e37ffbee7edf114275dc6f1811314a572e11a8e636}"
OPKG_IMAGE="${AWG_PROTO_OPKG_IMAGE:-openwrt/rootfs:x86-64-24.10.4@sha256:1310ccbd24f30b3df6e210a48dbd0fb902445ee80e21ffc8b8e882b94987a411}"
PREFIX="${AWG_PROTO_PREFIX:-wayhop-awg-proto}"

command -v docker >/dev/null 2>&1 || { echo "no docker: the amneziawg protocol handler was NOT exercised" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "docker is not running: the amneziawg protocol handler was NOT exercised" >&2; exit 3; }
[ -f scripts/awg/check-openwrt-proto.sh ] || { echo "run from the repository root" >&2; exit 2; }
if [ -n "$BINDIR" ]; then
  for b in awg amneziawg-go; do
    [ -s "$BINDIR/$b" ] || { echo "$BINDIR/$b is missing: real mode needs x86_64 awg and amneziawg-go" >&2; exit 2; }
  done
fi

# Git Bash rewrites unix-looking container paths; hand Docker paths it can resolve.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }
dk() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker "$@"; }
SRC="$(hostpath "$PWD")"

# Real mode first replaces busybox ip with ip-tiny; opkg needs its lock directory in these images.
GET_IP='if command -v apk >/dev/null 2>&1; then apk update >/dev/null && apk add ip-tiny >/dev/null
else mkdir -p /var/lock && opkg update >/dev/null && opkg install ip-tiny >/dev/null; fi || exit 9
ip -V 2>&1 | grep -q iproute2 || { echo "FAIL: ip-tiny did not provide ip(8)"; exit 9; }'

total_ok=0; total_fail=0; bad_runs=""; ran=""
run_case() { # label image mode
  name="$PREFIX-$1-$$"
  if [ "$3" = stub ]; then
    out="$(dk run --rm --network none --name "$name" -v "$SRC:/src:ro" "$2" \
      sh /src/scripts/awg/check-openwrt-proto.sh 2>&1)"; rc=$?
  else
    out="$(dk run --rm --name "$name" --cap-add NET_ADMIN --device /dev/net/tun \
      -v "$SRC:/src:ro" -v "$(hostpath "$BINDIR"):/bin2:ro" "$2" \
      sh -c "$GET_IP
sh /src/scripts/awg/check-openwrt-proto.sh /bin2/awg /bin2/amneziawg-go" 2>&1)"; rc=$?
  fi
  printf '%s\n' "$out" | sed "s/^/  [$1] /"
  ok="$(printf '%s\n' "$out" | grep -c '^ok: ' || :)"
  bad="$(printf '%s\n' "$out" | grep -c '^FAIL' || :)"
  total_ok=$((total_ok + ok)); total_fail=$((total_fail + bad))
  ran="$ran $1"
  # A run counts only when the check finished and said so: exit 0 alone could be a script that
  # stopped before its first check.
  if [ "$rc" != 0 ] || ! printf '%s\n' "$out" | grep -qx 'check-openwrt-proto: all passed'; then
    bad_runs="$bad_runs $1(exit $rc)"
  fi
}

run_case stub-apk "$APK_IMAGE" stub
run_case stub-opkg "$OPKG_IMAGE" stub
if [ -n "$BINDIR" ]; then
  run_case real-apk "$APK_IMAGE" real
  run_case real-opkg "$OPKG_IMAGE" real
else
  echo "  real mode NOT run: no directory with x86_64 awg and amneziawg-go was given"
fi

echo "openwrt proto: $total_ok checks passed, $total_fail failed, in runs:$ran (apk: ${APK_IMAGE%%@*}, opkg: ${OPKG_IMAGE%%@*})"
if [ -n "$bad_runs" ]; then
  echo "FAIL  runs that did not complete:$bad_runs" >&2
  exit 1
fi
[ "$total_fail" = 0 ]
