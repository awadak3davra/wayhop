#!/bin/sh
# qemu-docker.sh - run scripts/awg/qemu-e2e.sh inside a digest-pinned Alpine container.
#
# The e2e needs root, a TUN device for the peer, QEMU and python3. Inside a throwaway container all
# of that is the container's: the peer's interface, routes and sockets live in the container's own
# network namespace, so neither a CI runner nor a developer machine is reconfigured. /dev/kvm is
# passed through when the host has it (GitHub's Linux runners do), otherwise QEMU uses TCG.
#
# Usage: qemu-docker.sh <feedroot> <release> <target/subtarget>
# Env:   AWG_E2E_KEYS, AWG_E2E_PEER_DIR  host paths, as for qemu-e2e.sh (required / default as there)
#        AWG_E2E_CACHE   host dir for downloaded images and the container's apk cache
#                        (default ${XDG_CACHE_HOME:-~/.cache}/wayhop-awg-e2e)
#        AWG_E2E_OUT     host dir for logs + summary (default ./awg-e2e-out/<release>-<target>)
#        AWG_E2E_CONTAINER_PREFIX  container name prefix (default awg-e2e)
#        AWG_E2E_CASES, AWG_E2E_MEM, AWG_E2E_EXPECT_TOOLS, AWG_E2E_CONSOLE_ECHO and
#        AWG_E2E_BOOT_TIMEOUT are passed through.
#        QEMU_HOST_IMAGE overrides the pinned image.
# Exit:  qemu-e2e.sh's status; 3 when docker is unavailable (nothing was tested).
set -eu

QEMU_HOST_IMAGE="${QEMU_HOST_IMAGE:-alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6}"

[ "$#" -eq 3 ] || { echo "usage: qemu-docker.sh <feedroot> <release> <target/subtarget>" >&2; exit 2; }
FEED="$1"; REL="$2"; TGT="$3"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }
abspath() { mkdir -p "$1" && (cd "$1" && pwd); }

command -v docker >/dev/null 2>&1 || { echo "qemu-docker: no docker - the e2e was NOT run" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "qemu-docker: docker is not running - the e2e was NOT run" >&2; exit 3; }
[ -d "$FEED" ] || { echo "qemu-docker: $FEED is not a directory" >&2; exit 2; }
[ -n "${AWG_E2E_KEYS:-}" ] && [ -d "$AWG_E2E_KEYS" ] || { echo "qemu-docker: AWG_E2E_KEYS must name the test key directory" >&2; exit 2; }
peer="${AWG_E2E_PEER_DIR:-$repo/dist/awg/userspace/amd64}"
[ -d "$peer" ] || { echo "qemu-docker: peer directory $peer is missing" >&2; exit 2; }

feed_abs="$(cd "$FEED" && pwd)"
keys_abs="$(cd "$AWG_E2E_KEYS" && pwd)"
peer_abs="$(cd "$peer" && pwd)"
cache_abs="$(abspath "${AWG_E2E_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/wayhop-awg-e2e}")"
out_abs="$(abspath "${AWG_E2E_OUT:-awg-e2e-out/$REL-$(printf '%s' "$TGT" | tr '/' '-')}")"
mkdir -p "$cache_abs/apk" "$cache_abs/images"

name="${AWG_E2E_CONTAINER_PREFIX:-awg-e2e}-$REL-$(printf '%s' "$TGT" | tr '/' '-')-$$"
kvm=""
[ -e /dev/kvm ] && kvm="--device=/dev/kvm"

# $kvm is empty or one whole option; the container script is expanded inside the container.
# shellcheck disable=SC2016,SC2086
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --name "$name" \
  --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun $kvm \
  -v "$(hostpath "$repo"):/src:ro" -v "$(hostpath "$feed_abs"):/feed:ro" \
  -v "$(hostpath "$peer_abs"):/peer:ro" -v "$(hostpath "$keys_abs"):/keys:ro" \
  -v "$(hostpath "$cache_abs"):/cache" -v "$(hostpath "$out_abs"):/out" \
  -e AWG_E2E_PEER_DIR=/peer -e AWG_E2E_KEYS=/keys -e AWG_E2E_CACHE=/cache/images -e AWG_E2E_OUT=/out \
  -e AWG_E2E_SUMMARY=/out/summary.md \
  -e AWG_E2E_CASES -e AWG_E2E_MEM -e AWG_E2E_EXPECT_TOOLS \
  -e AWG_E2E_CONSOLE_ECHO -e AWG_E2E_BOOT_TIMEOUT \
  "$QEMU_HOST_IMAGE" sh -euc '
    mkdir -p /cache/apk && ln -sfn /cache/apk /etc/apk/cache
    apk add -q qemu-system-x86_64 qemu-system-mipsel python3 iproute2 curl >/dev/null
    rm -f /out/summary.md
    exec sh /src/scripts/awg/qemu-e2e.sh /feed "$1" "$2"
  ' sh "$REL" "$TGT"
