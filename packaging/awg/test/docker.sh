#!/bin/sh
# docker.sh -- run the install-awg.sh unit tests (run.sh) and the --with-awg hook tests (hooks.sh)
# under the two shells that matter: busybox ash (what OpenWrt and Keenetic run; Alpine's /bin/sh is
# the same busybox) and dash (a strict POSIX sh; catches bashisms busybox would forgive). Then the real
# installers run with --with-awg in an OpenWrt rootfs and in Alpine with /opt (hooks-container.sh).
# Images are pinned by digest; every container runs with --network none.
#
# Needs Docker. Without it this exits 3 and says so, like the other package gates.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
ASH_IMAGE="${AWG_TEST_ASH_IMAGE:-alpine:edge@sha256:d77617aef5805191da75fbbfe2f9dc2043582ecad0f4d381b27c151034765a76}"
DASH_IMAGE="${AWG_TEST_DASH_IMAGE:-debian:stable-slim@sha256:0d97731c59efdde181e19c4a5ec22d16e9eefcb73175598b9b7bae712c7214eb}"
OPENWRT_IMAGE="${AWG_TEST_OPENWRT_IMAGE:-openwrt/rootfs:x86-64-25.12.0@sha256:1a7f3e9c66e6b77d4014b7e37ffbee7edf114275dc6f1811314a572e11a8e636}"

command -v docker >/dev/null 2>&1 || { echo "no docker: the install-awg unit tests were NOT run" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "docker is not running: the install-awg unit tests were NOT run" >&2; exit 3; }

# Git Bash rewrites unix-looking paths; hand Docker a path it can mount.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }

rc=0
run_in() { # label image shell-command
  echo "== $1 =="
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --network none --name "wayhop-awg-test-unit-$1-$$" \
    -v "$(hostpath "$REPO"):/repo:ro" "$2" sh -c "$3" || rc=1
}
run_in ash  "$ASH_IMAGE"  'AWG_TEST_SH="busybox ash" busybox ash /repo/packaging/awg/test/run.sh &&
                           AWG_TEST_SH="busybox ash" busybox ash /repo/packaging/awg/test/hooks.sh'
run_in dash "$DASH_IMAGE" 'AWG_TEST_SH=dash dash /repo/packaging/awg/test/run.sh &&
                           AWG_TEST_SH=dash dash /repo/packaging/awg/test/hooks.sh'
run_in hooks-openwrt "$OPENWRT_IMAGE" 'sh /repo/packaging/awg/test/hooks-container.sh openwrt'
run_in hooks-entware "$ASH_IMAGE" 'sh /repo/packaging/awg/test/hooks-container.sh entware'
exit "$rc"
