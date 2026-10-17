#!/bin/sh
# build-openwrt-docker.sh - run scripts/awg/build-openwrt.sh in a debian:12 container, so a developer
# machine (Windows, macOS or Linux with Docker) builds exactly what CI's ubuntu runner builds.
#
# Usage: scripts/awg/build-openwrt-docker.sh <release> <target>/<subtarget> [outdir]  (default dist/awg)
#
# Why the build stays inside the container: an SDK unpacks into tens of thousands of small files,
# and a bind mount from a Windows or macOS host is many times slower than the container's own
# filesystem. Only the sources go in (read-only) and only the finished packages come out (docker cp).
# The container installs the host packages (build-openwrt.sh --install-deps) as root, then builds as
# an unprivileged user, as on a CI runner.
#
# Environment:
#   AWG_DOCKER_PREFIX  prefix of the container and volume names (default "awg-")
#   AWG_DOCKER_IMAGE   build image (default: debian:12, pinned by digest below)
#   AWG_JOBS, AWG_VERBOSE   passed through to build-openwrt.sh
#   AWG_KEEP_WORK=1    keep the stopped container (and the unpacked SDK in it) for inspection
# SDK tarballs are cached in the named volume <prefix>sdk-cache, so a rebuild downloads nothing.
set -eu

[ $# -ge 2 ] && [ $# -le 3 ] || {
	echo "usage: $0 <release> <target>/<subtarget> [outdir]" >&2
	exit 1
}
release="$1"
tgt="$2"
outdir="${3:-dist/awg}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
prefix="${AWG_DOCKER_PREFIX:-awg-}"
# debian:12, the image the packages were validated with (the same pin as scripts/check-feed-index.sh).
BUILD_IMAGE="${AWG_DOCKER_IMAGE:-debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931}"
t_start=$(date +%s)

mkdir -p "$outdir"
host_root="$root"
host_out="$outdir"
if command -v cygpath >/dev/null 2>&1; then
	# Git Bash on Windows: give docker Windows paths and keep MSYS from rewriting container paths.
	host_root="$(cygpath -w "$root")"
	host_out="$(cygpath -w "$outdir")"
	export MSYS_NO_PATHCONV=1
fi

cache_vol="${prefix}sdk-cache"
docker volume create "$cache_vol" >/dev/null

name="${prefix}openwrt-$(echo "$release-$tgt" | tr './' '--')-$$"
cleanup() {
	if [ "${AWG_KEEP_WORK:-0}" = 1 ]; then
		echo "build-openwrt-docker: container kept: $name"
	else
		docker rm -f "$name" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

# shellcheck disable=SC2016  # the inner script is expanded by the container's shell
docker run --name "$name" -v "$cache_vol:/cache" -v "$host_root:/src:ro" \
	-e AWG_SDK_CACHE=/cache -e AWG_WORK_DIR=/home/build/work \
	-e AWG_JOBS -e AWG_VERBOSE -e AWG_KEEP_WORK \
	"$BUILD_IMAGE" sh -c '
		set -e
		sh /src/scripts/awg/build-openwrt.sh --install-deps
		useradd -m build
		chown build: /cache
		cd /home/build
		exec runuser -u build -- sh /src/scripts/awg/build-openwrt.sh "$@"
	' sh "$release" "$tgt" /home/build/out

docker cp "$name:/home/build/out/." "$host_out"
echo "build-openwrt-docker: $release $tgt done in $(($(date +%s) - t_start))s -> $outdir"
