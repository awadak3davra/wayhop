#!/bin/sh
# build-openwrt.sh - build WayHop's AmneziaWG 3.1 OpenWrt packages (kmod-amneziawg, amneziawg-tools,
# luci-proto-amneziawg, luci-i18n-amneziawg-ru) for one OpenWrt release and target, with that
# release's official SDK.
#
# Usage: scripts/awg/build-openwrt.sh <release> <target>/<subtarget> [outdir]   (default dist/awg)
#        scripts/awg/build-openwrt.sh --install-deps    (only install the host packages, apt-get)
#
# Output: <outdir>/openwrt/<release>/<target>/<subtarget>/ holding the packages and BUILDINFO, the
# layout and key=value format docs/AWG_FULL_INSTALL.md (development repository) defines.
#
# Why the official SDK of the exact release and target: a kmod loads only into the kernel build it
# was compiled against, and OpenWrt pins that with a "kernel (=<version>~<vermagic>-r<n>)"
# dependency. Only the release's own SDK carries that kernel tree and config, so the package
# installs next to the official kmod-* it depends on. The script proves it: the dependency must
# name a kmods/ directory that exists for the target on downloads.openwrt.org, and the module's
# vermagic must start with that kernel version.
#
# Why so many checks before building: the SDK tarball must match the release's sha256sums; the
# package Makefiles must carry exactly the pins in packaging/awg/VERSIONS (and the tags must still
# resolve to the pinned commits upstream); the LuCI page is fetched at AWG_LUCI_COMMIT and nothing
# else. Only the base and luci feeds are used, at the commits the SDK's feeds.conf.default pins.
#
# Environment:
#   AWG_SDK_CACHE     SDK tarball cache, laid out like the download URL (default $HOME/.cache/awg-sdk);
#                     a cached tarball is re-verified against sha256sums on every use
#   AWG_WORK_DIR      where SDKs are unpacked and built (default ${TMPDIR:-/tmp}/awg-openwrt); each
#                     build gets its own subdirectory, removed at the end unless AWG_KEEP_WORK=1
#   AWG_JOBS          make -j (default: number of CPUs)
#   AWG_VERBOSE=1     stream the SDK build output (otherwise it is logged and the tail shown on failure)
#   AWG_INSTALL_DEPS=1  install the host packages first (always done when GITHUB_ACTIONS=true)
#   AWG_OPENWRT_DOWNLOADS  base URL (default https://downloads.openwrt.org)
set -eu

die() {
	echo "build-openwrt: $*" >&2
	exit 1
}
log() {
	echo "build-openwrt: $*"
}

install_deps() {
	# Host tools the SDK's prereq check asks for, plus what this script uses (curl, zstd, strings).
	pkgs="build-essential binutils bzip2 ca-certificates curl diffutils file findutils gawk git
		libncurses-dev patch perl python3 rsync tar unzip wget xz-utils zstd"
	sudo=""
	[ "$(id -u)" = 0 ] || sudo="sudo -n"
	# shellcheck disable=SC2086  # word splitting of $sudo and $pkgs is intended
	$sudo env DEBIAN_FRONTEND=noninteractive apt-get update -qq
	# Python < 3.12 (Debian 12) keeps distutils in its own package; 3.12+ (Ubuntu 24.04) has none
	# (apt still knows the name there, without an installable candidate).
	if apt-cache policy python3-distutils 2>/dev/null | grep -Eq 'Candidate: [0-9]'; then
		pkgs="$pkgs python3-distutils"
	fi
	# shellcheck disable=SC2086
	$sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends $pkgs
}

if [ "${1:-}" = "--install-deps" ]; then
	install_deps
	exit 0
fi

[ $# -ge 2 ] && [ $# -le 3 ] || die "usage: $0 <release> <target>/<subtarget> [outdir]"
release="$1"
target="${2%%/*}"
subtarget="${2#*/}"
outdir="${3:-dist/awg}"
echo "$release" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$' || die "bad release '$release'"
echo "$2" | grep -Eq '^[a-z0-9_-]+/[a-z0-9_-]+$' || die "bad target '$2' (want <target>/<subtarget>)"

t_start=$(date +%s)
root="$(cd "$(dirname "$0")/../.." && pwd)"
feed_src="$root/packaging/awg/openwrt"
# shellcheck source-path=SCRIPTDIR/../.. source=packaging/awg/VERSIONS
. "$root/packaging/awg/VERSIONS"

if [ "${GITHUB_ACTIONS:-}" = true ] || [ "${AWG_INSTALL_DEPS:-0}" = 1 ]; then
	install_deps
fi
for cmd in curl git make gcc g++ perl python3 rsync tar unzip bzip2 wget xz zstd file gawk strings sha256sum; do
	command -v "$cmd" >/dev/null 2>&1 || die "missing host command '$cmd' (run $0 --install-deps)"
done

# --- pins -------------------------------------------------------------------------------------
# Value of a "VAR:=value" line in a package Makefile.
mk_value() {
	sed -n "s/^$2:=//p" "$1" | head -n 1
}
check_pin() {
	got="$(mk_value "$1" "$2")"
	[ "$got" = "$3" ] || die "${1#"$root"/}: $2 is '$got' but packaging/awg/VERSIONS says '$3'"
}
# The tag must still point at the pinned commit upstream (annotated tags: the peeled ^{} entry).
check_tag() {
	refs="$(git ls-remote "$1" "refs/tags/$2" "refs/tags/$2^{}")" || die "git ls-remote $1 failed"
	got="$(echo "$refs" | awk -v t="refs/tags/$2^{}" '$2 == t { print $1 }')"
	[ -n "$got" ] || got="$(echo "$refs" | awk -v t="refs/tags/$2" '$2 == t { print $1 }')"
	[ "$got" = "$3" ] || die "tag $2 of $1 resolves to '$got', not the pinned $3 - refusing"
}
kmod_mk="$feed_src/kmod-amneziawg/Makefile"
tools_mk="$feed_src/amneziawg-tools/Makefile"
luci_mk="$feed_src/luci-proto-amneziawg/Makefile"
check_pin "$kmod_mk" PKG_VERSION "${AWG_KMOD_TAG#v}"
check_pin "$kmod_mk" PKG_SOURCE_URL "$AWG_KMOD_REPO.git"
check_pin "$kmod_mk" PKG_SOURCE_VERSION "$AWG_KMOD_COMMIT"
check_pin "$kmod_mk" PKG_RELEASE "$AWG_PKG_RELEASE"
check_pin "$tools_mk" PKG_VERSION "${AWG_TOOLS_TAG#v}"
check_pin "$tools_mk" PKG_SOURCE_URL "$AWG_TOOLS_REPO.git"
check_pin "$tools_mk" PKG_SOURCE_VERSION "$AWG_TOOLS_COMMIT"
check_pin "$tools_mk" PKG_RELEASE "$AWG_PKG_RELEASE"
check_pin "$luci_mk" PKG_RELEASE "$AWG_PKG_RELEASE"
check_tag "$AWG_KMOD_REPO" "$AWG_KMOD_TAG" "$AWG_KMOD_COMMIT"
check_tag "$AWG_TOOLS_REPO" "$AWG_TOOLS_TAG" "$AWG_TOOLS_COMMIT"

# --- work area --------------------------------------------------------------------------------
work_root="${AWG_WORK_DIR:-${TMPDIR:-/tmp}/awg-openwrt}"
build="$work_root/$release-$target-$subtarget"
rm -rf "$build"
mkdir -p "$build"
build="$(cd "$build" && pwd)"
cleanup() {
	if [ "${AWG_KEEP_WORK:-0}" = 1 ]; then
		log "work directory kept: $build"
	else
		rm -rf "$build"
	fi
}
trap cleanup EXIT

# --- the feed: our Makefiles + the LuCI page at the pinned commit -----------------------------
feed="$build/feed"
mkdir -p "$feed"
cp -R "$feed_src/." "$feed/"

luci_src="$build/luci-src"
git init -q "$luci_src"
git -C "$luci_src" fetch -q --depth 1 "$AWG_LUCI_REPO" "$AWG_LUCI_COMMIT" ||
	die "cannot fetch $AWG_LUCI_COMMIT from $AWG_LUCI_REPO"
git -C "$luci_src" -c advice.detachedHead=false checkout -q FETCH_HEAD
got="$(git -C "$luci_src" rev-parse HEAD)"
[ "$got" = "$AWG_LUCI_COMMIT" ] || die "LuCI checkout is $got, not the pinned $AWG_LUCI_COMMIT - refusing"
luci_date="$(TZ=UTC0 git -C "$luci_src" log -1 --format=%cd --date=format-local:%Y%m%d)"
luci_version="$(mk_value "$luci_mk" PKG_VERSION)"
[ "${luci_version##*.}" = "$luci_date" ] ||
	die "luci-proto-amneziawg PKG_VERSION $luci_version must end in the pinned commit's UTC date $luci_date"
for d in htdocs root po; do
	if [ -d "$luci_src/luci-proto-amneziawg/$d" ]; then
		cp -R "$luci_src/luci-proto-amneziawg/$d" "$feed/luci-proto-amneziawg/"
	fi
done
[ -f "$feed/luci-proto-amneziawg/htdocs/luci-static/resources/protocol/amneziawg.js" ] ||
	die "the pinned awg-openwrt commit has no luci-proto-amneziawg/htdocs/.../protocol/amneziawg.js"
with_ru=0
[ -d "$feed/luci-proto-amneziawg/po/ru" ] && with_ru=1

# --- the SDK ----------------------------------------------------------------------------------
t_dl=$(date +%s)
downloads="${AWG_OPENWRT_DOWNLOADS:-https://downloads.openwrt.org}"
base_url="$downloads/releases/$release/targets/$target/$subtarget"
curl -fsSL --retry 3 -o "$build/sha256sums" "$base_url/sha256sums" ||
	die "no sha256sums at $base_url (release or target does not exist?)"
sdk_line="$(grep -E "^[0-9a-f]{64} [* ]?openwrt-sdk-$release-$target-${subtarget}_[^ /]*\.Linux-x86_64\.tar\.(zst|xz)\$" "$build/sha256sums" || true)"
[ -n "$sdk_line" ] || die "no SDK listed in $base_url/sha256sums"
[ "$(echo "$sdk_line" | wc -l)" -eq 1 ] || die "more than one SDK listed in $base_url/sha256sums"
sdk_sha="${sdk_line%% *}"
sdk_file="${sdk_line##* }"
sdk_file="${sdk_file#\*}"

cache="${AWG_SDK_CACHE:-$HOME/.cache/awg-sdk}/releases/$release/targets/$target/$subtarget"
mkdir -p "$cache"
tarball="$cache/$sdk_file"
if [ -f "$tarball" ] && [ "$(sha256sum "$tarball" | cut -d' ' -f1)" = "$sdk_sha" ]; then
	log "SDK from cache: $tarball"
else
	log "downloading $base_url/$sdk_file"
	part="$cache/.$sdk_file.$$"
	curl -fsSL --retry 3 -o "$part" "$base_url/$sdk_file" || { rm -f "$part"; die "SDK download failed"; }
	got="$(sha256sum "$part" | cut -d' ' -f1)"
	if [ "$got" != "$sdk_sha" ]; then
		rm -f "$part"
		die "$sdk_file: sha256 $got does not match sha256sums ($sdk_sha)"
	fi
	mv -f "$part" "$tarball"
fi

sdk="$build/sdk"
mkdir -p "$sdk"
case "$sdk_file" in
	*.zst) zstd -dcq -- "$tarball" ;;
	*.xz) xz -dc -- "$tarball" ;;
esac | tar -xf - -C "$sdk" --strip-components=1
[ -x "$sdk/scripts/feeds" ] || die "$sdk_file did not unpack to an SDK"

# --- feeds: base + luci as the SDK pins them, and ours as a src-link --------------------------
# luci is pinned to a commit ("^<sha>"); base is pinned either to a commit (25.12) or to the
# release's own tag (24.10: "src-git-full base ...openwrt.git;v24.10.8"). Anything looser is refused.
t_feeds=$(date +%s)
{
	grep -E "^src-git(-full)? +(--[^ ]+ +)*base +[^ ]+(\\^[0-9a-f]{40}|;v$release)\$" "$sdk/feeds.conf.default" || true
	grep -E '^src-git(-full)? +(--[^ ]+ +)*luci +[^ ]+\^[0-9a-f]{40}$' "$sdk/feeds.conf.default" || true
} >"$sdk/feeds.conf"
[ "$(wc -l <"$sdk/feeds.conf")" -eq 2 ] ||
	die "feeds.conf.default of $sdk_file does not pin the base and luci feeds (base to a commit or v$release, luci to a commit)"
printf 'src-link awg %s\n' "$feed" >>"$sdk/feeds.conf"
sdk_log="$build/sdk-build.log"
run_sdk() {
	if [ "${AWG_VERBOSE:-0}" = 1 ]; then
		(cd "$sdk" && "$@")
	elif ! (cd "$sdk" && "$@") >>"$sdk_log" 2>&1; then
		tail -n 150 "$sdk_log" >&2
		die "failed in the SDK: $*"
	fi
}
run_sdk ./scripts/feeds update base luci awg
run_sdk ./scripts/feeds install -p awg -a

# Our three packages as modules, nothing selected by default. luci-base is selected only so its
# options exist: JavaScript minified as on an official image (CSS minifying is not needed, the page
# has no CSS), and the Russian translation, which luci.mk hides behind LUCI_LANG_ru.
{
	echo "CONFIG_PACKAGE_kmod-amneziawg=m"
	echo "CONFIG_PACKAGE_amneziawg-tools=m"
	echo "CONFIG_PACKAGE_luci-proto-amneziawg=m"
	echo "CONFIG_PACKAGE_luci-base=m"
	echo "CONFIG_LUCI_JSMIN=y"
	echo "# CONFIG_LUCI_CSSTIDY is not set"
	[ "$with_ru" = 0 ] || echo "CONFIG_LUCI_LANG_ru=y"
	echo "# CONFIG_ALL is not set"
	echo "# CONFIG_ALL_KMODS is not set"
	echo "# CONFIG_ALL_NONSHARED is not set"
} >"$sdk/.config"
run_sdk make defconfig
want="kmod-amneziawg amneziawg-tools luci-proto-amneziawg"
[ "$with_ru" = 0 ] || want="$want luci-i18n-amneziawg-ru"
for p in $want; do
	grep -q "^CONFIG_PACKAGE_$p=m\$" "$sdk/.config" ||
		die "$p is not selectable in this SDK (a dependency is missing?)"
done
grep -q '^CONFIG_LUCI_JSMIN=y$' "$sdk/.config" || die "CONFIG_LUCI_JSMIN did not stick"

# --- compile ----------------------------------------------------------------------------------
# NO_DEPS=1: the SDK would otherwise first build every runtime dependency from source (iproute2
# and its libraries for "ip", all selected kernel packages, even linux-firmware), which our
# packages do not need to compile: the kmod builds against the SDK's prepared kernel tree, awg needs
# only the C library, and the LuCI page only luci.mk's host tools (po2lmo, jsmin), built first.
t_compile=$(date +%s)
jobs="${AWG_JOBS:-$(nproc 2>/dev/null || echo 2)}"
run_sdk make -j"$jobs" package/luci-base/host/compile

# The kmod's packaging step checks that every module amneziawg.ko links against comes from one of its
# dependencies, reading their pkginfo/<package>.provides. NO_DEPS skips making those, and making all
# of package/kernel/linux would package the ~1000 kernel modules the SDK preselects (7 minutes and
# more). So package only the dependency closure of kmod-amneziawg from the SDK's prebuilt modules,
# dependencies first (a .provides includes those of its dependencies).
sdk_val() {
	(cd "$sdk" && make -s --no-print-directory -C "$1" TOPDIR="$sdk" "val.$2" 2>/dev/null)
}
pkginfo="$(sdk_val package/kernel/linux PKG_INFO_DIR)"
[ -n "$pkginfo" ] || die "cannot read PKG_INFO_DIR from the SDK"
# Make the package file (PACK_<name>), not the .provides: the rule makes both, but the package
# metadata (CONTROL, DESCRIPTION) is exported only for the package file target.
kmod_provides() {
	[ ! -f "$pkginfo/$1.provides" ] || return 0
	for dep in $(sdk_val package/kernel/linux "IDEPEND_$1"); do
		case "$dep" in kmod-*) (kmod_provides "$dep") ;; esac
	done
	pack="$(sdk_val package/kernel/linux "PACK_$1")"
	[ -n "$pack" ] || die "$1 is not a kernel package of this SDK"
	run_sdk make -C package/kernel/linux TOPDIR="$sdk" "$pack"
	[ -f "$pkginfo/$1.provides" ] || die "packaging $1 made no $pkginfo/$1.provides"
}
for dep in $(sdk_val package/feeds/awg/kmod-amneziawg IDEPEND_kmod-amneziawg); do
	case "$dep" in kmod-*) (kmod_provides "$dep") ;; esac
done
# The same check for awg wants the C library's provides (libc.so, libgcc_s.so.1): package the
# prebuilt toolchain libraries, which takes seconds.
run_sdk make -j"$jobs" NO_DEPS=1 package/toolchain/compile

run_sdk make -j"$jobs" NO_DEPS=1 V=s package/kmod-amneziawg/compile package/amneziawg-tools/compile \
	package/luci-proto-amneziawg/compile
t_collect=$(date +%s)

# --- collect and check ------------------------------------------------------------------------
pkgarch="$(sed -n 's/^CONFIG_TARGET_ARCH_PACKAGES="\(.*\)"$/\1/p' "$sdk/.config")"
[ -n "$pkgarch" ] || die "no CONFIG_TARGET_ARCH_PACKAGES in .config"
if grep -q '^CONFIG_USE_APK=y$' "$sdk/.config"; then fmt=apk; else fmt=ipk; fi

dest="$outdir/openwrt/$release/$target/$subtarget"
mkdir -p "$dest"
rm -f "$dest"/*.ipk "$dest"/*.apk "$dest/BUILDINFO"
names="kmod-amneziawg amneziawg-tools luci-proto-amneziawg"
[ "$with_ru" = 0 ] || names="$names luci-i18n-amneziawg-ru"
for n in $names; do
	# ipk: <name>_<version>_<arch>.ipk, apk: <name>-<version>.apk (version starts with a digit)
	found="$(find "$sdk/bin" -type f \( -name "${n}_[0-9]*.$fmt" -o -name "${n}-[0-9]*.$fmt" \))"
	[ -n "$found" ] || die "no $n package was built"
	[ "$(echo "$found" | wc -l)" -eq 1 ] || die "more than one $n package was built: $found"
	cp "$found" "$dest/"
done

kmod_pkg="$(find "$dest" -name "kmod-amneziawg[-_][0-9]*.$fmt")"
inspect="$build/inspect"
mkdir -p "$inspect"
if [ "$fmt" = apk ]; then
	apk_tool="$sdk/staging_dir/host/bin/apk"
	kernel_dep="$("$apk_tool" adbdump "$kmod_pkg" | sed -n 's/^ *- \(kernel=[^ ]*\)$/\1/p')"
	"$apk_tool" extract --allow-untrusted --no-chown --destination "$inspect" "$kmod_pkg" >/dev/null
	kver_rel="${kernel_dep#kernel=}"
else
	tar -xzOf "$kmod_pkg" ./control.tar.gz | tar -xzOf - ./control >"$inspect/control"
	kernel_dep="$(sed -n 's/^Depends: .*\(kernel (=[^)]*)\).*$/\1/p' "$inspect/control")"
	tar -xzOf "$kmod_pkg" ./data.tar.gz | tar -xzf - -C "$inspect"
	kver_rel="${kernel_dep#kernel (=}"
	kver_rel="${kver_rel%)}"
fi
[ -n "$kernel_dep" ] || die "kmod-amneziawg has no kernel dependency"
kernel_version="${kver_rel%%~*}"          # 6.12.94
kernel_hash="${kver_rel#*~}"
kernel_hash="${kernel_hash%-r*}"          # the vermagic hash
kernel_release="${kver_rel##*-r}"         # 1

ko="$(find "$inspect" -name amneziawg.ko)"
[ -n "$ko" ] || die "kmod-amneziawg contains no amneziawg.ko"
vermagic="$(strings -a "$ko" | sed -n 's/^vermagic=//p' | head -n 1)"
[ "${vermagic%% *}" = "$kernel_version" ] ||
	die "amneziawg.ko vermagic '$vermagic' does not match kernel $kernel_version"
kmods_dir="$kernel_version-$kernel_release-$kernel_hash"
curl -fsSL --retry 3 "$base_url/kmods/" | grep -q "href=\"$kmods_dir/\"" ||
	die "$base_url/kmods/ has no $kmods_dir: the kmod would not match the official kernel"

{
	echo "release=$release"
	echo "target=$target"
	echo "subtarget=$subtarget"
	echo "pkgarch=$pkgarch"
	echo "pkg_format=$fmt"
	echo "kernel_version=$kernel_version"
	echo "kernel_dep=$kernel_dep"
	for f in "$dest"/*."$fmt"; do
		echo "file=$(basename "$f") size=$(wc -c <"$f" | tr -d ' ') sha256=$(sha256sum "$f" | cut -d' ' -f1)"
	done
} >"$dest/BUILDINFO"

t_end=$(date +%s)
log "$release $target/$subtarget ($pkgarch, $fmt, kernel $kernel_version, vermagic '$vermagic'): $dest"
sed -n 's/^file=/  /p' "$dest/BUILDINFO"
log "time: total $((t_end - t_start))s = prepare $((t_dl - t_start))s, SDK $((t_feeds - t_dl))s," \
	"feeds+config $((t_compile - t_feeds))s, compile $((t_collect - t_compile))s, checks $((t_end - t_collect))s"
