#!/bin/sh
# feed-layout.sh - lay WayHop's AmneziaWG packages into the package-feed tree and index them.
#
# Input is the build output tree (dist/awg, see the "Output layout" of the AWG full-install plan in
# docs/AWG_FULL_INSTALL.md, development repository); output is the feed tree feed.yml publishes:
#
#   dist/awg/openwrt/<rel>/<target>/<sub>/*  ->  <feed>/awg/openwrt/<rel>/<target>/<sub>/  own index
#   dist/awg/entware/<token>/*.ipk           ->  <feed>/entware/<token>/   (shares wayhop's index)
#   dist/awg/ipk/<pkgarch>/*.ipk             ->  <feed>/ipk/<pkgarch>/     (shares wayhop's index)
#   dist/awg/apk/<pkgarch>/*.apk             ->  <feed>/apk/<pkgarch>/     (shares wayhop's index)
#   packaging/awg/install-awg.sh             ->  <feed>/awg/install-awg.sh
#
# Every directory it touches gets a fresh UNSIGNED index built from all the packages in it: opkg
# `Packages` + `Packages.gz` (the same control-file reading as packaging/feed/make-index.sh) and apk
# `packages.adb` (`apk mkndx` in the digest-pinned apk-tools image, no network). Signing is NOT done
# here: feed.yml signs with the real keys in its key-bearing steps, the tests sign with throwaway keys
# (scripts/awg/qemu-feed-sign.sh). In feed.yml make-index.sh and the apk step later rebuild the shared
# ipk/entware/apk indexes with wayhop's own packages in them; the per-target awg indexes are built
# only here.
#
# A per-target directory is refused unless its BUILDINFO lists exactly the packages present, each
# with the recorded size and sha256, all in the one pkg_format it declares, kmod and tools included.
# A package already in a shared directory under the same package name is replaced, nothing else
# there is touched.
#
# Usage: feed-layout.sh <dist/awg> <feedroot>
#        feed-layout.sh --check <feedroot>   every awg per-target directory carries the complete,
#                                            signed index its package format needs (after signing)
# Env:   AWG_INSTALLER  installer to publish (default: packaging/awg/install-awg.sh when present)
#        APK_TOOLS_IMAGE  override of the pinned apk-tools image
# Exit:  0 ok, 1 refused input / incomplete feed, 2 usage, 3 docker missing for apk packages.
set -eu

APK_TOOLS_IMAGE="${APK_TOOLS_IMAGE:-alpine:edge@sha256:d77617aef5805191da75fbbfe2f9dc2043582ecad0f4d381b27c151034765a76}"

die() { echo "feed-layout: $*" >&2; exit 1; }
usage() { echo "usage: feed-layout.sh <dist/awg> <feedroot> | --check <feedroot>" >&2; exit 2; }
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }
here="$(cd "$(dirname "$0")" && pwd)"

# A package file name the feed will serve. Refusing anything else keeps a path, a glob or a shell
# metacharacter out of the index and out of the commands below.
valid_pkg_name() {
  printf '%s\n' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._+~-]*\.(ipk|apk)$'
}

# Package name from the file name: `name_version_arch.ipk` (opkg) or `name-version.apk` (apk).
pkg_name_of() {
  case "$1" in
    *.ipk) printf '%s\n' "${1%%_*}" ;;
    *.apk) printf '%s\n' "$1" | sed -E 's/-[0-9][^-]*(-r[0-9]+)?\.apk$//' ;;
  esac
}

# --- check mode -------------------------------------------------------------------------------------
check_feed() {
  root="$1"
  [ -d "$root" ] || die "$root is not a directory"
  n=0; bad=0
  for d in "$root"/awg/openwrt/*/*/*/; do
    [ -d "$d" ] || continue
    d="${d%/}"; n=$((n + 1))
    ipks=$(find "$d" -maxdepth 1 -type f -name '*.ipk' | wc -l | tr -d ' ')
    apks=$(find "$d" -maxdepth 1 -type f -name '*.apk' | wc -l | tr -d ' ')
    if [ "$ipks" -gt 0 ] && [ "$apks" -gt 0 ]; then
      echo "FAIL  $d mixes ipk and apk packages" >&2; bad=$((bad + 1)); continue
    fi
    if [ "$ipks" -gt 0 ]; then
      for f in Packages Packages.gz Packages.sig; do
        [ -s "$d/$f" ] || { echo "FAIL  $d has packages and no $f" >&2; bad=$((bad + 1)); }
      done
      listed=$(grep -c '^Filename: ' "$d/Packages" 2>/dev/null || true)
      [ "${listed:-0}" = "$ipks" ] || { echo "FAIL  $d/Packages lists ${listed:-0} of $ipks packages" >&2; bad=$((bad + 1)); }
    elif [ "$apks" -gt 0 ]; then
      [ -s "$d/packages.adb" ] || { echo "FAIL  $d has packages and no packages.adb" >&2; bad=$((bad + 1)); }
    else
      echo "FAIL  $d is an empty target directory" >&2; bad=$((bad + 1))
    fi
  done
  [ "$bad" = 0 ] || die "$bad problem(s) in the AmneziaWG part of $root"
  echo "feed-layout: $n AmneziaWG target director(ies) carry a complete index"
}

if [ "${1:-}" = "--check" ]; then
  [ "$#" -eq 2 ] || usage
  check_feed "$2"
  exit 0
fi
[ "$#" -eq 2 ] || usage
SRC="$1"; DST="$2"
[ -d "$SRC" ] || die "$SRC is not a directory"
mkdir -p "$DST"
DST="$(cd "$DST" && pwd)"
case "$DST" in *[[:space:]]*) die "feed root '$DST' contains whitespace" ;; esac

touched_opkg=""   # directories that need a (re)built opkg index
touched=0

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# --- per-target OpenWrt packages (kmod + tools + luci): each target directory is its own feed --------
for d in "$SRC"/openwrt/*/*/*/; do
  [ -d "$d" ] || continue
  d="${d%/}"
  sub="${d##*/}"; rest="${d%/*}"; tgt="${rest##*/}"; rest="${rest%/*}"; rel="${rest##*/}"
  printf '%s\n' "$rel" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "$d: release '$rel' is not MAJOR.MINOR.PATCH"
  printf '%s/%s\n' "$tgt" "$sub" | grep -Eq '^[a-z0-9_-]+/[a-z0-9_-]+$' || die "$d: '$tgt/$sub' is not a target/subtarget"
  info="$d/BUILDINFO"
  [ -s "$info" ] || die "$d has no BUILDINFO"
  fmt="$(sed -n 's/^pkg_format=//p' "$info" | head -n1 | tr -d '\r')"
  case "$fmt" in ipk|apk) ;; *) die "$info: pkg_format '$fmt' is not ipk or apk" ;; esac
  for k in release target subtarget; do
    v="$(sed -n "s/^$k=//p" "$info" | head -n1 | tr -d '\r')"
    case "$k" in release) want="$rel" ;; target) want="$tgt" ;; subtarget) want="$sub" ;; esac
    [ "$v" = "$want" ] || die "$info says $k=$v, the directory says $want"
  done
  # Every package present is in BUILDINFO with its size and digest, and every listed one is present.
  listed=0
  while IFS= read -r line; do
    line="$(printf '%s' "$line" | tr -d '\r')"
    case "$line" in file=*) ;; *) continue ;; esac
    # shellcheck disable=SC2086  # `file=.. size=.. sha256=..` is split into its fields on purpose
    set -- $line
    f="${1#file=}"; sz="${2#size=}"; sum="${3#sha256=}"
    valid_pkg_name "$f" || die "$info lists an unacceptable file name: $f"
    case "$f" in *."$fmt") ;; *) die "$info lists $f, which is not a .$fmt package" ;; esac
    [ -f "$d/$f" ] || die "$info lists $f, which is not in $d"
    [ "$(wc -c < "$d/$f" | tr -d ' ')" = "$sz" ] || die "$d/$f: size differs from BUILDINFO"
    [ "$(sha256_of "$d/$f")" = "$sum" ] || die "$d/$f: sha256 differs from BUILDINFO"
    listed=$((listed + 1))
  done < "$info"
  present=0; has_kmod=0; has_tools=0
  for p in "$d"/*.ipk "$d"/*.apk; do
    [ -e "$p" ] || continue
    b="${p##*/}"
    grep -q "^file=$b " "$info" || die "$d/$b is not listed in BUILDINFO"
    present=$((present + 1))
    case "$b" in kmod-amneziawg[_-]*) has_kmod=1 ;; amneziawg-tools[_-]*) has_tools=1 ;; esac
  done
  [ "$present" -gt 0 ] && [ "$present" = "$listed" ] || die "$d: BUILDINFO lists $listed package(s), $present present"
  [ "$has_kmod" = 1 ] && [ "$has_tools" = 1 ] || die "$d: kmod-amneziawg and amneziawg-tools are both required"
  out="$DST/awg/openwrt/$rel/$tgt/$sub"
  rm -rf "$out"
  mkdir -p "$out"
  cp "$info" "$out/BUILDINFO"
  for p in "$d"/*."$fmt"; do cp "$p" "$out/"; done
  [ "$fmt" = ipk ] && touched_opkg="$touched_opkg $out"
  touched=$((touched + 1))
  echo "  laid out awg/openwrt/$rel/$tgt/$sub ($present $fmt package(s))"
done

# --- userspace packages: they join the existing wayhop directories and indexes ------------------------
# <directory under dist/awg and under the feed>:<package extension>
for spec in entware:ipk ipk:ipk apk:apk; do
  kind="${spec%%:*}"; ext="${spec##*:}"
  for d in "$SRC/$kind"/*/; do
    [ -d "$d" ] || continue
    d="${d%/}"; tok="${d##*/}"
    printf '%s\n' "$tok" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' || die "$d: '$tok' is not a package architecture"
    out="$DST/$kind/$tok"
    mkdir -p "$out"
    n=0
    for p in "$d"/*."$ext"; do
      [ -e "$p" ] || continue
      b="${p##*/}"
      valid_pkg_name "$b" || die "$p: unacceptable package file name"
      name="$(pkg_name_of "$b")"
      [ -n "$name" ] && [ "$name" != "$b" ] || die "$p: cannot tell the package name from the file name"
      case "$name" in wayhop) die "$p: the AmneziaWG build must not ship a package named wayhop" ;; esac
      # Replace an older build of the same package, never anything else in the directory.
      for old in "$out/${name}"_*."$ext" "$out/${name}"-[0-9]*."$ext"; do
        [ -e "$old" ] || continue
        [ "$(pkg_name_of "${old##*/}")" = "$name" ] && rm -f "$old"
      done
      cp "$p" "$out/"
      n=$((n + 1))
    done
    [ "$n" -gt 0 ] || die "$d holds no .$ext package"
    [ "$ext" = ipk ] && touched_opkg="$touched_opkg $out"
    touched=$((touched + 1))
    echo "  laid out $kind/$tok ($n package(s))"
  done
done

[ "$touched" -gt 0 ] || die "$SRC holds no package directory - nothing to lay out"

# --- installer ------------------------------------------------------------------------------------
inst="${AWG_INSTALLER:-$here/../../packaging/awg/install-awg.sh}"
if [ -f "$inst" ]; then
  mkdir -p "$DST/awg"
  cp "$inst" "$DST/awg/install-awg.sh"
  chmod 0644 "$DST/awg/install-awg.sh"
  echo "  published awg/install-awg.sh"
elif [ -n "${AWG_INSTALLER:-}" ]; then
  die "AWG_INSTALLER=$AWG_INSTALLER does not exist"
else
  echo "  note: packaging/awg/install-awg.sh is not in this tree; no installer published"
fi

# --- opkg indexes (unsigned) --------------------------------------------------------------------------
for out in $touched_opkg; do
  pkgs="$out/Packages"
  : > "$pkgs"
  for ipk in "$out"/*.ipk; do
    [ -e "$ipk" ] || continue
    tmp="$(mktemp -d)"
    # Same container reading as make-index.sh: an .ipk is a gzipped tar holding ./control.tar.gz.
    if ! tar -xzOf "$ipk" ./control.tar.gz 2>/dev/null | tar -xz -C "$tmp" 2>/dev/null; then
      rm -rf "$tmp"; die "cannot read $ipk - the package format and this indexer disagree"
    fi
    ctl="$tmp/control"
    [ -f "$ctl" ] || ctl="$(find "$tmp" -name control -type f | head -n1)"
    [ -n "$ctl" ] && [ -s "$ctl" ] || { rm -rf "$tmp"; die "no control file inside $ipk"; }
    grep -q '^Package: ' "$ctl" || { rm -rf "$tmp"; die "$ipk: control has no Package field"; }
    # Drop a trailing blank line so every stanza is closed by exactly the one written below.
    sed -e '/^[[:space:]]*$/d' "$ctl" | tr -d '\r' >> "$pkgs"
    printf 'Filename: %s\nSize: %s\nSHA256sum: %s\n\n' \
      "${ipk##*/}" "$(wc -c < "$ipk" | tr -d ' ')" "$(sha256_of "$ipk")" >> "$pkgs"
    rm -rf "$tmp"
  done
  gzip -9nc "$pkgs" > "$pkgs.gz"
  rm -f "$out/Packages.sig"   # any older signature no longer matches; the signing step writes a new one
  echo "  indexed ${out#"$DST"/}/Packages ($(grep -c '^Package:' "$pkgs") package(s), unsigned)"
done

# --- apk indexes (unsigned), pinned image, no network -----------------------------------------------
apkdirs=""
for d in "$DST"/apk/*/ "$DST"/awg/openwrt/*/*/*/; do
  [ -d "$d" ] || continue
  set -- "${d%/}"/*.apk
  [ -e "$1" ] || continue
  rm -f "${d%/}/packages.adb"
  apkdirs="$apkdirs ${d#"$DST"/}"
done
if [ -n "$apkdirs" ]; then
  command -v docker >/dev/null 2>&1 || { echo "feed-layout: docker is required to index apk packages - NOT indexed" >&2; exit 3; }
  docker info >/dev/null 2>&1 || { echo "feed-layout: docker daemon unavailable - apk packages NOT indexed" >&2; exit 3; }
  # shellcheck disable=SC2016  # expanded inside the container
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --network none --read-only \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=64m \
    --env AWG_APK_DIRS="$apkdirs" -v "$(hostpath "$DST"):/feed" -w /feed "$APK_TOOLS_IMAGE" sh -euc '
    for d in $AWG_APK_DIRS; do
      # apk fetches <name>-<version>.apk (the default package name spec); a package stored under
      # any other name is in the index and cannot be downloaded.
      for f in "/feed/$d"*.apk; do
        meta="$(apk adbdump "$f")"
        n="$(printf "%s\n" "$meta" | sed -n "s/^  name: //p" | head -n 1)"
        v="$(printf "%s\n" "$meta" | sed -n "s/^  version: //p" | head -n 1)"
        [ -n "$n" ] && [ -n "$v" ] || { echo "cannot read name/version of $d${f##*/}" >&2; exit 1; }
        [ "${f##*/}" = "$n-$v.apk" ] || { echo "$d${f##*/}: apk clients download $n-$v.apk, so the file must be named that" >&2; exit 1; }
      done
      ( cd "/feed/$d" && apk --allow-untrusted mkndx -o packages.adb ./*.apk )
      [ -s "/feed/$d/packages.adb" ] || { echo "no index written for $d" >&2; exit 1; }
      echo "  indexed ${d%/}/packages.adb (unsigned)"
    done
  '
fi
echo "feed-layout: $touched package director(ies) laid out into $DST"
