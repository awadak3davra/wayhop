#!/bin/sh
# pack-userspace.sh - package the userspace AmneziaWG 3.1 binaries (scripts/awg/build-userspace.sh)
# for WayHop's feed:
#
#   <outdir>/entware/<entware-token>/amneziawg-go_<ver>_<token>.ipk      /opt/sbin/amneziawg-go
#   <outdir>/entware/<entware-token>/amneziawg-tools_<ver>_<token>.ipk   /opt/bin/awg
#   <outdir>/ipk/<openwrt-pkgarch>/amneziawg-go_<ver>_<pkgarch>.ipk      /usr/bin/amneziawg-go
#   <outdir>/apk/<openwrt-pkgarch>/amneziawg-go-<ver>.apk                /usr/bin/amneziawg-go
#
# The tokens come from packaging/feed/arch-map.txt, the same map WayHop's own packages use: one
# static binary per Go arch, re-stamped once per token a device may report. Versions are the
# upstream tags plus WayHop's packaging release (packaging/awg/VERSIONS): 3.1.20260828-r1.
#
# The containers mirror packaging/feed/pack-entware.sh and pack-ipk.sh (an .ipk is a gzipped tar of
# ./debian-binary ./data.tar.gz ./control.tar.gz, in that order) and pack-apk.sh (`apk mkpkg`, in
# the digest-pinned apk-tools v3 image feed.yml uses, without network). The packages carry no
# maintainer scripts: installing a binary starts nothing; WayHop (or the operator) runs it.
#
# OpenWrt's amneziawg-go depends on kmod-tun, as OpenWrt's own userspace VPN packages do: without
# /dev/net/tun it cannot run, and default images do not carry the module. Entware has no kernel
# packages; the firmware provides TUN there.
#
# Usage: scripts/awg/pack-userspace.sh <indir> <outdir>
#   <indir> holds userspace/<go-token>/{amneziawg-go,awg} (build-userspace.sh's <outdir>).
#   Needs Linux with GNU tar for the .ipk files; the .apk files are made with `apk` when it is on
#   PATH, else through docker (--network none) in APK_IMAGE below, the digest-pinned apk-tools v3
#   image feed.yml packs WayHop's own apks with.
#   AWG_PACK_FORMATS="entware ipk apk"   the formats to make (default: all three)
#   AWG_APK_IMAGE=<ref>                  another apk-tools image
#   SOURCE_DATE_EPOCH                    the mtime of every packed file (default: 0)
#   --apk <indir> <outdir>               only the .apk files, as run inside the apk-tools image
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=packaging/awg/VERSIONS
. "$repo/packaging/awg/VERSIONS"
APK_IMAGE="${AWG_APK_IMAGE:-alpine:edge@sha256:d77617aef5805191da75fbbfe2f9dc2043582ecad0f4d381b27c151034765a76}"
ARCHMAP="$repo/packaging/feed/arch-map.txt"
: "${SOURCE_DATE_EPOCH:=0}"
GO_VER="${AWG_GO_TAG#v}-r${AWG_PKG_RELEASE}"
TOOLS_VER="${AWG_TOOLS_TAG#v}-r${AWG_PKG_RELEASE}"
MAINT="WayHop <noreply@wayhop.dev>"
GO_URL="https://github.com/amnezia-vpn/amneziawg-go"
TOOLS_URL="https://github.com/amnezia-vpn/amneziawg-tools"
GO_DESC="AmneziaWG 3.1 userspace daemon (amneziawg-go ${AWG_GO_TAG}, WayHop low-memory build)"
TOOLS_DESC="AmneziaWG 3.1 configuration tool awg (amneziawg-tools ${AWG_TOOLS_TAG}, static)"

# Each arch-map line as "<go-token> <entware-token> <openwrt-token>...".
archmap() {
  while IFS= read -r line; do
    case "$line" in ""|\#*) continue ;; esac
    ow="${line%%|*}"
    ew="$(echo "${line#*|}" | tr -d ' ')"
    # shellcheck disable=SC2086  # the OpenWrt half is a word list on purpose
    set -- $ow
    go="$1"; shift
    echo "$go $ew $*"
  done < "$ARCHMAP"
}

# A tree with fixed owner, mtime and order, gzipped without a name or timestamp.
tar_repro() {
  tar --numeric-owner --owner=0 --group=0 --mtime="@${SOURCE_DATE_EPOCH}" --sort=name -C "$1" -cf - . | gzip -n -9 > "$2"
}

# ipk <data-dir> <control-text> <out-file>
ipk() {
  d="$(mktemp -d "$work/ipk.XXXXXX")"
  tar_repro "$1" "$d/data.tar.gz"
  mkdir -p "$d/control"
  printf '%s\n' "$2" > "$d/control/control"
  chmod 0644 "$d/control/control"
  tar_repro "$d/control" "$d/control.tar.gz"
  printf '2.0\n' > "$d/debian-binary"
  mkdir -p "$(dirname "$3")"
  # The members are listed, not sorted: their order is part of the format.
  ( cd "$d" && tar --numeric-owner --owner=0 --group=0 --mtime="@${SOURCE_DATE_EPOCH}" \
      -cf - ./debian-binary ./data.tar.gz ./control.tar.gz ) | gzip -n -9 > "$3"
  rm -rf "$d"
}

# control <package> <version> <arch> <isize> <license> <source> <depends> <description>
control() {
  printf 'Package: %s\nVersion: %s\n' "$1" "$2"
  [ -z "$7" ] || printf 'Depends: %s\n' "$7"
  printf 'Source: %s\nLicense: %s\nSection: net\nPriority: optional\nMaintainer: %s\nArchitecture: %s\nInstalled-Size: %s\nDescription: %s\n' \
    "$6" "$5" "$MAINT" "$3" "$4" "$8"
}

# payload <dir> <binary> <path-in-package>: a data tree holding one 0755 binary.
payload() {
  rm -rf "$1"
  mkdir -p "$1/$(dirname "$3")"
  install -m 0755 "$2" "$1/$3"
  find "$1" -exec touch -d "@${SOURCE_DATE_EPOCH}" {} +
}

need_bin() {
  [ -f "$1" ] || { echo "pack-userspace: missing $1 (run scripts/awg/build-userspace.sh first)" >&2; exit 1; }
}

pack_apk() {
  in="$1"; out="$2"
  command -v apk >/dev/null 2>&1 || { echo "pack-userspace: apk-tools v3 not found" >&2; exit 1; }
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
  archmap | while read -r go _ow tokens; do
    need_bin "$in/userspace/$go/amneziawg-go"
    payload "$work/root-$go" "$in/userspace/$go/amneziawg-go" usr/bin/amneziawg-go
    for tok in $tokens; do
      dst="$out/apk/$tok"; mkdir -p "$dst"
      apk mkpkg \
        --info "name:amneziawg-go" \
        --info "version:$GO_VER" \
        --info "arch:$tok" \
        --info "description:$GO_DESC" \
        --info "url:$GO_URL" \
        --info "license:MIT" \
        --info "maintainer:$MAINT" \
        --info "depends:kmod-tun" \
        --files "$work/root-$go" \
        -o "$dst/amneziawg-go-$GO_VER.apk"
      echo "  built apk/$tok/amneziawg-go-$GO_VER.apk"
    done
  done
}

if [ "${1:-}" = "--apk" ]; then
  [ "$#" -eq 3 ] || { echo "usage: pack-userspace.sh --apk <indir> <outdir>" >&2; exit 2; }
  pack_apk "$2" "$3"
  exit 0
fi

[ "$#" -eq 2 ] || { echo "usage: pack-userspace.sh <indir> <outdir>" >&2; exit 2; }
IN="$(cd "$1" && pwd)"
mkdir -p "$2"; OUT="$(cd "$2" && pwd)"
FORMATS="${AWG_PACK_FORMATS:-entware ipk apk}"
has() { case " $FORMATS " in *" $1 "*) return 0 ;; esac; return 1; }

if has entware || has ipk; then
  [ "$(uname -s)" = Linux ] || { echo "pack-userspace: the .ipk files need Linux (file modes)" >&2; exit 1; }
  tar --version 2>/dev/null | grep -q 'GNU tar' || { echo "pack-userspace: GNU tar is required" >&2; exit 1; }
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
  archmap > "$work/map"
  while read -r go ew tokens; do
    need_bin "$IN/userspace/$go/amneziawg-go"
    need_bin "$IN/userspace/$go/awg"
    if has entware; then
      payload "$work/d" "$IN/userspace/$go/amneziawg-go" opt/sbin/amneziawg-go
      isize="$(du -sb "$work/d" | cut -f1)"
      ipk "$work/d" "$(control amneziawg-go "$GO_VER" "$ew" "$isize" MIT "$GO_URL" "" "$GO_DESC")" \
        "$OUT/entware/$ew/amneziawg-go_${GO_VER}_$ew.ipk"
      payload "$work/d" "$IN/userspace/$go/awg" opt/bin/awg
      isize="$(du -sb "$work/d" | cut -f1)"
      ipk "$work/d" "$(control amneziawg-tools "$TOOLS_VER" "$ew" "$isize" GPL-2.0 "$TOOLS_URL" "" "$TOOLS_DESC")" \
        "$OUT/entware/$ew/amneziawg-tools_${TOOLS_VER}_$ew.ipk"
      echo "  built entware/$ew/amneziawg-go_${GO_VER}_$ew.ipk amneziawg-tools_${TOOLS_VER}_$ew.ipk"
    fi
    if has ipk; then
      payload "$work/d" "$IN/userspace/$go/amneziawg-go" usr/bin/amneziawg-go
      isize="$(du -sb "$work/d" | cut -f1)"
      for tok in $tokens; do
        ipk "$work/d" "$(control amneziawg-go "$GO_VER" "$tok" "$isize" MIT "$GO_URL" kmod-tun "$GO_DESC")" \
          "$OUT/ipk/$tok/amneziawg-go_${GO_VER}_$tok.ipk"
        echo "  built ipk/$tok/amneziawg-go_${GO_VER}_$tok.ipk"
      done
    fi
  done < "$work/map"
fi

if has apk; then
  if command -v apk >/dev/null 2>&1; then
    pack_apk "$IN" "$OUT"
  else
    command -v docker >/dev/null 2>&1 || { echo "pack-userspace: neither apk nor docker is available for the .apk files" >&2; exit 1; }
    docker run --rm --network none --read-only --user "$(id -u):$(id -g)" \
      --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=256m \
      -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      -v "$repo:/repo:ro" -v "$IN:/in:ro" -v "$OUT:/out" "$APK_IMAGE" \
      sh /repo/scripts/awg/pack-userspace.sh --apk /in /out
  fi
fi
