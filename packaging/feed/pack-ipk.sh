#!/bin/sh
# pack-ipk.sh — build OpenWrt .ipk package(s) for a PREBUILT WayHop binary, by hand (no SDK).
# An .ipk is a gzipped TAR of: debian-binary, data.tar.gz, control.tar.gz (in that order). This
# header used to say "ar archive", which is what the packer built and what opkg rejected outright;
# the correction lives at the tar call below. Anything that READS an .ipk has to match this.
# One data payload is built once; only the control's Architecture field differs per token, so one
# binary yields one .ipk per CPU-family token.
#
# Usage: pack-ipk.sh <binpath> <version> <release> <outdir> <arch-token> [arch-token...]
set -eu
BIN="$1"; VER="$2"; REL="$3"; OUT="$4"; shift 4
HERE="$(cd "$(dirname "$0")" && pwd)"
INIT="$HERE/../openwrt/wayhop.init"
HARDEN="$HERE/../harden-state.sh"
: "${SOURCE_DATE_EPOCH:=0}"
[ -f "$BIN" ]  || { echo "pack-ipk: binary not found: $BIN" >&2; exit 1; }
[ -f "$INIT" ] || { echo "pack-ipk: init not found: $INIT" >&2; exit 1; }
[ -f "$HARDEN" ] || { echo "pack-ipk: state hardener not found: $HARDEN" >&2; exit 1; }
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"   # absolute: `ar` runs after cd into the work dir
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

# data tree: the binary + the procd init, reproducible (fixed owner/mtime, sorted).
mkdir -p "$work/data/usr/sbin" "$work/data/usr/libexec/wayhop" "$work/data/etc/init.d"
install -m0755 "$BIN"  "$work/data/usr/sbin/wayhop"
install -m0755 "$INIT" "$work/data/etc/init.d/wayhop"
install -m0755 "$HARDEN" "$work/data/usr/libexec/wayhop/harden-state.sh"
# Keep the saved config/connections across a firmware sysupgrade (the binary is wiped from the
# overlay and reinstalled from the feed; /etc/wayhop must survive). OpenWrt reads /lib/upgrade/keep.d.
if [ -f "$HERE/../openwrt/wayhop.keep" ]; then
  mkdir -p "$work/data/lib/upgrade/keep.d"
  install -m0644 "$HERE/../openwrt/wayhop.keep" "$work/data/lib/upgrade/keep.d/wayhop"
fi
# PROTECTION-BY-OMISSION CONTRACT: the payload must NEVER ship /etc/wayhop. opkg only touches
# files a package owns, so keeping the config tree OUT of the package is what makes upgrades and
# removes unable to clobber user config (postinst SEEDS a config when absent instead). This guard
# fails the build if anyone ever adds config files to the tree.
if [ -e "$work/data/etc/wayhop" ]; then
  echo "pack-ipk: REFUSING to build — payload contains etc/wayhop (would clobber user config on upgrade)" >&2
  exit 1
fi
isize="$(du -sb "$work/data" | cut -f1)"

tar_repro() {
  tar --numeric-owner --owner=0 --group=0 --mtime="@${SOURCE_DATE_EPOCH}" --sort=name -C "$1" -czf "$2" .
}
tar_repro "$work/data" "$work/data.tar.gz"

mkdir -p "$work/control"
install -m0755 "$HERE/preinst"  "$work/control/preinst"
install -m0755 "$HERE/postinst" "$work/control/postinst"
install -m0755 "$HERE/prerm"    "$work/control/prerm"
printf '2.0\n' > "$work/debian-binary"

for tok in "$@"; do
  sed -e "s/@VER@/$VER/g" -e "s/@REL@/$REL/g" -e "s/@ARCH@/$tok/g" -e "s/@ISIZE@/$isize/g" \
      "$HERE/control.tmpl" > "$work/control/control"
  tar_repro "$work/control" "$work/control.tar.gz"
  out_dir="$OUT/$tok"; mkdir -p "$out_dir"
  out="$out_dir/wayhop_${VER}-${REL}_${tok}.ipk"
  rm -f "$out"
  # An OpenWrt .ipk is a gzipped TAR of the three members, not an ar archive. opkg rejected every
  # package this produced with "Malformed package file", and nothing noticed because the router this
  # is developed against runs OpenWrt 25.x, which has no opkg at all — the .ipk half of the feed was
  # published and never installed. Compared against a real feed package (`tar tzf libubox….ipk` ->
  # ./debian-binary ./data.tar.gz ./control.tar.gz) inside an OpenWrt rootfs.
  #
  # The members are listed explicitly rather than sorted: the order is part of the format, and
  # --sort=name would put control before data. The reproducibility flags match tar_repro.
  ( cd "$work" && tar --numeric-owner --owner=0 --group=0 --mtime="@${SOURCE_DATE_EPOCH}" \
      -czf "$out" ./debian-binary ./data.tar.gz ./control.tar.gz )
  echo "  built $tok/$(basename "$out")"
done
