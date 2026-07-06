#!/bin/sh
# pack-apk.sh — build OpenWrt apk (apk-tools v3 / .apk) package(s) for a PREBUILT WayHop binary.
# RUN INSIDE an alpine container that ships apk-tools v3 (provides `apk mkpkg`). apk filenames carry
# no arch, so each token gets its OWN directory; the device selects via $(cat /etc/apk/arch) in the
# feed URL. Index generation + signing is done by the caller (feed.yml) after all tokens are packed.
#
# Usage: pack-apk.sh <binpath> <version> <release> <outdir> <arch-token> [token...]
set -eu
BIN="$1"; VER="$2"; REL="$3"; OUT="$4"; shift 4
HERE="$(cd "$(dirname "$0")" && pwd)"
INIT="$HERE/../openwrt/wayhop.init"
[ -f "$BIN" ]  || { echo "pack-apk: binary not found: $BIN" >&2; exit 1; }
[ -f "$INIT" ] || { echo "pack-apk: init not found: $INIT" >&2; exit 1; }
command -v apk >/dev/null 2>&1 || { echo "pack-apk: apk-tools v3 not found (run inside alpine)" >&2; exit 1; }

KEEP="$HERE/../openwrt/wayhop.keep"
[ -f "$KEEP" ] || { echo "pack-apk: keep file not found: $KEEP" >&2; exit 1; }

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/usr/sbin" "$work/root/etc/init.d" "$work/root/lib/upgrade/keep.d"
install -m0755 "$BIN"  "$work/root/usr/sbin/wayhop"
install -m0755 "$INIT" "$work/root/etc/init.d/wayhop"
# sysupgrade keep-list (mirrors pack-ipk.sh): without it a firmware sysupgrade on an apk device
# would DELETE /etc/wayhop — config, saved connections, keys.
install -m0644 "$KEEP" "$work/root/lib/upgrade/keep.d/wayhop"

# PROTECTION-BY-OMISSION CONTRACT: the payload must NEVER ship /etc/wayhop. opkg/apk only touch
# files a package owns, so keeping the config tree OUT of the package is what makes upgrades and
# removes unable to clobber user config (postinst SEEDS a config when absent instead). This guard
# fails the build if anyone ever adds config files to the tree.
if [ -e "$work/root/etc/wayhop" ]; then
  echo "pack-apk: REFUSING to build — payload contains etc/wayhop (would clobber user config on upgrade)" >&2
  exit 1
fi

for tok in "$@"; do
  dst="$OUT/apk/$tok"; mkdir -p "$dst"
  apk mkpkg \
    --info "name:wayhop" \
    --info "version:${VER}-r${REL}" \
    --info "arch:${tok}" \
    --info "description:WayHop - VPN/proxy control panel for your router" \
    --info "url:https://github.com/awadak3davra/wayhop" \
    --info "license:MIT" \
    --info "depends:nftables" \
    --files "$work/root" \
    --script "post-install:$HERE/postinst.apk" \
    --script "pre-deinstall:$HERE/prerm.apk" \
    --script "post-upgrade:$HERE/postupgrade.apk" \
    -o "$dst/wayhop-${VER}-r${REL}.apk"
  echo "  built apk/$tok/wayhop-${VER}-r${REL}.apk"
done
