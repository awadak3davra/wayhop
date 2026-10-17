#!/bin/sh
# qemu-feed-sign.sh - sign a TEST feed tree with throwaway keys made on the spot.
#
# The end-to-end and lifecycle tests install from a feed laid out by feed-layout.sh. A device only
# installs from a signed index, and the real keys never leave the release environment, so the tests
# generate a fresh key pair per run (usign for opkg, ECDSA P-256 for apk - the same tools and the
# same pinned offline apk signer feed.yml uses), sign every index in the tree with it, verify each
# signature against the public half, and leave only the PUBLIC halves for the device side:
#
#   <keydir>/usign.pub      opkg-key add          (opkg: OpenWrt 24.10, Entware)
#   <keydir>/apk.pem.pub    /etc/apk/keys/*.pem   (apk: OpenWrt 25.12)
#
# The secret halves are removed before the script exits. Nothing here can sign a real feed: the keys
# are new every run and trusted by nothing but the test device they are handed to.
#
# Usage: qemu-feed-sign.sh <feedroot> <keydir>
# Needs: go (builds packaging/feed/usigntool and scripts/testdata/apk-keygen.go), docker for apk.
# Exit:  0 signed, 1 failure, 2 usage, 3 docker missing while the tree holds apk indexes.
set -eu

APK_TOOLS_IMAGE="${APK_TOOLS_IMAGE:-alpine:edge@sha256:d77617aef5805191da75fbbfe2f9dc2043582ecad0f4d381b27c151034765a76}"
GO="${GO:-go}"

[ "$#" -eq 2 ] || { echo "usage: qemu-feed-sign.sh <feedroot> <keydir>" >&2; exit 2; }
FEED="$1"; KEYS="$2"
[ -d "$FEED" ] || { echo "qemu-feed-sign: $FEED is not a directory" >&2; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }

mkdir -p "$KEYS"
KEYS="$(cd "$KEYS" && pwd)"
FEED="$(cd "$FEED" && pwd)"
secret="$(mktemp -d)"
cleanup() { rm -rf "$secret"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

exe="$("$GO" env GOEXE)"
( cd "$repo" && "$GO" build -trimpath -o "$secret/usigntool$exe" ./packaging/feed/usigntool )
( cd "$repo" && "$GO" build -trimpath -o "$secret/apk-keygen$exe" ./scripts/testdata/apk-keygen.go )
usign="$secret/usigntool$exe"

fp="$("$usign" genkey -comment "wayhop awg e2e throwaway key" -pub "$KEYS/usign.pub" -sec "$secret/usign.sec")"
"$secret/apk-keygen$exe" "$secret/apk.pem" "$KEYS/apk.pem.pub"
mkdir -p "$secret/apkkey"
cp "$secret/apk.pem" "$secret/apkkey/wayhop-test.pem"

signed=0
for p in "$FEED"/ipk/*/Packages "$FEED"/entware/*/Packages "$FEED"/awg/openwrt/*/*/*/Packages; do
  [ -f "$p" ] || continue
  "$usign" sign -sec "$secret/usign.sec" -m "$p" -out "$p.sig"
  "$usign" verify -pub "$KEYS/usign.pub" -m "$p" -sig "$p.sig" >/dev/null
  signed=$((signed + 1))
  echo "  signed ${p#"$FEED"/} (usign $fp)"
done

adbs=""; nadb=0
for a in "$FEED"/apk/*/packages.adb "$FEED"/awg/openwrt/*/*/*/packages.adb; do
  [ -f "$a" ] || continue
  adbs="$adbs ${a#"$FEED"/}"
  nadb=$((nadb + 1))
done
if [ -n "$adbs" ]; then
  command -v docker >/dev/null 2>&1 || { echo "qemu-feed-sign: docker is required to sign apk indexes" >&2; exit 3; }
  mkdir -p "$secret/apkpub"
  cp "$KEYS/apk.pem.pub" "$secret/apkpub/wayhop-test.pem"
  # shellcheck disable=SC2016  # expanded inside the container
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --network none --read-only \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=32m \
    --env AWG_ADBS="$adbs" -v "$(hostpath "$FEED"):/feed" \
    -v "$(hostpath "$secret/apkkey"):/sign:ro" -v "$(hostpath "$secret/apkpub"):/keys:ro" \
    "$APK_TOOLS_IMAGE" sh -euc '
    for a in $AWG_ADBS; do
      apk --allow-untrusted adbsign --sign-key /sign/wayhop-test.pem "/feed/$a"
      apk --keys-dir /keys verify "/feed/$a" >/dev/null
      echo "  signed $a (apk throwaway key)"
    done'
  signed=$((signed + nadb))
fi
[ "$signed" -gt 0 ] || { echo "qemu-feed-sign: no index found under $FEED - nothing was signed" >&2; exit 1; }
echo "qemu-feed-sign: $signed index(es) signed with throwaway keys; public halves in $KEYS"
