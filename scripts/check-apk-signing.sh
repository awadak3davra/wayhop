#!/bin/sh
# Exercise the exact apk-tools v3 sign/verify boundary used by feed.yml with disposable keys.
# The key-bearing container is immutable, read-only and has no network; real crypto, not a mock,
# proves that packages.adb signed by one key verifies only against its public half.
set -eu

APK_IMAGE="${WAYHOP_APK_TOOLS_IMAGE:-alpine:edge@sha256:d77617aef5805191da75fbbfe2f9dc2043582ecad0f4d381b27c151034765a76}"
GO_IMAGE="${WAYHOP_GO_IMAGE:-golang@sha256:2005724102f45917a63e9d092fc0e4ea56ea575048ce147caad5f5f61502c365}"

command -v docker >/dev/null 2>&1 || { echo "no docker — apk signing was NOT exercised" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "docker is not running — apk signing was NOT exercised" >&2; exit 3; }

hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }

work=$(mktemp -d)
cleanup() {
  st=$?
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$work"):/w" \
    "$APK_IMAGE" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || :
  rm -rf "$work" 2>/dev/null || :
  exit "$st"
}
trap cleanup EXIT

MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --network none --read-only \
  --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=512m \
  --env GOCACHE=/tmp/go-build \
  -v "$(hostpath "$PWD"):/src:ro" \
  -v "$(hostpath "$work"):/w" -w /src "$GO_IMAGE" sh -euc '
  go build -o /w/apk-keygen ./scripts/testdata/apk-keygen.go
  /w/apk-keygen /w/good.pem /w/good.pub
  /w/apk-keygen /w/wrong.pem /w/wrong.pub
'
mkdir "$work/good-sign" "$work/wrong-sign" "$work/good-keys" "$work/wrong-keys"
cp "$work/good.pem" "$work/good-sign/wayhop.pem"
cp "$work/wrong.pem" "$work/wrong-sign/wayhop.pem"
cp "$work/good.pub" "$work/good-keys/wayhop.pem"
cp "$work/wrong.pub" "$work/wrong-keys/wayhop.pem"
printf '#!/bin/sh\nexit 0\n' > "$work/dummy"
chmod +x "$work/dummy"

MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --network none --read-only \
  --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=64m \
  -v "$(hostpath "$PWD"):/src:ro" \
  -v "$(hostpath "$work"):/w" -w /src "$APK_IMAGE" sh -euc '
  sh packaging/feed/pack-apk.sh /w/dummy 1.0.0 1 /w/feed x86_64
  cd /w/feed/apk/x86_64
  apk --allow-untrusted mkndx -o packages.adb ./*.apk
  cp packages.adb unsigned.adb
' >/dev/null

dir="$work/feed/apk/x86_64"
sign_with() {
  keydir="$1"; file="$2"
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --network none --read-only \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=32m \
    -v "$(hostpath "$dir"):/repo" \
    -v "$(hostpath "$keydir"):/keys:ro" "$APK_IMAGE" apk --allow-untrusted adbsign --sign-key /keys/wayhop.pem "/repo/$file"
}
verify_with() {
  keydir="$1"; file="$2"
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --network none --read-only \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=32m \
    -v "$(hostpath "$dir"):/repo:ro" \
    -v "$(hostpath "$keydir"):/keys:ro" "$APK_IMAGE" apk --keys-dir /keys verify "/repo/$file"
}

pass=0
if verify_with "$work/good-keys" unsigned.adb >/dev/null 2>&1; then
  echo "FAIL  unsigned index verified" >&2; exit 1
else
  pass=$((pass + 1)); echo "  PASS  unsigned index is refused"
fi

sign_with "$work/good-sign" packages.adb >/dev/null
verify_with "$work/good-keys" packages.adb >/dev/null
pass=$((pass + 1)); echo "  PASS  signed index verifies against its public key"

if verify_with "$work/wrong-keys" packages.adb >/dev/null 2>&1; then
  echo "FAIL  signature verified against a different public key" >&2; exit 1
else
  pass=$((pass + 1)); echo "  PASS  wrong public key is refused"
fi

cp "$dir/packages.adb" "$dir/tampered.adb"
size=$(wc -c < "$dir/tampered.adb")
[ "$size" -gt 128 ] || { echo "FAIL  signed index is unexpectedly small" >&2; exit 1; }
printf '\377\376\375\374' | dd of="$dir/tampered.adb" bs=1 seek="$((size / 2))" conv=notrunc 2>/dev/null
cmp -s "$dir/packages.adb" "$dir/tampered.adb" && { echo "FAIL  tamper fixture did not change the index" >&2; exit 1; }
if verify_with "$work/good-keys" tampered.adb >/dev/null 2>&1; then
  echo "FAIL  modified signed index verified" >&2; exit 1
else
  pass=$((pass + 1)); echo "  PASS  modified signed index is refused"
fi

cp "$dir/unsigned.adb" "$dir/wrong-signed.adb"
sign_with "$work/wrong-sign" wrong-signed.adb >/dev/null
if verify_with "$work/good-keys" wrong-signed.adb >/dev/null 2>&1; then
  echo "FAIL  wrong signing key matched the published key" >&2; exit 1
else
  pass=$((pass + 1)); echo "  PASS  wrong signing key is refused by post-sign verification"
fi

echo "apk signing: $pass real-crypto checks passed with a pinned offline signer"
[ "$pass" = 5 ]
