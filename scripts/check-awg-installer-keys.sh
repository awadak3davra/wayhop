#!/bin/sh
# check-awg-installer-keys.sh -- the feed keys embedded in the AmneziaWG installer must be the keys
# the feed is signed with.
#
# install-awg.sh carries WayHop's usign key (opkg feeds), its fingerprint (the file name opkg looks
# the key up by) and the apk key (OpenWrt 25.12+), so a router can trust the feed without fetching a
# key over the same channel as the packages. The --with-awg hooks in bootstrap.sh and both
# install.sh carry the release key (the same usign key) to verify a downloaded install-awg.sh.
# A rotated key in packaging/feed/keys/ that does not reach these copies would make every new
# install refuse the feed, or keep trusting a retired key; this fails the build on any drift.
#
# Usage: sh scripts/check-awg-installer-keys.sh   (from the repository root)
set -u

USIGN_PUB="packaging/feed/keys/wayhop.pub"
APK_PUB="packaging/feed/keys/wayhop-apk.pem.pub"
INSTALLER="packaging/awg/install-awg.sh"
for f in "$USIGN_PUB" "$APK_PUB" "$INSTALLER" packaging/bootstrap.sh; do
  [ -s "$f" ] || { echo "FAIL  $f is missing: this check has no subject" >&2; exit 2; }
done

work="$(mktemp -d)" || exit 2
trap 'rm -rf "$work"' EXIT
fails=0; checks=0

# extract FILE VAR -> the (possibly multi-line) value of VAR="..." as the script assigns it
extract() {
  awk -v v="$2" '
    !inside && index($0, v "=\"") == 1 { inside = 1; $0 = substr($0, length(v) + 3) }
    inside { if (sub(/"$/, "")) { print; exit } print }' "$1"
}

same() { # label file-with-embedded-value VAR reference-file
  checks=$((checks + 1))
  extract "$2" "$3" > "$work/got"
  if [ ! -s "$work/got" ]; then
    echo "FAIL  $1: $2 has no $3"; fails=$((fails + 1)); return
  fi
  if cmp -s "$work/got" "$4"; then echo "  ok  $1"
  else echo "FAIL  $1: $3 in $2 differs from $4"; fails=$((fails + 1)); fi
}

# The usign key id: bytes 2..9 of the decoded key ("Ed" | keynum[8] | pub[32]), as `usign -F` prints.
fingerprint_of() {
  sed -n '2p' "$1" | tr -d '\r' | base64 -d 2>/dev/null | od -An -tx1 -j2 -N8 | tr -d ' \n'
}

same "install-awg.sh usign key"  "$INSTALLER" AWG_USIGN_PUBKEY "$USIGN_PUB"
same "install-awg.sh apk key"    "$INSTALLER" AWG_APK_PUBKEY   "$APK_PUB"
checks=$((checks + 1))
want_fp="$(fingerprint_of "$USIGN_PUB")"
got_fp="$(extract "$INSTALLER" AWG_USIGN_FINGERPRINT)"
if [ "${#want_fp}" != 16 ]; then
  echo "FAIL  cannot compute the fingerprint of $USIGN_PUB (need base64 and od)"; fails=$((fails + 1))
elif [ "$got_fp" = "$want_fp" ]; then
  echo "  ok  install-awg.sh usign fingerprint ($want_fp)"
else
  echo "FAIL  install-awg.sh AWG_USIGN_FINGERPRINT is '$got_fp', $USIGN_PUB has id $want_fp"; fails=$((fails + 1))
fi

# Release key copies used by the --with-awg hooks (bootstrap.sh's is also checked by build.yml).
same "bootstrap.sh release key" packaging/bootstrap.sh RELEASE_PUBKEY "$USIGN_PUB"
for f in packaging/install.sh packaging/openwrt/install.sh; do
  if grep -q '^RELEASE_PUBKEY="' "$f" 2>/dev/null; then same "$f release key" "$f" RELEASE_PUBKEY "$USIGN_PUB"; fi
done

# The comparison must be able to fail: a copy with one character changed has to be caught.
sed 's/^RWRP/RWRQ/' "$INSTALLER" > "$work/mutated.sh"
extract "$work/mutated.sh" AWG_USIGN_PUBKEY > "$work/mut"
if cmp -s "$work/mut" "$USIGN_PUB"; then
  echo "FAIL  self-test: a changed key still compares equal, so this check proves nothing"; fails=$((fails + 1))
fi

if [ "$fails" -gt 0 ]; then echo "$fails of $checks embedded key check(s) failed" >&2; exit 1; fi
echo "embedded feed keys match packaging/feed/keys: $checks checks"
