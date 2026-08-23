#!/bin/sh
# check-package-install-apk.sh — the same lifecycle, on the format the supported router actually uses.
#
# check-package-install.sh drives opkg, which is OpenWrt 23/24. OpenWrt 25.x ships apk and no opkg at
# all — it is the release a live router runs, and the one the .ipk being broken went unnoticed
# behind. A format nobody exercises is how that happened once; leaving the other half unexercised
# would be the same bet on the other side.
#
# Packed with an immutable Alpine edge digest that already contains apk-tools v3 (`apk mkpkg`); no
# mutable package install happens during the gate. It is installed in the OpenWrt image, which is
# where the maintainer scripts have to work.
#
# Needs Docker. Without it this exits 3 and says so — a lifecycle nobody ran must not report as one
# that passed.
set -eu

TARGET_IMAGE="${WAYHOP_APK_TARGET_IMAGE:-openwrt/rootfs:x86-64-25.12.0@sha256:1a7f3e9c66e6b77d4014b7e37ffbee7edf114275dc6f1811314a572e11a8e636}"
BUILDER_IMAGE="${WAYHOP_APK_BUILDER_IMAGE:-alpine:edge@sha256:d77617aef5805191da75fbbfe2f9dc2043582ecad0f4d381b27c151034765a76}"

command -v docker >/dev/null 2>&1 || { echo "no docker — the apk lifecycle was NOT exercised" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "docker is not running — the apk lifecycle was NOT exercised" >&2; exit 3; }
if [ -z "${WAYHOP_TEST_BINARY:-}" ]; then
  command -v go >/dev/null 2>&1 || { echo "no go toolchain on PATH and WAYHOP_TEST_BINARY is unset" >&2; exit 2; }
else
  [ -f "$WAYHOP_TEST_BINARY" ] || { echo "WAYHOP_TEST_BINARY does not name a file" >&2; exit 2; }
fi

# Git Bash rewrites unix-looking container paths into Windows ones, and hands the daemon a mount
# source it cannot resolve. Both are no-ops on a Linux runner.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }

work=$(mktemp -d)

# Same root-owned-bind-mount trap as check-package-install.sh, and it would have bitten here for
# the same reason: with `set -e` a failing `rm` in an EXIT trap becomes the script's exit status,
# so a lifecycle that passed would report failure. The opkg gate reached the runner first and hid
# this one behind its own red step. Take the status before cleanup, restore it after.
cleanup() {
  st=$?
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$work"):/w" \
    "$BUILDER_IMAGE" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || :
  rm -rf "$work" 2>/dev/null || :
  exit "$st"
}
trap cleanup EXIT

echo "building an amd64 binary for the package"
if [ -n "${WAYHOP_TEST_BINARY:-}" ]; then
  cp "$WAYHOP_TEST_BINARY" "$work/wayhop-amd64"
else
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$work/wayhop-amd64" ./cmd/wayhop
fi

echo "packing two versions with the shipped packer"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm \
  -v "$(hostpath "$PWD"):/src:ro" -v "$(hostpath "$work"):/w" -w /w "$BUILDER_IMAGE" sh -euc '
  # No probe for mkpkg here: `apk mkpkg --help` exits non-zero even when the subcommand exists, so
  # the probe reported the tool absent while packing with it worked. The packer needs mkpkg and
  # fails with the message apk itself gives, which is the more accurate report anyway.
  cp -r /src/packaging /w/packaging
  sh /w/packaging/feed/pack-apk.sh /w/wayhop-amd64 1.0.0 1 /w/out  x86_64
  sh /w/packaging/feed/pack-apk.sh /w/wayhop-amd64 1.0.1 1 /w/out2 x86_64
' >/dev/null

[ -n "$(find "$work/out" -name '*.apk' | head -n1)" ] || { echo "the packer produced no .apk" >&2; exit 1; }

echo "installing, upgrading and removing on $TARGET_IMAGE"
legacy_out=$(MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$work"):/pkg:ro" "$TARGET_IMAGE" sh -euc '
  mkdir -p /etc/wayhop /usr/sbin
  echo "LEGACY-CONFIG-KEEP" > /etc/wayhop/config.json
  echo "LEGACY-BINARY-KEEP" > /usr/sbin/wayhop
  chmod 0755 /usr/sbin/wayhop
  apk add --allow-untrusted /pkg/out/apk/x86_64/*.apk >/dev/null 2>&1 \
    || { echo "  FAIL  the install over an older installation was refused"; exit 1; }
  echo "  PASS  an install over an older installation is accepted"
  grep -q LEGACY-BINARY-KEEP /usr/sbin/wayhop \
    && { echo "  FAIL  the install left the old binary in place"; exit 1; } \
    || echo "  PASS  the install replaced the old binary"
  grep -q LEGACY-CONFIG-KEEP /etc/wayhop/config.json \
    && echo "  PASS  the install keeps the existing config" \
    || { echo "  FAIL  the install overwrote the existing config"; exit 1; }
') || {
  echo "$legacy_out"
  echo "the apk install-over-an-older-installation lifecycle failed on OpenWrt" >&2
  exit 1
}
echo "$legacy_out"
legacy_n=$(echo "$legacy_out" | grep -c '  PASS ')

out=$(MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$work"):/pkg:ro" "$TARGET_IMAGE" sh -euc '
  fail=0
  ok() { echo "  PASS  $1"; }
  no() { echo "  FAIL  $1"; fail=$((fail + 1)); }

  command -v opkg >/dev/null 2>&1 && no "this image has opkg — it is not the apk-only release this gate is for" \
    || ok "the target is the apk-only OpenWrt release"

  install_log=$(apk add --allow-untrusted /pkg/out/apk/x86_64/*.apk 2>&1) || {
    echo "  FAIL  apk refused the package: $install_log"; exit 1;
  }

  [ -x /usr/sbin/wayhop ]   && ok "the binary is installed executable at /usr/sbin/wayhop" || no "the binary is missing or not executable"
  [ -x /etc/init.d/wayhop ] && ok "the procd init is installed executable"                 || no "the procd init is missing or not executable"
  [ -f /etc/wayhop/config.json ] && ok "a config was seeded" || no "no config was seeded"
  perms=$(ls -l /etc/wayhop/config.json | cut -c1-10)
  [ "$perms" = "-rw-------" ] && ok "the seeded config is owner-only ($perms)" || no "the seeded config is $perms"
  [ "$(ls -ld /etc/wayhop | cut -c1-10)" = "drwx------" ] && ok "the state root is owner-only" || no "the state root is listable"
  [ "$(ls -ld /var/lib/wayhop | cut -c1-10)" = "drwx------" ] && ok "the data root is owner-only" || no "the data root is listable"

  # Protection by omission: apk must not own the config tree either.
  if apk info -L wayhop 2>/dev/null | grep -q "etc/wayhop/"; then
    no "the package OWNS files under /etc/wayhop — an upgrade or a remove could clobber them"
  else
    ok "the package owns nothing under /etc/wayhop"
  fi

  echo "MARKER-KEEP-ME" >> /etc/wayhop/config.json
  echo "{\"endpoints\":[]}" > /etc/wayhop/profile.json
  echo "CACHE-MODE-FIXTURE" > /etc/wayhop/cache.db
  mkdir -p /etc/wayhop/plugins /var/lib/wayhop/backups
  echo "DATA-PROFILE-MODE-FIXTURE" > /var/lib/wayhop/profile.json
  echo "PLUGIN-MODE-FIXTURE" > /etc/wayhop/plugins/test.conf
  echo "OPERATOR-NOTE" > /etc/wayhop/plugins/operator-note.txt
  echo "BACKUP-MODE-FIXTURE" > /var/lib/wayhop/backups/wayhop-backup-20260101T000000Z.json
  echo "OPERATOR-BACKUP-NOTE" > /var/lib/wayhop/backups/operator-note.txt
  chmod 0755 /etc/wayhop /etc/wayhop/plugins /var/lib/wayhop /var/lib/wayhop/backups
  chmod 0644 /etc/wayhop/profile.json /etc/wayhop/cache.db /etc/wayhop/plugins/test.conf \
    /var/lib/wayhop/profile.json \
    /etc/wayhop/plugins/operator-note.txt /var/lib/wayhop/backups/wayhop-backup-20260101T000000Z.json \
    /var/lib/wayhop/backups/operator-note.txt
  before=$(cat /etc/wayhop/config.json)

  upgrade_log=$(apk add --allow-untrusted /pkg/out2/apk/x86_64/*.apk 2>&1) || {
    echo "  FAIL  the upgrade was refused: $upgrade_log"; exit 1;
  }
  [ "$(cat /etc/wayhop/config.json)" = "$before" ] && ok "the config survived the upgrade byte for byte" || no "the upgrade rewrote the config"
  grep -q MARKER-KEEP-ME /etc/wayhop/config.json && ok "an operator edit survived the upgrade" || no "an operator edit was lost in the upgrade"
  [ -f /etc/wayhop/profile.json ] && ok "the profile survived the upgrade" || no "the profile was lost in the upgrade"
  [ -x /usr/sbin/wayhop ] && ok "the binary is still installed after the upgrade" || no "the upgrade left no binary"
  [ "$(ls -ld /etc/wayhop | cut -c1-10)" = "drwx------" ] && ok "upgrade repairs the state root to 0700" || no "upgrade left the state root listable"
  [ "$(ls -ld /var/lib/wayhop | cut -c1-10)" = "drwx------" ] && ok "upgrade repairs the data root to 0700" || no "upgrade left the data root listable"
  [ "$(ls -l /etc/wayhop/profile.json | cut -c1-10)" = "-rw-------" ] && ok "upgrade repairs profile.json to 0600" || no "upgrade left profile.json readable"
  [ "$(ls -l /etc/wayhop/cache.db | cut -c1-10)" = "-rw-------" ] && ok "upgrade repairs cache.db to 0600" || no "upgrade left cache.db readable"
  [ "$(ls -l /var/lib/wayhop/profile.json | cut -c1-10)" = "-rw-------" ] && ok "upgrade repairs a legacy data-root profile to 0600" || no "upgrade left a data-root profile readable"
  [ "$(ls -ld /etc/wayhop/plugins | cut -c1-10)" = "drwx------" ] && ok "upgrade repairs the plugin directory to 0700" || no "upgrade left the plugin directory listable"
  [ "$(ls -l /etc/wayhop/plugins/test.conf | cut -c1-10)" = "-rw-------" ] && ok "upgrade repairs plugin configs to 0600" || no "upgrade left plugin configs readable"
  [ "$(ls -l /var/lib/wayhop/backups/wayhop-backup-20260101T000000Z.json | cut -c1-10)" = "-rw-------" ] && ok "upgrade repairs WayHop backups to 0600" || no "upgrade left WayHop backups readable"
  [ "$(ls -l /etc/wayhop/plugins/operator-note.txt | cut -c1-10)" = "-rw-r--r--" ] && ok "plugin operator files keep their original mode" || no "upgrade changed an unrelated plugin file"
  [ "$(ls -l /var/lib/wayhop/backups/operator-note.txt | cut -c1-10)" = "-rw-r--r--" ] && ok "backup operator files keep their original mode" || no "upgrade changed an unrelated backup file"

  apk del wayhop >/dev/null 2>&1 || { echo "  FAIL  apk del failed"; exit 1; }
  [ ! -e /usr/sbin/wayhop ] && ok "the remove took the binary" || no "the remove left the binary behind"
  [ -f /etc/wayhop/config.json ] && ok "the remove KEPT the operator config" || no "the remove deleted the config"
  grep -q MARKER-KEEP-ME /etc/wayhop/config.json 2>/dev/null && ok "the operator edit is still there after the remove" || no "the operator edit was deleted on remove"

  [ "$fail" = 0 ]
') || {
  echo "$out"
  echo "the apk lifecycle failed on OpenWrt" >&2
  exit 1
}
echo "$out"
n=$((legacy_n + $(echo "$out" | grep -c '  PASS ')))
echo "apk lifecycle: $n checks on a real apk — install, upgrade with an operator edit, remove"
