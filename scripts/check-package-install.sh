#!/bin/sh
# check-package-install.sh — install, upgrade and remove the real package on a real OpenWrt.
#
# scripts/check-package-manifests.sh reads the packaging and asserts what it SAYS. This runs it: the
# .ipk is built by the shipped packer and handed to a real opkg inside an OpenWrt rootfs, and the
# guarantees are checked against the filesystem afterwards rather than against the script that was
# supposed to produce it.
#
# The one that matters most is the upgrade: /etc/wayhop is kept out of the payload so opkg cannot
# touch it, and the only way to know that holds is to put something in a config, upgrade over it, and
# look. A static reading of the packer cannot tell you what opkg actually did.
#
# Needs Docker. Without it this exits 3 and says so — a package lifecycle nobody exercised must not
# report as one that passed.
#
# Usage: check-package-install.sh
set -eu

# The releases this package claims to support, and the reason the list is here rather than one
# image: 21.02 was the release a hard `Depends: nftables` shut out completely, and a gate that only
# ever ran 23.05 would have called that "the package works". The oldest entry is the one most worth
# keeping — a regression at the top of the range is obvious, one at the bottom is invisible.
#
# WAYHOP_OPENWRT_IMAGE still names a single image, for a quick loop while working on the packer.
OPENWRT_IMAGES="${WAYHOP_OPENWRT_IMAGE:-${WAYHOP_OPENWRT_IMAGES:-openwrt/rootfs:x86-64-21.02.7@sha256:7fc2353153c65d64a35a5fb4dc21a15bb048d812c19df3d8d4ea97745349ef79 openwrt/rootfs:x86-64-22.03.6@sha256:56fef0e63771592a41054d7a3d301f2f65deb134ba5a4e1fff9c29b905ede95e openwrt/rootfs:x86-64-23.05.5@sha256:a44cce5d8f3619e30b0b7cf74e236d4e62cb3bf118953f57e044dc684d7cfc36 openwrt/rootfs:x86-64-24.10.4@sha256:1310ccbd24f30b3df6e210a48dbd0fb902445ee80e21ffc8b8e882b94987a411}}"
BUILDER_IMAGE="${WAYHOP_BUILDER_IMAGE:-debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931}"

command -v docker >/dev/null 2>&1 || {
  echo "no docker — the package lifecycle was NOT exercised" >&2
  exit 3
}
docker info >/dev/null 2>&1 || {
  echo "docker is installed but not running — the package lifecycle was NOT exercised" >&2
  exit 3
}
if [ -z "${WAYHOP_TEST_BINARY:-}" ]; then
  command -v go >/dev/null 2>&1 || { echo "no go toolchain on PATH and WAYHOP_TEST_BINARY is unset" >&2; exit 2; }
else
  [ -f "$WAYHOP_TEST_BINARY" ] || { echo "WAYHOP_TEST_BINARY does not name a file" >&2; exit 2; }
fi

# A bind mount needs a path the DAEMON understands. Git Bash hands out /tmp/... which Docker Desktop
# resolves as a Linux path that does not exist, so the mount came up empty and the packer reported a
# missing binary that was sitting right there. cygpath -m gives the daemon the form it wants; off
# Windows there is nothing to convert.
hostpath() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi
}

work=$(mktemp -d)

# The builder runs as root and writes into $work through the bind mount, so on a Linux host those
# files come back owned by root and the invoking user cannot remove them. Docker Desktop hides it —
# its bind mounts synthesise ownership — which is why one `rm -rf` in a trap behaved for months on
# the dev box and then bit on the first runner. It cost two distinct things:
#   - with `set -e`, a failing command in an EXIT trap makes the shell exit with THAT status, in
#     both dash and busybox ash. The gate printed all 52 of its checks and then reported failure.
#     A gate whose verdict can be decided by its own housekeeping is not measuring the package, so
#     the real status is taken before cleanup and restored after it.
#   - the temp tree was left behind on the runner. Hand the files back, then remove them.
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

# MSYS_NO_PATHCONV/MSYS2_ARG_CONV_EXCL: Git Bash rewrites a container path that looks like a unix
# path into a Windows one, so -w /w reached the daemon as W:/ and the run died before doing
# anything. Harmless on a Linux runner, required on the dev box.
# The packer needs GNU tar, which the OpenWrt rootfs does not carry — pack in the pinned Debian
# builder, install in the target. Two immutable images, each doing the one thing it has tools for.
echo "packing the .ipk with the shipped packer"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$PWD"):/src:ro" -v "$(hostpath "$work"):/w" -w /w "$BUILDER_IMAGE" sh -euc '
  cp -r /src/packaging /w/packaging
  SOURCE_DATE_EPOCH=0 sh /w/packaging/feed/pack-ipk.sh /w/wayhop-amd64 1.0.0 1 /w/out x86_64
  SOURCE_DATE_EPOCH=0 sh /w/packaging/feed/pack-ipk.sh /w/wayhop-amd64 1.0.1 1 /w/out2 x86_64
' >/dev/null

first=$(find "$work/out" -name '*.ipk' | head -n1)
second=$(find "$work/out2" -name '*.ipk' | head -n1)
[ -n "$first" ] && [ -n "$second" ] || { echo "the packer produced no .ipk" >&2; exit 1; }
cp "$first" "$work/wayhop-1.0.0.ipk"
cp "$second" "$work/wayhop-1.0.1.ipk"

total=0
for OPENWRT_IMAGE in $OPENWRT_IMAGES; do
echo "installing, upgrading and removing on $OPENWRT_IMAGE"
out=$(MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$work"):/pkg:ro" "$OPENWRT_IMAGE" sh -euc '
  # The rootfs image ships without /var/lock, which opkg needs for its own lock file. An artefact of
  # the container image, not of the package.
  mkdir -p /var/lock /var/run
  fail=0
  say() { echo "  $1  $2"; }
  ok()  { say PASS "$1"; }
  no()  { say FAIL "$1"; fail=$((fail + 1)); }

  # Installing over an older installation must SUCCEED and must not rewrite the operator config:
  # the daemon imports whatever applied state it finds on first start, so there is nothing for the
  # package scripts to refuse, and the one thing they must not do is replace a live config.
  mkdir -p /etc/wayhop /usr/sbin
  echo "LEGACY-CONFIG-KEEP" > /etc/wayhop/config.json
  echo "LEGACY-BINARY-KEEP" > /usr/sbin/wayhop
  chmod 0755 /usr/sbin/wayhop
  legacy_log=$(opkg install /pkg/wayhop-1.0.0.ipk 2>&1) && ok "an install over an older installation is accepted" || no "the install over an older installation was refused: $legacy_log"
  grep -q LEGACY-BINARY-KEEP /usr/sbin/wayhop && no "the install left the old binary in place" || ok "the install replaced the old binary"
  grep -q LEGACY-CONFIG-KEEP /etc/wayhop/config.json && ok "the install keeps the existing config" || no "the install overwrote the existing config"
  opkg remove wayhop >/dev/null 2>&1
  rm -rf /etc/wayhop /var/lib/wayhop
  rm -f /usr/sbin/wayhop

  install_log=$(opkg install /pkg/wayhop-1.0.0.ipk 2>&1) || {
    echo "  FAIL  opkg install refused the package: $install_log"; exit 1;
  }

  [ -x /usr/sbin/wayhop ]      && ok "the binary is installed executable at /usr/sbin/wayhop" || no "the binary is missing or not executable"
  [ -x /etc/init.d/wayhop ]    && ok "the procd init is installed executable"                 || no "the procd init is missing or not executable"
  [ -L /etc/rc.d/S95wayhop ] || [ -e /etc/rc.d/S95wayhop ] \
    && ok "the service is enabled for boot" || no "the service was not enabled (no rc.d entry)"
  [ -f /etc/wayhop/config.json ] && ok "a config was seeded" || no "no config was seeded"
  # busybox on OpenWrt has no stat -c, and the fallback quietly reported "?" as a mode — a check
  # whose subject it could not read, printed as a failure about the package.
  perms=$(ls -l /etc/wayhop/config.json | cut -c1-10)
  [ "$perms" = "-rw-------" ] && ok "the seeded config is owner-only ($perms)" || no "the seeded config is $perms, not -rw-------"
  state_perms=$(ls -ld /etc/wayhop | cut -c1-10)
  data_perms=$(ls -ld /var/lib/wayhop | cut -c1-10)
  [ "$state_perms" = "drwx------" ] && ok "the state root is owner-only ($state_perms)" || no "the state root is $state_perms"
  [ "$data_perms" = "drwx------" ] && ok "the data root is owner-only ($data_perms)" || no "the data root is $data_perms"

  # opkg must not own the config tree: that omission is what makes an upgrade safe.
  if opkg files wayhop 2>/dev/null | grep -q "/etc/wayhop/"; then
    no "the package OWNS files under /etc/wayhop — an upgrade or a remove could clobber them"
  else
    ok "the package owns nothing under /etc/wayhop"
  fi

  # The upgrade case. A marker in the config, and a profile the operator would have created.
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

  upgrade_log=$(opkg install /pkg/wayhop-1.0.1.ipk 2>&1) || {
    echo "  FAIL  the upgrade was refused: $upgrade_log"; exit 1;
  }
  [ "$(cat /etc/wayhop/config.json)" = "$before" ] \
    && ok "the config survived the upgrade byte for byte" || no "the upgrade rewrote the config"
  grep -q MARKER-KEEP-ME /etc/wayhop/config.json \
    && ok "an operator edit survived the upgrade" || no "an operator edit was lost in the upgrade"
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

  opkg remove wayhop >/dev/null 2>&1 || { echo "  FAIL  opkg remove failed"; exit 1; }
  [ ! -e /usr/sbin/wayhop ] && ok "the remove took the binary" || no "the remove left the binary behind"
  [ -f /etc/wayhop/config.json ] && ok "the remove KEPT the operator config" || no "the remove deleted the config"
  grep -q MARKER-KEEP-ME /etc/wayhop/config.json 2>/dev/null \
    && ok "the operator edit is still there after the remove" || no "the operator edit was deleted on remove"

  echo "COUNT $fail"
  [ "$fail" = 0 ]
') || {
  echo "$out"
  echo "the package lifecycle failed on a real OpenWrt" >&2
  exit 1
}
echo "$out" | grep -v '^COUNT '
n=$(echo "$out" | grep -c '  PASS ')
total=$((total + n))
done

# The per-image counts are summed: a run that quietly dropped an image would report a smaller number
# than the evidence floor, rather than passing with fewer releases measured.
echo "package lifecycle: $total checks on a real opkg — install, upgrade with an operator edit, remove"
