#!/bin/sh
# openwrt_upgrade_harness.sh - the tarball installers re-run as an UPGRADE on a nearly full flash, their
# --cleanup, and the update supervisor that rolls a bad build back: on the real OpenWrt userland (25.12
# apk and 24.10 opkg images) and on an Entware-like /opt (Alpine busybox, the real S99wayhop).
#
# Why this exists: the AX3000T's overlay is 60 MiB with 13-20 MiB free and a WayHop binary is
# ~14 MiB. The upgrade used to need room for two more binaries beside the old one and its previous
# rollback copy, failed half-way, and left the service stopped with a partial wayhop.new holding the
# room. Every case below boots a fresh container whose install directory sits on a small tmpfs (as an
# overlay with a small upper layer on OpenWrt, as /opt on Entware), installs the OLD tarball, fills
# the flash to a chosen level, seeds what earlier installs and hand deploys leave behind, runs the NEW
# tarball's installer (or the supervisor) and checks the result on disk and on the port:
#
#   raw        room for the new binary only (not the old installer's two): upgrades, the rollback copy
#              is the old binary (hard link), nothing left behind, the result recorded as ok
#   gz         room for less than the new binary: upgrades with the old binary kept as a verified
#              wayhop.bak.gz
#   full       room for neither: refuses BEFORE stopping anything, names the MiB to free, the old
#              daemon still answers and nothing on disk changed
#   leftovers  partial staging files, old-name builds, an orphaned temp dir: reclaimed first, so the
#              upgrade fits; files that are not WayHop's are untouched
#   obsolete   an older hand-deployed build is what blocks it: removed because the upgrade needs it
#   cleanup    --cleanup --dry-run lists and changes nothing; --cleanup removes leftovers, keeps one
#              rollback copy compressed, never touches the running binary or the daemon
#   apkcopy    (OpenWrt) the second binary copy an older apk install left becomes a hard link
#   rollback   the installer's new build never answers: rolled back from the compressed copy
#   vcrash     the panel's swap to a build that crashes on start, judged by update-verify.sh: rolled
#              back, the reason recorded, and judged once (a second run finds nothing to do)
#   vhang      ... to a build that runs and never answers: rolled back
#   vwrong     ... where another build answers on the port: rolled back
#   vok        ... to a build that answers: kept, and on a nearly full flash the plain rollback copy
#              is compressed
#   vboot      a second boot inside the window rolls back at once
#   vinit      (Entware) the init itself finishes an unjudged update at start
#
# procd cannot run in a container, so on OpenWrt the tarballs' init is replaced by a start-stop-daemon
# stand-in; scripts/qemu-update.sh covers the real procd path on a booted OpenWrt. Needs Docker with
# --privileged (for the mounts); without Docker it exits 3 and says nothing was tested.
#
# Usage: sh packaging/test/openwrt_upgrade_harness.sh
# Env:   WAYHOP_UPGRADE_OLD / WAYHOP_UPGRADE_NEW  amd64 tarballs (OpenWrt flavour) to upgrade between
#        (default: two builds of this tree, stamped apart). WAYHOP_UPGRADE_NEW_BIN  an amd64 binary to
#        pack with THIS tree's scripts. WAYHOP_UPGRADE_IMAGES  "flavour|image" words.
#        WAYHOP_UPGRADE_CASES, GO (the go command; default: go).
set -eu

IMAGES="${WAYHOP_UPGRADE_IMAGES:-openwrt|openwrt/rootfs:x86-64-25.12.0@sha256:1a7f3e9c66e6b77d4014b7e37ffbee7edf114275dc6f1811314a572e11a8e636 openwrt|openwrt/rootfs:x86-64-24.10.4@sha256:1310ccbd24f30b3df6e210a48dbd0fb902445ee80e21ffc8b8e882b94987a411 entware|alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6}"
CASES="${WAYHOP_UPGRADE_CASES:-raw gz full leftovers obsolete cleanup apkcopy rollback vcrash vhang vwrong vok vboot vinit}"
MARGIN_KB=2048   # the installers' MARGIN_KB: the cases sit just either side of its thresholds

# =================================================================================================
# Inside the container
# =================================================================================================
guest() {
  set +e   # every failure here is a finding to report, not a reason to stop reporting
  CASE="$1"; TAG="$2"; FLAV="$3"; F=0
  pass() { echo "  PASS  [$TAG $CASE] $1"; }
  fail() { echo "  FAIL  [$TAG $CASE] $1"; F=$((F + 1)); }
  check() { _d="$1"; shift; if "$@"; then pass "$_d"; else fail "$_d"; fi; }
  case "$CASE:$FLAV" in apkcopy:entware|vinit:openwrt) echo "  SKIPPED [$TAG $CASE] not this flavour's"; return 0 ;; esac
  if [ "$FLAV" = entware ]; then
    S=/opt/sbin; E=/opt/etc/wayhop; INIT=/opt/etc/init.d/S99wayhop
    if ! { mkdir -p /opt && mount -t tmpfs -o size=72m,mode=0755 tmpfs /opt && mkdir -p /opt/sbin /opt/bin /opt/etc/init.d /opt/var; }; then
      echo "  FAIL  [$TAG $CASE] could not mount the small /opt (the container needs --privileged)"; return 1
    fi
    printf '#!/bin/sh\necho "sing-box version 1.12.17"\n' > /opt/sbin/sing-box && chmod 0755 /opt/sbin/sing-box
  else
    S=/usr/sbin; E=/etc/wayhop; INIT=/etc/init.d/wayhop
    mkdir -p /mnt/ov
    if ! { mount -t tmpfs -o size=72m tmpfs /mnt/ov && mkdir -p /mnt/ov/u /mnt/ov/w &&
           mount -t overlay overlay -o lowerdir=/usr,upperdir=/mnt/ov/u,workdir=/mnt/ov/w /usr; }; then
      echo "  FAIL  [$TAG $CASE] could not build the small overlay (the container needs --privileged)"; return 1
    fi
    # A stand-in sing-box: with none, the installer offers the feed's (~46 MiB) and the overlay is gone.
    printf '#!/bin/sh\necho "sing-box version 1.12.17"\n' > /usr/bin/sing-box && chmod 0755 /usr/bin/sing-box
  fi
  unpack() {
    rm -rf "/tmp/$1"; mkdir -p "/tmp/$1"; tar -xzf "/w/$FLAV-$1.tar.gz" -C "/tmp/$1"; chmod 0755 /tmp/"$1"/*
    [ "$FLAV" = openwrt ] && cp /w/test-init "/tmp/$1/wayhop.init"
    return 0
  }
  # A sync that notes whether the update marker was on the flash while the new binary still waited for
  # its name: the installer's one sync ran before the marker existed, so a power cut could keep the
  # marker's rename with no data, and verify.sh drops an empty marker at boot.
  mkdir -p /tmp/stub
  printf '#!/bin/sh\n[ -s "%s/update.pending" ] && [ -e "%s/wayhop.new" ] && echo marker-synced-before-swap >> "${SYNC_LOG:-/dev/null}"\nexec /bin/sync "$@"\n' \
    "$E" "$S" > /tmp/stub/sync && chmod 0755 /tmp/stub/sync
  inst() { _t="$1"; shift; rm -f "/tmp/$_t.sync"; ( cd "/tmp/$_t" && SYNC_LOG="/tmp/$_t.sync" PATH="/tmp/stub:$PATH" sh ./install.sh -y "$@" ) < /dev/null > "/tmp/$_t.log" 2>&1; echo $? > "/tmp/$_t.rc"; }
  marker_synced() { grep -q marker-synced-before-swap "/tmp/$1.sync" 2>/dev/null; }
  rc_of() { cat "/tmp/$1.rc"; }
  logged() { grep -q -e "$2" "/tmp/$1.log"; }
  avail() { df -Pk "$S" | awk 'NR == 2 { print $4 }'; }
  kib() { echo $(( ($(wc -c < "$1") + 1023) / 1024 )); }
  sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
  fill_to() { rm -f "$S/.filler"; _n=$(( $(avail) - $1 )); [ "$_n" -le 0 ] || dd if=/dev/zero of="$S/.filler" bs=1024 count="$_n" 2>/dev/null; FILLER="$(sha "$S/.filler")"; }
  answers() { # the daemon on :8088 is the build in $1
    _h="$(wget -q -O - -T 3 http://127.0.0.1:8088/api/health 2>/dev/null || true)"
    sh /tmp/old/identity-match.sh "$("$1" --version 2>/dev/null)" "$_h"
  }
  answers_soon() { _i=0; while [ "$_i" -lt 20 ]; do answers "$1" && return 0; sleep 1; _i=$((_i + 1)); done; return 1; }
  pidnow() { if [ "$FLAV" = openwrt ]; then cat /tmp/wayhop-test.pid 2>/dev/null; else pidof wayhop; fi; }
  absent() { for _f in "$@"; do [ ! -e "$_f" ] || return 1; done; }
  partials_gone() { absent "$S/wayhop.new" "$S/wayhop.bak.new" "$S/wayhop.bak.gz.new" "$S/wayhop.rb"; }
  user_files_intact() {
    [ "$(cat "$S/wayhop.bak-notes" 2>/dev/null)" = "my notes" ] && [ "$(cat "$S/mytool.new" 2>/dev/null)" = "not wayhop" ] &&
      { [ -z "${FILLER:-}" ] || [ "$(sha "$S/.filler")" = "$FILLER" ]; }
  }
  gz_is() { [ -f "$S/wayhop.bak.gz" ] && [ "$(gzip -dc "$S/wayhop.bak.gz" | sha256sum | cut -d' ' -f1)" = "$1" ]; }
  result_is() { grep -q "\"result\":\"$1\"" "$E/update-result.json" 2>/dev/null; }
  reason_has() { grep -q "$1" "$E/update-result.json" 2>/dev/null; }
  commit_of() { "$1" --version 2>/dev/null | sed -n 's/^wayhop [^ ]* (\([0-9a-f]*\),.*/\1/p'; }
  # sim_swap <new binary> <want commit> [boots]: the panel's self-update, as the daemon performs it --
  # the rollback copy a hard link, the update recorded, the new build renamed into place.
  sim_swap() {
    rm -f "$S/wayhop.bak.tmp"; ln "$S/wayhop" "$S/wayhop.bak.tmp" && mv "$S/wayhop.bak.tmp" "$S/wayhop.bak"
    printf 'bin=%s\ninit=%s\nconfig=%s\nrollback=%s\nnorollback=\nwant_commit=%s\nwant_version=\nfrom=%s\nto=v9.9.9\nby=panel\nwindow=15\nboots=%s\n' \
      "$S/wayhop" "$INIT" "$E/config.json" "$S/wayhop.bak" "$2" "$("$S/wayhop" --version | head -n 1)" "${3:-0}" > "$E/update.pending"
    cp "$1" "$S/wayhop.new" && chmod 0755 "$S/wayhop.new" && mv "$S/wayhop.new" "$S/wayhop"
  }
  judge() { sh "$E/update-verify.sh" "$@" < /dev/null > /tmp/verify.log 2>&1; }

  unpack old; unpack new
  OLD=/tmp/old/wayhop-amd64; NEW=/tmp/new/wayhop-amd64
  OLD_SHA="$(sha "$OLD")"; NEW_SHA="$(sha "$NEW")"
  N_OLD="$(kib "$OLD")"; N_NEW="$(kib "$NEW")"; G_OLD=$(( $(gzip -c "$OLD" | wc -c) / 1024 + 1 ))
  DELTA=0; [ "$N_NEW" -gt "$N_OLD" ] && DELTA=$((N_NEW - N_OLD))
  printf 'my notes\n' > "$S/wayhop.bak-notes"   # names that look like ours, contents that are not
  printf 'not wayhop\n' > "$S/mytool.new"
  inst old
  if [ "$(rc_of old)" != 0 ] || ! answers_soon "$OLD"; then
    fail "the old tarball did not install: $(tail -n 3 /tmp/old.log | tr '\n' ' ')"; return 1
  fi
  # The supervisor cases start from the NEW build installed and judged by its own installer.
  case "$CASE" in v*)
    inst new
    if [ "$(rc_of new)" != 0 ] || ! answers_soon "$NEW"; then
      fail "the new tarball did not install: $(tail -n 3 /tmp/new.log | tr '\n' ' ')"; return 1
    fi
    check "the installer wrote the update supervisor beside the config" [ -f "$E/update-verify.sh" ]
    [ -f "$E/update-verify.sh" ] || cp /w/update-verify.sh "$E/update-verify.sh"   # a release binary predates it
    ;;
  esac

  case "$CASE" in
    raw)
      fill_to $((N_NEW + MARGIN_KB + 1024))
      inst new
      check "upgrades with room for the new binary alone (the old installer needed $(( (N_NEW + N_OLD) / 1024 )) MiB)" [ "$(rc_of new)" = 0 ]
      check "the new build answers on the port" answers "$NEW"
      check "the binary is the new build" [ "$(sha "$S/wayhop")" = "$NEW_SHA" ]
      check "the rollback copy is the old build" [ "$(sha "$S/wayhop.bak")" = "$OLD_SHA" ]
      check "no compressed copy beside the plain one" absent "$S/wayhop.bak.gz"
      check "no staging file left behind" partials_gone
      check "the update is recorded as judged ok, nothing left pending" sh -c "grep -q '\"result\":\"ok\"' '$E/update-result.json' && [ ! -e '$E/update.pending' ]"
      check "the update marker was synced before the new binary took the name" marker_synced new
      check "files that are not WayHop's are untouched" user_files_intact ;;
    gz)
      fill_to $((G_OLD + MARGIN_KB + DELTA + 1536))
      inst new
      check "upgrades with less room than the new binary takes" [ "$(rc_of new)" = 0 ]
      check "it said why it keeps a compressed copy" logged new "compressed rollback copy"
      check "the new build answers on the port" answers "$NEW"
      check "the binary is the new build" [ "$(sha "$S/wayhop")" = "$NEW_SHA" ]
      check "wayhop.bak.gz unpacks to the old build" gz_is "$OLD_SHA"
      check "no plain rollback copy" absent "$S/wayhop.bak"
      check "no staging file left behind" partials_gone
      check "files that are not WayHop's are untouched" user_files_intact ;;
    full)
      fill_to $((G_OLD / 2))
      _p="$(pidnow)"
      inst new
      check "refuses" [ "$(rc_of new)" != 0 ]
      check "names the MiB to free" logged new "free at least [0-9]* MiB more"
      check "says the running WayHop was not stopped" logged new "was not stopped"
      check "the old daemon still answers, never restarted" [ "$_p" = "$(pidnow)" ]
      check "the old build still answers on the port" answers "$OLD"
      check "the binary is still the old build" [ "$(sha "$S/wayhop")" = "$OLD_SHA" ]
      check "no rollback copy and no staging file written" absent "$S/wayhop.bak" "$S/wayhop.bak.gz" "$S/wayhop.new"
      check "files that are not WayHop's are untouched" user_files_intact ;;
    leftovers)
      head -c 3145728 /dev/urandom > "$S/wayhop.new"                 # an interrupted install
      head -c 2097152 /dev/urandom > "$S/.wayhop.new"                # an interrupted panel update
      head -c 2097152 /dev/urandom > "$S/wayhop.bak.tmp"
      touch -d "2026-01-01 00:00:00" "$S/.wayhop.new" "$S/wayhop.bak.tmp"
      cp "$OLD" "$S/velinx"                                          # the old project name, no service
      cp "$OLD" "$S/wakeroute.bak-fb51ee6"
      mkdir -p /tmp/wayhop-boot.99999 && head -c 1048576 /dev/urandom > /tmp/wayhop-boot.99999/junk
      touch -d "2026-01-01 00:00:00" /tmp/wayhop-boot.99999
      fill_to $((N_NEW + MARGIN_KB - 3072))
      inst new
      check "upgrades once its own leftovers are gone" [ "$(rc_of new)" = 0 ]
      check "it reported what it reclaimed" logged new "reclaimed [0-9]* MiB"
      check "the new build answers on the port" answers "$NEW"
      check "a plain rollback copy of the old build (the room was there after the reclaim)" [ "$(sha "$S/wayhop.bak")" = "$OLD_SHA" ]
      check "staging files, old-name builds and the orphaned temp dir are gone" \
        absent "$S/.wayhop.new" "$S/wayhop.bak.tmp" "$S/velinx" "$S/wakeroute.bak-fb51ee6" /tmp/wayhop-boot.99999
      check "files that are not WayHop's are untouched" user_files_intact ;;
    obsolete)
      { cat "$OLD"; printf x; } > "$S/wayhop.bak-1234abc"            # an older hand-deployed build
      fill_to $((G_OLD / 2))
      inst new
      check "upgrades once the older build is out of the way" [ "$(rc_of new)" = 0 ]
      check "it said the older build was in the way" logged new "older WayHop builds beside the binary are in the way"
      check "the older build is gone" absent "$S/wayhop.bak-1234abc"
      check "the new build answers on the port" answers "$NEW"
      check "a rollback copy of the old build is kept" sh -c "[ \"\$(sha256sum '$S/wayhop.bak' 2>/dev/null | cut -d' ' -f1)\" = '$OLD_SHA' ] || [ \"\$(gzip -dc '$S/wayhop.bak.gz' 2>/dev/null | sha256sum | cut -d' ' -f1)\" = '$OLD_SHA' ]"
      check "files that are not WayHop's are untouched" user_files_intact ;;
    cleanup)
      inst new
      [ "$(rc_of new)" = 0 ] || { fail "the setup upgrade failed: $(tail -n 3 /tmp/new.log | tr '\n' ' ')"; return 1; }
      head -c 3145728 /dev/urandom > "$S/wayhop.new"                 # an install interrupted long ago
      touch -d "2026-01-01 00:00:00" "$S/wayhop.new"
      head -c 1048576 /dev/urandom > "$S/.wayhop.new"                # a panel update writing it now
      cp "$NEW" "$S/wayhop.bak-dup"                                  # a duplicate of the binary
      { cat "$OLD"; printf xy; } > "$S/wayhop.bak-old2"              # an older build
      _p="$(pidnow)"; _before="$(ls -a "$S" | sort | tr '\n' ' ')"; _a0="$(avail)"
      ( cd /tmp/new && sh ./install.sh --cleanup --dry-run ) > /tmp/dry.log 2>&1; _drc=$?
      check "--cleanup --dry-run succeeds" [ "$_drc" = 0 ]
      check "--cleanup --dry-run lists what it would remove" grep -q "would remove $S/wayhop.bak-old2" /tmp/dry.log
      check "--cleanup --dry-run changes nothing" [ "$(ls -a "$S" | sort | tr '\n' ' ')" = "$_before" ]
      ( cd /tmp/new && sh ./install.sh --cleanup ) > /tmp/clean.log 2>&1; _crc=$?
      check "--cleanup succeeds" [ "$_crc" = 0 ]
      check "it reported the space reclaimed" grep -q "reclaimed [0-9]* MiB" /tmp/clean.log
      check "the old staging file, the duplicate and the older build are gone" \
        absent "$S/wayhop.new" "$S/wayhop.bak-dup" "$S/wayhop.bak-old2"
      check "a staging file a running update may still be writing is kept" [ -f "$S/.wayhop.new" ]
      check "the rollback copy is kept, compressed, and unpacks to the old build" gz_is "$OLD_SHA"
      check "no plain rollback copy beside it" absent "$S/wayhop.bak"
      check "the running binary is untouched" [ "$(sha "$S/wayhop")" = "$NEW_SHA" ]
      check "the daemon was not restarted" [ "$(pidnow)" = "$_p" ]
      check "more space is free than before" [ "$(avail)" -gt "$_a0" ]
      check "files that are not WayHop's are untouched" user_files_intact ;;
    apkcopy)
      # What an apk install up to 0.5.8 left: the package file and a second, identical live copy.
      mkdir -p /usr/libexec/wayhop && cp "$S/wayhop" /usr/libexec/wayhop/wayhop
      _p="$(pidnow)"; _a0="$(avail)"
      ( cd /tmp/new && sh ./install.sh --cleanup ) > /tmp/clean.log 2>&1; _crc=$?
      check "--cleanup succeeds" [ "$_crc" = 0 ]
      check "the live binary is now a hard link of the package file" [ "$S/wayhop" -ef /usr/libexec/wayhop/wayhop ]
      check "the live binary is the same build" [ "$(sha "$S/wayhop")" = "$OLD_SHA" ]
      check "the daemon was not restarted" [ "$(pidnow)" = "$_p" ]
      "$INIT" stop
      check "once the daemon stops, the second copy's room is free" [ "$(avail)" -ge $((_a0 + N_OLD - 1024)) ] ;;
    rollback)
      unpack bad
      fill_to $((G_OLD + MARGIN_KB + 1536))
      inst bad
      check "a new build that never answers fails the upgrade" [ "$(rc_of bad)" = 1 ]
      check "it went the compressed-copy way" logged bad "compressed rollback copy"
      check "it rolled back" logged bad "rolled back"
      check "the binary is the old build again" [ "$(sha "$S/wayhop")" = "$OLD_SHA" ]
      check "the old build answers on the port" answers_soon "$OLD"
      check "the rollback is recorded for the panel and the bot" result_is rolled_back
      # The build that failed, not the one restored: auto-update skips the release this names.
      check "the record names the build that was rolled back" grep -q '"to":"wayhop 9.9.9 (999999999999' "$E/update-result.json"
      check "no staging file left behind" partials_gone ;;
    vcrash)
      sim_swap /w/crash-bin 999999999999
      judge restart
      check "the supervisor rolled the crashing build back" result_is rolled_back
      check "it recorded why: the build does not stay running" reason_has "not running\|does not stay running"
      check "the binary is the build it replaced" [ "$(sha "$S/wayhop")" = "$NEW_SHA" ]
      check "the replaced build answers again" answers_soon "$NEW"
      check "nothing is left pending" absent "$E/update.pending"
      judge restart
      check "judged once: a second run finds nothing to do and changes nothing" sh -c "grep -q 'no update is pending' /tmp/verify.log && [ \"\$(sha256sum '$S/wayhop' | cut -d' ' -f1)\" = '$NEW_SHA' ]" ;;
    vhang)
      sim_swap /w/hang-bin 999999999999
      judge restart
      check "the supervisor rolled the hanging build back" result_is rolled_back
      check "it recorded why: the build runs but does not answer" reason_has "does not answer"
      check "the replaced build answers again" answers_soon "$NEW" ;;
    vwrong)
      sim_swap "$OLD" deadbeef1234
      judge restart
      check "a build answering with another commit is rolled back" result_is rolled_back
      check "it recorded why: something else answers" reason_has "something else answers"
      check "the binary is the build it replaced" [ "$(sha "$S/wayhop")" = "$NEW_SHA" ]
      check "the replaced build answers again" answers_soon "$NEW" ;;
    vok)
      sim_swap "$OLD" "$(commit_of "$OLD")"
      fill_to $((N_OLD + 1024))   # under one more binary's worth + head-room: compress the copy
      judge restart
      check "a build that answers is kept" result_is ok
      check "it answers on the port" answers "$OLD"
      check "on the nearly full flash the plain rollback copy was compressed" gz_is "$NEW_SHA"
      check "no plain rollback copy beside it" absent "$S/wayhop.bak"
      check "nothing is left pending" absent "$E/update.pending" ;;
    vboot)
      sim_swap /w/crash-bin 999999999999 1   # this boot is the second inside the window
      judge boot
      check "a second boot inside the window rolls back at once" result_is rolled_back
      check "it recorded why" reason_has "restarted again"
      check "the replaced build answers again" answers_soon "$NEW" ;;
    vinit)
      # The power went inside the window: the daemon is gone, the marker is on flash, /tmp is empty.
      sim_swap /w/crash-bin 999999999999
      "$INIT" stop >/dev/null 2>&1; rm -f /tmp/wayhop-update-verify.pid
      "$INIT" start >/dev/null 2>&1
      _i=0; while [ "$_i" -lt 150 ] && ! result_is rolled_back; do sleep 1; _i=$((_i + 1)); done
      check "the init itself judged the update and rolled it back" result_is rolled_back
      check "the replaced build answers again" answers_soon "$NEW" ;;
    *) fail "unknown case"; return 1 ;;
  esac
  if [ "$F" != 0 ]; then echo "  ---- logs ($CASE) ----"; tail -n 30 /tmp/*.log | sed 's/^/  | /'; cat "$E/update-result.json" 2>/dev/null | sed 's/^/  | /'; fi
  return "$F"
}

if [ "${1:-}" = --guest ]; then guest "$2" "$3" "$4"; exit $?; fi

# =================================================================================================
# On the host
# =================================================================================================
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }
command -v docker >/dev/null 2>&1 || { echo "no docker - the upgrade cases were NOT run" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "docker is not running - the upgrade cases were NOT run" >&2; exit 3; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# pack <flavour> <binary> <out.tar.gz>: the tarball as build.yml assembles it, from this tree's scripts.
pack() {
  _s="$work/stage"; rm -rf "$_s"; mkdir -p "$_s"
  cp "$2" "$_s/wayhop-amd64"
  if [ "$1" = openwrt ]; then
    cp "$repo/packaging/openwrt/install.sh" "$repo/packaging/openwrt/uninstall.sh" "$repo/packaging/openwrt/wayhop.init" \
       "$repo/packaging/openwrt/wayhop.keep" "$_s/"
  else
    cp "$repo/packaging/install.sh" "$repo/packaging/uninstall.sh" "$repo/packaging/S99wayhop" "$_s/"
  fi
  cp "$repo/packaging/identity-match.sh" "$repo/packaging/retire-iptv.sh" "$repo/packaging/harden-state.sh" "$_s/"
  tar -C "$_s" -czf "$3" .
}
build() { # <version> <commit> <out>
  ( cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${GO:-go}" build -trimpath \
      -ldflags "-s -w -X wayhop/internal/version.Version=$1 -X wayhop/internal/version.Commit=$2 -X wayhop/internal/version.Date=2026-10-17T00:00:00Z -X wayhop/internal/version.Dirty=false" \
      -o "$3" ./cmd/wayhop )
}
if [ -n "${WAYHOP_UPGRADE_OLD:-}" ]; then
  mkdir -p "$work/ox"; tar -xzf "$WAYHOP_UPGRADE_OLD" -C "$work/ox"; cp "$work/ox/wayhop-amd64" "$work/old-bin"
else echo "building the old build"; build 0.0.1 1111111111111111111111111111111111111111 "$work/old-bin"; fi
if [ -n "${WAYHOP_UPGRADE_NEW:-}" ]; then
  mkdir -p "$work/nx"; tar -xzf "$WAYHOP_UPGRADE_NEW" -C "$work/nx"; cp "$work/nx/wayhop-amd64" "$work/new-bin"
elif [ -n "${WAYHOP_UPGRADE_NEW_BIN:-}" ]; then cp "$WAYHOP_UPGRADE_NEW_BIN" "$work/new-bin"
else echo "building the new build"; build 0.0.2 2222222222222222222222222222222222222222 "$work/new-bin"; fi
# Builds that do not work, each the size of a real one: one prints a version and exits, one prints a
# version and then runs without ever answering. Shell scripts named wayhop: pidof sees them as wayhop.
{ printf '#!/bin/sh\ncase "$1" in --version|-version) echo "wayhop 9.9.9 (999999999999, 2026-10-17)"; exit 0 ;; esac\nexit 1\n'; head -c 15000000 /dev/zero; } > "$work/crash-bin"
{ printf '#!/bin/sh\ncase "$1" in --version|-version) echo "wayhop 9.9.9 (999999999999, 2026-10-17)"; exit 0 ;; esac\nwhile :; do sleep 1; done\n'; head -c 15000000 /dev/zero; } > "$work/hang-bin"
chmod 0755 "$work/crash-bin" "$work/hang-bin"
for fl in openwrt entware; do
  if [ "$fl" = openwrt ] && [ -n "${WAYHOP_UPGRADE_OLD:-}" ]; then cp "$WAYHOP_UPGRADE_OLD" "$work/$fl-old.tar.gz"
  else pack "$fl" "$work/old-bin" "$work/$fl-old.tar.gz"; fi
  if [ "$fl" = openwrt ] && [ -n "${WAYHOP_UPGRADE_NEW:-}" ]; then cp "$WAYHOP_UPGRADE_NEW" "$work/$fl-new.tar.gz"
  else pack "$fl" "$work/new-bin" "$work/$fl-new.tar.gz"; fi
  # The installer's own bad build: a version, then an exit, as the one above.
  pack "$fl" "$work/crash-bin" "$work/$fl-bad.tar.gz"
done
cp "$repo/internal/updatetx/verify.sh" "$work/update-verify.sh"
# The init stand-in: procd needs ubus, which a container does not run.
cat > "$work/test-init" <<'EOF'
#!/bin/sh
P=/usr/sbin/wayhop; PID=/tmp/wayhop-test.pid
case "$1" in
  start) start-stop-daemon -S -b -m -p "$PID" -x "$P" -- --config /etc/wayhop/config.json ;;
  stop) [ -f "$PID" ] || exit 0
        p="$(cat "$PID")"; kill -TERM "$p" 2>/dev/null; i=0
        while kill -0 "$p" 2>/dev/null && [ "$i" -lt 10 ]; do sleep 1; i=$((i + 1)); done
        kill -KILL "$p" 2>/dev/null; rm -f "$PID" ;;
  restart) "$0" stop; "$0" start ;;
  enable|disable) : ;;
esac
EOF

fails=0; n=0; checks=0
for entry in $IMAGES; do
  fl="${entry%%|*}"; img="${entry#*|}"
  tag="$fl-${img#*:}"; tag="${tag%%@*}"
  for c in $CASES; do
    n=$((n + 1))
    rc=0
    MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --privileged --name "wh-upd-$$-$n" \
      -v "$(hostpath "$work"):/w:ro" -v "$(hostpath "$here"):/h:ro" "$img" \
      sh /h/openwrt_upgrade_harness.sh --guest "$c" "$tag" "$fl" > "$work/out" 2>&1 || rc=$?
    cat "$work/out"
    checks=$((checks + $(grep -c '^  PASS ' "$work/out" || :)))
    [ "$rc" = 0 ] || fails=$((fails + 1))
  done
done
echo
if [ "$fails" = 0 ]; then echo "upgrade harness: all $n case runs passed ($checks checks)"; exit 0; fi
echo "upgrade harness: $fails of $n case runs FAILED"; exit 1
