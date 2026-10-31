#!/bin/sh
# qemu-update.sh - WayHop updates on a real OpenWrt booted in QEMU, on a nearly full overlay.
#
# Boots the official squashfs image of each <release> (overlayfs over a small writable layer, as on a
# router flash; downloaded from downloads.openwrt.org and checked against its sha256sums), then, in
# one VM per release:
#
#   s1  installs v0.5.7 the public way: the release's own bootstrap.sh (checked here against GitHub's
#       published digest), which downloads, signature-checks and installs the tarball itself
#   s2  BEFORE, panel: fills the overlay to the test router's level and asks v0.5.7's self-update API
#       (with a real session) for v0.5.8
#   s3  BEFORE, installer: re-runs the public v0.5.8 bootstrap as the upgrade
#   s4  AFTER, installer: this tree's install.sh with the public v0.5.8 binary, straight onto what s3
#       left behind
#   s5  a power cut inside the compressed-copy swap (old binary only in wayhop.bak.gz, a half-written
#       wayhop.new): QEMU is killed and the same disk booted again; the init must restore the binary
#   s6  this tree's own build installed through its installer
#   s7  AFTER, panel: leftovers seeded, overlay filled between the exact need and the old estimate, the
#       self-update API asked for v0.5.8; procd restarts onto it
#   s8  --cleanup --dry-run, then --cleanup
#   s9  the feed packages, packed from the public binaries with THIS tree's maintainer scripts, through
#       the router's own package manager: v0.5.7, then v0.5.8 with 10 MiB free, which must either
#       complete whole or be refused with v0.5.7 untouched (then retried with room for the package);
#       on apk, one copy of the binary on the flash
#   s10 the panel's swap to a build that CRASHES on start, judged by the update supervisor the way the
#       daemon starts it (detached): rolled back, the reason recorded, the previous build answers
#   s11 the same swap, and the power goes before anything judges it: the init finishes the judgement at
#       boot and rolls back
#   s12 a feed-installed WayHop (this tree's build, from a signed test feed) updated FROM THE PANEL:
#       the daemon hands `apk upgrade wayhop` / `opkg upgrade wayhop` to the supervisor, which judges
#       the build the package leaves running
#
# Usage: sh scripts/qemu-update.sh <release>...        e.g.  sh scripts/qemu-update.sh 25.12.2 24.10.4
# Env:   WAYHOP_QEMU_OUT    logs, consoles and summary.txt (default ./qemu-update-out)
#        WAYHOP_QEMU_CACHE  downloaded images (default ${XDG_CACHE_HOME:-~/.cache}/wayhop-qemu-update)
#        WAYHOP_QEMU_DEV_BIN  an amd64 build of this tree to use in s6/s7 (default: built with $GO)
#        GO                 the go command (default go); QEMU_HOST_IMAGE overrides the pinned Alpine
# Needs Docker (the VM runs in a pinned Alpine container; KVM when /dev/kvm is there, TCG otherwise) and
# network access to github.com and downloads.openwrt.org. Exit: 0 all passed, 1 a check failed,
# 2 usage/environment, 3 no docker (nothing was tested). The test credentials it creates exist only
# inside the throwaway VM.
set -eu

QEMU_HOST_IMAGE="${QEMU_HOST_IMAGE:-alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6}"
REPO_GH="awadak3davra/wayhop"
OLD_TAG=v0.5.7
NEW_TAG=v0.5.8
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
die() { echo "qemu-update: $*" >&2; exit 2; }
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }

# =================================================================================================
# In the container: one VM per release
# =================================================================================================
if [ "${1:-}" = --vm ]; then
  REL="$2"; W=/w; OUT=/out; CACHE=/cache
  PORT=8080; BASE="http://10.0.2.2:$PORT"; API="http://127.0.0.1:18088"
  RES="$OUT/results-$REL.txt"; : > "$RES"
  record() { # <PASS|FAIL|NOTE> <step> <what> [detail]
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$REL" "$2" "$3" "${4:-}" >> "$RES"
    printf '  %-5s %-8s %-4s %-52s %s\n' "$1" "$REL" "$2" "$3" "${4:-}"
  }
  pass() { record PASS "$@"; }
  fail() { record FAIL "$@"; }
  note() { record NOTE "$@"; }
  check() { # <step> <what> <detail> <test...>
    _n="$1"; _w="$2"; _d="$3"; shift 3
    if "$@"; then pass "$_n" "$_w" "$_d"; else fail "$_n" "$_w" "$_d"; fi
  }
  val() { sed -n "s/^E2E $1=//p" "$OUT/guest-$REL.out" | tail -n 1; }

  img="openwrt-$REL-x86-64-generic-squashfs-combined.img.gz"
  idir="$CACHE/$REL"; mkdir -p "$idir"
  url="https://downloads.openwrt.org/releases/$REL/targets/x86/64"
  curl -fsSL --retry 3 -o "$idir/sha256sums" "$url/sha256sums" || die "cannot fetch $url/sha256sums"
  want="$(awk -v f="*$img" '$2 == f { print $1 }' "$idir/sha256sums")"
  [ -n "$want" ] || die "$img is not in $url/sha256sums"
  if [ ! -f "$idir/$img" ] || [ "$(sha256sum "$idir/$img" | cut -d' ' -f1)" != "$want" ]; then
    curl -fsSL --retry 3 -o "$idir/$img.part" "$url/$img" || die "download failed: $url/$img"
    [ "$(sha256sum "$idir/$img.part" | cut -d' ' -f1)" = "$want" ] || { rm -f "$idir/$img.part"; die "$img does not match sha256sums"; }
    mv "$idir/$img.part" "$idir/$img"
  fi
  note image "$img" "sha256=$want"
  rc=0; gzip -dc "$idir/$img" > "$W/disk-$REL.img" || rc=$?
  [ "$rc" = 0 ] || [ "$rc" = 2 ] || die "cannot unpack $img"   # OpenWrt pads its .img.gz: exit 2 after a full decode

  python3 -m http.server --bind 127.0.0.1 --directory "$W/www" "$PORT" > "$OUT/http-$REL.log" 2>&1 &
  hpid=$!
  qpid=""
  cleanup() { [ -z "$qpid" ] || kill -9 "$qpid" 2>/dev/null || :; kill "$hpid" 2>/dev/null || :; rm -f "$W/disk-$REL.img"; }
  trap cleanup EXIT
  ACCEL=tcg; [ -r /dev/kvm ] && [ -w /dev/kvm ] && ACCEL=kvm
  con() { python3 "$repo/scripts/awg/qemu-console.py" --sock "$W/console.sock" "$@"; }
  boot() { # <n>
    rm -f "$W/console.sock"
    set -- -m 256 -smp 2 -nodefaults -display none -monitor none \
      -chardev "socket,id=con0,path=$W/console.sock,server=on,wait=off,logfile=$OUT/console-$REL-$1.log" \
      -serial chardev:con0 -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:18088-:8088" -device virtio-net-pci,netdev=n0 \
      -drive "file=$W/disk-$REL.img,format=raw,if=virtio"
    if [ "$ACCEL" = kvm ]; then set -- "$@" -enable-kvm -cpu host; else set -- "$@" -accel tcg; fi
    qemu-system-x86_64 "$@" > "$OUT/qemu-$REL.log" 2>&1 &
    qpid=$!
    con wait-shell --timeout 900 > /dev/null || return 1
    con run --timeout 30 -- "dmesg -n 1" > /dev/null || :
    # The image's lan is a static 192.168.50.1; under QEMU user networking it takes DHCP instead.
    con run --timeout 120 -- "uci set network.lan.proto=dhcp; uci -q delete network.lan.ipaddr; uci -q delete network.lan.netmask; uci -q delete network.lan.ip6assign; uci commit network; /etc/init.d/network reload" > /dev/null || :
    con run --timeout 240 -- "i=0; until wget -q -O /tmp/g.sh $BASE/guest.sh; do i=\$((i+1)); [ \$i -ge 100 ] && exit 1; sleep 2; done" > /dev/null
  }
  phase() { # <timeout> <args...>
    _t="$1"; shift
    con run --timeout "$_t" -- "sh /tmp/g.sh $BASE $*" > "$W/phase.out" 2>&1 || :
    { echo "### $*"; cat "$W/phase.out"; } >> "$OUT/guest-$REL.out"
  }
  api() { # <method> <path> [json] -> body on stdout, status in $W/status
    if [ -n "${3:-}" ]; then
      curl -s -m 300 -c "$W/jar" -b "$W/jar" -o "$W/body" -w '%{http_code}' -X "$1" -H 'Content-Type: application/json' \
        -H "X-WayHop-CSRF: $(cat "$W/csrf" 2>/dev/null)" -d "$3" "$API$2" > "$W/status" || echo 000 > "$W/status"
    else
      curl -s -m 60 -c "$W/jar" -b "$W/jar" -o "$W/body" -w '%{http_code}' "$API$2" > "$W/status" || echo 000 > "$W/status"
    fi
    cat "$W/body" 2>/dev/null
  }
  session() { # set up the panel's test credentials once, or log in with them
    _c='{"username":"e2e","password":"'"$(cat "$W/pw")"'"}'
    _b="$(api POST /api/auth/setup "$_c")"
    case "$(cat "$W/status")" in 201) ;; *) _b="$(api POST /api/auth/login "$_c")" ;; esac
    printf '%s' "$_b" | sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p' > "$W/csrf"
  }
  health_commit() { curl -s -m 5 "$API/api/health" 2>/dev/null | sed -n 's/.*"commit":"\([0-9a-f]*\)".*/\1/p'; }
  wait_commit() { # <commit prefix> <seconds>
    _i=0; while [ "$_i" -lt "$2" ]; do case "$(health_commit)" in "$1"*) return 0 ;; esac; sleep 3; _i=$((_i + 3)); done; return 1
  }
  wait_result() { # <result> <seconds> <name>: poll the supervisor's record until it says <result>
    _i=0
    while [ "$_i" -lt "$2" ]; do
      phase 30 result "$3"
      [ "$(val "$3_result")" = "$1" ] && [ "$(val "$3_pending")" = no ] && [ "$(val "$3_judging")" = no ] && return 0
      sleep 10; _i=$((_i + 10))
    done
    return 1
  }
  OLD_COMMIT="$(cat "$W/old.commit")"; NEW_COMMIT="$(cat "$W/new.commit")"; DEV_COMMIT="$(cat "$W/dev.commit")"
  FIXED_SHA="$(sha256sum "$W/www/fixed.tar.gz" | cut -d' ' -f1)"; DEV_SHA="$(sha256sum "$W/www/dev.tar.gz" | cut -d' ' -f1)"
  head -c 18 /dev/urandom | base64 | tr -d '/+=' > "$W/pw"; rm -f "$W/jar" "$W/csrf"
  : > "$OUT/guest-$REL.out"

  t0=$(date +%s)
  boot 1 || { fail boot "no shell or no network (console-$REL-1.log)"; exit 1; }
  pass boot "$(( $(date +%s) - t0 ))s ($ACCEL)"

  # s1 -------------------------------------------------------------------------------------------
  phase 900 bootstrap "$OLD_TAG" s1; phase 60 state s1
  check s1 "v0.5.7 installed by its public bootstrap" "bootstrap rc=$(val s1_rc)" [ "$(val s1_rc)" = 0 ]
  check s1 "v0.5.7 answers" "health commit $(val s1_health)" sh -c "case '$(val s1_health)' in '$OLD_COMMIT'*) exit 0;; esac; exit 1"
  note s1 overlay "$(( $(val s1_overlay_free_kib) / 1024 )) MiB free after the install"

  # s2: the panel, before --------------------------------------------------------------------------
  phase 120 fill 16384
  note s2 overlay "filled to $(( $(val fill_free_kib) / 1024 )) MiB free (the test router has 13-20)"
  session
  _b="$(api POST /api/updater/self/install '{"version":"'"$NEW_TAG"'"}')"
  _st="$(cat "$W/status")"
  printf '%s\n' "$_b" > "$OUT/s2-$REL.json"
  note s2 "BEFORE panel self-update" "HTTP $_st: $(printf '%s' "$_b" | head -c 300)"

  # s3: the public installer, before -------------------------------------------------------------
  phase 900 bootstrap "$NEW_TAG" s3; phase 60 state s3
  note s3 "BEFORE bootstrap $NEW_TAG" "rc=$(val s3_rc) running=$(val s3_running) health=$(val s3_health) files=$(val s3_files)"

  # s4: this tree's installer, after ---------------------------------------------------------------
  phase 900 tarball fixed.tar.gz "$FIXED_SHA" s4; phase 60 state s4
  check s4 "upgrades on the same overlay" "rc=$(val s4_rc)" [ "$(val s4_rc)" = 0 ]
  check s4 "v0.5.8 answers under procd" "health commit $(val s4_health)" sh -c "case '$(val s4_health)' in '$NEW_COMMIT'*) exit 0;; esac; exit 1"
  check s4 "a rollback copy of v0.5.7 is kept" "bak=$(val s4_bak_sha | cut -c1-12) bak.gz=$(val s4_bakgz_sha | cut -c1-12)" \
    sh -c "[ '$(val s4_bak_sha)' = '$(val s1_sha)' ] || [ '$(val s4_bakgz_sha)' = '$(val s1_sha)' ]"
  check s4 "what s3 left behind is gone" "files=$(val s4_files)" sh -c "case '$(val s4_files)' in *wayhop.new,*|*wayhop.bak.new,*) exit 1;; esac"
  note s4 overlay "$(( $(val s4_overlay_free_kib) / 1024 )) MiB free after"

  # s5: a power cut in the compressed-copy window ------------------------------------------------
  phase 120 cut
  kill -9 "$qpid" 2>/dev/null || :; wait "$qpid" 2>/dev/null || :; qpid=""
  t0=$(date +%s)
  if boot 2; then
    pass s5 "booted again after the cut" "$(( $(date +%s) - t0 ))s"
    sleep 10; phase 60 state s5
    check s5 "the init restored the binary from wayhop.bak.gz" "sha $(val s5_sha | cut -c1-12)" [ "$(val s5_sha)" = "$(val cut_sha)" ]
    check s5 "WayHop runs after the cut" "health commit $(val s5_health)" sh -c "case '$(val s5_health)' in '$NEW_COMMIT'*) exit 0;; esac; exit 1"
  else
    fail s5 "booted again after the cut" "no shell or network (console-$REL-2.log)"; exit 1
  fi

  # s6: this tree's build -------------------------------------------------------------------------
  phase 900 tarball dev.tar.gz "$DEV_SHA" s6; phase 60 state s6
  check s6 "this tree's build installed" "rc=$(val s6_rc) health $(val s6_health)" sh -c "case '$(val s6_health)' in '$DEV_COMMIT'*) exit 0;; esac; exit 1"

  # s7: the panel, after ---------------------------------------------------------------------------
  phase 60 seed
  # Between what the binary really needs (14.7 + 2 MiB) and the old pre-flight's 3x estimate: staged
  # in RAM it is measured exactly. The rollback copy it supersedes is room too, so it is subtracted.
  phase 60 state s7pre
  room=18330; free=$((room - $(val s7pre_superseded_kib) - 3072))   # 3072: the seeded staging file
  [ "$free" -ge 3072 ] || free=3072
  phase 120 fill "$free"
  note s7 overlay "filled to $(( $(val fill_free_kib) / 1024 )) MiB free + $(( $(val s7pre_superseded_kib) / 1024 )) MiB superseded rollback copy + 3 MiB leftover"
  phase 30 forget
  session
  _b="$(api POST /api/updater/self/install '{"version":"'"$NEW_TAG"'"}')"
  _st="$(cat "$W/status")"
  printf '%s\n' "$_b" > "$OUT/s7-$REL.json"
  check s7 "the panel self-update is accepted" "HTTP $_st: $(printf '%s' "$_b" | head -c 160)" [ "$_st" = 200 ]
  check s7 "procd restarts onto v0.5.8" "health commit $(health_commit)" wait_commit "$NEW_COMMIT" 120
  wait_result ok 180 s7r || :
  phase 60 state s7
  check s7 "the rollback copy is the build it replaced (compressed if the flash is nearly full)" "bak $(val s7_bak_sha | cut -c1-12) bak.gz $(val s7_bakgz_sha | cut -c1-12)" \
    sh -c "[ '$(val s7_bak_sha)' = '$(val s6_sha)' ] || [ '$(val s7_bakgz_sha)' = '$(val s6_sha)' ]"
  check s7 "the interrupted install's staging file was reclaimed" "files=$(val s7_files)" sh -c "case '$(val s7_files)' in *wayhop.new,*) exit 1;; esac"
  check s7 "the update supervisor judged the panel's update from outside the daemon: ok" "$(val s7r_result) by=$(val s7r_by)" \
    sh -c "[ '$(val s7r_result)' = ok ] && [ '$(val s7r_by)' = panel ]"
  note s7 overlay "$(( $(val s7_overlay_free_kib) / 1024 )) MiB free after"

  # s8: --cleanup ---------------------------------------------------------------------------------
  phase 300 cleanup dev.tar.gz "$DEV_SHA" s8dry --dry-run; phase 60 state s8a
  check s8 "--cleanup --dry-run changes nothing" "files=$(val s8a_files)" [ "$(val s8a_files)" = "$(val s7_files)" ]
  phase 300 cleanup dev.tar.gz "$DEV_SHA" s8; phase 60 state s8b
  check s8 "--cleanup succeeds" "rc=$(val s8_rc)" [ "$(val s8_rc)" = 0 ]
  check s8 "the old-name build is gone, the rollback copy compressed" "files=$(val s8b_files)" \
    sh -c "case '$(val s8b_files)' in *wakeroute*) exit 1;; esac; [ '$(val s8b_bakgz_sha)' = '$(val s6_sha)' ]"
  check s8 "WayHop still answers" "health commit $(val s8b_health)" sh -c "case '$(val s8b_health)' in '$NEW_COMMIT'*) exit 0;; esac; exit 1"
  note s8 overlay "$(( $(val s8b_overlay_free_kib) / 1024 )) MiB free after (was $(( $(val s7_overlay_free_kib) / 1024 )))"

  # s9: the feed packages (this tree's maintainer scripts) with the router's own package manager --
  case "$REL" in 2[5-9].*|[3-9]*) PK=apk; PMK=apk ;; *) PK=ipk; PMK=opkg ;; esac
  s_old="$(sha256sum "$W/www/old.$PK" | cut -d' ' -f1)"; s_new="$(sha256sum "$W/www/new.$PK" | cut -d' ' -f1)"
  phase 300 cleanup dev.tar.gz "$DEV_SHA" s9c --drop-rollback   # the package brings its own copy
  phase 120 fill 1048576                                          # no filler: room for the first install
  phase 900 pkg "old.$PK" "$s_old" s9a
  wait_commit "$OLD_COMMIT" 90 || :; phase 60 state s9a
  check s9 "the v0.5.7 package installs over the tarball install" "rc=$(val s9a_rc) health $(val s9a_health)" \
    sh -c "case '$(val s9a_health)' in '$OLD_COMMIT'*) exit 0;; esac; exit 1"
  [ "$PK" = apk ] && check s9 "the apk install keeps one copy of the binary" "onecopy=$(val s9a_onecopy)" [ "$(val s9a_onecopy)" = yes ]
  phase 120 fill 10240
  note s9 overlay "filled to $(( $(val fill_free_kib) / 1024 )) MiB free for the package upgrade"
  # With 10 MiB free the package manager may complete it (apk did here: root may write into the file
  # system's reserve, which df does not count) or refuse it (opkg did: it wants the whole package's
  # size free). Either is right; a half-done upgrade is not.
  phase 900 pkg "new.$PK" "$s_new" s9b
  [ "$(val s9b_rc)" = 0 ] && { wait_commit "$NEW_COMMIT" 90 || :; }
  phase 60 state s9b
  check s9 "tight: the upgrade completes whole, or is refused with v0.5.7 untouched" \
    "rc=$(val s9b_rc) sha=$(val s9b_sha | cut -c1-12) health=$(val s9b_health | cut -c1-12) free=$(( $(val s9b_overlay_free_kib) / 1024 ))MiB" \
    sh -c "if [ '$(val s9b_rc)' = 0 ]; then
             [ '$(val s9b_sha)' = '$(val s4_sha)' ] && case '$(val s9b_health)' in '$NEW_COMMIT'*) exit 0;; esac; exit 1
           fi
           [ '$(val s9b_sha)' = '$(val s9a_sha)' ] && [ '$(val s9b_overlay_free_kib)' -ge 9216 ] &&
             case '$(val s9b_health)' in '$OLD_COMMIT'*) exit 0;; esac; exit 1"
  if [ "$(val s9b_rc)" = 0 ]; then
    note s9 "with 10 MiB free" "$PK completed the upgrade"
    fin=s9b
  else
    note s9 "with 10 MiB free" "$PK refused the upgrade (rc=$(val s9b_rc)); retrying with room for the package"
    phase 120 fill 17408
    phase 900 pkg "new.$PK" "$s_new" s9d
    wait_commit "$NEW_COMMIT" 90 || :; phase 60 state s9d
    fin=s9d
  fi
  check s9 "the package upgrade lands: v0.5.8 whole and answering" "rc=$(val ${fin}_rc) health=$(val ${fin}_health | cut -c1-12)" \
    sh -c "[ '$(val ${fin}_rc)' = 0 ] && [ '$(val ${fin}_sha)' = '$(val s4_sha)' ] && case '$(val ${fin}_health)' in '$NEW_COMMIT'*) exit 0;; esac; exit 1"
  [ "$PK" = apk ] && check s9 "one copy of the binary on the flash after the upgrade" "onecopy=$(val ${fin}_onecopy)" [ "$(val ${fin}_onecopy)" = yes ]

  # s10: the panel's swap to a build that crashes, judged from outside the daemon -------------------
  phase 120 fill 1048576                         # s9's filler goes: room for this tree's build
  phase 900 tarball dev.tar.gz "$DEV_SHA" s10i   # this tree's build runs, so its panel can report the rollback
  # The installer pulls the feed's sing-box in (~46 MiB) wherever it finds the room for it; the
  # supervisor cases need that room for the crashing build instead.
  phase 120 nosingbox
  check s10 "this tree's build is installed for the supervisor cases" "rc=$(val s10i_rc) health $(health_commit)" wait_commit "$DEV_COMMIT" 90
  phase 30 forget
  CRASH_SHA="$(sha256sum "$W/www/crash-bin" | cut -d' ' -f1)"
  phase 120 simswap crash-bin "$CRASH_SHA" 999999999999
  check s10 "the panel-style swap put the crashing build in place" "rc=$(val simswap_rc)" [ "$(val simswap_rc)" = 0 ]
  phase 30 judge
  wait_result rolled_back 240 s10r || :
  check s10 "a build that crashes on start is rolled back by the supervisor" "result=$(val s10r_result)" [ "$(val s10r_result)" = rolled_back ]
  check s10 "the reason is recorded for the panel and the bot" "$(val s10r_reason | cut -c1-120)" sh -c "case '$(val s10r_reason)' in *running*) exit 0;; esac; exit 1"
  check s10 "the previous build answers again" "health $(health_commit)" wait_commit "$DEV_COMMIT" 60
  session   # the daemon restarted: a fresh session
  _b="$(api GET /api/updater/self)"
  check s10 "the panel's status carries the rollback" "$(printf '%s' "$_b" | sed -n 's/.*"last_update_note":"\([^"]*\)".*/\1/p' | cut -c1-100)" \
    sh -c "printf '%s' '$(printf '%s' "$_b" | tr -d "'")' | grep -q 'last_update_note'"

  # s11: the power goes inside the window ------------------------------------------------------------
  phase 30 forget
  phase 120 simswap crash-bin "$CRASH_SHA" 999999999999
  phase 60 state s11pre
  note s11 "before the cut" "binary $(val s11pre_sha | cut -c1-12) (the crashing build: $(printf '%s' "$CRASH_SHA" | cut -c1-12)), update pending"
  kill -9 "$qpid" 2>/dev/null || :; wait "$qpid" 2>/dev/null || :; qpid=""
  if boot 3; then
    wait_result rolled_back 300 s11r || :
    check s11 "after a power cut inside the window the init judged the update and rolled it back" "result=$(val s11r_result) $(val s11r_reason | cut -c1-90)" [ "$(val s11r_result)" = rolled_back ]
    check s11 "the previous build answers after the boot" "health $(health_commit)" wait_commit "$DEV_COMMIT" 60
  else
    fail s11 "booted again after the cut" "no shell or network (console-$REL-3.log)"
  fi

  # s12: a feed-installed WayHop updated from the panel ---------------------------------------------
  phase 300 cleanup dev.tar.gz "$DEV_SHA" s12c --drop-rollback   # room on the small test overlay
  phase 120 fill 1048576
  note s12 overlay "$(( $(val fill_free_kib) / 1024 )) MiB free for the package cases"
  phase 300 feed feedA keysA s12a
  check s12 "the signed test feed is trusted and read" "rc=$(val s12a_rc)" [ "$(val s12a_rc)" = 0 ]
  phase 900 pkgcmd s12i "$PK" install-old
  rc_then_commit() { [ "$1" = 0 ] && wait_commit "$2" "$3"; }
  check s12 "this tree's build installed from the feed (as 0.5.7.1)" "rc=$(val s12i_rc) health $(health_commit)" rc_then_commit "$(val s12i_rc)" "$DEV_COMMIT" 120
  phase 300 feed feedB keysB s12b
  phase 30 forget
  session
  _b="$(api POST /api/updater/self/install '{}')"
  _st="$(cat "$W/status")"
  printf '%s\n' "$_b" > "$OUT/s12-$REL.json"
  check s12 "the panel hands the update to the package manager" "HTTP $_st: $(printf '%s' "$_b" | head -c 200)" sh -c "[ '$_st' = 200 ] && printf '%s' '$(printf '%s' "$_b" | tr -d "'")' | grep -q 'updating through'"
  check s12 "the package manager installs v0.5.8 and it answers" "health $(health_commit)" wait_commit "$NEW_COMMIT" 400
  wait_result ok 200 s12r || :
  check s12 "the supervisor judged the package's build: ok, by the package manager" "result=$(val s12r_result) by=$(val s12r_by)" \
    sh -c "[ '$(val s12r_result)' = ok ] && [ '$(val s12r_by)' = '$PMK' ]"
  phase 60 state s12s
  [ "$PK" = apk ] && check s12 "one copy of the binary on the flash" "files=$(val s12s_files)" sh -c "[ -n '$(val s12s_sha)' ]"

  con poweroff --timeout 60 > /dev/null 2>&1 || :
  ! grep -q '^FAIL' "$RES"
  exit $?
fi

# =================================================================================================
# On the host: inputs, then the container
# =================================================================================================
[ "$#" -ge 1 ] || die "usage: qemu-update.sh <release>...   (e.g. 25.12.2 24.10.4)"
for r in "$@"; do printf '%s\n' "$r" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "release '$r' is not MAJOR.MINOR.PATCH"; done
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "qemu-update: no docker - nothing was tested" >&2; exit 3; }
OUT="${WAYHOP_QEMU_OUT:-qemu-update-out}"; mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
CACHE="${WAYHOP_QEMU_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/wayhop-qemu-update}"; mkdir -p "$CACHE"; CACHE="$(cd "$CACHE" && pwd)"
W="$OUT/work"; rm -rf "$W"; mkdir -p "$W/www"
cp "$here/qemu-update-guest.sh" "$W/www/guest.sh"

# Release files, each checked before use: the bootstrap scripts against the digest GitHub publishes for
# the asset, the tarball against the release's SHA256SUMS.txt.
gh_digest() { # <tag> <asset> -> the hex digest GitHub's release API publishes for it
  _py="$(command -v python3 || command -v python)" || die "python3 is required to read the release metadata"
  curl -fsSL "https://api.github.com/repos/$REPO_GH/releases/tags/$1" | "$_py" -I -c '
import json, sys
for a in json.load(sys.stdin).get("assets", []):
    if a.get("name") == sys.argv[1] and str(a.get("digest", "")).startswith("sha256:"):
        print(a["digest"][7:]); break' "$2"
}
for tag in "$OLD_TAG" "$NEW_TAG"; do
  d="$(gh_digest "$tag" bootstrap.sh)"; [ "${#d}" = 64 ] || die "no published digest for $tag bootstrap.sh"
  curl -fsSL -o "$W/www/bootstrap-$tag.sh" "https://github.com/$REPO_GH/releases/download/$tag/bootstrap.sh"
  [ "$(sha256sum "$W/www/bootstrap-$tag.sh" | cut -d' ' -f1)" = "$d" ] || die "$tag bootstrap.sh does not match its published digest"
done
release_binary() { # <tag> <dir>: the release's amd64 OpenWrt binary, its tarball checked first
  _v="${1#v}"; _t="wayhop-$_v-amd64-openwrt.tar.gz"
  curl -fsSL -o "$W/SHA256SUMS-$1.txt" "https://github.com/$REPO_GH/releases/download/$1/SHA256SUMS.txt"
  curl -fsSL -o "$W/$_t" "https://github.com/$REPO_GH/releases/download/$1/$_t"
  _w="$(awk -v f="$_t" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$W/SHA256SUMS-$1.txt")"
  [ "$(sha256sum "$W/$_t" | cut -d' ' -f1)" = "$_w" ] || die "$_t does not match the release's SHA256SUMS.txt"
  mkdir -p "$2" && tar -xzf "$W/$_t" -C "$2" && rm -f "$W/$_t"
}
release_binary "$NEW_TAG" "$W/pub"
release_binary "$OLD_TAG" "$W/pub7"
# s9's packages: both public binaries packed by the shipped packers with this tree's maintainer
# scripts, in the builder images the package-lifecycle gates pin.
OWNER="$(id -u):$(id -g)"   # files the containers write stay the caller's (root-owned ones would not clean up)
IPK_BUILDER_IMAGE="debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931"
APK_BUILDER_IMAGE="alpine:edge@sha256:d77617aef5805191da75fbbfe2f9dc2043582ecad0f4d381b27c151034765a76"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$repo"):/src:ro" -v "$(hostpath "$W"):/w" "$IPK_BUILDER_IMAGE" sh -euc '
  cp -r /src/packaging /tmp/p
  SOURCE_DATE_EPOCH=0 sh /tmp/p/feed/pack-ipk.sh /w/pub7/wayhop-amd64 0.5.7 1 /w/ipk7 x86_64 >/dev/null
  SOURCE_DATE_EPOCH=0 sh /tmp/p/feed/pack-ipk.sh /w/pub/wayhop-amd64 0.5.8 1 /w/ipk8 x86_64 >/dev/null
  cp /w/ipk7/x86_64/*.ipk /w/www/old.ipk; cp /w/ipk8/x86_64/*.ipk /w/www/new.ipk; chown -R "$1" /w' sh "$OWNER" || die "could not pack the .ipk"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$repo"):/src:ro" -v "$(hostpath "$W"):/w" "$APK_BUILDER_IMAGE" sh -euc '
  cp -r /src/packaging /tmp/p
  sh /tmp/p/feed/pack-apk.sh /w/pub7/wayhop-amd64 0.5.7 1 /w/apk7 x86_64 >/dev/null
  sh /tmp/p/feed/pack-apk.sh /w/pub/wayhop-amd64 0.5.8 1 /w/apk8 x86_64 >/dev/null
  cp /w/apk7/apk/x86_64/*.apk /w/www/old.apk; cp /w/apk8/apk/x86_64/*.apk /w/www/new.apk; chown -R "$1" /w' sh "$OWNER" || die "could not pack the .apk"
pack() { # <binary> <out>: the OpenWrt tarball as build.yml assembles it, with THIS tree's scripts
  _s="$W/stage"; rm -rf "$_s"; mkdir -p "$_s"; cp "$1" "$_s/wayhop-amd64"
  cp "$repo/packaging/openwrt/install.sh" "$repo/packaging/openwrt/uninstall.sh" "$repo/packaging/openwrt/wayhop.init" \
     "$repo/packaging/openwrt/wayhop.keep" "$repo/packaging/identity-match.sh" "$repo/packaging/retire-iptv.sh" \
     "$repo/packaging/harden-state.sh" "$_s/"
  tar -C "$_s" --mode='a+rx' -czf "$2" .
}
pack "$W/pub/wayhop-amd64" "$W/www/fixed.tar.gz"
if [ -n "${WAYHOP_QEMU_DEV_BIN:-}" ]; then cp "$WAYHOP_QEMU_DEV_BIN" "$W/dev-bin"
else
  ( cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${GO:-go}" build -trimpath \
      -ldflags "-s -w $(sh scripts/buildinfo.sh 0.5.9-dev)" -o "$W/dev-bin" ./cmd/wayhop )
fi
pack "$W/dev-bin" "$W/www/dev.tar.gz"
# s10/s11's build that crashes on start: a version line, then an exit (the size of a real one).
{ printf '#!/bin/sh\ncase "$1" in --version|-version) echo "wayhop 9.9.9 (999999999999, 2026-10-17)"; exit 0 ;; esac\nexit 1\n'; head -c 15000000 /dev/zero; } > "$W/www/crash-bin"
# s12's feeds, signed with throwaway keys (scripts/awg/qemu-feed-sign.sh): feedA carries this tree's
# build packaged as 0.5.7.1, feedB adds the public v0.5.8 package beside it.
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$repo"):/src:ro" -v "$(hostpath "$W"):/w" "$IPK_BUILDER_IMAGE" sh -euc '
  cp -r /src/packaging /tmp/p
  SOURCE_DATE_EPOCH=0 sh /tmp/p/feed/pack-ipk.sh /w/dev-bin 0.5.7.1 1 /w/ipkd x86_64 >/dev/null
  for f in feedA feedB; do mkdir -p /w/www/$f/ipk/x86_64; cp /w/ipkd/x86_64/*.ipk /w/www/$f/ipk/x86_64/; done
  cp /w/ipk8/x86_64/*.ipk /w/www/feedB/ipk/x86_64/; chown -R "$1" /w' sh "$OWNER" || die "could not pack the test feed's .ipk"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm -v "$(hostpath "$repo"):/src:ro" -v "$(hostpath "$W"):/w" "$APK_BUILDER_IMAGE" sh -euc '
  cp -r /src/packaging /tmp/p
  sh /tmp/p/feed/pack-apk.sh /w/dev-bin 0.5.7.1 1 /w/apkd x86_64 >/dev/null
  for f in feedA feedB; do mkdir -p /w/www/$f/apk/x86_64; cp /w/apkd/apk/x86_64/*.apk /w/www/$f/apk/x86_64/; done
  cp /w/apk8/apk/x86_64/*.apk /w/www/feedB/apk/x86_64/
  for f in feedA feedB; do ( cd /w/www/$f/apk/x86_64 && apk --allow-untrusted mkndx -o packages.adb ./*.apk >/dev/null ); done
  chown -R "$1" /w' sh "$OWNER" || die "could not index the test feed's .apk"
( cd "$repo" && CGO_ENABLED=0 "${GO:-go}" build -trimpath -o "$W/usigntool$("${GO:-go}" env GOEXE)" ./packaging/feed/usigntool )
"$W/usigntool$("${GO:-go}" env GOEXE)" genkey -comment "qemu-update index key" -pub "$W/idx.pub" -sec "$W/idx.sec" >/dev/null
for f in feedA feedB; do
  sh "$repo/packaging/feed/make-index.sh" "$W/www/$f" "$W/idx.sec" "$W/idx.pub" "$W/usigntool$("${GO:-go}" env GOEXE)" >/dev/null
  GO="${GO:-go}" sh "$repo/scripts/awg/qemu-feed-sign.sh" "$W/www/$f" "$W/www/keys${f#feed}" >/dev/null
done
rm -f "$W/idx.sec"
# The commits each build reports on /api/health, from the version line each binary prints.
commit_of() { MSYS_NO_PATHCONV=1 docker run --rm -v "$(hostpath "$1"):/b:ro" "$QEMU_HOST_IMAGE" /b --version | sed -n 's/^wayhop [^ ]* (\([0-9a-f]*\),.*/\1/p'; }
commit_of "$W/pub/wayhop-amd64" > "$W/new.commit"
commit_of "$W/dev-bin" > "$W/dev.commit"
printf '447a04fa7422\n' > "$W/old.commit"   # v0.5.7's, as its binary reports it
for f in new dev; do [ -s "$W/$f.commit" ] || die "could not read the $f build's commit"; done

kvm=""; [ -e /dev/kvm ] && kvm="--device=/dev/kvm"
rc=0
for rel in "$@"; do
  # shellcheck disable=SC2086  # $kvm is empty or one whole option
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm --name "wh-upd-qemu-$rel-$$" $kvm \
    -v "$(hostpath "$repo"):/src:ro" -v "$(hostpath "$W"):/w" -v "$(hostpath "$OUT"):/out" -v "$(hostpath "$CACHE"):/cache" \
    "$QEMU_HOST_IMAGE" sh -euc 'apk add -q qemu-system-x86_64 python3 curl >/dev/null; r=0; sh /src/scripts/qemu-update.sh --vm "$1" || r=$?; chown -R "$2" /w /out /cache; exit "$r"' sh "$rel" "$OWNER" || rc=1
done
cat "$OUT"/results-*.txt > "$OUT/summary.txt" 2>/dev/null || :
echo; echo "qemu-update: $(grep -c '^PASS' "$OUT/summary.txt" || :) passed, $(grep -c '^FAIL' "$OUT/summary.txt" || :) failed -> $OUT/summary.txt"
exit "$rc"
