#!/bin/sh
# qemu-update-guest.sh - the in-guest half of scripts/qemu-update.sh. Runs on the OpenWrt VM (busybox
# ash), fetched from the runner's HTTP server, one phase per call. It reports `E2E <key>=<value>` lines
# and does not judge; the host decides PASS/FAIL from them.
#
# Usage: sh qemu-update-guest.sh <base-url> <phase> [args]
#   bootstrap <tag> <name>      the public one-command install: the release's own bootstrap.sh (served
#                               by the runner after it checked the file against GitHub's digest) with
#                               WAYHOP_VERSION=<tag>; it downloads and verifies the tarball itself
#   tarball <file> <sha> <name> a tarball from the runner, checked against <sha>, unpacked, install.sh -y
#   cleanup <file> <sha> <name> [--dry-run]   the same tarball's install.sh --cleanup
#   pkg <file> <sha> <name>     a feed package from the runner, checked against <sha>, installed with
#                               the router's own package manager (apk add / opkg install)
#   fill <free-kib>             leave <free-kib> free on the overlay (a filler file in /root)
#   seed                        what earlier installs and hand deploys leave beside the binary
#   cut                         the state a power cut inside the compressed-copy swap leaves: the old
#                               binary only in wayhop.bak.gz, a half-written wayhop.new, synced
#   state <name>                binary, rollback copies, daemon, port, overlay
#   simswap <file> <sha> <commit> the panel's self-update as the daemon performs it, with <file> as the
#                               new build: the rollback copy a hard link, the update recorded for the
#                               supervisor (expecting <commit>), the new build renamed into place
#   judge                       the supervisor started the way the daemon starts it: detached
#   result <name>               the supervisor's last judgement, and whether one is still running
#   forget                      drop the last judgement, so the next one cannot be mistaken for it
#   nosingbox                   remove the feed's sing-box the installer pulled in (room for s12)
#   feed <root> <keys> <name>   trust the runner's signed test feed and read it
#   pkgcmd <name> <apk|ipk> install-old   this tree's build (0.5.7.1) from the test feed
set -u

BASE="${1:?base url}"
PHASE="${2:?phase}"
shift 2
say() { echo "E2E $1=$2"; }
S=/usr/sbin
ovl() { _f=/; [ -d /overlay ] && _f=/overlay; df -k "$_f" | awk 'NR == 2 { print $4 }'; }
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

case "$PHASE" in
  bootstrap)
    tag="$1"; n="$2"
    wget -q -O "/tmp/bootstrap-$n.sh" "$BASE/bootstrap-$tag.sh" || { say "${n}_rc" 127; exit 0; }
    # stdin is not the console: the bootstrap runs as it does under curl | sh, with no TTY to prompt on
    WAYHOP_VERSION="$tag" sh "/tmp/bootstrap-$n.sh" < /dev/null > "/tmp/$n.log" 2>&1
    say "${n}_rc" "$?"
    sed 's/^/| /' "/tmp/$n.log" | tail -n 60 ;;
  tarball|cleanup)
    f="$1"; want="$2"; n="$3"; shift 3
    rm -rf "/tmp/$n" && mkdir -p "/tmp/$n"
    wget -q -O "/tmp/$n.tar.gz" "$BASE/$f" || { say "${n}_rc" 127; exit 0; }
    [ "$(sha "/tmp/$n.tar.gz")" = "$want" ] || { say "${n}_rc" 126; say "${n}_why" "sha256 mismatch"; exit 0; }
    tar -xzf "/tmp/$n.tar.gz" -C "/tmp/$n" && rm -f "/tmp/$n.tar.gz"
    if [ "$PHASE" = tarball ]; then ( cd "/tmp/$n" && sh ./install.sh -y ) < /dev/null > "/tmp/$n.log" 2>&1
    else ( cd "/tmp/$n" && sh ./install.sh --cleanup "$@" ) < /dev/null > "/tmp/$n.log" 2>&1; fi
    say "${n}_rc" "$?"
    sed 's/^/| /' "/tmp/$n.log" | tail -n 60 ;;
  pkg)
    f="$1"; want="$2"; n="$3"
    wget -q -O "/tmp/$f" "$BASE/$f" || { say "${n}_rc" 127; exit 0; }
    [ "$(sha "/tmp/$f")" = "$want" ] || { say "${n}_rc" 126; say "${n}_why" "sha256 mismatch"; exit 0; }
    if command -v apk >/dev/null 2>&1 && [ -d /etc/apk ]; then apk add --allow-untrusted "/tmp/$f" < /dev/null > "/tmp/$n.log" 2>&1
    else opkg install "/tmp/$f" < /dev/null > "/tmp/$n.log" 2>&1; fi
    say "${n}_rc" "$?"
    rm -f "/tmp/$f"
    sed 's/^/| /' "/tmp/$n.log" | tail -n 40
    if [ -f /usr/libexec/wayhop/wayhop ]; then
      say "${n}_onecopy" "$([ "$S/wayhop" -ef /usr/libexec/wayhop/wayhop ] && echo yes || echo no)"
    fi ;;
  simswap)
    f="$1"; want="$2"; wc="$3"
    wget -q -O /tmp/sim.bin "$BASE/$f" || { say simswap_rc 127; exit 0; }
    [ "$(sha /tmp/sim.bin)" = "$want" ] || { say simswap_rc 126; exit 0; }
    rm -f "$S/wayhop.bak.tmp"; ln "$S/wayhop" "$S/wayhop.bak.tmp" && mv "$S/wayhop.bak.tmp" "$S/wayhop.bak"
    printf 'bin=%s\ninit=%s\nconfig=%s\nrollback=%s\nnorollback=\nwant_commit=%s\nwant_version=\nfrom=%s\nto=v9.9.9\nby=panel\nwindow=30\nboots=0\n' \
      "$S/wayhop" /etc/init.d/wayhop /etc/wayhop/config.json "$S/wayhop.bak" "$wc" "$("$S/wayhop" --version | head -n 1)" > /etc/wayhop/update.pending
    if cp /tmp/sim.bin "$S/wayhop.new" && chmod 0755 "$S/wayhop.new" && mv "$S/wayhop.new" "$S/wayhop"; then _r=0
    else rm -f "$S/wayhop.new" /etc/wayhop/update.pending; _r=1; fi
    rm -f /tmp/sim.bin; sync
    say simswap_rc "$_r" ;;
  judge)
    if command -v setsid >/dev/null 2>&1; then
      setsid sh /etc/wayhop/update-verify.sh restart </dev/null >>/tmp/wayhop-update.log 2>&1 &
    else
      sh /etc/wayhop/update-verify.sh restart </dev/null >>/tmp/wayhop-update.log 2>&1 &
    fi
    say judge_started yes ;;
  result)
    n="$1"; r=/etc/wayhop/update-result.json
    say "${n}_result" "$(sed -n 's/.*"result":"\([^"]*\)".*/\1/p' "$r" 2>/dev/null)"
    say "${n}_reason" "$(sed -n 's/.*"reason":"\([^"]*\)".*/\1/p' "$r" 2>/dev/null)"
    say "${n}_by" "$(sed -n 's/.*"by":"\([^"]*\)".*/\1/p' "$r" 2>/dev/null)"
    say "${n}_pending" "$([ -f /etc/wayhop/update.pending ] && echo yes || echo no)"
    _vp="$(cat /tmp/wayhop-update-verify.pid 2>/dev/null)"
    say "${n}_judging" "$([ -n "$_vp" ] && kill -0 "$_vp" 2>/dev/null && echo yes || echo no)"
    tail -n 5 /tmp/wayhop-update.log 2>/dev/null | sed 's/^/| /' ;;
  forget)
    rm -f /etc/wayhop/update-result.json
    say forgot yes ;;
  nosingbox)
    # Room for the package cases on a small test overlay: the installer pulled the feed's sing-box in.
    if command -v apk >/dev/null 2>&1 && [ -d /etc/apk ]; then apk del sing-box >/dev/null 2>&1; else opkg remove sing-box >/dev/null 2>&1; fi
    sync
    say nosingbox_free_kib "$(ovl)" ;;
  feed)
    root="$1"; keys="$2"; n="$3"
    if command -v apk >/dev/null 2>&1 && [ -d /etc/apk ]; then
      wget -q -O "/etc/apk/keys/wayhop-test-$keys.pem" "$BASE/$keys/apk.pem.pub" &&
        echo "$BASE/$root/apk/x86_64/packages.adb" > /etc/apk/repositories.d/wayhop-test.list &&
        apk update > "/tmp/$n.log" 2>&1
    else
      wget -q -O /tmp/feed.pub "$BASE/$keys/usign.pub" && opkg-key add /tmp/feed.pub &&
        { sed -i '/wayhop_test/d' /etc/opkg/customfeeds.conf; echo "src/gz wayhop_test $BASE/$root/ipk/x86_64" >> /etc/opkg/customfeeds.conf; } &&
        opkg update > "/tmp/$n.log" 2>&1
    fi
    say "${n}_rc" "$?"
    tail -n 8 "/tmp/$n.log" 2>/dev/null | sed 's/^/| /' ;;
  pkgcmd)
    n="$1"; kind="$2"
    case "$kind" in
      # `apk add wayhop=<version>` pins that version in /etc/apk/world; the second add unpins it, as an
      # ordinary `apk add wayhop` install is, so that an upgrade can happen at all.
      apk) { apk add wayhop=0.5.7.1-r1 && apk add wayhop; } < /dev/null > "/tmp/$n.log" 2>&1 ;;
      *)   { opkg remove wayhop && opkg install "$BASE/feedA/ipk/x86_64/wayhop_0.5.7.1-1_x86_64.ipk"; } < /dev/null > "/tmp/$n.log" 2>&1 ;;
    esac
    say "${n}_rc" "$?"
    tail -n 12 "/tmp/$n.log" | sed 's/^/| /' ;;
  fill)
    rm -f /root/.filler; sync
    n=$(( $(ovl) - $1 ))
    [ "$n" -le 0 ] || dd if=/dev/zero of=/root/.filler bs=1024 count="$n" 2>/dev/null
    sync
    say fill_free_kib "$(ovl)" ;;
  seed)
    head -c 3145728 /dev/urandom > "$S/wayhop.new"; touch -d "2026-01-01 00:00:00" "$S/wayhop.new"
    ln "$S/wayhop" "$S/wakeroute.bak-fb51ee6"   # a build under the old name; a link, so it costs no room
    printf 'my notes\n' > "$S/wayhop.bak-notes"
    sync
    say seed_free_kib "$(ovl)" ;;
  cut)
    /etc/init.d/wayhop stop 2>/dev/null; sleep 2
    say cut_sha "$(sha "$S/wayhop")"
    gzip -c "$S/wayhop" > "$S/wayhop.bak.gz.new" && mv "$S/wayhop.bak.gz.new" "$S/wayhop.bak.gz" &&
      rm -f "$S/wayhop.bak" "$S/wayhop" && head -c 1048576 /dev/urandom > "$S/wayhop.new"
    sync
    say cut_binary_present "$([ -e "$S/wayhop" ] && echo yes || echo no)" ;;
  state)
    n="$1"
    say "${n}_version" "$("$S/wayhop" --version 2>/dev/null | head -n 1 | tr ' ' '_')"
    say "${n}_sha" "$(sha "$S/wayhop")"
    say "${n}_bak_sha" "$(sha "$S/wayhop.bak")"
    say "${n}_bakgz_sha" "$( [ -f "$S/wayhop.bak.gz" ] && gzip -dc "$S/wayhop.bak.gz" | sha256sum | cut -d' ' -f1)"
    say "${n}_files" "$(for f in "$S"/wayhop* "$S"/.wayhop* "$S"/velinx* "$S"/wakeroute*; do [ -e "$f" ] && printf '%s,' "${f##*/}"; done)"
    say "${n}_running" "$(pidof wayhop >/dev/null 2>&1 && echo yes || echo no)"
    say "${n}_health" "$(wget -q -O - -T 5 http://127.0.0.1:8088/api/health 2>/dev/null | sed -n 's/.*"commit":"\([0-9a-f]*\)".*/\1/p')"
    say "${n}_overlay_free_kib" "$(ovl)"
    sup=0
    if [ -f "$S/wayhop.bak" ] && [ ! "$S/wayhop.bak" -ef "$S/wayhop" ]; then sup=$(du -k "$S/wayhop.bak" | cut -f1); fi
    [ -f "$S/wayhop.bak.gz" ] && sup=$((sup + $(du -k "$S/wayhop.bak.gz" | cut -f1)))
    say "${n}_superseded_kib" "$sup"
    say "${n}_logread" "$(logread 2>/dev/null | grep -E 'wayhop: .*(restored|missing)' | tail -n 2 | tr ' ' '_' | tr '\n' ';')" ;;
  *) say error "unknown phase $PHASE"; exit 2 ;;
esac
