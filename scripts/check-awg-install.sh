#!/bin/sh
# check-awg-install.sh -- packaging/awg/install-awg.sh against the real package managers.
#
# The unit tests (packaging/awg/test/) drive the installer with a stub package manager; this gate
# runs it with the real apk-tools v3 (OpenWrt 25.12) and opkg (OpenWrt 24.10) in their official
# rootfs images, against a feed served over HTTP from a sibling container on a private, internal
# Docker network. Per image: dry run (changes nothing), userspace install, verification, a second
# run (current, changes nothing), uninstall (no residue: files and package list as before), the
# kernel-module path (install + uninstall, then a failed verification that must roll back to the
# exact previous state), and a feed signed with a different key (must be refused and rolled back).
#
# Default feed: tiny fixture packages built at test time with the tools WayHop's feed uses (ipk =
# gzip-tar outer, indexed by packaging/feed/make-index.sh; apk via `apk mkpkg`/`mkndx`/`adbsign` in
# the digest-pinned Alpine image from feed.yml) and signed with THROWAWAY keys generated here
# (usign via packaging/feed/usigntool, apk ECDSA via packaging/awg/test/keygen.go). The installer
# trusts them through its test-only AWG_INSTALL_TEST_KEYS hook.
#
# With a feed directory argument the real packages in it are used instead (re-indexed and signed with
# the throwaway keys). It may be in feed layout (ipk/ apk/ entware/ awg/openwrt/...) or in the
# dist/awg layout (ipk/ apk/ entware/ openwrt/...). Real packages pull dependencies (kmod-tun,
# kmod-udptunnel*) from the official OpenWrt feeds, so this mode leaves the network open; set
# AWG_CHECK_INTERNAL=1 to keep it closed.
#
# The kernel-module path cannot load a module here (the container shares the host's kernel): its
# install, rollback and uninstall plumbing is exercised with the verification replaced through the
# test-only AWG_INSTALL_TEST_VERIFY hook (it checks that amneziawg.ko landed and awg runs). Loading
# the real module is tested in QEMU (scripts/awg/qemu-e2e.sh).
#
# Needs Docker and a Go toolchain (GO=..., else `go` on PATH, else ~/go-toolchain/go/bin/go).
# Without Docker this exits 3 and says so: a lifecycle nobody ran must not report as one that passed.
#
# Usage: sh scripts/check-awg-install.sh [feeddir]     (from the repository root)
set -eu

FEEDDIR="${1:-}"
APK_IMAGE="${AWG_CHECK_APK_IMAGE:-openwrt/rootfs:x86-64-25.12.0@sha256:1a7f3e9c66e6b77d4014b7e37ffbee7edf114275dc6f1811314a572e11a8e636}"
OPKG_IMAGE="${AWG_CHECK_OPKG_IMAGE:-openwrt/rootfs:x86-64-24.10.4@sha256:1310ccbd24f30b3df6e210a48dbd0fb902445ee80e21ffc8b8e882b94987a411}"
BUILDER_IMAGE="${AWG_CHECK_BUILDER_IMAGE:-alpine:edge@sha256:d77617aef5805191da75fbbfe2f9dc2043582ecad0f4d381b27c151034765a76}"

command -v docker >/dev/null 2>&1 || { echo "no docker: the install-awg lifecycle was NOT exercised" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "docker is not running: the install-awg lifecycle was NOT exercised" >&2; exit 3; }
[ -f packaging/awg/install-awg.sh ] || { echo "run from the repository root" >&2; exit 2; }
if [ -n "$FEEDDIR" ] && [ ! -d "$FEEDDIR" ]; then echo "feed directory $FEEDDIR does not exist" >&2; exit 2; fi

GO="${GO:-}"
if [ -z "$GO" ]; then
  if command -v go >/dev/null 2>&1; then GO=go
  elif [ -x "$HOME/go-toolchain/go/bin/go" ]; then GO="$HOME/go-toolchain/go/bin/go"
  elif [ -x "$HOME/go-toolchain/go/bin/go.exe" ]; then GO="$HOME/go-toolchain/go/bin/go.exe"
  else echo "no Go toolchain (set GO=...)" >&2; exit 2; fi
fi
export GOTOOLCHAIN=local

# Git Bash rewrites unix-looking container paths; hand Docker paths it can resolve.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf %s "$1"; fi; }
dk() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker "$@"; }

tag="wayhop-awg-test-$$"
NET="$tag-net"; SERVER="$tag-feed"
work="$(mktemp -d)"
cleanup() {
  st=$?
  if [ "${AWG_CHECK_KEEP:-0}" = 1 ]; then   # debugging: leave the server, network and work tree
    echo "kept: container $SERVER, network $NET, work tree $work" >&2; exit "$st"
  fi
  dk rm -f "$SERVER" >/dev/null 2>&1 || :
  dk network rm "$NET" >/dev/null 2>&1 || :
  # Files written by root in containers: hand them back before removing the work tree.
  dk run --rm -v "$(hostpath "$work"):/w" "$BUILDER_IMAGE" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || :
  rm -rf "$work" 2>/dev/null || :
  exit "$st"
}
trap cleanup EXIT
mkdir -p "$work/bin" "$work/keys" "$work/keys-wrong" "$work/feed"

echo "building the feed signer and throwaway keys"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -trimpath -o "$work/bin/usigntool" ./packaging/feed/usigntool
"$GO" run ./packaging/awg/test/keygen.go "$work/keys/wayhop-apk.pem" "$work/keys/wayhop-apk.pem.pub"
"$GO" run ./packaging/awg/test/keygen.go "$work/keys-wrong/wayhop-apk.pem" "$work/keys-wrong/wayhop-apk.pem.pub"
# The fixture amneziawg-go is a real ELF, so --uninstall has a running packaged binary to find.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -trimpath -ldflags "-s -w" -o "$work/bin/fakego" ./packaging/awg/test/fakego.go
cp "${AWG_CHECK_INSTALLER:-packaging/awg/install-awg.sh}" "$work/install-awg.sh"   # override: mutation checks

if [ -n "$FEEDDIR" ]; then
  echo "using the packages in $FEEDDIR"
  if [ -d "$FEEDDIR/awg/openwrt" ] || [ ! -d "$FEEDDIR/openwrt" ]; then
    cp -R "$FEEDDIR/." "$work/feed/"
  else
    for d in ipk apk entware; do [ -d "$FEEDDIR/$d" ] && cp -R "$FEEDDIR/$d" "$work/feed/$d"; done
    mkdir -p "$work/feed/awg"; cp -R "$FEEDDIR/openwrt" "$work/feed/awg/openwrt"
  fi
  # Indexes are rebuilt and signed with the throwaway keys below.
  find "$work/feed" \( -name 'Packages' -o -name 'Packages.gz' -o -name 'Packages.sig' -o -name 'packages.adb' \) -exec rm -f {} +
  INTERNAL="${AWG_CHECK_INTERNAL:-0}"
else
  INTERNAL="${AWG_CHECK_INTERNAL:-1}"
fi

echo "building fixture packages, indexes and signatures"
# shellcheck disable=SC2016  # the script below runs in the container and expands there
dk run --rm --network none -v "$(hostpath "$PWD"):/src:ro" -v "$(hostpath "$work"):/w" \
  -e FIXTURES="$([ -n "$FEEDDIR" ] && echo 0 || echo 1)" "$BUILDER_IMAGE" sh -euc '
  U=/w/bin/usigntool
  for k in keys keys-wrong; do
    "$U" genkey -comment "install-awg lifecycle throwaway key" -pub /w/$k/wayhop.pub -sec /w/$k/wayhop.sec >/dev/null
    "$U" fingerprint -pub /w/$k/wayhop.pub > /w/$k/wayhop.pub.fingerprint
  done
  if [ "$FIXTURES" = 1 ]; then
    t=/tmp/fx; mkdir -p "$t"
    mkroot() { # dir file content
      mkdir -p "$1/$(dirname "$2")"; printf "%s\n" "$3" > "$1/$2"; chmod 0755 "$1/$2"
    }
    mkipk() { # name version arch depends outdir rootdir
      p=$(mktemp -d); mkdir -p "$p/control"
      {
        printf "Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: WayHop test\n" "$1" "$2" "$3"
        [ -n "$4" ] && printf "Depends: %s\n" "$4"
        printf "Installed-Size: %s\nDescription: install-awg lifecycle fixture\n" "$(( $(du -sk "$6" | cut -f1) * 1024 ))"
      } > "$p/control/control"
      (cd "$6" && tar -czf "$p/data.tar.gz" .)
      (cd "$p/control" && tar -czf "$p/control.tar.gz" .)
      printf "2.0\n" > "$p/debian-binary"
      mkdir -p "$5"
      (cd "$p" && tar -czf "$5/$1_$2_$3.ipk" ./debian-binary ./data.tar.gz ./control.tar.gz)
      rm -rf "$p"
    }
    mkapk() { # name version arch depends outdir rootdir
      mkdir -p "$5"
      if [ -n "$4" ]; then
        apk mkpkg --info "name:$1" --info "version:$2" --info "arch:$3" --info "license:MIT" \
          --info "description:install-awg lifecycle fixture" --info "depends:$4" --files "$6" -o "$5/$1-$2.apk"
      else
        apk mkpkg --info "name:$1" --info "version:$2" --info "arch:$3" --info "license:MIT" \
          --info "description:install-awg lifecycle fixture" --files "$6" -o "$5/$1-$2.apk"
      fi
    }
    mkdir -p $t/go/usr/bin; cp /w/bin/fakego $t/go/usr/bin/amneziawg-go; chmod 0755 $t/go/usr/bin/amneziawg-go
    # A dependency each path pulls in, as the real kmod-udptunnel*/kmod-tun are: an uninstall has to
    # take it away again (opkg does not by itself), and only it.
    mkroot $t/dep-kmod usr/lib/awg-test-dep-kmod.marker "fixture dependency"   # in a dir that exists
    mkroot $t/dep-go usr/lib/awg-test-dep-go.marker "fixture dependency"
    mkroot $t/tools usr/bin/awg "#!/bin/sh
echo \"amneziawg-tools v3.1.20260812 (lifecycle fixture)\""
    mkroot $t/tools lib/netifd/proto/amneziawg.sh "#!/bin/sh"
    mkroot $t/k24 lib/modules/6.6.110/amneziawg.ko "fixture module"
    mkroot $t/k25 lib/modules/6.12.71/amneziawg.ko "fixture module"
    mkroot $t/luci www/luci-static/resources/protocol/amneziawg.js "// fixture"
    # OpenWrt 24.10.4 x86/64 (opkg); the kernel dependency is the image kernel package version.
    mkipk amneziawg-go 3.1.20260828-1 x86_64 "awg-test-dep-go" /w/feed/ipk/x86_64 $t/go
    mkipk awg-test-dep-go 1-1 x86_64 "" /w/feed/ipk/x86_64 $t/dep-go
    o=/w/feed/awg/openwrt/24.10.4/x86/64
    mkipk kmod-amneziawg 6.6.110.3.1.20260906-1 x86_64 "kernel (=6.6.110~484466e2719a743506c36b4bb2103582-r1), awg-test-dep-kmod" $o $t/k24
    mkipk awg-test-dep-kmod 1-1 x86_64 "" $o $t/dep-kmod
    mkipk amneziawg-tools 3.1.20260812-1 x86_64 "" $o $t/tools
    mkipk luci-proto-amneziawg 3.1.20260906-1 all "luci-base, amneziawg-tools" $o $t/luci
    # OpenWrt 25.12.0 x86/64 (apk).
    mkapk amneziawg-go 3.1.20260828-r1 x86_64 "awg-test-dep-go" /w/feed/apk/x86_64 $t/go
    mkapk awg-test-dep-go 1-r1 x86_64 "" /w/feed/apk/x86_64 $t/dep-go
    o=/w/feed/awg/openwrt/25.12.0/x86/64
    mkapk kmod-amneziawg 6.12.71.3.1.20260906-r1 x86_64 "kernel=6.12.71~dad96e0b324e75e311f44d061391d208-r1 awg-test-dep-kmod" $o $t/k25
    mkapk awg-test-dep-kmod 1-r1 x86_64 "" $o $t/dep-kmod
    mkapk amneziawg-tools 3.1.20260812-r1 x86_64 "" $o $t/tools
    mkapk luci-proto-amneziawg 3.1.20260906-r1 noarch "luci-base amneziawg-tools" $o $t/luci
  fi
  # opkg indexes: the shipped indexer for ipk/ and entware/; per-target dirs through a staging root.
  if [ -n "$(find /w/feed/ipk /w/feed/entware -name "*.ipk" 2>/dev/null | head -n1)" ]; then
    sh /src/packaging/feed/make-index.sh /w/feed /w/keys/wayhop.sec /w/keys/wayhop.pub "$U"
  fi
  find /w/feed/awg -name "*.ipk" 2>/dev/null | sed "s#/[^/]*\$##" | sort -u | while read -r d; do
    st=$(mktemp -d); mkdir -p "$st/ipk/x"; cp "$d"/*.ipk "$st/ipk/x/"
    sh /src/packaging/feed/make-index.sh "$st" /w/keys/wayhop.sec /w/keys/wayhop.pub "$U"
    cp "$st"/ipk/x/Packages "$st"/ipk/x/Packages.gz "$st"/ipk/x/Packages.sig "$d/"
    rm -rf "$st"
  done
  # apk indexes: the same mkndx + adbsign + verify sequence as feed.yml.
  mkdir -p /tmp/kv; cp /w/keys/wayhop-apk.pem.pub /tmp/kv/
  find /w/feed -name "*.apk" | sed "s#/[^/]*\$##" | sort -u | while read -r d; do
    (cd "$d" && apk --allow-untrusted mkndx -o packages.adb ./*.apk >/dev/null &&
      apk --allow-untrusted adbsign --sign-key /w/keys/wayhop-apk.pem packages.adb &&
      apk --keys-dir /tmp/kv verify packages.adb >/dev/null)
    echo "  indexed + signed + verified $d/packages.adb"
  done
  cp /w/keys/wayhop.pub /w/feed/wayhop.pub
  chmod -R a+rX /w/feed   # usigntool writes 0600 files; a web server serves only world-readable ones
  rm -f /w/keys/wayhop.sec /w/keys-wrong/wayhop.sec /w/keys/wayhop-apk.pem /w/keys-wrong/wayhop-apk.pem
'

echo "serving the feed on an isolated docker network"
if [ "$INTERNAL" = 1 ]; then dk network create --internal "$NET" >/dev/null; else dk network create "$NET" >/dev/null; fi
dk run -d --name "$SERVER" --network "$NET" --network-alias feed -v "$(hostpath "$work/feed"):/feed:ro" \
  "$OPKG_IMAGE" /usr/sbin/uhttpd -f -p 0.0.0.0:8080 -h /feed >/dev/null

cat > "$work/lifecycle.sh" <<'LIFECYCLE'
#!/bin/sh
# Runs inside an OpenWrt rootfs container: the install-awg.sh lifecycle with the real package manager.
set -u
FEED="http://feed:8080"
fails=0
ok() { echo "  PASS  $1"; }
no() { echo "  FAIL  $1"; fails=$((fails + 1)); }
expect() { # description command...
  ex_d="$1"; shift
  if "$@"; then ok "$ex_d"; else no "$ex_d"; fi
}
mkdir -p /var/lock
if [ -d /etc/apk ]; then PMK=apk; else PMK=opkg; fi
# shellcheck disable=SC1091  # the router's own release file
. /etc/openwrt_release
REL="$DISTRIB_RELEASE"; TGT="$DISTRIB_TARGET"
if [ "${OFFLINE:-1}" = 1 ]; then
  # The gate is offline: the official feeds cannot answer, and each unreachable one costs ~40 s.
  if [ "$PMK" = apk ]; then : > /etc/apk/repositories.d/distfeeds.list; else : > /etc/opkg/distfeeds.conf; fi
fi
i=0
until wget -q -O /dev/null "$FEED/wayhop.pub" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -ge 30 ] && { no "the feed server never answered"; exit 1; }; sleep 1
done

KEYS=/w/keys
run() { # installer args... -> RC, /tmp/awg.out (stdout), /tmp/awg.err
  AWG_INSTALL_TEST_KEYS="$KEYS" sh /w/install-awg.sh --feed "$FEED" --yes --json "$@" > /tmp/awg.out 2> /tmp/awg.err < /dev/null
  RC=$?
}
j() { tail -n1 /tmp/awg.out | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
jb() { tail -n1 /tmp/awg.out | sed -n "s/.*\"$1\":\([a-z]*\).*/\1/p"; }
# netifd reads its proto handlers only at start: amneziawg-tools (which carries the handler)
# installed, upgraded or removed must be reported as needing a netifd restart.
netifd_is() { # description want
  expect "$1: netifd_restart_needed is $(jb netifd_restart_needed), want $2" test "$(jb netifd_restart_needed)" = "$2"
}
pkgs() { if [ "$PMK" = apk ]; then apk list --manifest -I 2>/dev/null; else opkg list-installed 2>/dev/null; fi | sort; }
owned() { if [ "$PMK" = apk ]; then apk list --manifest -I "$1" 2>/dev/null; else opkg status "$1" 2>/dev/null; fi | grep -q .; }
snap() {
  find /etc /usr /lib /www \( -path /lib/apk -o -path /usr/lib/opkg \) -prune -o -print 2>/dev/null | sort |
    while IFS= read -r f; do if [ -f "$f" ]; then echo "F $f $(sha256sum < "$f")"; else echo "D $f"; fi; done
}
show() { sed 's/^/        | /' /tmp/awg.err | tail -n 12; tail -n1 /tmp/awg.out | sed 's/^/        | /'; }
verdict() { # description rc result [path]
  if [ "$RC" = "$2" ] && [ "$(j result)" = "$3" ] && { [ -z "${4:-}" ] || [ "$(j path)" = "$4" ]; }; then ok "$1"
  else no "$1 (exit $RC, result $(j result), path $(j path))"; show; fi
}
# delta OLD NEW: lines only in one of them (busybox on OpenWrt 24.10 has no diff)
delta() { awk 'NR == FNR { o[$0] = 1; next } { n[$0] = 1; if (!($0 in o)) print "+ " $0 } END { for (l in o) if (!(l in n)) print "- " l }' "$1" "$2"; }
same_as_base() { # what
  snap > /tmp/snap.now; pkgs > /tmp/pkgs.now
  if cmp -s /tmp/snap.base /tmp/snap.now; then ok "$1: files exactly as before"
  else no "$1: files differ from before"; delta /tmp/snap.base /tmp/snap.now | head -n 10 | sed 's/^/        | /'; fi
  if cmp -s /tmp/pkgs.base /tmp/pkgs.now; then ok "$1: installed packages exactly as before"
  else no "$1: installed packages differ"; delta /tmp/pkgs.base /tmp/pkgs.now | head -n 10 | sed 's/^/        | /'; fi
}

echo "== OpenWrt $REL $TGT ($PMK) =="
# An interface of the amneziawg protocol, the way an operator or WayHop configures one: --uninstall
# brings it down first and must leave its configuration exactly as it was.
[ -f /etc/config/network ] || : > /etc/config/network
uci set network.awgtest=interface && uci set network.awgtest.proto=amneziawg && uci commit network
snap > /tmp/snap.base; pkgs > /tmp/pkgs.base
alive() { [ -d "/proc/$1" ] && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null; }
ARCH="$(cat /etc/apk/arch 2>/dev/null || opkg print-architecture | awk '$1 == "arch" && $2 != "all" && $2 != "noarch" { print $2; exit }')"
if [ "$PMK" = apk ]; then PA_LINE="$FEED/apk/$ARCH/packages.adb"; PA_FILE=/etc/apk/repositories.d/wayhop.list
else PA_LINE="src/gz wayhop $FEED/ipk/$ARCH"; PA_FILE=/etc/opkg/customfeeds.conf; fi

run --mode userspace --dry-run
verdict "dry run reports the userspace plan" 0 dry-run userspace
same_as_base "after --dry-run"

run --mode userspace
verdict "userspace install" 0 installed userspace
expect "amneziawg-go --version runs" sh -c 'amneziawg-go --version >/dev/null 2>&1'
expect "the pkgarch feed line was added" grep -qxF "$PA_LINE" "$PA_FILE"
if [ "$PMK" = apk ]; then expect "the feed key is trusted by apk" cmp -s /etc/apk/keys/wayhop.pem "$KEYS/wayhop-apk.pem.pub"
else expect "the feed key is trusted by opkg" cmp -s "/etc/opkg/keys/$(cat "$KEYS/wayhop.pub.fingerprint")" "$KEYS/wayhop.pub"; fi
expect "the package manager owns amneziawg-go" owned amneziawg-go
if tail -n1 /tmp/awg.out | grep -q '"amneziawg-tools"'; then TOOLS=true; else TOOLS=false; fi
netifd_is "userspace install (amneziawg-tools: $TOOLS)" "$TOOLS"
expect "the network was not restarted without --restart-network" test "$(jb network_restarted)" = false

snap > /tmp/snap.installed
run --mode userspace
verdict "a second run reports current" 0 current userspace
netifd_is "second run" false
snap > /tmp/snap.again
expect "the second run changed no file" cmp -s /tmp/snap.installed /tmp/snap.again

GOPID=""
if [ "${FIXTURES:-0}" = 1 ]; then
  /usr/bin/amneziawg-go awgtest > /dev/null 2>&1 &   # the fixture binary waits until stopped
  GOPID=$!
  sleep 1
  expect "the packaged amneziawg-go is running before the uninstall" alive "$GOPID"
fi
run --uninstall
verdict "uninstall" 0 removed
netifd_is "uninstall (amneziawg-tools was installed: $TOOLS)" "$TOOLS"
expect "amneziawg-go is gone" sh -c '! command -v amneziawg-go >/dev/null 2>&1'
if [ -n "$GOPID" ]; then
  expect "the uninstall stopped the running packaged amneziawg-go" sh -c "! { [ -d /proc/$GOPID ] && ! grep -q '^State:[[:space:]]*Z' /proc/$GOPID/status; }"
  kill -KILL "$GOPID" 2>/dev/null; wait "$GOPID" 2>/dev/null   # never left running, never waited on forever
else
  echo "  SKIP  stopping a running amneziawg-go: real packages (needs the fixture binary)"
fi
expect "the uninstall brought the amneziawg interface down" grep -q 'bringing down interface awgtest' /tmp/awg.err
expect "the interface configuration is untouched" test "$(uci -q get network.awgtest.proto)" = amneziawg
expect "the generation after the removal is none" test "$(j generation)" = none
same_as_base "after --uninstall (dependencies included)"

if [ "$PMK" = apk ]; then PT_INDEX=packages.adb; else PT_INDEX=Packages.gz; fi
if wget -q -O /dev/null "$FEED/awg/openwrt/$REL/$TGT/$PT_INDEX" 2>/dev/null; then
  # TEST ONLY: no module can be loaded in a container; check that it landed and that awg runs.
  # shellcheck disable=SC2089,SC2016  # a command string the installer runs with sh -c
  export AWG_INSTALL_TEST_VERIFY='[ -n "$(find /lib/modules -name amneziawg.ko)" ] && awg --version'
  run
  verdict "kernel-module install (verification stubbed: no module loading in a container)" 0 installed kmod
  netifd_is "kernel-module install" true
  # shellcheck disable=SC2016
  expect "amneziawg.ko is on disk" sh -c '[ -n "$(find /lib/modules -name amneziawg.ko)" ]'
  expect "LuCI is installed, so is luci-proto-amneziawg" sh -c "tail -n1 /tmp/awg.out | grep -q luci-proto-amneziawg"
  run --uninstall
  verdict "kernel-module uninstall" 0 removed
  same_as_base "after the kernel-module uninstall"
  # shellcheck disable=SC2090
  export AWG_INSTALL_TEST_VERIFY=false
  run
  verdict "a failed verification is reported as failed" 1 failed kmod
  same_as_base "after the rollback"
  # SIGTERM in the middle of a real install (during the stubbed verification): rolled back.
  # shellcheck disable=SC2090
  export AWG_INSTALL_TEST_VERIFY='sleep 3'
  AWG_INSTALL_TEST_KEYS="$KEYS" sh /w/install-awg.sh --feed "$FEED" --yes --json > /tmp/awg.out 2> /tmp/awg.err < /dev/null &
  BGPID=$!
  i=0
  until grep -q 'TEST ONLY: verification replaced' /tmp/awg.err 2>/dev/null; do
    i=$((i + 1)); [ "$i" -ge 60 ] && break; sleep 1
  done
  kill -TERM "$BGPID" 2>/dev/null
  wait "$BGPID"; RC=$?
  verdict "SIGTERM in the middle of an install is reported as failed" 1 failed kmod
  expect "the reason says interrupted" sh -c 'tail -n1 /tmp/awg.out | grep -q interrupted'
  same_as_base "after the interrupted install"
  unset AWG_INSTALL_TEST_VERIFY
else
  echo "  SKIP  kernel-module path: the feed has no build for $REL $TGT"
fi

KEYS=/w/keys-wrong
run --mode userspace
verdict "a feed signed with another key is not installed" 1 failed userspace
same_as_base "after the refused signature"

echo "RESULT fails=$fails"
[ "$fails" = 0 ]
LIFECYCLE

offline=1; [ "$INTERNAL" = 1 ] || offline=0
fixtures=1; [ -n "$FEEDDIR" ] && fixtures=0
total_fail=0; total_pass=0; skips=0
for img in "$APK_IMAGE" "$OPKG_IMAGE"; do
  out="$(dk run --rm --network "$NET" -e OFFLINE="$offline" -e FIXTURES="$fixtures" -v "$(hostpath "$work"):/w:ro" "$img" sh /w/lifecycle.sh 2>&1)" || :
  echo "$out"
  p="$(printf '%s\n' "$out" | grep -c '  PASS ' || :)"; f="$(printf '%s\n' "$out" | grep -c '  FAIL ' || :)"
  s="$(printf '%s\n' "$out" | grep -c '  SKIP ' || :)"
  printf '%s\n' "$out" | grep -q '^RESULT fails=' || { echo "  FAIL  the lifecycle in $img did not finish"; f=$((f + 1)); }
  total_pass=$((total_pass + p)); total_fail=$((total_fail + f)); skips=$((skips + s))
done

echo "install-awg lifecycle: $total_pass checks passed, $total_fail failed, $skips skipped (apk: ${APK_IMAGE%%@*}, opkg: ${OPKG_IMAGE%%@*})"
[ "$total_fail" = 0 ]
