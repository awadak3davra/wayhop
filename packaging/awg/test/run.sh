#!/bin/sh
# run.sh -- table-driven unit tests for packaging/awg/install-awg.sh.
#
# Every case builds a fixture root (fake /etc/openwrt_release, /proc/meminfo, /proc/version, opkg or
# apk configuration, Entware /opt), a stub package manager (stub-pm.sh via AWG_INSTALL_PKG) that logs
# its calls, stub df/modprobe/awg/amneziawg-go on PATH, and a stub feed served from files, then runs
# the installer with --json and checks the exit code, the JSON verdict and the files it touched.
# No root, no network, no Docker inside. Run it with the shell under test:
#   busybox ash packaging/awg/test/run.sh      dash packaging/awg/test/run.sh
# (packaging/awg/test/docker.sh runs both). AWG_TEST_SH names the shell that runs the installer.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="${AWG_TEST_INSTALLER:-$HERE/../install-awg.sh}"   # override: mutation checks
KEYS="$HERE/../../feed/keys"
SHX="${AWG_TEST_SH:-sh}"
TAB_="$(printf '\t')"
[ -f "$INSTALLER" ] || { echo "install-awg.sh not found at $INSTALLER" >&2; exit 2; }

WORK="$(mktemp -d "${AWG_TEST_TMP:-/tmp}/awg-unit.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0; CASES=0
pass() { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s: %s\n' "$CASE" "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }
check() { # description command...
  ck_d="$1"; shift
  if "$@"; then pass; else fail "$ck_d"; fi
}

# --- versions used by the fixtures ---------------------------------------------------------------
K25="6.12.71~dad96e0b324e75e311f44d061391d208-r1"
K24="6.6.110~484466e2719a743506c36b4bb2103582-r1"
KMT="6.6.110~0123456789abcdef0123456789abcdef-r1"
V_KMOD25="6.12.71.3.1.20260906-r1"; V_TOOLS25="3.1.20260812-r1"; V_LUCI25="3.1.20260906-r1"; V_GO25="3.1.20260828-r1"
V_KMOD24="6.6.110.3.1.20260906-1";  V_TOOLS24="3.1.20260812-1";  V_GO24="3.1.20260828-1"

# --- stubs ---------------------------------------------------------------------------------------
BIN="$WORK/bin"; mkdir -p "$BIN"
printf '#!/bin/sh\nexec sh "%s" "$@"\n' "$HERE/stub-pm.sh" > "$BIN/pm"
cat > "$BIN/df" <<'EOF'
#!/bin/sh
p=""; for a in "$@"; do case "$a" in -*) ;; *) p="$a" ;; esac; done
case "$p" in /tmp) f="$AWG_STUB_DIR/tmp_free" ;; *) f="$AWG_STUB_DIR/flash_free" ;; esac
printf 'Filesystem           1024-blocks    Used Available Capacity Mounted on\n'
printf 'fake 1000000 1 %s 1%% %s\n' "$(cat "$f")" "$p"
EOF
cat > "$BIN/modprobe" <<'EOF'
#!/bin/sh
echo "modprobe $*" >> "$AWG_STUB_DIR/log"
grep -q '^kmod-amneziawg ' "$AWG_STUB_DIR/installed" || { echo "modprobe: module $1 not found"; exit 1; }
[ -f "$AWG_STUB_DIR/kmod_fail" ] && { echo "modprobe: failed to load $1: Exec format error"; exit 1; }
mkdir -p "$AWG_INSTALL_ROOT/sys/module/amneziawg"
echo live > "$AWG_INSTALL_ROOT/sys/module/amneziawg/initstate"
EOF
cp "$BIN/modprobe" "$BIN/insmod"
cat > "$BIN/rmmod" <<'EOF'
#!/bin/sh
echo "rmmod $*" >> "$AWG_STUB_DIR/log"
[ -f "$AWG_STUB_DIR/rmmod_fail" ] && { echo "rmmod: ERROR: Module $1 is in use"; exit 1; }
rm -rf "$AWG_INSTALL_ROOT/sys/module/$1"
EOF
# uci, ifdown and ip: just enough of OpenWrt's for the uninstall's runtime stop. ifdown stands in for
# netifd tearing the interface (and its link) down.
cat > "$BIN/uci" <<'EOF'
#!/bin/sh
echo "uci $*" >> "$AWG_STUB_DIR/log"
[ "$*" = "-q show network" ] && cat "$AWG_INSTALL_ROOT/etc/config/network.show" 2>/dev/null
exit 0
EOF
cat > "$BIN/ifdown" <<'EOF'
#!/bin/sh
echo "ifdown $*" >> "$AWG_STUB_DIR/log"
rm -rf "$AWG_INSTALL_ROOT/sys/class/net/$1"
EOF
cat > "$BIN/ip" <<'EOF'
#!/bin/sh
echo "ip $*" >> "$AWG_STUB_DIR/log"
[ "$1 $2 $3" = "link del dev" ] && rm -rf "$AWG_INSTALL_ROOT/sys/class/net/$4"
exit 0
EOF
cat > "$BIN/awg" <<'EOF'
#!/bin/sh
grep -q '^amneziawg-tools ' "$AWG_STUB_DIR/installed" || { echo "awg: not found"; exit 127; }
[ -f "$AWG_STUB_DIR/verify_fail" ] && { echo "awg: Exec format error"; exit 1; }
echo "amneziawg-tools v3.1.20260812 - https://amnezia.org"
EOF
cat > "$BIN/amneziawg-go" <<'EOF'
#!/bin/sh
grep -q '^amneziawg-go ' "$AWG_STUB_DIR/installed" || { echo "amneziawg-go: not found"; exit 127; }
[ -f "$AWG_STUB_DIR/verify_fail" ] && { echo "amneziawg-go: Exec format error"; exit 1; }
echo "amneziawg-go v3.1.20260828"
EOF
chmod +x "$BIN"/*

# --- stub feed ----------------------------------------------------------------------------------
FEEDP="$WORK/feed"
apk_entry() { # name version isize fsize [depends...]
  printf '  - name: %s\n    version: %s\n    hashes: 00\n    description: fixture\n    arch: x86_64\n    license: GPL-2.0\n    installed-size: %s\n    file-size: %s\n' "$1" "$2" "$3" "$4"
  shift 4
  if [ $# -gt 0 ]; then
    printf '    depends: # %s items\n' "$#"
    for d in "$@"; do printf '      - %s\n' "$d"; done
  fi
}
apk_index() { # dir, entries on stdin
  mkdir -p "$1"
  { printf '#%%SCHEMA: 78646E69\n# ADB block, size: 1, compat: 0, ver: 0\npackages: # n items\n'; cat; } > "$1/packages.adb"
}
ipk_entry() { # name version isize size depends
  printf 'Package: %s\nVersion: %s\n' "$1" "$2"
  [ -n "$5" ] && printf 'Depends: %s\n' "$5"
  printf 'Architecture: x\nInstalled-Size: %s\nFilename: %s_%s.ipk\nSize: %s\nSHA256sum: 00\nDescription: fixture\n\n' "$3" "$1" "$2" "$4"
}
ipk_index() { mkdir -p "$1"; gzip -c > "$1/Packages.gz"; }

{ apk_entry kmod-amneziawg "$V_KMOD25" 97280 40000 "kernel=$K25" kmod-udptunnel4 kmod-udptunnel6
  apk_entry amneziawg-tools "$V_TOOLS25" 66560 30000 libc
  apk_entry luci-proto-amneziawg "$V_LUCI25" 20480 9000 luci-base amneziawg-tools
  apk_entry luci-i18n-amneziawg-ru "$V_LUCI25" 4096 3000 luci-proto-amneziawg
} | apk_index "$FEEDP/awg/openwrt/25.12.0/x86/64"
apk_entry amneziawg-go "$V_GO25" 5242880 1572864 kmod-tun | apk_index "$FEEDP/apk/x86_64"
{ ipk_entry kmod-amneziawg "$V_KMOD24" 97280 40000 "kernel (=$K24), kmod-udptunnel4, kmod-udptunnel6"
  ipk_entry amneziawg-tools "$V_TOOLS24" 66560 30000 "libc"
  ipk_entry luci-proto-amneziawg "$V_TOOLS24" 20480 9000 "luci-base, amneziawg-tools"
} | ipk_index "$FEEDP/awg/openwrt/24.10.4/x86/64"
{ ipk_entry kmod-amneziawg "6.6.110.3.1.20260906-1" 97280 40000 "kernel (=$KMT), kmod-udptunnel4"
  ipk_entry amneziawg-tools "$V_TOOLS24" 66560 30000 "libc"
} | ipk_index "$FEEDP/awg/openwrt/24.10.4/ramips/mt7621"
ipk_entry amneziawg-go "$V_GO24" 5242880 1572864 "kmod-tun" | ipk_index "$FEEDP/ipk/x86_64"
ipk_entry amneziawg-go "$V_GO24" 5242880 1572864 "kmod-tun" | ipk_index "$FEEDP/ipk/mipsel_24kc"
{ ipk_entry amneziawg-go "$V_GO24" 5242880 1572864 ""
  ipk_entry amneziawg-tools "$V_TOOLS24" 70000 30000 ""
} | ipk_index "$FEEDP/entware/mipselsf-k3.4"
cp "$KEYS/wayhop.pub" "$FEEDP/wayhop.pub"
FEED="file://$FEEDP"

# --- fixture roots ------------------------------------------------------------------------------
new_case() { # name
  CASE="$1"; C="$WORK/case-$1"; ROOT="$C/root"; S="$C/stub"
  mkdir -p "$ROOT/proc" "$ROOT/sys/module" "$S" "$C/tmp"
  : > "$S/log"; : > "$S/installed"; : > "$S/available"; : > "$S/deps"; : > "$S/files"
  echo 100000 > "$S/flash_free"; echo 60000 > "$S/tmp_free"
}
meminfo() { printf 'MemTotal:       %s kB\nMemFree:        %s kB\nMemAvailable:   %s kB\n' "$1" "$(($1 / 2))" "$(($1 / 2))" > "$ROOT/proc/meminfo"; }
owrt() { # release target/subtarget pkgarch apk|opkg kernel-pkg-version kernel-release memKiB
  mkdir -p "$ROOT/etc" "$ROOT/overlay" "$ROOT/lib/netifd/proto"
  printf "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='%s'\nDISTRIB_REVISION='r1-fixture'\nDISTRIB_TARGET='%s'\nDISTRIB_ARCH='%s'\nDISTRIB_DESCRIPTION='OpenWrt %s'\nDISTRIB_TAINTS=''\n" \
    "$1" "$2" "$3" "$1" > "$ROOT/etc/openwrt_release"
  printf 'Linux version %s (builder@buildhost) (x86_64-openwrt-linux-musl-gcc) #0 SMP\n' "$6" > "$ROOT/proc/version"
  meminfo "$7"
  echo "$4" > "$S/kind"; echo "$3" > "$S/arch"
  if [ "$4" = apk ]; then
    mkdir -p "$ROOT/etc/apk/keys" "$ROOT/etc/apk/repositories.d"
    echo "$3" > "$ROOT/etc/apk/arch"
    echo "-----BEGIN PUBLIC KEY-----OPENWRT-----END PUBLIC KEY-----" > "$ROOT/etc/apk/keys/openwrt-25.12.pem"
    printf 'https://downloads.openwrt.org/releases/%s/targets/%s/packages/packages.adb\n' "$1" "$2" > "$ROOT/etc/apk/repositories.d/distfeeds.list"
    printf '# add your custom package feeds here\n#\n# http://www.example.com/path/to/files/packages.adb\n' > "$ROOT/etc/apk/repositories.d/customfeeds.list"
  else
    mkdir -p "$ROOT/etc/opkg/keys"
    printf 'dest root /\ndest ram /tmp\nlists_dir ext /var/opkg-lists\noption overlay_root /overlay\noption check_signature\n' > "$ROOT/etc/opkg.conf"
    printf 'src/gz openwrt_core https://downloads.openwrt.org/releases/%s/targets/%s/packages\n' "$1" "$2" > "$ROOT/etc/opkg/distfeeds.conf"
    printf '# add your custom package feeds here\n#\n# src/gz example_feed_name http://www.example.com/path/to/files\n' > "$ROOT/etc/opkg/customfeeds.conf"
    echo "untrusted comment: OpenWrt usign key" > "$ROOT/etc/opkg/keys/d310c6f2833e97f7"
  fi
  printf 'kernel %s\nbusybox 1.37.0-r1\nlibc 1.2.5-r5\n' "$5" > "$S/installed"
  echo "amneziawg-tools /lib/netifd/proto/amneziawg.sh" > "$S/files"   # the netifd proto handler
}
entware() { # pkgarch memKiB keenetic(0|1)
  mkdir -p "$ROOT/opt/bin" "$ROOT/opt/etc/opkg" "$ROOT/opt/sbin"
  : > "$ROOT/opt/bin/opkg"
  printf 'src/gz entware http://bin.entware.net/%s\ndest root /\nlists_dir ext /opt/var/opkg-lists\narch all 100\narch %s 150\n' "$1" "$1" > "$ROOT/opt/etc/opkg.conf"
  printf 'Linux version 4.9-ndm-5 (developers@ndmsystems.com) #0 SMP\n' > "$ROOT/proc/version"
  meminfo "$2"
  if [ "$3" = 1 ]; then mkdir -p "$ROOT/bin"; : > "$ROOT/bin/ndmc"; fi
  echo opkg > "$S/kind"; echo "$1" > "$S/arch"
  printf 'busybox 1.36.1-1\nlibc 2.27-11\n' > "$S/installed"
}
avail25() {
  printf 'kmod-amneziawg %s\namneziawg-tools %s\nluci-proto-amneziawg %s\nluci-i18n-amneziawg-ru %s\namneziawg-go %s\n' \
    "$V_KMOD25" "$V_TOOLS25" "$V_LUCI25" "$V_LUCI25" "$V_GO25" > "$S/available"
  printf 'kmod-amneziawg kmod-udptunnel4 6.12.71-r1\nkmod-amneziawg kmod-udptunnel6 6.12.71-r1\namneziawg-go kmod-tun 6.12.71-r1\n' > "$S/deps"
}
avail24() {
  printf 'kmod-amneziawg %s\namneziawg-tools %s\nluci-proto-amneziawg %s\namneziawg-go %s\n' \
    "$V_KMOD24" "$V_TOOLS24" "$V_TOOLS24" "$V_GO24" > "$S/available"
  printf 'kmod-amneziawg kmod-udptunnel4 6.6.110-1\namneziawg-go kmod-tun 6.6.110-1\n' > "$S/deps"
}
availEW() { printf 'amneziawg-go %s\namneziawg-tools %s\n' "$V_GO24" "$V_TOOLS24" > "$S/available"; : > "$S/deps"; }

# --- fixtures (one per table row) ---------------------------------------------------------------
fx_owrt25_kmod()         { owrt 25.12.0 x86/64 x86_64 apk "$K25" 6.12.71 524288; avail25; }
fx_owrt24_kmod()         { owrt 24.10.4 x86/64 x86_64 opkg "$K24" 6.6.110 524288; avail24; chmod 600 "$ROOT/etc/opkg/customfeeds.conf"; }
netscript() { # exit-code -> a stub /etc/init.d/network that logs its call
  mkdir -p "$ROOT/etc/init.d"
  # shellcheck disable=SC2016  # expanded when the stub runs
  printf '#!/bin/sh\necho "network $*" >> "%s/log"\nexit %s\n' "$S" "$1" > "$ROOT/etc/init.d/network"
  chmod +x "$ROOT/etc/init.d/network"
}
fx_restart_network()     { fx_owrt24_kmod; netscript 0; }
fx_restart_net_fails()   { fx_owrt24_kmod; netscript 1; }
fx_no_restart_flag()     { fx_owrt24_kmod; netscript 0; }
fx_remove_nothing()      { fx_owrt24_kmod; }
fx_kernel_mismatch()     { owrt 25.12.0 x86/64 x86_64 apk "6.12.71~ffffffffffffffffffffffffffffffff-r1" 6.12.71 524288; avail25; }
fx_no_target_dir()       { owrt 25.12.0 mediatek/filogic x86_64 apk "6.12.71~aaaa-r1" 6.12.71 1048576; avail25; }
fx_flash8mb_kmod()       { owrt 24.10.4 ramips/mt7621 mipsel_24kc opkg "$KMT" 6.6.110 65536; avail24
                           echo "kmod-amneziawg 6.6.110.3.1.20260906-1" >> "$S/available"; echo 600 > "$S/flash_free"; }
fx_flash2mb_compressed() { owrt 24.10.4 ramips/mt76x8 mipsel_24kc opkg "$KMT" 6.6.110 65536; avail24; echo 2048 > "$S/flash_free"; echo 20000 > "$S/tmp_free"; }
fx_flash1mb_nofit()      { owrt 24.10.4 ramips/mt76x8 mipsel_24kc opkg "$KMT" 6.6.110 65536; avail24; echo 1024 > "$S/flash_free"; echo 20000 > "$S/tmp_free"; }
fx_keenetic_128()        { entware mipselsf-k3.4 131072 1; availEW; echo 900000 > "$S/flash_free"; }
fx_entware_mem40()       { entware mipselsf-k3.4 40960 0; availEW; }
fx_mem40_kmod_ok()       { owrt 25.12.0 x86/64 x86_64 apk "$K25" 6.12.71 40960; avail25; }
fx_current()             { fx_owrt25_kmod; printf 'kmod-amneziawg %s\namneziawg-tools %s\nkmod-udptunnel4 6.12.71-r1\n' "$V_KMOD25" "$V_TOOLS25" >> "$S/installed"; }
fx_newer_installed()     { fx_owrt24_kmod; printf 'kmod-amneziawg 6.6.110.3.1.20270101-1\namneziawg-tools 3.1.20270101-1\n' >> "$S/installed"; }
fx_verify_rollback()     { fx_owrt24_kmod; touch "$S/kmod_fail"; }
fx_verify_rollback_apk() { fx_owrt25_kmod; touch "$S/kmod_fail"; }
fx_userspace_fail()      { fx_keenetic_128; touch "$S/verify_fail"; }
fx_install_fail()        { fx_owrt24_kmod; touch "$S/fail_install"; }
fx_dry_run()             { fx_owrt24_kmod; }
fx_dry_run_apk()         { fx_owrt25_kmod; }
fx_mode_userspace()      { fx_owrt25_kmod; }
fx_mode_kmod_entware()   { fx_keenetic_128; }
fx_mode_kmod_mismatch()  { fx_kernel_mismatch; }
fx_luci()                { fx_owrt25_kmod; printf 'luci-base 26.001-r1\nluci-i18n-base-ru 26.001-r1\n' >> "$S/installed"; }
fx_luci_noflash()        { fx_luci; echo 450 > "$S/flash_free"; }
fx_upgrade_entware()     { fx_keenetic_128; echo "amneziawg-go 3.1.20260101-1" >> "$S/installed"; }
fx_feed_present()        { fx_owrt24_kmod; echo "src/gz mine file://$FEEDP/awg/openwrt/24.10.4/x86/64/" >> "$ROOT/etc/opkg/customfeeds.conf"; }
fx_name_taken()          { fx_owrt24_kmod; echo "src/gz wayhop_awg http://example.invalid/other" >> "$ROOT/etc/opkg/customfeeds.conf"; }
fx_apk_key_conflict()    { fx_owrt25_kmod; echo "-----BEGIN PUBLIC KEY-----SOMEONE ELSE-----END PUBLIC KEY-----" > "$ROOT/etc/apk/keys/wayhop.pem"; }
fx_no_arch_in_feed()     { owrt 24.10.4 ath79/generic mips_24kc opkg "$KMT" 6.6.110 131072; avail24; }
fx_feed_unreachable()    { fx_no_arch_in_feed; FEED_OVERRIDE="file://$WORK/no-such-feed"; }
fx_unsupported()         { echo opkg > "$S/kind"; meminfo 131072; }
fx_update_errors()       { fx_owrt24_kmod; echo 1 > "$S/update_rc"; }
fx_lock_held()           { fx_owrt24_kmod; mkdir -p "$C/tmp/install-awg.lock"; echo $$ > "$C/tmp/install-awg.lock/pid"; }
fx_stale_lock()          { fx_owrt24_kmod; mkdir -p "$C/tmp/install-awg.lock"; echo 999999 > "$C/tmp/install-awg.lock/pid"; }
fx_usage()               { fx_owrt24_kmod; }
fx_mode_userspace_lowram() { owrt 25.12.0 x86/64 x86_64 apk "$K25" 6.12.71 40960; avail25; }
fx_mode_kmod_noflash()   { fx_owrt24_kmod; echo 200 > "$S/flash_free"; }
post_mode_userspace_lowram() { check "kmod installed although userspace was requested" test -z "$(mutating_calls)"; }
post_mode_kmod_noflash() { check "fell back to userspace" sh -c "tail -n1 '$C/out' | grep -q kernel-module"; }
fx_keep_feed_rollback()  { fx_owrt24_kmod; touch "$S/kmod_fail"; }

# --- helpers ------------------------------------------------------------------------------------
snap() { # dir -> a listing of every file with its checksum
  ( cd "$1" && find . -print | sort | while IFS= read -r f; do
      if [ -f "$f" ]; then printf 'F %s %s\n' "$f" "$(cksum < "$f")"; else printf 'D %s\n' "$f"; fi
    done )
}
installer() { # args... (environment from the current case)
  # shellcheck disable=SC2086
  AWG_INSTALL_ROOT="$ROOT" AWG_INSTALL_PKG="$BIN/pm" AWG_STUB_DIR="$S" TMPDIR="$C/tmp" PATH="$BIN:$PATH" \
    $SHX "$INSTALLER" "$@"
}
jget() { tail -n1 "$C/out" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
jnum() { tail -n1 "$C/out" | sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p"; }
jbool() { tail -n1 "$C/out" | sed -n "s/.*\"$1\":\([a-z]*\).*/\1/p"; }
jpkgs() { tail -n1 "$C/out" | sed -n 's/.*"packages":\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr ',' ' '; }
mutating_calls() { grep -E '^(update|install|remove|add|del)( |$)' "$S/log"; }
inst_has() { grep -q "^$1 " "$S/installed"; }
file_has() { [ -f "$ROOT$1" ] && grep -qxF "$2" "$ROOT$1"; }

# --- the table ----------------------------------------------------------------------------------
# name | extra args | exit | result | path | packages
TABLE='
owrt25_kmod            |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
owrt24_kmod            |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
kernel_mismatch        |                    |0|installed  |userspace|amneziawg-go amneziawg-tools
no_target_dir          |                    |0|installed  |userspace|amneziawg-go
flash8mb_kmod          |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
flash2mb_compressed    |                    |2|refused    |userspace|amneziawg-go
flash1mb_nofit         |                    |2|refused    |userspace|amneziawg-go
keenetic_128           |                    |0|installed  |userspace|amneziawg-go amneziawg-tools
entware_mem40          |                    |2|refused    |userspace|
mem40_kmod_ok          |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
current                |                    |0|current    |kmod     |kmod-amneziawg amneziawg-tools
newer_installed        |                    |0|current    |kmod     |kmod-amneziawg amneziawg-tools
verify_rollback        |                    |1|failed     |kmod     |kmod-amneziawg amneziawg-tools
verify_rollback_apk    |                    |1|failed     |kmod     |kmod-amneziawg amneziawg-tools
userspace_fail         |                    |1|failed     |userspace|amneziawg-go amneziawg-tools
install_fail           |                    |1|failed     |kmod     |kmod-amneziawg amneziawg-tools
dry_run                |--dry-run           |0|dry-run    |kmod     |kmod-amneziawg amneziawg-tools
dry_run_apk            |--dry-run           |0|dry-run    |kmod     |kmod-amneziawg amneziawg-tools
mode_userspace         |--mode userspace    |0|installed  |userspace|amneziawg-go amneziawg-tools
mode_kmod_entware      |--mode kmod         |2|refused    |kmod     |
mode_kmod_mismatch     |--mode=kmod         |2|refused    |kmod     |
luci                   |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools luci-proto-amneziawg luci-i18n-amneziawg-ru
luci_noflash           |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
upgrade_entware        |                    |0|installed  |userspace|amneziawg-go amneziawg-tools
feed_present           |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
name_taken             |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
apk_key_conflict       |                    |2|refused    |kmod     |kmod-amneziawg amneziawg-tools
no_arch_in_feed        |                    |2|refused    |userspace|
feed_unreachable       |                    |1|failed     |userspace|
unsupported            |                    |2|refused    |         |
update_errors          |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
lock_held              |                    |1|failed     |kmod     |kmod-amneziawg amneziawg-tools
stale_lock             |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
keep_feed_rollback     |--keep-feed         |1|failed     |kmod     |kmod-amneziawg amneziawg-tools
restart_network        |--restart-network   |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
restart_net_fails      |--restart-network   |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
no_restart_flag        |                    |0|installed  |kmod     |kmod-amneziawg amneziawg-tools
remove_nothing         |--uninstall         |0|removed    |         |
mode_userspace_lowram  |--mode userspace    |2|refused    |userspace|
mode_kmod_noflash      |--mode kmod         |2|refused    |kmod     |kmod-amneziawg amneziawg-tools
usage                  |--mode bogus        |3|failed     |         |
'

# --- per-case checks beyond the table -----------------------------------------------------------
post_owrt25_kmod() {
  check "apk per-target repository line" file_has /etc/apk/repositories.d/wayhop.list "$FEEDP/awg/openwrt/25.12.0/x86/64/packages.adb"
  check "no pkgarch line on the kmod path" sh -c "[ \$(grep -c . '$ROOT/etc/apk/repositories.d/wayhop.list') = 1 ]"
  check "apk key is the production WayHop key" cmp -s "$ROOT/etc/apk/keys/wayhop.pem" "$KEYS/wayhop-apk.pem.pub"
  check "package manager called with add -u" grep -qx 'add -u kmod-amneziawg amneziawg-tools' "$S/log"
  check "module loaded" test -f "$ROOT/sys/module/amneziawg/initstate"
  check "state records the line and the key" sh -c "grep -q '^line' '$ROOT/etc/wayhop-awg.state' && grep -q '^key' '$ROOT/etc/wayhop-awg.state'"
  check "generation 3.1" test "$(jget generation)" = 3.1
  check "profile normal at 512 MiB" test "$(jget profile)" = normal
  check "json is the only stdout line" test "$(grep -c . "$C/out")" = 1
}
post_owrt24_kmod() {
  check "opkg per-target feed line" file_has /etc/opkg/customfeeds.conf "src/gz wayhop_awg $FEED/awg/openwrt/24.10.4/x86/64"
  check "usign key under its fingerprint" cmp -s "$ROOT/etc/opkg/keys/4f22205b1687318e" "$KEYS/wayhop.pub"
  check "opkg install called" grep -qx 'install kmod-amneziawg amneziawg-tools' "$S/log"
  check "dependency pulled in" inst_has kmod-udptunnel4
  check "flash_free_kib reported" test "$(jnum flash_free_kib)" = 100000
  check "mem_total_kib reported" test "$(jnum mem_total_kib)" = 524288
}
post_kernel_mismatch() {
  check "reason for skipping the kmod is printed" grep -q 'built for kernel' "$C/err"
  check "pkgarch apk line" file_has /etc/apk/repositories.d/wayhop.list "$FEEDP/apk/x86_64/packages.adb"
  check "per-target line for the tools" file_has /etc/apk/repositories.d/wayhop.list "$FEEDP/awg/openwrt/25.12.0/x86/64/packages.adb"
}
post_no_target_dir() {
  check "only the pkgarch line" sh -c "[ \$(grep -c . '$ROOT/etc/apk/repositories.d/wayhop.list') = 1 ]"
  check "no kmod build reason" grep -q 'no kernel-module build for OpenWrt 25.12.0 mediatek/filogic' "$C/err"
}
post_flash8mb_kmod() {
  check "lowmem profile at 64 MiB" test "$(jget profile)" = lowmem
  check "flash 600 KiB reported" test "$(jnum flash_free_kib)" = 600
}
post_flash2mb_compressed() {
  check "compressed-store advice" test "$(jget advice)" = compressed-store
  check "reason names the compressed store" sh -c "tail -n1 '$C/out' | grep -q 'compressed store'"
  check "nothing installed" test -z "$(mutating_calls)"
}
post_flash1mb_nofit() {
  check "no advice when even compressed does not fit" test -z "$(jget advice)"
  check "reason says it does not fit" sh -c "tail -n1 '$C/out' | grep -q 'does not fit'"
}
post_keenetic_128() {
  check "lowmem profile at 128 MiB" test "$(jget profile)" = lowmem
  check "Entware feed line" file_has /opt/etc/opkg/customfeeds.conf "src/gz wayhop $FEED/entware/mipselsf-k3.4"
  check "no key without check_signature" test ! -e "$ROOT/opt/etc/opkg/keys"
  check "Keenetic is mentioned" grep -q KeeneticOS "$C/err"
  check "state on /opt" test -f "$ROOT/opt/etc/wayhop-awg.state"
}
post_entware_mem40() { check "reason names 48 MiB" sh -c "tail -n1 '$C/out' | grep -q '48 MiB'"; check "nothing changed" test -z "$(mutating_calls)"; }
post_mem40_kmod_ok() { check "lowmem reported" test "$(jget profile)" = lowmem; }
post_current() {
  check "no package-manager changes" test -z "$(mutating_calls)"
  check "files untouched" cmp -s "$C/before" "$C/after"
}
post_newer_installed() { post_current; }
rolled_back() {
  check "root tree is exactly as before" cmp -s "$C/before" "$C/after"
  check "installed packages exactly as before" cmp -s "$C/installed.before" "$S/installed"
  check "reason says rolled back state" sh -c "tail -n1 '$C/out' | grep -q '\"result\":\"failed\"'"
}
post_verify_rollback() { rolled_back; check "module failure named" sh -c "tail -n1 '$C/out' | grep -q 'did not load'"; }
post_verify_rollback_apk() { rolled_back; }
post_userspace_fail() { rolled_back; check "amneziawg-go failure named" sh -c "tail -n1 '$C/out' | grep -q 'amneziawg-go --version failed'"; }
post_install_fail() { rolled_back; }
post_dry_run() {
  check "dry run changes no file" cmp -s "$C/before" "$C/after"
  check "dry run makes no package-manager change" test -z "$(mutating_calls)"
  check "dry run shows the feed line" grep -q "would add to /etc/opkg/customfeeds.conf: src/gz wayhop_awg" "$C/err"
}
post_dry_run_apk() { check "dry run changes no file" cmp -s "$C/before" "$C/after"; check "no package-manager change" test -z "$(mutating_calls)"; }
post_mode_userspace() { check "kmod not installed" sh -c "! grep -q '^kmod-amneziawg ' '$S/installed'"; }
post_mode_kmod_entware() { check "reason: OpenWrt only" sh -c "tail -n1 '$C/out' | grep -q 'OpenWrt only'"; }
post_mode_kmod_mismatch() { check "reason: kernel mismatch" sh -c "tail -n1 '$C/out' | grep -q 'built for kernel'"; }
post_luci_noflash() { check "LuCI skipped for flash" grep -q 'too little for luci-proto-amneziawg' "$C/err"; }
post_upgrade_entware() { check "amneziawg-go upgraded" grep -q "^amneziawg-go $V_GO24\$" "$S/installed"; }
post_feed_present() {
  check "no duplicate feed line" test "$(grep -c 'awg/openwrt/24.10.4' "$ROOT/etc/opkg/customfeeds.conf")" = 1
  check "state has no line entry" sh -c "! grep -q '^line' '$ROOT/etc/wayhop-awg.state' 2>/dev/null"
}
post_name_taken() { check "free source name chosen" file_has /etc/opkg/customfeeds.conf "src/gz wayhop_awg_2 $FEED/awg/openwrt/24.10.4/x86/64"; }
post_apk_key_conflict() { check "foreign key untouched" grep -q 'SOMEONE ELSE' "$ROOT/etc/apk/keys/wayhop.pem"; check "nothing installed" test -z "$(mutating_calls)"; }
post_no_arch_in_feed() { check "reason: no packages for the arch" sh -c "tail -n1 '$C/out' | grep -q 'no packages for mips_24kc'"; }
post_feed_unreachable() { check "reason: unreachable" sh -c "tail -n1 '$C/out' | grep -q unreachable"; }
post_update_errors() { check "update error tolerated with a warning" grep -q 'reported errors' "$C/err"; }
post_lock_held() { check "lock left to its owner" test -d "$C/tmp/install-awg.lock"; check "nothing installed" test -z "$(mutating_calls)"; }
post_stale_lock() { check "stale lock cleared" test ! -d "$C/tmp/install-awg.lock"; }
post_keep_feed_rollback() {
  check "packages rolled back" cmp -s "$C/installed.before" "$S/installed"
  check "feed line kept" file_has /etc/opkg/customfeeds.conf "src/gz wayhop_awg $FEED/awg/openwrt/24.10.4/x86/64"
  check "kept line recorded for --uninstall" grep -q "^line" "$ROOT/etc/wayhop-awg.state"
}


# --- netifd: the amneziawg proto handler ships in amneziawg-tools; netifd reads it only at start ----
net_is() { # want-needed want-restarted
  check "netifd_restart_needed '$(jbool netifd_restart_needed)', want $1" test "$(jbool netifd_restart_needed)" = "$1"
  check "network_restarted '$(jbool network_restarted)', want $2" test "$(jbool network_restarted)" = "$2"
}
net_owrt25_kmod()       { net_is true false; check "the restart note is printed" grep -q 'netifd loads protocol handlers only at start' "$C/err"; }
# shellcheck disable=SC2012  # a fixed file name; ls -l is the portable way to read a mode
net_owrt24_kmod()       { net_is true false; check "customfeeds.conf keeps its mode" test "$(ls -l "$ROOT/etc/opkg/customfeeds.conf" | cut -c1-10)" = "-rw-------"; }
net_kernel_mismatch()   { net_is true false; }
net_no_target_dir()     { net_is false false; check "no restart note without a handler change" sh -c "! grep -q 'netifd loads' '$C/err'"; }
net_keenetic_128()      { net_is false false; }
net_current()           { net_is false false; }
net_dry_run_apk()       { net_is true false; }
net_verify_rollback()   { net_is false false; }
net_install_fail()      { net_is false false; }
net_restart_network()   { net_is false true; check "network restarted once" test "$(grep -c '^network restart$' "$S/log")" = 1; }
net_restart_net_fails() { net_is true false; check "a failed restart is reported" grep -q 'network restart failed' "$C/err"; }
net_no_restart_flag()   { net_is true false; check "the network was restarted without --restart-network" sh -c "! grep -q '^network' '$S/log'"; }
net_remove_nothing()    { check "nothing to remove still reports an empty package list" test -z "$(jpkgs)"; net_is false false; }

# --- run the table ------------------------------------------------------------------------------
checkd() { # description detail command... (detail is printed on failure)
  cd_d="$1"; cd_x="$2"; shift 2
  if "$@"; then pass; else fail "$cd_d" "$cd_x"; fi
}
case_done() { [ "$FAIL" = "$before_fail" ] && printf '  ok    %s\n' "$1"; }

while IFS='|' read -r name args want_rc want_res want_path want_pkgs; do
  name="$(echo "$name" | tr -d ' ')"
  [ -n "$name" ] || continue
  args="$(echo "$args" | sed 's/^ *//; s/ *$//')"; want_res="$(echo "$want_res" | tr -d ' ')"
  want_path="$(echo "$want_path" | tr -d ' ')"; want_pkgs="$(echo "$want_pkgs" | sed 's/^ *//; s/ *$//')"
  FEED_OVERRIDE=""
  new_case "$name"
  "fx_$name"
  snap "$ROOT" > "$C/before"; cp "$S/installed" "$C/installed.before"
  # shellcheck disable=SC2086
  installer --feed "${FEED_OVERRIDE:-$FEED}" --json $args > "$C/out" 2> "$C/err" < /dev/null
  rc=$?
  snap "$ROOT" > "$C/after"
  CASES=$((CASES + 1)); before_fail=$FAIL
  checkd "exit $rc, want $want_rc" "$(tail -n 5 "$C/err")" test "$rc" = "$want_rc"
  checkd "result '$(jget result)', want '$want_res'" "$(tail -n1 "$C/out")" test "$(jget result)" = "$want_res"
  check "path '$(jget path)', want '$want_path'" test "$(jget path)" = "$want_path"
  check "packages '$(jpkgs)', want '$want_pkgs'" test "$(jpkgs)" = "$want_pkgs"
  if command -v "post_$name" >/dev/null 2>&1; then "post_$name"; fi
  if command -v "net_$name" >/dev/null 2>&1; then "net_$name"; fi
  if [ "${AWG_TEST_SHOW:-}" = "$name" ]; then cat "$C/err" "$C/out"; fi
  case_done "$name"
done <<EOF
$TABLE
EOF

# --- sequences: install, then something else ----------------------------------------------------
seq_uninstall() { # fixture -> install, then uninstall; the root must return to its pristine state
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case "uninstall_$1"
  "fx_$1"
  snap "$ROOT" > "$C/pristine"; sort "$S/installed" > "$C/installed.pristine"
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null; rc=$?
  checkd "the install before the uninstall failed" "$(tail -n 5 "$C/install.out")" test "$rc" = 0
  installer --feed "$FEED" --json --uninstall > "$C/out" 2> "$C/err"; rc=$?
  checkd "uninstall exit $rc" "$(tail -n 5 "$C/err")" test "$rc" = 0
  check "uninstall result '$(jget result)'" test "$(jget result)" = removed
  for p in kmod-amneziawg amneziawg-tools amneziawg-go luci-proto-amneziawg luci-i18n-amneziawg-ru; do
    if inst_has "$p"; then fail "$p still installed after --uninstall"; fi
  done
  sort "$S/installed" > "$C/installed.after"
  checkd "packages differ from before the install (dependencies left behind?)" \
    "$(diff "$C/installed.pristine" "$C/installed.after" 2>/dev/null | head -n 10)" cmp -s "$C/installed.pristine" "$C/installed.after"
  check "a loaded module was not unloaded" test ! -d "$ROOT/sys/module/amneziawg"
  check "generation after the removal '$(jget generation)', want none" test "$(jget generation)" = none
  check "the log does not end on the generation the JSON reports" grep -q "AmneziaWG now: $(jget generation)\$" "$C/err"
  snap "$ROOT" > "$C/after"
  checkd "files differ from before the install" "$(diff "$C/pristine" "$C/after" 2>/dev/null | head -n 10)" cmp -s "$C/pristine" "$C/after"
  case_done "uninstall after install ($1)"
}
alive() { [ -d "/proc/$1" ] && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null; }
dead() { ! alive "$1"; }
seq_uninstall_runtime() { # interfaces down, links deleted, packaged amneziawg-go stopped, module out
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case uninstall_runtime
  fx_owrt24_kmod
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null; rc=$?
  check "install failed" test "$rc" = 0
  mkdir -p "$ROOT/etc/config"
  printf "network.lan=interface\nnetwork.lan.proto='static'\nnetwork.awg0=interface\nnetwork.awg0.proto='amneziawg'\nnetwork.wr_main=interface\nnetwork.wr_main.proto='amneziawg'\nnetwork.wg0.proto='wireguard'\n" \
    > "$ROOT/etc/config/network.show"
  cp "$ROOT/etc/config/network.show" "$C/network.before"
  for l in awg0 wr_main stray0; do mkdir -p "$ROOT/sys/class/net/$l"; printf 'DEVTYPE=amneziawg\nINTERFACE=%s\n' "$l" > "$ROOT/sys/class/net/$l/uevent"; done
  mkdir -p "$ROOT/sys/class/net/wg0"; printf 'DEVTYPE=wireguard\nINTERFACE=wg0\n' > "$ROOT/sys/class/net/wg0/uevent"
  sleep 60 & pkg_pid=$!
  sleep 60 & own_pid=$!
  mkdir -p "$ROOT/proc/$pkg_pid" "$ROOT/proc/$own_pid"
  ln -s /usr/bin/amneziawg-go "$ROOT/proc/$pkg_pid/exe"            # the packaged binary
  ln -s /tmp/wayhop/bin/amneziawg-go "$ROOT/proc/$own_pid/exe"     # WayHop's own copy: not ours
  : > "$S/log"
  installer --feed "$FEED" --json --uninstall > "$C/out" 2> "$C/err"; rc=$?
  check "uninstall exit $rc" test "$rc" = 0
  check "awg0 was not brought down" grep -qx 'ifdown awg0' "$S/log"
  check "wr_main was not brought down" grep -qx 'ifdown wr_main' "$S/log"
  check "a non-amneziawg interface was brought down" sh -c "! grep -q 'ifdown \\(lan\\|wg0\\)' '$S/log'"
  check "the stray amneziawg link was not deleted" grep -qx 'ip link del dev stray0' "$S/log"
  check "the wireguard link was touched" test -d "$ROOT/sys/class/net/wg0"
  check "interfaces went down after the packages were removed" \
    sh -c "awk '/^ifdown awg0/ { i = NR } /^remove .*amneziawg-tools/ { r = NR } END { exit !(i && r && i < r) }' '$S/log'"
  check "the network configuration was changed" cmp -s "$C/network.before" "$ROOT/etc/config/network.show"
  check "the packaged amneziawg-go still runs" dead "$pkg_pid"
  check "WayHop's own amneziawg-go was stopped" alive "$own_pid"
  check "the module was not unloaded" grep -qx 'rmmod amneziawg' "$S/log"
  check "generation '$(jget generation)' after the removal, want none" test "$(jget generation)" = none
  kill "$own_pid" "$pkg_pid" 2>/dev/null; wait "$own_pid" "$pkg_pid" 2>/dev/null
  case_done "uninstall stops what runs on AmneziaWG first, and only that"
}
seq_uninstall_module_busy() { # the module cannot go: reported, and the generation stays what runs
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case uninstall_module_busy
  fx_owrt24_kmod
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null
  touch "$S/rmmod_fail"
  installer --feed "$FEED" --json --uninstall > "$C/out" 2> "$C/err"; rc=$?
  check "uninstall exit $rc" test "$rc" = 0
  check "the busy module is not reported" sh -c "tail -n1 '$C/out' | grep -q 'stays loaded until reboot'"
  check "generation '$(jget generation)' with the 3.1 module still loaded, want 3.1" test "$(jget generation)" = 3.1
  check "the log and the JSON disagree on the generation" grep -q 'AmneziaWG now: 3.1$' "$C/err"
  case_done "a module that stays loaded is reported, with the generation that runs"
}
seq_uninstall_deps() { # a dependency present before stays; one something else needs stays recorded
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case uninstall_deps
  fx_owrt24_kmod
  echo "kmod-amneziawg kmod-crypto-lib-chacha20 6.6.110-1" >> "$S/deps"
  echo "kmod-crypto-lib-chacha20 6.6.110-1" >> "$S/installed"          # there before the install
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null
  check "the install did not record the dependency it pulled in" grep -q "^pkg${TAB_}kmod-udptunnel4\$" "$ROOT/etc/wayhop-awg.state"
  check "the install recorded a package that was there before" sh -c "! grep -q 'kmod-crypto-lib-chacha20' '$ROOT/etc/wayhop-awg.state'"
  echo "kmod-wireguard 6.6.110-1" >> "$S/installed"                    # installed later, needs udptunnel4
  echo "kmod-wireguard kmod-udptunnel4 6.6.110-1" >> "$S/deps"
  installer --feed "$FEED" --json --uninstall > "$C/out" 2> "$C/err"; rc=$?
  check "uninstall exit $rc" test "$rc" = 0
  check "the pre-existing dependency was removed" inst_has kmod-crypto-lib-chacha20
  check "a dependency another package needs was removed" inst_has kmod-udptunnel4
  check "kmod-amneziawg is still installed" sh -c "! grep -q '^kmod-amneziawg ' '$S/installed'"
  check "the kept dependency is not reported" sh -c "tail -n1 '$C/out' | grep -q 'kept dependencies other packages still need: kmod-udptunnel4'"
  check "the kept dependency is no longer recorded for a later --uninstall" grep -q "^pkg${TAB_}kmod-udptunnel4\$" "$ROOT/etc/wayhop-awg.state"
  sed -i '/^kmod-wireguard /d' "$S/installed"
  installer --feed "$FEED" --json --uninstall > "$C/out" 2> "$C/err"; rc=$?
  check "a later uninstall did not remove the now unneeded dependency" sh -c "! grep -q '^kmod-udptunnel4 ' '$S/installed'"
  check "the state file stayed behind" test ! -e "$ROOT/etc/wayhop-awg.state"
  case_done "uninstall removes only the dependencies its installs pulled in and nothing needs"
}
seq_uninstall_keeps_foreign() { # a feed line the operator had survives
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case uninstall_keeps_foreign
  fx_feed_present
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null; rc=$?
  check "install failed" test "$rc" = 0
  installer --feed "$FEED" --json --uninstall > "$C/out" 2> "$C/err"; rc=$?
  check "uninstall failed" test "$rc" = 0
  check "the operator's own feed line was removed" file_has /etc/opkg/customfeeds.conf "src/gz mine file://$FEEDP/awg/openwrt/24.10.4/x86/64/"
  case_done "uninstall keeps a feed line it did not add"
}
seq_uninstall_shared_feed() { # wayhop itself installed from the feed: its line and key stay
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case uninstall_shared_feed
  fx_keenetic_128
  sed -i 's/^arch all 100$/option check_signature\narch all 100/' "$ROOT/opt/etc/opkg.conf"
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null; rc=$?
  check "install failed" test "$rc" = 0
  check "check_signature on Entware did not install the key" test -f "$ROOT/opt/etc/opkg/keys/4f22205b1687318e"
  echo "wayhop 0.5.7-1" >> "$S/installed"
  installer --feed "$FEED" --json --uninstall > "$C/out" 2> "$C/err"; rc=$?
  check "uninstall failed" test "$rc" = 0
  check "the shared feed line was removed while wayhop is installed" file_has /opt/etc/opkg/customfeeds.conf "src/gz wayhop $FEED/entware/mipselsf-k3.4"
  check "the shared key was removed while wayhop is installed" test -f "$ROOT/opt/etc/opkg/keys/4f22205b1687318e"
  check "the kept entries are no longer recorded" grep -q '^line' "$ROOT/opt/etc/wayhop-awg.state"
  if inst_has amneziawg-go; then fail "amneziawg-go still installed"; fi
  case_done "uninstall keeps the feed the wayhop package uses"
}
seq_uninstall_dry_run() {
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case uninstall_dry_run
  fx_owrt24_kmod
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null; rc=$?
  check "install failed" test "$rc" = 0
  snap "$ROOT" > "$C/before"; cp "$S/installed" "$C/installed.before"; : > "$S/log"
  installer --feed "$FEED" --json --uninstall --dry-run > "$C/out" 2> "$C/err"; rc=$?
  check "uninstall --dry-run exit $rc" test "$rc" = 0
  check "uninstall --dry-run result $(jget result)" test "$(jget result)" = dry-run
  snap "$ROOT" > "$C/after"
  check "uninstall --dry-run changed files" cmp -s "$C/before" "$C/after"
  check "uninstall --dry-run changed packages" cmp -s "$C/installed.before" "$S/installed"
  case_done "uninstall --dry-run changes nothing"
}
seq_reinstall_current() {
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case reinstall_current
  fx_owrt25_kmod
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null; rc=$?
  check "install failed" test "$rc" = 0
  snap "$ROOT" > "$C/before"; : > "$S/log"
  installer --feed "$FEED" --json > "$C/out" 2> "$C/err"; rc=$?
  check "second run exit $rc" test "$rc" = 0
  check "second run result $(jget result)" test "$(jget result)" = current
  snap "$ROOT" > "$C/after"
  check "second run changed files" cmp -s "$C/before" "$C/after"
  check "second run asked the package manager for a change" test -z "$(mutating_calls)"
  case_done "a second run reports current and changes nothing"
}
seq_uninstall_netifd() { # removing amneziawg-tools removes the handler: a restart is needed again
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case uninstall_netifd
  fx_restart_network
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null; rc=$?
  check "install failed" test "$rc" = 0
  installer --feed "$FEED" --json --uninstall > "$C/out" 2> "$C/err"; rc=$?
  check "uninstall exit $rc" test "$rc" = 0
  net_is true false
  fx_owrt24_kmod >/dev/null 2>&1; : > "$S/log"; netscript 0
  installer --feed "$FEED" --yes > "$C/install.out" 2>&1 < /dev/null
  installer --feed "$FEED" --json --uninstall --restart-network > "$C/out" 2> "$C/err"; rc=$?
  check "uninstall --restart-network exit $rc" test "$rc" = 0
  net_is false true
  case_done "uninstall reports (and with --restart-network performs) the netifd restart"
}
bg_installer() { # args... -> runs the installer in the background as its own process; PID in BG
  # shellcheck disable=SC2016  # "$@" is expanded by the wrapper
  printf '#!/bin/sh\nexec env AWG_INSTALL_ROOT="%s" AWG_INSTALL_PKG="%s" AWG_STUB_DIR="%s" TMPDIR="%s" PATH="%s" %s "%s" "$@"\n' \
    "$ROOT" "$BIN/pm" "$S" "$C/tmp" "$BIN:$PATH" "$SHX" "$INSTALLER" > "$C/bg.sh"
  sh "$C/bg.sh" "$@" > "$C/out" 2> "$C/err" < /dev/null &
  BG=$!
}
wait_for() { # file pattern -> 0 once a line matches (10 s at most)
  wf_i=0
  until grep -q "$2" "$1" 2>/dev/null; do
    wf_i=$((wf_i + 1)); [ "$wf_i" -gt 50 ] && return 1; sleep 0.2 2>/dev/null || sleep 1
  done
}
seq_interrupt() { # SIGTERM while the package manager runs: the run rolls back everything
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case interrupt_term
  fx_owrt24_kmod; echo 2 > "$S/slow_install"
  snap "$ROOT" > "$C/before"; cp "$S/installed" "$C/installed.before"
  bg_installer --feed "$FEED" --json
  check "the package manager was never reached" wait_for "$S/log" '^install '
  check "the state file did not record the feed line before the package manager ran" grep -q '^line' "$ROOT/etc/wayhop-awg.state"
  kill -TERM "$BG" 2>/dev/null
  wait "$BG"; rc=$?
  check "interrupted run exits $rc, want 1" test "$rc" = 1
  check "result '$(jget result)', want failed" test "$(jget result)" = failed
  check "reason does not say interrupted" sh -c "tail -n1 '$C/out' | grep -q interrupted"
  if [ -n "${AWG_TEST_DEBUG:-}" ]; then cat "$C/err" "$C/out"; fi
  snap "$ROOT" > "$C/after"
  checkd "files differ from before the interrupted run" "$(diff "$C/before" "$C/after" 2>/dev/null | head -n 10)" cmp -s "$C/before" "$C/after"
  check "packages differ from before the interrupted run" cmp -s "$C/installed.before" "$S/installed"
  check "the lock was left behind" test ! -d "$C/tmp/install-awg.lock"
  case_done "SIGTERM mid-install rolls back to the exact previous state"
}
seq_killed_rerun() { # SIGKILL mid-install: a re-run recovers, --uninstall leaves nothing behind
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case killed_rerun
  fx_owrt24_kmod; echo 1 > "$S/slow_install"
  snap "$ROOT" > "$C/pristine"
  bg_installer --feed "$FEED" --json
  check "the package manager was never reached" wait_for "$S/log" '^install '
  kill -KILL "$BG" 2>/dev/null; wait "$BG" 2>/dev/null
  wait_for "$S/installed" '^amneziawg-tools ' || :   # the orphaned package manager finishes
  rm -f "$S/slow_install"
  check "no *.awgtmp.* file may be left as a config file" sh -c "! find '$ROOT/etc' -name '*.awgtmp.*' | grep -q ."
  installer --feed "$FEED" --json > "$C/out" 2> "$C/err"; rc=$?
  checkd "re-run after a kill exits $rc" "$(tail -n 5 "$C/err")" test "$rc" = 0
  check "re-run duplicated the feed line" test "$(grep -c 'wayhop_awg' "$ROOT/etc/opkg/customfeeds.conf")" = 1
  installer --feed "$FEED" --json --uninstall > "$C/out" 2> "$C/err"; rc=$?
  check "uninstall after the recovery exits $rc" test "$rc" = 0
  rm -rf "$ROOT/sys/module/amneziawg"
  snap "$ROOT" > "$C/after"
  checkd "files differ from before the killed run" "$(diff "$C/pristine" "$C/after" 2>/dev/null | head -n 10)" cmp -s "$C/pristine" "$C/after"
  case_done "SIGKILL mid-install: a re-run recovers and --uninstall removes everything"
}
seq_usage() {
  CASES=$((CASES + 1)); before_fail=$FAIL
  new_case usage_more
  fx_owrt24_kmod
  installer --bogus > /dev/null 2>&1; rc=$?
  check "unknown flag exits $rc, not 3" test "$rc" = 3
  installer --feed > /dev/null 2>&1; rc=$?
  check "--feed without a value exits $rc, not 3" test "$rc" = 3
  installer --feed ftp://x > /dev/null 2>&1; rc=$?
  check "a non-http feed exits $rc, not 3" test "$rc" = 3
  installer --help > "$C/help" 2>&1; rc=$?
  check "--help exits $rc" test "$rc" = 0
  check "--help does not describe --keep-feed" grep -q -- '--keep-feed' "$C/help"
  case_done "usage errors exit 3, --help exits 0"
}

seq_uninstall owrt24_kmod
seq_uninstall owrt25_kmod
seq_uninstall keenetic_128
seq_uninstall luci
seq_uninstall_runtime
seq_uninstall_module_busy
seq_uninstall_deps
seq_uninstall_keeps_foreign
seq_uninstall_shared_feed
seq_uninstall_dry_run
seq_reinstall_current
seq_uninstall_netifd
seq_interrupt
seq_killed_rerun
seq_usage

echo "install-awg unit tests ($SHX): $CASES cases, $PASS checks passed, $FAIL failed"
[ "$FAIL" = 0 ]
