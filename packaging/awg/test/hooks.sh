#!/bin/sh
# hooks.sh -- tests for the --with-awg hooks in packaging/bootstrap.sh, packaging/install.sh and
# packaging/openwrt/install.sh. No router, no network, no root: `curl`, `uname`, `id` (and `usign`
# where a case needs a verifier) are stubbed on PATH and a fake GitHub release is served from a temp
# directory, the way packaging/test/bootstrap_harness.sh does it.
#
#   bootstrap.sh   driven end to end with a fake release (install.sh and install-awg.sh are stubs
#                  that record how they were called)
#   install.sh     the hook block (between the ">>> with-awg hook" markers, identical in both
#                  installers) is sourced and driven directly; argument parsing is checked by
#                  running the real installers
#
# Run: sh packaging/awg/test/hooks.sh   (docker.sh also runs it under busybox ash and dash)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PKG="$(cd "$HERE/../.." && pwd)"
BOOT="$PKG/bootstrap.sh"
SHX="${AWG_TEST_SH:-sh}"
# The cases run with a PATH of stubs only: name the shell under test by its absolute path.
# shellcheck disable=SC2086  # "busybox ash" is two words on purpose
set -- $SHX
_shx="$(command -v "$1")" || { echo "shell under test not found: $1" >&2; exit 2; }
shift
SHX="$_shx${*:+ $*}"

PASS=0; FAIL=0
CASE=""
pass() { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s: %s\n' "$CASE" "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }
check() { ck_d="$1"; shift; if "$@"; then pass; else fail "$ck_d"; fi; }
done_case() { [ "$FAIL" = "$before" ] && printf '  ok    %s\n' "$CASE"; }

WORK="$(mktemp -d "${AWG_TEST_TMP:-/tmp}/awg-hooks.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT

# --- a PATH without the host's usign/signify ------------------------------------------------------
MOCKS="$WORK/bin"; mkdir -p "$MOCKS"
SYSTEM_PATH="$PATH"
for cmd in sh awk cat chmod cp cut dd grep gzip head mkdir mktemp od rm sed sha256sum tar tr wc ls; do
  real="$(PATH="$SYSTEM_PATH" command -v "$cmd" 2>/dev/null || true)"
  [ -n "$real" ] || { echo "required test command not found: $cmd" >&2; exit 2; }
  printf '#!/bin/sh\nexec "%s" "$@"\n' "$real" > "$MOCKS/$cmd"
done
cat > "$MOCKS/uname" <<'EOF'
#!/bin/sh
case "$1" in -m) echo x86_64 ;; *) echo Linux ;; esac
EOF
cat > "$MOCKS/id" <<'EOF'
#!/bin/sh
case "$1" in -u) echo 0 ;; -un) echo root ;; *) echo "uid=0(root)" ;; esac
EOF
cat > "$MOCKS/curl" <<'EOF'
#!/bin/sh
url=""; out=""
while [ $# -gt 0 ]; do case "$1" in -o) shift; out="$1" ;; http://*|https://*) url="$1" ;; esac; shift; done
echo "$url" >> "$MOCK_SRV/curl.log"
f="$MOCK_SRV/${url##*/}"
[ -f "$f" ] || exit 22
if [ -n "$out" ]; then cp "$f" "$out"; else cat "$f"; fi
EOF
chmod +x "$MOCKS"/*
VERIFIER="$WORK/verifier"; mkdir -p "$VERIFIER"
cat > "$VERIFIER/usign" <<'EOF'
#!/bin/sh
echo "usign $*" >> "$MOCK_SRV/usign.log"
exit "${MOCK_USIGN_RC:-0}"
EOF
chmod +x "$VERIFIER/usign"

# --- fake release ---------------------------------------------------------------------------------
# stub_awg SOURCE -> an install-awg.sh stub that records its source and arguments
stub_awg() {
  # shellcheck disable=SC2016  # expanded when the stub runs
  printf '#!/bin/sh\necho "source=%s args=$*" >> "$MOCK_SRV/awg.log"\nexit "${MOCK_AWG_RC:-0}"\n' "$1"
}
new_release() { # name tarball-has-awg(0|1) list-asset(0|1|bad)
  CASE="$1"; before=$FAIL
  MOCK_SRV="$WORK/srv-$1"; export MOCK_SRV
  mkdir -p "$MOCK_SRV/stage"
  : > "$MOCK_SRV/curl.log"; : > "$MOCK_SRV/awg.log"; : > "$MOCK_SRV/install.log"
  # shellcheck disable=SC2016  # expanded when the stub runs
  printf '#!/bin/sh\necho "args=$*" >> "$MOCK_SRV/install.log"\nexit "${MOCK_INSTALL_RC:-0}"\n' > "$MOCK_SRV/stage/install.sh"
  [ "$2" = 1 ] && stub_awg tarball > "$MOCK_SRV/stage/install-awg.sh"
  ( cd "$MOCK_SRV/stage" && tar -czf "$MOCK_SRV/wayhop-1.2.3-amd64.tar.gz" . )
  stub_awg asset > "$MOCK_SRV/install-awg.sh"
  ( cd "$MOCK_SRV" && sha256sum wayhop-1.2.3-amd64.tar.gz > SHA256SUMS.txt )
  case "$3" in
    1)   ( cd "$MOCK_SRV" && sha256sum install-awg.sh >> SHA256SUMS.txt ) ;;
    bad) echo "0000000000000000000000000000000000000000000000000000000000000000  install-awg.sh" >> "$MOCK_SRV/SHA256SUMS.txt" ;;
  esac
}
BOOT_AWG_RC=0; BOOT_INSTALL_RC=0
boot() { # bootstrap args... -> RC, $MOCK_SRV/out (stub exit codes from BOOT_AWG_RC / BOOT_INSTALL_RC)
  # shellcheck disable=SC2086  # SHX may be "busybox ash"
  MOCK_AWG_RC="$BOOT_AWG_RC" MOCK_INSTALL_RC="$BOOT_INSTALL_RC" WAYHOP_VERSION=v1.2.3 PATH="$MOCKS" \
    $SHX "$BOOT" "$@" > "$MOCK_SRV/out" 2>&1
  RC=$?
  BOOT_AWG_RC=0; BOOT_INSTALL_RC=0
}
awg_args() { sed -n 's/.*args=//p' "$MOCK_SRV/awg.log"; }
awg_src() { sed -n 's/^source=\([a-z]*\) .*/\1/p' "$MOCK_SRV/awg.log"; }
fetched() { grep -q "/$1\$" "$MOCK_SRV/curl.log"; }

echo "== bootstrap.sh --with-awg =="
new_release default 1 1
boot
check "exit $RC" test "$RC" = 0
check "install.sh got exactly --arch amd64" test "$(cat "$MOCK_SRV/install.log")" = "args=--arch amd64"
check "install-awg.sh ran without --with-awg" test ! -s "$MOCK_SRV/awg.log"
check "install-awg.sh was downloaded without --with-awg" sh -c "! grep -q install-awg '$MOCK_SRV/curl.log'"
done_case

new_release from_tarball 1 1
boot --with-awg
check "exit $RC" test "$RC" = 0
check "install.sh did not run first" test "$(cat "$MOCK_SRV/install.log")" = "args=--arch amd64"
check "the tarball's copy ran" test "$(awg_src)" = tarball
check "arguments '$(awg_args)'" test "$(awg_args)" = "--mode auto --yes"
check "a separate copy was downloaded" sh -c "! grep -q install-awg '$MOCK_SRV/curl.log'"
done_case

new_release from_asset 0 1
boot --with-awg=userspace
check "exit $RC" test "$RC" = 0
check "the release asset ran" test "$(awg_src)" = asset
check "arguments '$(awg_args)'" test "$(awg_args)" = "--mode userspace --yes"
check "the asset was fetched" fetched install-awg.sh
done_case

new_release asset_not_listed 0 0
boot --with-awg
check "exit $RC is 0" test "$RC" != 0
check "install.sh ran although install-awg.sh cannot be verified" test ! -s "$MOCK_SRV/install.log"
check "no reason given" grep -q 'lists no install-awg.sh' "$MOCK_SRV/out"
done_case

new_release asset_digest_mismatch 0 bad
boot --with-awg
check "exit $RC is 0" test "$RC" != 0
check "install.sh ran with a mismatching install-awg.sh" test ! -s "$MOCK_SRV/install.log"
check "the mismatching script ran" test ! -s "$MOCK_SRV/awg.log"
check "no mismatch message" grep -q 'SHA-256 MISMATCH for install-awg.sh' "$MOCK_SRV/out"
done_case

new_release bad_mode 1 1
boot --with-awg=everything
check "exit $RC is 0" test "$RC" != 0
check "anything was downloaded for an invalid mode" test ! -s "$MOCK_SRV/curl.log"
done_case

new_release awg_refused 1 1
BOOT_AWG_RC=2; boot --with-awg
check "exit $RC, want 2" test "$RC" = 2
check "WayHop was not installed first" test -s "$MOCK_SRV/install.log"
check "no 'WayHop is installed' note" grep -q 'WayHop is installed; AmneziaWG was NOT' "$MOCK_SRV/out"
done_case

new_release awg_failed 1 1
BOOT_AWG_RC=1; boot --with-awg
check "exit $RC, want 1" test "$RC" = 1
done_case

new_release install_failed 1 1
BOOT_INSTALL_RC=1; boot --with-awg
check "exit $RC is 0" test "$RC" != 0
check "install-awg.sh ran after a failed install.sh" test ! -s "$MOCK_SRV/awg.log"
done_case

new_release forwarded 1 1
boot --with-awg -- --port 8089
check "install.sh args '$(cat "$MOCK_SRV/install.log")'" test "$(cat "$MOCK_SRV/install.log")" = "args=--arch amd64 --port 8089"
check "install-awg.sh did not run" test -s "$MOCK_SRV/awg.log"
done_case

# --- the install.sh hook block ---------------------------------------------------------------------
echo "== install.sh --with-awg hook =="
hook_of() { awk '/^# >>> with-awg hook/ { f = 1 } f { print } /^# <<< with-awg hook/ { f = 0 }' "$1"; }
hook_of "$PKG/install.sh" > "$WORK/hook-entware.sh"
hook_of "$PKG/openwrt/install.sh" > "$WORK/hook-openwrt.sh"
CASE="hook block"; before=$FAIL
check "no hook block in packaging/install.sh" test -s "$WORK/hook-entware.sh"
check "the two installers carry different hook blocks" cmp -s "$WORK/hook-entware.sh" "$WORK/hook-openwrt.sh"
check "the hook block is not one function set" grep -q '^with_awg()' "$WORK/hook-entware.sh"
done_case

# hook CASE SRC-has-awg(0|1) list-asset(0|1|bad) ASSUME verifier(0|1) [with_awg args...] -> RC
# Knobs (reset after every call): HK_MODE, HK_VERSION, HK_SIG (ship a .sig), HK_USIGN_RC, HK_AWG_RC.
hk_reset() { HK_MODE=auto; HK_VERSION=""; HK_SIG=0; HK_USIGN_RC=0; HK_AWG_RC=0; }
hk_reset
hook() {
  hk_name="$1"; hk_has="$2"; hk_list="$3"; hk_assume="$4"; hk_ver="$5"; shift 5
  new_release "$hk_name" 0 "$hk_list"
  [ "$HK_SIG" = 1 ] && echo "signature" > "$MOCK_SRV/SHA256SUMS.txt.sig"
  SRCDIR="$MOCK_SRV/src"; mkdir -p "$SRCDIR"
  [ "$hk_has" = 1 ] && stub_awg beside > "$SRCDIR/install-awg.sh"
  hk_path="$MOCKS"; [ "$hk_ver" = 1 ] && hk_path="$VERIFIER:$MOCKS"
  # shellcheck disable=SC2016,SC2086  # expanded by the inner shell; SHX may be "busybox ash"
  PATH="$hk_path" SRC="$SRCDIR" ASSUME="$hk_assume" AWG_MODE="$HK_MODE" WAYHOP_VERSION="$HK_VERSION" \
    MOCK_USIGN_RC="$HK_USIGN_RC" MOCK_AWG_RC="$HK_AWG_RC" HOOK="$WORK/hook-entware.sh" \
    $SHX -c '
      say() { echo "say: $*"; }; ok() { echo "ok: $*"; }; info() { echo "info: $*"; }
      warn() { echo "warn: $*"; }; hdr() { echo "== $* =="; }
      . "$HOOK"
      with_awg "$@"' hook "$@" > "$MOCK_SRV/out" 2>&1
  RC=$?
  hk_reset
}

hook beside 1 0 "" 0
check "exit $RC" test "$RC" = 0
check "the copy beside install.sh ran" test "$(awg_src)" = beside
check "arguments '$(awg_args)'" test "$(awg_args)" = "--mode auto --yes"
check "anything was downloaded" test ! -s "$MOCK_SRV/curl.log"
done_case

HK_MODE=kmod; hook dry_run_and_mode 1 0 "" 0 --dry-run
check "arguments '$(awg_args)'" test "$(awg_args)" = "--mode kmod --yes --dry-run"
done_case

hook assume_no 1 0 no 0
check "-n did not become --dry-run: '$(awg_args)'" test "$(awg_args)" = "--mode auto --dry-run"
done_case

hook download_latest 0 1 "" 0
check "exit $RC" test "$RC" = 0
check "the downloaded copy did not run" test "$(awg_src)" = asset
check "not fetched from releases/latest" grep -q 'releases/latest/download/install-awg.sh$' "$MOCK_SRV/curl.log"
check "no warning that the signature is unchecked" grep -q 'manifest signature is not checked' "$MOCK_SRV/out"
done_case

HK_VERSION=1.2.3; hook download_pinned 0 1 "" 0
check "not fetched from the pinned release" grep -q 'releases/download/v1.2.3/install-awg.sh$' "$MOCK_SRV/curl.log"
done_case

hook download_not_listed 0 0 "" 0
check "exit $RC, want 1" test "$RC" = 1
check "an unlisted script ran" test ! -s "$MOCK_SRV/awg.log"
done_case

hook download_mismatch 0 bad "" 0
check "exit $RC, want 1" test "$RC" = 1
check "a mismatching script ran" test ! -s "$MOCK_SRV/awg.log"
check "no mismatch message" grep -q 'SHA-256 MISMATCH' "$MOCK_SRV/out"
done_case

hook verifier_no_sig 0 1 "" 1
check "exit $RC, want 1 (no .sig on a verifier-capable device)" test "$RC" = 1
check "the script ran without a signed manifest" test ! -s "$MOCK_SRV/awg.log"
done_case

HK_SIG=1; HK_USIGN_RC=1; hook verifier_bad_sig 0 1 "" 1
check "exit $RC, want 1 (bad manifest signature)" test "$RC" = 1
check "the script ran despite a bad signature" test ! -s "$MOCK_SRV/awg.log"
check "the verifier was not asked" test -s "$MOCK_SRV/usign.log"
done_case

HK_SIG=1; hook verifier_good_sig 0 1 "" 1
check "exit $RC, want 0 (good manifest signature)" test "$RC" = 0
check "the verified script did not run" test "$(awg_src)" = asset
check "the release key was not handed to the verifier" grep -q -- '-p .*release.pub' "$MOCK_SRV/usign.log"
done_case

for rc_case in 2:2 1:1 7:1; do
  HK_AWG_RC="${rc_case%%:*}"; hook "exit_${rc_case%%:*}" 1 0 "" 0
  check "install-awg.sh exit ${rc_case%%:*} maps to $RC, want ${rc_case##*:}" test "$RC" = "${rc_case##*:}"
  done_case
done

# --- argument parsing in the real installers --------------------------------------------------------
echo "== install.sh argument parsing =="
for inst in "$PKG/install.sh" "$PKG/openwrt/install.sh"; do
  CASE="$(basename "$(dirname "$inst")")/install.sh"; before=$FAIL
  PATH="$MOCKS" $SHX "$inst" --help > "$WORK/help" 2>&1; RC=$?
  check "--help exits $RC" test "$RC" = 0
  check "--help does not mention --with-awg" grep -q -- '--with-awg' "$WORK/help"
  PATH="$MOCKS" $SHX "$inst" --with-awg=everything > "$WORK/out" 2>&1; RC=$?
  check "an invalid mode exits $RC" test "$RC" = 1
  check "an invalid mode is not named" grep -q "invalid --with-awg mode 'everything'" "$WORK/out"
  PATH="$MOCKS" $SHX "$inst" --with-awg=kmod --bogus > "$WORK/out" 2>&1
  check "--with-awg=kmod is not accepted by the parser" grep -q 'unknown option: --bogus' "$WORK/out"
  done_case
done

echo "--with-awg hook tests ($SHX): $PASS checks passed, $FAIL failed"
[ "$FAIL" = 0 ]
