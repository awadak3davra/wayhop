#!/bin/sh
# bootstrap_harness.sh — offline, reproducible test harness for packaging/bootstrap.sh.
#
# No router, no network, no root needed. It stubs `uname`, `curl`, and `id` on PATH, builds a fake
# GitHub release (tarball + SHA256SUMS) in a temp dir, and drives bootstrap.sh against it — asserting
# the guarantees the spec cares about: arch detection, ARMv6 rejection BEFORE any system change,
# MANDATORY SHA-256 (good / mismatch / missing manifest / missing asset / unlisted), fail-closed
# signature handling when a verifier exists, version pinning, and the install.sh handoff. The real install.sh is replaced
# by a stub that records its args — this harness covers bootstrap ONLY (install/update/uninstall e2e
# live in install_harness.sh, which needs a Linux root).
#
# Run:  sh packaging/test/bootstrap_harness.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
BOOT="$HERE/../bootstrap.sh"
[ -f "$BOOT" ] || { echo "bootstrap.sh not found at $BOOT" >&2; exit 1; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- mock commands (prepended to PATH) ----
MOCKS="$WORK/bin"; mkdir -p "$MOCKS"
SYSTEM_PATH="$PATH"
# Build a deterministic command PATH that deliberately contains no host usign/signify. Wrappers use
# the exact tools already selected on the host; only verifier discovery is isolated by omission.
for cmd in sh awk cat chmod cp cut dd grep gzip head mkdir mktemp od rm sed sha256sum tar tr wc; do
  real="$(PATH="$SYSTEM_PATH" command -v "$cmd" 2>/dev/null || true)"
  [ -n "$real" ] || { echo "required test command not found: $cmd" >&2; exit 2; }
  printf '#!/bin/sh\nexec "%s" "$@"\n' "$real" > "$MOCKS/$cmd"
  chmod +x "$MOCKS/$cmd"
done
cat > "$MOCKS/uname" <<'EOF'
#!/bin/sh
case "$1" in -m) echo "${MOCK_UNAME_M:-x86_64}" ;; *) exec /usr/bin/uname "$@" ;; esac
EOF
cat > "$MOCKS/id" <<'EOF'
#!/bin/sh
case "$1" in -u) echo 0 ;; -un) echo root ;; *) exec /usr/bin/id "$@" ;; esac
EOF
cat > "$MOCKS/curl" <<'EOF'
#!/bin/sh
url=""; out=""
while [ $# -gt 0 ]; do case "$1" in -o) shift; out="$1" ;; http://*|https://*) url="$1" ;; esac; shift; done
base="${url##*/}"
case "$url" in
  */releases/latest) f="$MOCK_SRV/releases_latest.json" ;;
  */releases)        f="$MOCK_SRV/releases_all.json" ;;
  *)                 f="$MOCK_SRV/$base" ;;
esac
[ -f "$f" ] || exit 22   # emulate curl -f on a 404
if [ -n "$out" ]; then cp "$f" "$out"; else cat "$f"; fi
EOF
chmod +x "$MOCKS/uname" "$MOCKS/id" "$MOCKS/curl"
export PATH="$MOCKS"

# Installed only for the signature cases below. Keeping it out of PATH for the ordinary cases models
# Keenetic/busybox (SHA-256 only); adding it models an OpenWrt device with signify available.
SIGMOCK="$WORK/signify"
cat > "$SIGMOCK" <<'EOF'
#!/bin/sh
pub=""; sig=""; msg=""
while [ $# -gt 0 ]; do
  case "$1" in
    -p) shift; pub="${1:-}" ;;
    -x) shift; sig="${1:-}" ;;
    -m) shift; msg="${1:-}" ;;
  esac
  shift
done
[ -s "$pub" ] && [ -s "$sig" ] && [ -s "$msg" ] || exit 2
[ -z "${MOCK_EVENT_LOG:-}" ] || printf 'verify\n' >> "$MOCK_EVENT_LOG"
case "${MOCK_SIG_RESULT:-ok}" in
  ok) exit 0 ;;
  bad) exit 1 ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$SIGMOCK"
sigmock_on() { cp "$SIGMOCK" "$MOCKS/signify"; }
usignmock_on() { cp "$SIGMOCK" "$MOCKS/usign"; }
sigmock_off() { rm -f "$MOCKS/signify" "$MOCKS/usign"; }
MOCK_EVENT_LOG="$WORK/events.txt"; export MOCK_EVENT_LOG

# ---- build a fake release whose install.sh only records its args ----
mkrelease() {  # $1=arch label in the asset name, $2="-openwrt" or ""
  MOCK_SRV="$WORK/srv"; rm -rf "$MOCK_SRV"; mkdir -p "$MOCK_SRV"; export MOCK_SRV
  printf '{"tag_name": "v1.0.0"}\n' > "$MOCK_SRV/releases_latest.json"
  printf '[{"tag_name":"v1.1.0-rc1"},{"tag_name":"v1.0.0"}]\n' > "$MOCK_SRV/releases_all.json"
  pkg="$WORK/pkg"; rm -rf "$pkg"; mkdir -p "$pkg"
  cat > "$pkg/install.sh" <<IEOF
#!/bin/sh
printf 'install\n' >> "$MOCK_EVENT_LOG"
printf '%s\n' "\$*" > "$WORK/install-args.txt"
exit \${STUB_RC:-0}
IEOF
  ( cd "$pkg" && tar -czf "$MOCK_SRV/wayhop-1.0.0-$1$2.tar.gz" . )
  ( cd "$MOCK_SRV" && sha256sum "wayhop-1.0.0-$1$2.tar.gz" > SHA256SUMS.txt )
}
runb() {
  rm -f "$WORK/install-args.txt" "$WORK/out.txt" "$MOCK_EVENT_LOG"
  set +e; sh "$BOOT" "$@" </dev/null >"$WORK/out.txt" 2>&1; _rc=$?; set -e
  echo "$_rc"
}
args() { cat "$WORK/install-args.txt" 2>/dev/null || true; }

echo "== bootstrap.sh harness =="

# 1. clean amd64 install, arch forwarded to install.sh
MOCK_UNAME_M=x86_64 STUB_RC=0; export MOCK_UNAME_M STUB_RC; mkrelease amd64 ""
rc="$(runb)"; case "$(args)" in *"--arch amd64"*) [ "$rc" = 0 ] && grep -q 'authenticity is not independently verified' "$WORK/out.txt" && ok "clean amd64 install + explicit SHA-only warning + --arch forwarded" || bad "amd64 rc=$rc" "$(cat "$WORK/out.txt")" ;; *) bad "amd64 handoff args" "rc=$rc args=[$(args)]"; cat "$WORK/out.txt" ;; esac

# 2. arm64 detection
MOCK_UNAME_M=aarch64; mkrelease arm64 ""; rc="$(runb)"
case "$(args)" in *"--arch arm64"*) ok "arm64 detected" ;; *) bad "arm64 detection" "rc=$rc" ;; esac

# 3. mipsle default (mips little-endian via mocked uname; asset served accordingly)
MOCK_UNAME_M=mips; mkrelease mipsle ""; rc="$(runb)"
case "$(args)" in *"--arch mipsle"*) ok "mips -> mipsle (LE default)" ;; *) bad "mipsle detection" "rc=$rc" ;; esac

# 4. ARMv6 REJECTED before any download/handoff
MOCK_UNAME_M=armv6l; mkrelease arm ""; rc="$(runb)"
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ] && grep -qi 'armv6' "$WORK/out.txt"; then ok "ARMv6 rejected, no handoff"; else bad "ARMv6 rejection" "rc=$rc"; fi

# 5. armv7 -> arm
MOCK_UNAME_M=armv7l; mkrelease arm ""; rc="$(runb)"
case "$(args)" in *"--arch arm"*) ok "armv7 -> arm" ;; *) bad "armv7 mapping" "rc=$rc" ;; esac

# 6. OpenWrt flavour (forced) pulls the -openwrt asset
MOCK_UNAME_M=x86_64; mkrelease amd64 "-openwrt"; rc="$(runb --openwrt)"
case "$(args)" in *"--arch amd64"*) [ "$rc" = 0 ] && ok "--openwrt pulls the -openwrt tarball" || bad "openwrt rc=$rc" "$(cat "$WORK/out.txt")" ;; *) bad "openwrt flavour" "rc=$rc" ;; esac

# 7. BAD checksum -> abort, no handoff
MOCK_UNAME_M=x86_64; mkrelease amd64 ""; echo "0000000000000000000000000000000000000000000000000000000000000000  wayhop-1.0.0-amd64.tar.gz" > "$MOCK_SRV/SHA256SUMS.txt"
rc="$(runb)"
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ] && grep -qi 'mismatch' "$WORK/out.txt"; then ok "checksum MISMATCH aborts, nothing installed"; else bad "bad checksum not enforced" "rc=$rc"; fi

# 8. MISSING SHA256SUMS -> abort (mandatory, not best-effort)
MOCK_UNAME_M=x86_64; mkrelease amd64 ""; rm -f "$MOCK_SRV/SHA256SUMS.txt"
rc="$(runb)"
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ]; then ok "missing SHA256SUMS aborts (mandatory)"; else bad "missing manifest not enforced" "rc=$rc"; fi

# 9. asset not listed in the manifest -> abort
MOCK_UNAME_M=x86_64; mkrelease amd64 ""; echo "abc123  some-other-file.tar.gz" > "$MOCK_SRV/SHA256SUMS.txt"
rc="$(runb)"
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ]; then ok "asset-not-listed aborts"; else bad "unlisted asset not caught" "rc=$rc"; fi

# 9b. regex-near filename is not the requested asset (dots must be compared literally)
MOCK_UNAME_M=x86_64; mkrelease amd64 ""
sum="$(awk '{print $1}' "$MOCK_SRV/SHA256SUMS.txt")"
printf '%s  %s\n' "$sum" 'wayhop-1X0X0-amd64.tarXgz' > "$MOCK_SRV/SHA256SUMS.txt"
rc="$(runb)"
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ] && grep -q 'not listed' "$WORK/out.txt"; then
  ok "near-match filename is refused by literal comparison"
else
  bad "near-match filename" "rc=$rc output=$(cat "$WORK/out.txt")"
fi

# 10. missing asset (404) -> abort
MOCK_UNAME_M=x86_64; mkrelease amd64 ""; rm -f "$MOCK_SRV"/wayhop-1.0.0-amd64.tar.gz
rc="$(runb)"
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ]; then ok "missing asset (404) aborts"; else bad "404 not caught" "rc=$rc"; fi

# 11. WAYHOP_VERSION env pins the version (bare number gets a v prefix)
MOCK_UNAME_M=x86_64; mkrelease amd64 ""
rm -f "$WORK/install-args.txt" "$WORK/out.txt"; WAYHOP_VERSION=1.0.0 sh "$BOOT" </dev/null >"$WORK/out.txt" 2>&1; rc=$?
if [ "$rc" = 0 ] && grep -q 'release=v1.0.0' "$WORK/out.txt"; then ok "WAYHOP_VERSION pins version"; else bad "WAYHOP_VERSION" "rc=$rc"; fi

# 12. install.sh non-zero exit is propagated by bootstrap
MOCK_UNAME_M=x86_64 STUB_RC=7; export STUB_RC; mkrelease amd64 ""; rc="$(runb)"; STUB_RC=0
[ "$rc" != 0 ] && ok "install.sh failure propagates non-zero exit" || bad "exit-code propagation" "rc=$rc"

# 13. verifier + valid signature -> signature is checked before handoff
MOCK_UNAME_M=x86_64 STUB_RC=0 MOCK_SIG_RESULT=ok; export STUB_RC MOCK_SIG_RESULT
mkrelease amd64 ""; printf 'test signature\n' > "$MOCK_SRV/SHA256SUMS.txt.sig"; sigmock_on; rc="$(runb)"; sigmock_off
if [ "$rc" = 0 ] && grep -q 'manifest signature verified' "$WORK/out.txt" && \
   [ "$(tr '\n' ' ' < "$MOCK_EVENT_LOG")" = "verify install " ]; then
  ok "verifier + valid signature permits the verified handoff"
else
  bad "valid signature path" "rc=$rc output=$(cat "$WORK/out.txt")"
fi

# 14. verifier + missing signature -> fail closed, never hand off
MOCK_SIG_RESULT=ok; export MOCK_SIG_RESULT; mkrelease amd64 ""; sigmock_on; rc="$(runb)"; sigmock_off
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ] && grep -q 'ships no SHA256SUMS.txt.sig' "$WORK/out.txt"; then
  ok "verifier + missing signature refuses the release"
else
  bad "missing signature downgrade" "rc=$rc output=$(cat "$WORK/out.txt")"
fi

# 15. verifier + invalid signature -> fail closed, never hand off
MOCK_SIG_RESULT=bad; export MOCK_SIG_RESULT
mkrelease amd64 ""; printf 'bad signature\n' > "$MOCK_SRV/SHA256SUMS.txt.sig"; sigmock_on; rc="$(runb)"; sigmock_off
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ] && grep -q 'SIGNATURE verification FAILED' "$WORK/out.txt"; then
  ok "verifier + invalid signature refuses the release"
else
  bad "invalid signature" "rc=$rc output=$(cat "$WORK/out.txt")"
fi

# 16. the usign fallback uses the same strict path when signify is absent
MOCK_SIG_RESULT=ok; export MOCK_SIG_RESULT
mkrelease amd64 ""; printf 'test signature\n' > "$MOCK_SRV/SHA256SUMS.txt.sig"; usignmock_on; rc="$(runb)"; sigmock_off
if [ "$rc" = 0 ] && grep -q 'manifest signature verified (usign)' "$WORK/out.txt" && \
   [ "$(tr '\n' ' ' < "$MOCK_EVENT_LOG")" = "verify install " ]; then
  ok "usign verifies before the install handoff"
else
  bad "usign signature path" "rc=$rc output=$(cat "$WORK/out.txt")"
fi

# 17. duplicate manifest entries are ambiguous even if the first digest is correct
MOCK_SIG_RESULT=ok; export MOCK_SIG_RESULT; mkrelease amd64 ""
line="$(head -n1 "$MOCK_SRV/SHA256SUMS.txt")"; printf '%s\n%s\n' "$line" "$line" > "$MOCK_SRV/SHA256SUMS.txt"
rc="$(runb)"
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ] && grep -q 'multiple entries' "$WORK/out.txt"; then
  ok "duplicate checksum entries are refused"
else
  bad "duplicate manifest entry" "rc=$rc output=$(cat "$WORK/out.txt")"
fi

# 18. malformed digests are not accepted as checksums
mkrelease amd64 ""; printf 'abcd  wayhop-1.0.0-amd64.tar.gz\n' > "$MOCK_SRV/SHA256SUMS.txt"; rc="$(runb)"
if [ "$rc" != 0 ] && [ ! -f "$WORK/install-args.txt" ] && grep -q 'malformed SHA-256' "$WORK/out.txt"; then
  ok "malformed checksum digests are refused"
else
  bad "malformed digest" "rc=$rc output=$(cat "$WORK/out.txt")"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
