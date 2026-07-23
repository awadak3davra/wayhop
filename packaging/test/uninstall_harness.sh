#!/bin/sh
# uninstall_harness.sh — offline test for the WayHop network cleanup in uninstall.sh.
#
# The file-removal steps no-op here (the /opt paths don't exist off-router); mock `nft` + `ip` let us
# assert the network cleanup: it deletes ONLY `nft table inet wayhop_pbr` and EVERY WayHop fwmark ip
# rule (one per egress in a multi-tunnel setup) plus the tables those rules point at, is idempotent,
# and never touches a foreign table/rule. Run:  sh packaging/test/uninstall_harness.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
UNINST="$HERE/../uninstall.sh"
[ -f "$UNINST" ] || { echo "uninstall.sh not found at $UNINST" >&2; exit 1; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
MOCKS="$WORK/bin"; mkdir -p "$MOCKS"
export NFT_LOG="$WORK/nft.log" IP_LOG="$WORK/ip.log" IP_STATE="$WORK/state"
mkdir -p "$IP_STATE"

cat > "$MOCKS/nft" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$NFT_LOG"
case "$*" in
  "list table inet wayhop_pbr") [ "${NFT_HAS_WAYHOP:-1}" = 1 ] && exit 0 || exit 1 ;;
  *) exit 0 ;;
esac
EOF
# Stateful `ip` mock: `rule show` prints whatever rules are currently in $IP_STATE/rules (seeded per
# run); `rule del fwmark M` removes the matching line, so the teardown loop can drain several marks;
# `route flush table N` is just logged (asserted separately).
cat > "$MOCKS/ip" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$IP_LOG"
RULES="$IP_STATE/rules"
case "$1 $2" in
  "rule show")
    printf '0:\tfrom all lookup local\n'
    [ -f "$RULES" ] && cat "$RULES"
    printf '32766:\tfrom all lookup main\n'
    ;;
  "rule del")
    if [ "$3" = "fwmark" ] && [ -f "$RULES" ]; then
      grep -v "fwmark $4 " "$RULES" > "$RULES.tmp" 2>/dev/null || : > "$RULES.tmp"
      mv "$RULES.tmp" "$RULES"
    fi ;;
  *) : ;;
esac
EOF
chmod +x "$MOCKS/nft" "$MOCKS/ip"
export PATH="$MOCKS:$PATH"

seed_rules() { printf '%b' "$1" > "$IP_STATE/rules"; }

echo "== uninstall.sh network-cleanup harness =="

# --- run 1: one WayHop rule + a foreign rule -> WayHop removed, foreign left ---
: > "$NFT_LOG"; : > "$IP_LOG"
seed_rules '100:\tfrom all fwmark 0x1234/0xffff lookup 42\n150:\tfrom all fwmark 0x20000/0xff0000 lookup 151\n'
NFT_HAS_WAYHOP=1 sh "$UNINST" </dev/null >"$WORK/out1.txt" 2>&1 || true

grep -q 'delete table inet wayhop_pbr' "$NFT_LOG" && ok "removes nft table inet wayhop_pbr" || bad "nft delete not issued" "$(cat "$NFT_LOG")"
grep -q 'rule del fwmark 0x20000/0xff0000' "$IP_LOG" && ok "removes the WayHop fwmark ip rule" || bad "ip rule del not issued" "$(cat "$IP_LOG")"
if grep -qE 'delete table inet (foreign|[^w]|w[^a])' "$NFT_LOG" || grep -q 'rule del fwmark 0x1234' "$IP_LOG"; then bad "touched a FOREIGN table/rule"; else ok "foreign table/rule untouched"; fi
if grep -E 'delete table' "$NFT_LOG" | grep -qv 'wayhop_pbr'; then bad "deleted a non-wayhop nft table"; else ok "only wayhop_pbr deleted"; fi

# --- run 2: nothing present -> idempotent, no deletes/flushes ---
: > "$NFT_LOG"; : > "$IP_LOG"; : > "$IP_STATE/rules"
NFT_HAS_WAYHOP=0 sh "$UNINST" </dev/null >"$WORK/out2.txt" 2>&1 || true
if grep -q 'delete table' "$NFT_LOG" || grep -q 'rule del' "$IP_LOG" || grep -q 'route flush' "$IP_LOG"; then bad "not idempotent (acted when nothing present)" "$(cat "$NFT_LOG" "$IP_LOG")"; else ok "idempotent: no deletes/flushes when nothing is present"; fi

# --- run 3: THREE egress marks (multi-tunnel failover) + a foreign -> ALL WayHop marks removed,
#            ALL their tables flushed, foreign untouched (the actual PBR-teardown fix) ---
: > "$NFT_LOG"; : > "$IP_LOG"
seed_rules '90:\tfrom all fwmark 0xffff/0xffff lookup 7\n150:\tfrom all fwmark 0x10000/0xff0000 lookup 151\n151:\tfrom all fwmark 0x20000/0xff0000 lookup 152\n152:\tfrom all fwmark 0x30000/0xff0000 lookup 153\n'
NFT_HAS_WAYHOP=1 sh "$UNINST" </dev/null >"$WORK/out3.txt" 2>&1 || true
_miss=""
for m in 0x10000 0x20000 0x30000; do grep -q "rule del fwmark $m/0xff0000" "$IP_LOG" || _miss="$_miss $m"; done
[ -z "$_miss" ] && ok "removes EVERY egress mark (0x10000/0x20000/0x30000)" || bad "missed egress mark(s):$_miss" "$(cat "$IP_LOG")"
_tmiss=""
for t in 151 152 153; do grep -q "route flush table $t" "$IP_LOG" || _tmiss="$_tmiss $t"; done
[ -z "$_tmiss" ] && ok "flushes EVERY per-egress table (151/152/153)" || bad "missed table flush(es):$_tmiss" "$(cat "$IP_LOG")"
if grep -q 'rule del fwmark 0xffff/0xffff' "$IP_LOG" || grep -q 'route flush table 7' "$IP_LOG"; then bad "touched the foreign 0xffff rule/table"; else ok "foreign mask (0xffff) + its table left alone"; fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
