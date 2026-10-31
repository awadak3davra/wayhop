#!/bin/sh
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
INIT=$HERE/../S99wayhop
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

BIN=$WORK/bin
STATE=$WORK/running
LOG=$WORK/logger.log
ARGS=$WORK/args
STARTS=$WORK/starts
NOFILE=$WORK/nofile
mkdir -p "$BIN"

cat >"$BIN/pidof" <<'EOF'
#!/bin/sh
[ -f "$WAYHOP_TEST_STATE" ]
EOF

cat >"$BIN/killall" <<'EOF'
#!/bin/sh
case ${1:-} in
	-HUP) exit 0 ;;
	-9) shift ;;
esac
rm -f "$WAYHOP_TEST_STATE"
EOF

cat >"$BIN/logger" <<'EOF'
#!/bin/sh
printf 'call:%s\n' "$*" >>"$WAYHOP_TEST_LOG"
if [ "$#" -eq 2 ]; then
	while IFS= read -r line; do
		printf 'line:%s\n' "$line" >>"$WAYHOP_TEST_LOG"
	done
fi
EOF

PROG=$WORK/wayhop
cat >"$PROG" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >"$WAYHOP_TEST_ARGS"
# shellcheck disable=SC3045
ulimit -n >"$WAYHOP_TEST_NOFILE"
echo start >>"$WAYHOP_TEST_STARTS"
: >"$WAYHOP_TEST_STATE"
echo '2026/08/14 21:03:44 apply: strict native runtime ready'
echo '2026/08/14 21:03:45 GET /api/health 200 (1ms)'
echo '+0300 2026-08-15 00:03:48 WARN noisy child engine line'
while [ -f "$WAYHOP_TEST_STATE" ]; do sleep 1; done
EOF
chmod +x "$BIN/pidof" "$BIN/killall" "$BIN/logger" "$PROG"

run_init() {
	WAYHOP_PROG=$PROG \
	WAYHOP_CONFIG=$WORK/config.json \
	WAYHOP_NAME=wayhop \
	WAYHOP_PATH=$BIN:$PATH \
	WAYHOP_TEST_STATE=$STATE \
	WAYHOP_TEST_LOG=$LOG \
	WAYHOP_TEST_ARGS=$ARGS \
	WAYHOP_TEST_STARTS=$STARTS \
	WAYHOP_TEST_NOFILE=$NOFILE \
	sh "$INIT" "$@"
}

pass=0
ok() {
	pass=$((pass + 1))
}

# Started from a shell at 1024 open files, the daemon gets 16384: the init raises the limit before
# it starts the daemon, which on Keenetic is otherwise 1024 soft / 4096 hard ("too many open files"
# on a busy router). Asserted only where this host lets a process go that high at all.
# shellcheck disable=SC3045
(ulimit -Sn 1024 2>/dev/null; run_init start test >/dev/null)
[ -f "$STATE" ]
ok

[ "$(cat "$ARGS")" = "--config $WORK/config.json" ]
ok

# shellcheck disable=SC3045
hard=$(ulimit -Hn)
if [ "$hard" = unlimited ] || [ "$hard" -ge 16384 ]; then
	[ "$(cat "$NOFILE")" = 16384 ]
	ok
fi

sleep 1
grep -q 'call:-t wayhop apply: strict native runtime ready' "$LOG"
! grep -q '/api/health' "$LOG"
! grep -q 'noisy child engine' "$LOG"
ok

run_init status >/dev/null
ok

run_init start test >/dev/null
[ -f "$STATE" ]
ok

run_init reconfigure >/dev/null
[ -f "$STATE" ]
[ "$(wc -l <"$STARTS")" -eq 2 ]
ok

run_init restart test >/dev/null
[ -f "$STATE" ]
[ "$(wc -l <"$STARTS")" -eq 3 ]
ok

run_init stop >/dev/null
[ ! -f "$STATE" ]
ok

set +e
run_init start cron >/dev/null
rc=$?
set -e
[ "$rc" -eq 7 ]
[ ! -f "$STATE" ]
ok

set +e
WAYHOP_PROG=$WORK/missing WAYHOP_CONFIG=$WORK/config.json WAYHOP_NAME=wayhop \
	WAYHOP_PATH=$BIN:$PATH WAYHOP_TEST_STATE=$STATE WAYHOP_TEST_LOG=$LOG \
	WAYHOP_TEST_ARGS=$ARGS WAYHOP_TEST_STARTS=$STARTS sh "$INIT" start test >/dev/null
rc=$?
set -e
[ "$rc" -eq 255 ]
grep -q 'missing or not executable' "$LOG"
ok

echo "s99wayhop: $pass lifecycle and log-sink checks passed"
