#!/bin/sh
# check-openwrt-proto.sh - exercise the netifd protocol handler amneziawg.sh (package amneziawg-tools)
# inside an OpenWrt root filesystem, with netifd's proto_* calls replaced by recorders.
#
# Usage, from the repository root (any openwrt/rootfs image; it needs /lib/functions.sh and uci):
#   docker run --rm -v "$PWD:/src:ro" openwrt/rootfs:x86-64-25.12.0 \
#       sh /src/scripts/awg/check-openwrt-proto.sh
# Without arguments awg, ip, modprobe and amneziawg-go are stubs: the check compares the exact
# configuration handed to "awg setconf", the addresses, routes and host dependencies reported to
# netifd, and the engine choice (kernel module, userspace fallback, neither).
#
#   docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -v "$PWD:/src:ro" -v <bin>:/bin2:ro \
#       openwrt/rootfs:x86-64-25.12.0 sh /src/scripts/awg/check-openwrt-proto.sh /bin2/awg /bin2/amneziawg-go
# With a real awg and amneziawg-go (x86_64 builds for the x86-64 image) it brings up a real
# userspace interface, checks every AmneziaWG 3.1 key with "awg showconf", renews it (syncconf) and
# tears it down. The real ip(8) is needed then (ip-tiny or ip-full).
# Not -u: OpenWrt's /lib/functions.sh and the handler read unset variables, as netifd allows.
set -e

proto="$(cd "$(dirname "$0")/../.." && pwd)/packaging/awg/openwrt/amneziawg-tools/files/amneziawg.sh"
real_awg="${1:-}"
real_go="${2:-}"
fails=0
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT

fail() {
	echo "FAIL: $*"
	fails=$((fails + 1))
}
pass() {
	echo "ok: $*"
}
# check <description> <command...>: the command's status decides
check() {
	desc="$1"
	shift
	if "$@"; then pass "$desc"; else fail "$desc"; fi
}

# --- stubs ---------------------------------------------------------------------------------------
mkdir -p "$t/bin"
calls="$t/calls"
: >"$calls"
cat >"$t/bin/logger" <<'EOF'
#!/bin/sh
echo "logger $*" >>"$CALLS"
EOF
cat >"$t/bin/modprobe" <<'EOF'
#!/bin/sh
echo "modprobe $*" >>"$CALLS"
exit 1
EOF
if [ -z "$real_awg" ]; then
	cat >"$t/bin/ip" <<'EOF'
#!/bin/sh
echo "ip $*" >>"$CALLS"
case "$*" in
	"link add dev "*" type amneziawg") [ "$STUB_KMOD" = 1 ] ;;
	*) exit 0 ;;
esac
EOF
	cat >"$t/awg" <<'EOF'
#!/bin/sh
case "$1" in
	genkey) echo "GENERATEDKEY" ;;
	show) printf 'PUB1\t[2001:db8::1]:443\nPUB3\t192.0.2.7:51820\nPUBX\t(none)\n' ;;
	setconf|syncconf) echo "awg $*" >>"$CALLS"; cat >"$AWG_CONFIG_OUT" ;;
esac
EOF
	cat >"$t/amneziawg-go" <<'EOF'
#!/bin/sh
echo "amneziawg-go $* AWG_SOCKET_DIR=$AWG_SOCKET_DIR LOG_LEVEL=[$LOG_LEVEL]" >>"$CALLS"
EOF
	chmod +x "$t/awg" "$t/amneziawg-go"
	cp "$t/awg" /usr/bin/awg
else
	cp "$real_awg" /usr/bin/awg
	cp "$real_go" /usr/bin/amneziawg-go
	chmod +x /usr/bin/awg /usr/bin/amneziawg-go
fi
chmod +x "$t/bin/"*
export CALLS="$calls" AWG_CONFIG_OUT="$t/config" STUB_KMOD=1
PATH="$t/bin:$PATH"

# --- netifd recorders ----------------------------------------------------------------------------
# shellcheck source=/dev/null
. /lib/functions.sh
proto_init_update() { echo "proto_init_update $*" >>"$CALLS"; }
proto_add_ipv4_address() { echo "addr4 $*" >>"$CALLS"; }
proto_add_ipv6_address() { echo "addr6 $*" >>"$CALLS"; }
proto_add_ipv4_route() { echo "route4 $*" >>"$CALLS"; }
proto_add_ipv6_route() { echo "route6 $*" >>"$CALLS"; }
proto_add_ipv6_prefix() { echo "prefix6 $*" >>"$CALLS"; }
proto_add_host_dependency() { echo "hostdep $*" >>"$CALLS"; }
proto_send_update() { echo "proto_send_update $*" >>"$CALLS"; }
proto_setup_failed() { echo "proto_setup_failed $*" >>"$CALLS"; }
proto_notify_error() { echo "proto_notify_error $*" >>"$CALLS"; }
proto_block_restart() { echo "proto_block_restart $*" >>"$CALLS"; }
# shellcheck disable=SC2034  # read by the sourced amneziawg.sh
INCLUDE_ONLY=1
# shellcheck source=/dev/null
. "$proto"

# --- the UCI configuration -----------------------------------------------------------------------
if [ -n "$real_awg" ]; then
	priv="$(awg genkey)"
	pub1="$(awg genkey | awg pubkey)"
	pub2="$(awg genkey | awg pubkey)"
	pub3="$(awg genkey | awg pubkey)"
	psk1="$(awg genpsk)"
	hpk="$(awg genpsk)"
else
	priv="PRIVKEY" pub1="PUB1" pub2="PUB2" pub3="PUB3" psk1="PSK1" hpk="HPKEY"
fi
mkdir -p /etc/config
cat >/etc/config/network <<EOF
config interface 'awg0'
	option proto 'amneziawg'
	option private_key '$priv'
	option listen_port '51820'
	list addresses '10.8.0.2/32'
	list addresses 'fd00::2/128'
	option ip6prefix 'fd42::/64'
	option mtu '1380'
	option fwmark '0x51'
	option awg_jc '4'
	option awg_jmin '40'
	option awg_jmax '70'
	option awg_s1 '15'
	option awg_s2 '20'
	option awg_s3 '25'
	option awg_s4 '12'
	option awg_h1 '100-200'
	option awg_h2 '300'
	option awg_h3 '400'
	option awg_h4 '500-600'
	option awg_i1 '<b 0xc0ffee><r 16>'
	option awg_header_protection_key '$hpk'
	option awg_content_padding_addition '8-16'
	option awg_rekey_after_time '120'
	option awg_rekey_timeout '5'
	option awg_reject_after_time '180'
	option awg_keepalive_timeout '10'
	option awg_max_handshake_attempts '20'
	option awg_random_trailers 'on'
	option awg_disable_cookies 'false'

config amneziawg_awg0 'peer1'
	option public_key '$pub1'
	option preshared_key '$psk1'
	list allowed_ips '0.0.0.0/0'
	list allowed_ips '::/0'
	option endpoint_host '2001:db8::1'
	option endpoint_port '443'
	option persistent_keepalive '25'
	option route_allowed_ips '1'

config amneziawg_awg0 'peer2'
	option public_key '$pub2'
	option endpoint_host '198.51.100.9'
	list allowed_ips '10.12.0.0/24'
	option disabled '1'

config amneziawg_awg0 'peer3'
	option public_key '$pub3'
	option endpoint_host '192.0.2.7'
	list allowed_ips '10.10.0.0/16'

config amneziawg_awg0 'nokey'
	list allowed_ips '10.11.0.0/16'
EOF

# netifd runs the handler without errexit; so does this (and in a subshell, as it may exit).
setup() {
	(
		set +e
		proto_amneziawg_setup awg0
	)
}

if [ -z "$real_awg" ]; then
	# 1. kernel module present: setconf with exactly this configuration
	setup || fail "setup with the kernel module failed"
	cat >"$t/want" <<EOF
[Interface]
PrivateKey=$priv
ListenPort=51820
FwMark=0x51
Jc=4
Jmin=40
Jmax=70
S1=15
S2=20
S3=25
S4=12
H1=100-200
H2=300
H3=400
H4=500-600
I1=<b 0xc0ffee><r 16>
HeaderProtectionKey=$hpk
ContentPaddingAddition=8-16
RekeyAfterTime=120
RekeyTimeout=5
RejectAfterTime=180
KeepaliveTimeout=10
MaxHandshakeAttempts=20
RandomTrailers=1

[Peer]
PublicKey=$pub1
PresharedKey=$psk1
Endpoint=[2001:db8::1]:443
AllowedIPs=0.0.0.0/0
AllowedIPs=::/0
PersistentKeepalive=25

[Peer]
PublicKey=$pub3
Endpoint=192.0.2.7:51820
AllowedIPs=10.10.0.0/16
EOF
	if cmp -s "$t/want" "$t/config"; then pass "setconf configuration"; else
		fail "setconf configuration differs:"
		diff "$t/want" "$t/config" || true
	fi
	for want in "ip link add dev awg0 type amneziawg" "ip link set mtu 1380 dev awg0" "awg setconf awg0 /dev/stdin" \
		"proto_init_update awg0 1" "addr4 10.8.0.2 32" "addr6 fd00::2 128" "prefix6 fd42::/64" \
		"route4 0.0.0.0 0" "route6 :: 0" "hostdep awg0 2001:db8::1 " "hostdep awg0 192.0.2.7 " \
		"proto_send_update awg0" "logger -t amneziawg awg0: peer nokey has no public_key, skipped"; do
		check "call: $want" grep -qxF "$want" "$calls"
	done
	grep -q "amneziawg-go\|route4 10.9\|route4 10.10\|hostdep.*PUBX\|(none)" "$calls" &&
		fail "unexpected call: $(grep "amneziawg-go\|route4 10.9\|route4 10.10\|(none)" "$calls")"

	# 2. no kernel module, amneziawg-go installed: userspace fallback with WayHop's socket dir
	: >"$calls"
	STUB_KMOD=0
	cp "$t/amneziawg-go" "$t/bin/amneziawg-go"
	setup || fail "setup with the userspace fallback failed"
	check "userspace fallback started amneziawg-go with AWG_SOCKET_DIR" 		grep -qxF "amneziawg-go awg0 AWG_SOCKET_DIR=/var/run/amneziawg LOG_LEVEL=[]" "$calls"
	check "modprobe tried before the fallback" grep -qxF "modprobe amneziawg" "$calls"
	check "userspace configured with setconf" grep -qxF "awg setconf awg0 /dev/stdin" "$calls"

	# 3. neither: a clear error and no restart loop
	: >"$calls"
	rm -f "$t/bin/amneziawg-go"
	if setup; then fail "setup without any engine succeeded"; else pass "setup without any engine fails"; fi
	check "NO_AMNEZIAWG reported" grep -qxF "proto_notify_error awg0 NO_AMNEZIAWG" "$calls"
	check "restart blocked" grep -qxF "proto_block_restart awg0" "$calls"
	grep -q "^awg " "$calls" && fail "awg ran although there is no link"

	# 4. the generated private key is stored when the option says "generate"
	uci set network.awg0.private_key=generate
	uci commit network
	ensure_key_is_generated awg0
	check "private_key=generate replaced by a stored key" [ "$(uci get network.awg0.private_key)" = GENERATEDKEY ]
else
	# Real awg + amneziawg-go (no kernel module in a container): the userspace path end to end.
	STUB_KMOD=0
	setup || fail "real setup failed: $(cat "$calls")"
	awg showconf awg0 >"$t/show" 2>&1 || fail "awg showconf failed: $(cat "$t/show")"
	for want in "ListenPort = 51820" "FwMark = 0x51" "Jc = 4" "Jmin = 40" "Jmax = 70" "S1 = 15" "S2 = 20" \
		"S3 = 25" "S4 = 12" "H1 = 100-200" "H2 = 300" "H3 = 400" "H4 = 500-600" "I1 = <b 0xc0ffee><r 16>" \
		"HeaderProtectionKey = $hpk" "ContentPaddingAddition = 8-16" "RekeyAfterTime = 120" \
		"RekeyTimeout = 5" "RejectAfterTime = 180" "KeepaliveTimeout = 10" "MaxHandshakeAttempts = 20" \
		"RandomTrailers = on" "DisableCookies = off" "PublicKey = $pub1" "PresharedKey = $psk1" \
		"AllowedIPs = 0.0.0.0/0, ::/0" "Endpoint = [2001:db8::1]:443" "PersistentKeepalive = 25" \
		"PublicKey = $pub3" "Endpoint = 192.0.2.7:51820" "AllowedIPs = 10.10.0.0/16"; do
		check "showconf: $want" grep -qxF "$want" "$t/show"
	done
	grep -qF "$pub2" "$t/show" && fail "the disabled peer was configured"
	check "mtu 1380 (is $(cat /sys/class/net/awg0/mtu))" [ "$(cat /sys/class/net/awg0/mtu)" = 1380 ]
	check "UAPI socket in /var/run/amneziawg" [ -S /var/run/amneziawg/awg0.sock ]
	check "host dependencies from awg show endpoints" grep -qxF "hostdep awg0 192.0.2.7 " "$calls"

	# renew with only a peer change: the same link and daemon, synced
	pid="$(pgrep -f "amneziawg-go awg0")"
	uci set network.peer2.disabled=0
	uci commit network
	setup || fail "renew with a peer change failed"
	awg showconf awg0 >"$t/show"
	check "renew added the enabled peer" grep -qxF "PublicKey = $pub2" "$t/show"
	check "renew kept the other peers" grep -qxF "PublicKey = $pub3" "$t/show"
	check "a peer-only renew kept the link (syncconf)" [ "$(pgrep -f "amneziawg-go awg0")" = "$pid" ]

	# renew with interface changes, one of them a removal: the link is created anew
	uci set network.awg0.awg_jc=5
	uci delete network.awg0.awg_i1
	uci delete network.awg0.awg_random_trailers
	uci commit network
	setup || fail "renew with interface changes failed"
	awg showconf awg0 >"$t/show"
	check "renew applied Jc = 5" grep -qxF "Jc = 5" "$t/show"
	check "renew removed I1" sh -c "! grep -q '^I1 ' '$t/show'"
	check "renew switched RandomTrailers off" grep -qxF "RandomTrailers = off" "$t/show"
	check "renew kept the peers" grep -qxF "PublicKey = $pub3" "$t/show"
	check "an interface change recreated the link" [ "$(pgrep -f "amneziawg-go awg0")" != "$pid" ]
	check "mtu still 1380 (is $(cat /sys/class/net/awg0/mtu))" [ "$(cat /sys/class/net/awg0/mtu)" = 1380 ]

	proto_amneziawg_teardown awg0
	i=0
	while pgrep -f "amneziawg-go awg0" >/dev/null 2>&1 && [ $i -lt 20 ]; do
		sleep 1
		i=$((i + 1))
	done
	check "teardown removed the link" [ ! -d /sys/class/net/awg0 ]
	check "amneziawg-go removed its socket" [ ! -e /var/run/amneziawg/awg0.sock ]
	check "teardown removed the state" [ ! -e /var/run/amneziawg-proto/awg0 ]
	if pgrep -f "amneziawg-go awg0" >/dev/null 2>&1; then
		fail "amneziawg-go still running after teardown"
	else
		pass "amneziawg-go exited after teardown"
	fi
fi

if [ "$fails" -ne 0 ]; then
	echo "check-openwrt-proto: $fails failure(s)"
	exit 1
fi
echo "check-openwrt-proto: all passed"
