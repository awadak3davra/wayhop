#!/bin/sh
# Copyright 2016-2017 Dan Luedtke <mail@danrl.com>
# Licensed to the public under the Apache License 2.0.
#
# Modified by the WayHop project for AmneziaWG 3.1: derived from OpenWrt's
# package/network/utils/wireguard-tools/files/wireguard.sh (openwrt-25.12). Changes: protocol
# "amneziawg" driven by awg, the AmneziaWG interface options (awg_*), peer sections
# "amneziawg_<interface>", a userspace amneziawg-go fallback when no kernel module is available,
# the configuration written line by line (no printf %b, no bash-only expansions) so it runs on
# busybox ash, and "setconf" for a new link ("syncconf" on a renew that changed only peers).
#
# shellcheck shell=dash
# shellcheck disable=SC2034,SC2317,SC2329
# SC2034/SC2317/SC2329: netifd reads the *_handler/available variables and calls the proto_* functions.

AWG=/usr/bin/awg
if [ ! -x "$AWG" ]; then
	logger -t "amneziawg" "error: missing amneziawg-tools (${AWG})"
	exit 0
fi

# Where amneziawg-go serves its UAPI sockets and awg looks for them. Exported as AWG_SOCKET_DIR, which
# WayHop's amneziawg-go and awg both read (their patches), so every awg call here - setconf on a new
# link, syncconf on a renew, show - finds the daemon whatever directory either was built with. It is
# also this package's own awg default (RUNSTATEDIR/amneziawg) and upstream amneziawg-go's.
AWG_GO_SOCKET_DIR=/var/run/amneziawg
export AWG_SOCKET_DIR="$AWG_GO_SOCKET_DIR"
# Per interface: a checksum of the interface settings last applied, to tell a renew that changed
# them from one that changed only peers.
AWG_PROTO_STATE=/var/run/amneziawg-proto

[ -n "$INCLUDE_ONLY" ] || {
	# shellcheck source=/dev/null
	. /lib/functions.sh
	# shellcheck source=/dev/null
	. ../netifd-proto.sh
	init_proto "$@"
}

proto_amneziawg_init_config() {
	renew_handler=1
	peer_detect=1

	proto_config_add_string "private_key"
	proto_config_add_int "listen_port"
	proto_config_add_int "mtu"
	proto_config_add_string "fwmark"
	proto_config_add_string "addresses"
	proto_config_add_string "awg_jc"
	proto_config_add_string "awg_jmin"
	proto_config_add_string "awg_jmax"
	proto_config_add_string "awg_s1"
	proto_config_add_string "awg_s2"
	proto_config_add_string "awg_s3"
	proto_config_add_string "awg_s4"
	proto_config_add_string "awg_h1"
	proto_config_add_string "awg_h2"
	proto_config_add_string "awg_h3"
	proto_config_add_string "awg_h4"
	proto_config_add_string "awg_i1"
	proto_config_add_string "awg_i2"
	proto_config_add_string "awg_i3"
	proto_config_add_string "awg_i4"
	proto_config_add_string "awg_i5"
	proto_config_add_string "awg_header_protection_key"
	proto_config_add_string "awg_content_padding_addition"
	proto_config_add_string "awg_rekey_after_time"
	proto_config_add_string "awg_rekey_timeout"
	proto_config_add_string "awg_reject_after_time"
	proto_config_add_string "awg_keepalive_timeout"
	proto_config_add_string "awg_max_handshake_attempts"
	proto_config_add_boolean "awg_random_trailers"
	proto_config_add_boolean "awg_disable_cookies"

	available=1
	no_proto_task=1
}

ensure_key_is_generated() {
	local private_key
	private_key="$(uci -q get network."$1".private_key)"

	if [ "$private_key" = "generate" ] || [ -z "$private_key" ]; then
		private_key="$("$AWG" genkey)"
		uci -q set network."$1".private_key="$private_key" && \
			uci -q commit network
	fi
}

# Create the AmneziaWG link: the kernel module first (loading it if it is installed but not loaded),
# then userspace amneziawg-go. amneziawg-go daemonises itself once the TUN device and its UAPI
# socket exist, so awg can configure it as soon as it returns. LOG_LEVEL is cleared so the daemon
# does not keep the captured stderr open.
amneziawg_add_link() {
	local iface="$1" out

	ip link add dev "$iface" type amneziawg >/dev/null 2>&1 && return 0
	if [ ! -d /sys/module/amneziawg ] && modprobe amneziawg >/dev/null 2>&1; then
		ip link add dev "$iface" type amneziawg >/dev/null 2>&1 && return 0
	fi

	if command -v amneziawg-go >/dev/null 2>&1; then
		mkdir -p "$AWG_GO_SOCKET_DIR"
		if out="$(LOG_LEVEL='' AWG_SOCKET_DIR="$AWG_GO_SOCKET_DIR" amneziawg-go "$iface" 2>&1)"; then
			logger -t "amneziawg" "${iface}: no AmneziaWG kernel module, using userspace amneziawg-go"
			return 0
		fi
		logger -t "amneziawg" "error: ${iface}: amneziawg-go failed: ${out}"
		return 1
	fi

	logger -t "amneziawg" "error: ${iface}: neither the AmneziaWG kernel module (kmod-amneziawg) nor amneziawg-go is available"
	return 1
}

# Delete the link to create it anew. Deleting it also ends a userspace amneziawg-go (it exits when
# its TUN device goes away and removes its socket); wait for that, so the new one can listen.
amneziawg_del_link() {
	local i=0

	ip link del dev "$1" >/dev/null 2>&1
	while [ -S "${AWG_GO_SOCKET_DIR}/$1.sock" ] && [ "$i" -lt 5 ]; do
		sleep 1
		i=$((i + 1))
	done
	rm -f "${AWG_PROTO_STATE}/$1"
}

proto_amneziawg_setup() {
	local config="$1"
	local private_key listen_port mtu fwmark addresses ip6prefix nohostroute tunlink
	local nl params params_sum awg_cmd awg_config peer_config address prefix peer_key

	nl='
'
	ensure_key_is_generated "${config}"

	config_load network
	config_get private_key "${config}" "private_key"
	config_get listen_port "${config}" "listen_port"
	config_get addresses "${config}" "addresses"
	config_get mtu "${config}" "mtu"
	config_get fwmark "${config}" "fwmark"
	config_get ip6prefix "${config}" "ip6prefix"
	config_get_bool nohostroute "${config}" "nohostroute" 0
	config_get tunlink "${config}" "tunlink"

	# The interface settings besides the private key, in awg's syntax. Every UCI option name is
	# spelled out (WayHop reads this file to learn which options the handler supports). Values go
	# through unchanged: H1-H4, the padding and the timers accept "x-y" ranges, I1-I5 keep their
	# inner spaces; awg validates them.
	params=""
	[ -n "${listen_port}" ] && params="${params}ListenPort=${listen_port}${nl}"
	[ -n "${fwmark}" ] && params="${params}FwMark=${fwmark}${nl}"
	amneziawg_param() {
		local value
		config_get value "${config}" "$1"
		[ -z "${value}" ] || params="${params}$2=${value}${nl}"
	}
	# Switches are written only when on; off is the default.
	amneziawg_switch() {
		local value
		config_get_bool value "${config}" "$1" 0
		[ "${value}" = 0 ] || params="${params}$2=1${nl}"
	}
	amneziawg_param awg_jc Jc
	amneziawg_param awg_jmin Jmin
	amneziawg_param awg_jmax Jmax
	amneziawg_param awg_s1 S1
	amneziawg_param awg_s2 S2
	amneziawg_param awg_s3 S3
	amneziawg_param awg_s4 S4
	amneziawg_param awg_h1 H1
	amneziawg_param awg_h2 H2
	amneziawg_param awg_h3 H3
	amneziawg_param awg_h4 H4
	amneziawg_param awg_i1 I1
	amneziawg_param awg_i2 I2
	amneziawg_param awg_i3 I3
	amneziawg_param awg_i4 I4
	amneziawg_param awg_i5 I5
	amneziawg_param awg_header_protection_key HeaderProtectionKey
	amneziawg_param awg_content_padding_addition ContentPaddingAddition
	amneziawg_param awg_rekey_after_time RekeyAfterTime
	amneziawg_param awg_rekey_timeout RekeyTimeout
	amneziawg_param awg_reject_after_time RejectAfterTime
	amneziawg_param awg_keepalive_timeout KeepaliveTimeout
	amneziawg_param awg_max_handshake_attempts MaxHandshakeAttempts
	amneziawg_switch awg_random_trailers RandomTrailers
	amneziawg_switch awg_disable_cookies DisableCookies

	# A new link gets the whole configuration with setconf. On renew, when only the private key or
	# the peers changed, the existing link is synced (syncconf keeps the sessions of unchanged
	# peers); when the interface settings changed it is created anew, because neither setconf nor
	# syncconf unsets an option that was removed (a switched-off RandomTrailers, a dropped I1).
	params_sum="$(printf '%s' "${params}" | md5sum)"
	params_sum="${params_sum%% *}"
	awg_cmd=setconf
	if [ -d "/sys/class/net/${config}" ]; then
		if [ "$(cat "${AWG_PROTO_STATE}/${config}" 2>/dev/null)" = "${params_sum}" ]; then
			awg_cmd=syncconf
		else
			amneziawg_del_link "${config}"
		fi
	fi
	if [ "${awg_cmd}" = setconf ] && ! amneziawg_add_link "${config}"; then
		proto_notify_error "${config}" "NO_AMNEZIAWG"
		proto_block_restart "${config}"
		exit 1
	fi

	proto_init_update "${config}" 1

	awg_config="[Interface]${nl}PrivateKey=${private_key}${nl}${params}"

	peer_config=""
	proto_amneziawg_setup_peer() {
		local section="$1"
		local disabled route_allowed_ips public_key preshared_key endpoint_host endpoint_port
		local allowed_ips persistent_keepalive allowed_ip

		config_get_bool disabled "${section}" "disabled" 0
		[ "${disabled}" = 1 ] && return 0
		config_get public_key "${section}" "public_key"
		if [ -z "${public_key}" ]; then
			logger -t "amneziawg" "${config}: peer ${section} has no public_key, skipped"
			return 0
		fi
		config_get_bool route_allowed_ips "${section}" "route_allowed_ips" 0
		config_get preshared_key "${section}" "preshared_key"
		config_get endpoint_host "${section}" "endpoint_host"
		config_get endpoint_port "${section}" "endpoint_port"
		config_get allowed_ips "${section}" "allowed_ips"
		config_get persistent_keepalive "${section}" "persistent_keepalive"

		peer_config="${peer_config}${nl}[Peer]${nl}PublicKey=${public_key}${nl}"
		[ -n "${preshared_key}" ] && peer_config="${peer_config}PresharedKey=${preshared_key}${nl}"
		if [ -n "${endpoint_host}" ]; then
			case "${endpoint_host}" in
				\[*) ;;
				*:*) endpoint_host="[${endpoint_host}]" ;;
			esac
			peer_config="${peer_config}Endpoint=${endpoint_host}:${endpoint_port:-51820}${nl}"
		fi
		for allowed_ip in ${allowed_ips}; do
			peer_config="${peer_config}AllowedIPs=${allowed_ip}${nl}"
		done
		[ -n "${persistent_keepalive}" ] && \
			peer_config="${peer_config}PersistentKeepalive=${persistent_keepalive}${nl}"

		[ "${route_allowed_ips}" = 1 ] || return 0
		for allowed_ip in ${allowed_ips}; do
			case "${allowed_ip}" in
				*:*/*) proto_add_ipv6_route "${allowed_ip%%/*}" "${allowed_ip##*/}" ;;
				*.*/*) proto_add_ipv4_route "${allowed_ip%%/*}" "${allowed_ip##*/}" ;;
				*:*) proto_add_ipv6_route "${allowed_ip%%/*}" "128" ;;
				*.*) proto_add_ipv4_route "${allowed_ip%%/*}" "32" ;;
			esac
		done
	}
	config_foreach proto_amneziawg_setup_peer "amneziawg_${config}"

	# The configuration holds the private key: pass it on stdin, never in a file or argv.
	if ! printf '%s' "${awg_config}${peer_config}" | "$AWG" "${awg_cmd}" "${config}" /dev/stdin; then
		logger -t "amneziawg" "error: ${config}: awg ${awg_cmd} failed"
		echo "Could not apply the AmneziaWG configuration"
		rm -f "${AWG_PROTO_STATE}/${config}"
		sleep 5
		proto_setup_failed "${config}"
		exit 1
	fi
	mkdir -p "${AWG_PROTO_STATE}"
	echo "${params_sum}" >"${AWG_PROTO_STATE}/${config}"

	# After the configuration, not before: a just started amneziawg-go sets the default MTU on its
	# TUN device once it is running, and it answers awg only after that.
	[ -n "${mtu}" ] && ip link set mtu "${mtu}" dev "${config}"

	for address in ${addresses}; do
		case "${address}" in
			*:*/*) proto_add_ipv6_address "${address%%/*}" "${address##*/}" ;;
			*.*/*) proto_add_ipv4_address "${address%%/*}" "${address##*/}" ;;
			*:*) proto_add_ipv6_address "${address%%/*}" "128" ;;
			*.*) proto_add_ipv4_address "${address%%/*}" "32" ;;
		esac
	done

	for prefix in ${ip6prefix}; do
		proto_add_ipv6_prefix "${prefix}"
	done

	# Keep the route to each peer's endpoint off the tunnel ("[v6]:port" or "v4:port"; "(none)"
	# when a peer has no endpoint).
	if [ "${nohostroute}" != 1 ]; then
		"$AWG" show "${config}" endpoints | while read -r peer_key address; do
			case "${address}" in
				\[*\]:*) address="${address%]:*}"; address="${address#\[}" ;;
				*.*:*) address="${address%:*}" ;;
				*) continue ;;
			esac
			proto_add_host_dependency "${config}" "${address}" "${tunlink}"
		done
	fi

	proto_send_update "${config}"
}

proto_amneziawg_renew() {
	local interface="$1"
	proto_amneziawg_setup "$interface"
}

proto_amneziawg_teardown() {
	local config="$1"
	ip link del dev "${config}" >/dev/null 2>&1
	rm -f "${AWG_PROTO_STATE}/${config}"
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol amneziawg
}
