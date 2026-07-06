// Package initserver generates an idempotent installer script that stands up a
// light VPN server (AmneziaWG and/or sing-box VLESS-Reality) on a fresh
// Debian/Ubuntu VPS, and (optionally, on-device) runs it over SSH and captures
// the client config the script prints. Credentials are never stored or logged.
package initserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// provisionOutputCap bounds how much remote SSH output Provision buffers in RAM. The
// output is consumed only for marker extraction (ExtractTagged) plus a short diagnostic
// tail, so a few MiB is ample — and a remote that spews hundreds of MB (a runaway apt/curl
// step, or an adversarial host the user was induced to add) can't OOM the memory-
// constrained router daemon.
const provisionOutputCap = 4 << 20

// capWriter accumulates up to max bytes and silently discards the rest, always reporting a
// full write so the child process is never blocked or errored by a short write. Safe for
// the concurrent stdout+stderr copies os/exec may perform.
type capWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := len(p)
	if n := c.max - c.buf.Len(); n > 0 {
		if len(p) > n {
			p = p[:n]
		}
		c.buf.Write(p)
	}
	return total, nil // always report the full write so the child process never blocks
}

func (c *capWriter) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// Protocol ids the UI sends.
const (
	ProtoAmneziaWG   = "amneziawg"
	ProtoWireGuard   = "wireguard"
	ProtoReality     = "vless-reality"
	ProtoVMess       = "vmess"
	ProtoTrojan      = "trojan"
	ProtoShadowsocks = "shadowsocks"
	ProtoHysteria2   = "hysteria2"
	ProtoTUIC        = "tuic"
)

const scriptHeader = `#!/bin/sh
# WayHop — server provisioning (idempotent). Run as root on Debian/Ubuntu.
set -e
# Born-secure: set a restrictive umask BEFORE any fragment writes a secret, so every
# key/cert/config this script creates (WireGuard keys, AmneziaWG keys, sing-box Reality
# identity, self-signed TLS, client configs) is owner-only from creation — never briefly
# world-readable in the window between write and a per-file chmod.
umask 077
log() { echo "[wayhop-init] $*"; }
# Guard: WireGuard/AmneziaWG need kernel modules — OpenVZ/LXC containers can't load
# them, so fail early with a clear message instead of a confusing runtime error.
VIRT="$(systemd-detect-virt 2>/dev/null || echo unknown)"
case "$VIRT" in openvz|lxc) log "WARNING: virtualization '$VIRT' may not support kernel WireGuard — AmneziaWG could fail";; esac
PUBLIC_IP="${WR_PUBLIC_IP:-$(curl -fsS https://api.ipify.org 2>/dev/null || ip -4 route get 1 2>/dev/null | awk 'NR==1{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')}"
WANIF="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
log "public ip: ${PUBLIC_IP:-unknown}, wan iface: ${WANIF:-eth0}, virt: ${VIRT}"
export DEBIAN_FRONTEND=noninteractive
# Performance tuning (idempotent): BBR + fair queueing, and larger UDP buffers so
# QUIC-based protocols aren't receive-starved. Best-effort; failures are non-fatal.
cat > /etc/sysctl.d/99-wayhop.conf <<'SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
SYSCTL
sysctl --system >/dev/null 2>&1 || true
`

const scriptAmneziaWG = `
# ---- AmneziaWG ----
log "installing AmneziaWG..."
if ! command -v awg >/dev/null 2>&1; then
  apt-get update -y || true
  apt-get install -y software-properties-common curl iptables || true
  add-apt-repository -y ppa:amnezia/ppa || log "PPA add failed (blocked in RU?) — AWG may need a source build"
  apt-get update -y || true
  apt-get install -y amneziawg amneziawg-tools || apt-get install -y amneziawg-dkms amneziawg-tools || { log "amneziawg install failed"; exit 1; }
fi
mkdir -p /etc/amnezia/amneziawg && cd /etc/amnezia/amneziawg
[ -f server.key ] || awg genkey > server.key
awg pubkey < server.key > server.pub
[ -f client.key ] || awg genkey > client.key
awg pubkey < client.key > client.pub
SK=$(cat server.key); SP=$(cat server.pub); CK=$(cat client.key); CP=$(cat client.pub)
JC=4; JMIN=40; JMAX=70; S1=0; S2=0
# H1-H4 are AmneziaWG's header-magic values. They MUST be randomized (not the
# WireGuard defaults 1/2/3/4) or the handshake message types stay unobfuscated and
# DPI fingerprints it as plain WireGuard — defeating AmneziaWG's purpose. Persist
# them (like the keys) so a re-run reuses the same values and existing clients keep working.
HF=/etc/amnezia/amneziawg/wr-hparams
[ -f "$HF" ] || awk 'BEGIN{srand();for(i=1;i<=4;i++)printf "H%d=%d\n",i,int(rand()*2000000000)+5}' > "$HF"
. "$HF"
cat > awg0.conf <<EOF
[Interface]
PrivateKey = $SK
Address = 10.13.13.1/24
ListenPort = 51820
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
[Peer]
PublicKey = $CP
AllowedIPs = 10.13.13.2/32
EOF
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
iptables -t nat -C POSTROUTING -s 10.13.13.0/24 -o "${WANIF:-eth0}" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.13.13.0/24 -o "${WANIF:-eth0}" -j MASQUERADE
awg-quick down awg0 2>/dev/null || true
awg-quick up awg0 || { log "awg-quick up failed (install issue?)"; exit 1; }
systemctl enable awg-quick@awg0 2>/dev/null || true
AWG_CONF="[Interface]
PrivateKey = $CK
Address = 10.13.13.2/32
DNS = 1.1.1.1
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
[Peer]
PublicKey = $SP
Endpoint = $PUBLIC_IP:51820
AllowedIPs = 0.0.0.0/0"
echo "WR_PROTO=amneziawg"
echo "WR_CLIENT_CONFIG_B64=$(printf '%s' "$AWG_CONF" | base64 -w0 2>/dev/null || printf '%s' "$AWG_CONF" | base64 | tr -d '\n')"
`

// scriptWireGuard provisions a STANDARD (interoperable) WireGuard server. It mirrors
// scriptAmneziaWG's structure exactly — same key-persistence guards, same MASQUERADE +
// ip_forward setup, same client-.conf emission via the WR_CLIENT_CONFIG_B64 marker — but
// uses the upstream wireguard-tools (`wg`/`wg-quick`) with NO obfuscation parameters, so
// any stock WireGuard client (mobile apps, in-kernel wg, etc.) imports it directly. It is
// NOT redundant with AmneziaWG: it trades DPI-resistance for zero obfuscation overhead and
// universal client compatibility. A distinct UDP port (51821) and subnet (10.14.14.0/24)
// are used so a mixed AmneziaWG (:51820, 10.13.13.0/24) + WireGuard provision can coexist.
const scriptWireGuard = `
# ---- WireGuard ----
log "installing WireGuard..."
if ! command -v wg >/dev/null 2>&1; then
  apt-get update -y || true
  apt-get install -y wireguard wireguard-tools iptables || apt-get install -y wireguard-tools iptables || { log "wireguard install failed"; exit 1; }
fi
mkdir -p /etc/wireguard && cd /etc/wireguard
# Persist the server + client keypairs so a re-run REUSES them (the [ -f ] || guard,
# mirroring the AmneziaWG/Reality guards). Regenerating on every provision would
# silently invalidate every previously-issued client config.
[ -f wg-server.key ] || wg genkey > wg-server.key
wg pubkey < wg-server.key > wg-server.pub
[ -f wg-client.key ] || wg genkey > wg-client.key
wg pubkey < wg-client.key > wg-client.pub
chmod 600 wg-server.key wg-client.key 2>/dev/null || true
SK=$(cat wg-server.key); SP=$(cat wg-server.pub); CK=$(cat wg-client.key); CP=$(cat wg-client.pub)
cat > wg0.conf <<EOF
[Interface]
PrivateKey = $SK
Address = 10.14.14.1/24
ListenPort = 51821
[Peer]
PublicKey = $CP
AllowedIPs = 10.14.14.2/32
EOF
chmod 600 wg0.conf 2>/dev/null || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
iptables -t nat -C POSTROUTING -s 10.14.14.0/24 -o "${WANIF:-eth0}" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.14.14.0/24 -o "${WANIF:-eth0}" -j MASQUERADE
# WireGuard is UDP — open the port if a firewall is active (best-effort).
iptables -C INPUT -p udp --dport 51821 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 51821 -j ACCEPT 2>/dev/null || true
wg-quick down wg0 2>/dev/null || true
wg-quick up wg0 || { log "wg-quick up failed (install issue / no kernel module?)"; exit 1; }
systemctl enable wg-quick@wg0 2>/dev/null || true
WG_CONF="[Interface]
PrivateKey = $CK
Address = 10.14.14.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = $SP
Endpoint = $PUBLIC_IP:51821
AllowedIPs = 0.0.0.0/0"
echo "WR_PROTO=wireguard"
echo "WR_CLIENT_CONFIG_B64=$(printf '%s' "$WG_CONF" | base64 -w0 2>/dev/null || printf '%s' "$WG_CONF" | base64 | tr -d '\n')"
`

const scriptReality = `
# ---- sing-box VLESS-Reality ----
log "installing sing-box (VLESS-Reality)..."
if ! command -v sing-box >/dev/null 2>&1; then
  apt-get install -y curl tar >/dev/null 2>&1 || true
  A=$(dpkg --print-architecture 2>/dev/null || echo amd64)
  case "$A" in amd64) SB=amd64;; arm64) SB=arm64;; armhf) SB=armv7;; *) SB=amd64;; esac
  VER=$(curl -fsS https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | grep -o '"tag_name":[^,]*' | head -1 | sed 's/.*"v\{0,1\}\([0-9][^"]*\)".*/\1/')
  # GitHub API blocked from this server? fall back to the releases atom feed (proxiable by
  # wr_fetch's mirror chain), taking the newest STABLE tag (skip -alpha/-beta/-rc suffixes).
  [ -n "$VER" ] || VER=$(wr_fetch https://github.com/SagerNet/sing-box/releases.atom 2>/dev/null | grep -o 'releases/tag/v[0-9][^"<]*' | sed 's@releases/tag/v@@' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
  [ -n "$VER" ] || { log "failed to resolve sing-box version (GitHub API + mirror both failed)"; exit 1; }
  wr_fetch "https://github.com/SagerNet/sing-box/releases/download/v${VER}/sing-box-${VER}-linux-${SB}.tar.gz" /tmp/sb.tgz || { log "failed to download sing-box ${VER}"; exit 1; }
  tar -xzf /tmp/sb.tgz -C /tmp || { log "failed to extract sing-box archive"; exit 1; }
  install -m755 "/tmp/sing-box-${VER}-linux-${SB}/sing-box" /usr/local/bin/sing-box
  rm -rf /tmp/sb.tgz "/tmp/sing-box-${VER}-linux-${SB}" 2>/dev/null || true
fi
mkdir -p /etc/sing-box
# Persist the Reality identity so a re-run REUSES it. Regenerating the uuid /
# keypair / short_id on every provision would silently invalidate every
# previously-issued client. Mirrors the AmneziaWG key guard above.
SBD=/etc/sing-box
[ -f "$SBD/wr-reality-uuid" ] || sing-box generate uuid > "$SBD/wr-reality-uuid"
[ -f "$SBD/wr-reality.key" ] || sing-box generate reality-keypair > "$SBD/wr-reality.key"
[ -f "$SBD/wr-reality-sid" ] || sing-box generate rand --hex 8 > "$SBD/wr-reality-sid"
chmod 600 "$SBD/wr-reality-uuid" "$SBD/wr-reality.key" "$SBD/wr-reality-sid" 2>/dev/null || true
UUID=$(cat "$SBD/wr-reality-uuid")
PRIV=$(awk '/PrivateKey/{print $2}' "$SBD/wr-reality.key")
PUB=$(awk '/PublicKey/{print $2}' "$SBD/wr-reality.key")
SID=$(cat "$SBD/wr-reality-sid")
SNI=www.microsoft.com
cat > /etc/sing-box/config.json <<EOF
{"inbounds":[{"type":"vless","listen":"::","listen_port":443,"users":[{"uuid":"$UUID","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"$SNI","reality":{"enabled":true,"handshake":{"server":"$SNI","server_port":443},"private_key":"$PRIV","short_id":["$SID"]}}}],"outbounds":[{"type":"direct"}]}
EOF
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box
After=network.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload 2>/dev/null || true
systemctl enable --now sing-box 2>/dev/null || true
echo "WR_PROTO=vless-reality"
echo "WR_CLIENT_CONFIG=vless://$UUID@$PUBLIC_IP:443?security=reality&sni=$SNI&fp=chrome&pbk=$PUB&sid=$SID&flow=xtls-rprx-vision&type=tcp#wayhop-server"
`

// scriptSingboxInstall installs sing-box (idempotent) the same way scriptReality
// does — kept as a standalone fragment so the additional sing-box-backed protocols
// (VMess / Trojan / Shadowsocks / Hysteria2 / TUIC) reuse the exact install logic
// without duplicating it. It is a no-op when sing-box is already present (Reality
// may have installed it earlier in a multi-protocol run), so prepending it to each
// fragment is safe and re-runnable.
const scriptSingboxInstall = `
if ! command -v sing-box >/dev/null 2>&1; then
  apt-get install -y curl tar >/dev/null 2>&1 || true
  A=$(dpkg --print-architecture 2>/dev/null || echo amd64)
  case "$A" in amd64) SB=amd64;; arm64) SB=arm64;; armhf) SB=armv7;; *) SB=amd64;; esac
  VER=$(curl -fsS https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | grep -o '"tag_name":[^,]*' | head -1 | sed 's/.*"v\{0,1\}\([0-9][^"]*\)".*/\1/')
  # GitHub API blocked from this server? fall back to the releases atom feed (proxiable by
  # wr_fetch's mirror chain), taking the newest STABLE tag (skip -alpha/-beta/-rc suffixes).
  [ -n "$VER" ] || VER=$(wr_fetch https://github.com/SagerNet/sing-box/releases.atom 2>/dev/null | grep -o 'releases/tag/v[0-9][^"<]*' | sed 's@releases/tag/v@@' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
  [ -n "$VER" ] || { log "failed to resolve sing-box version (GitHub API + mirror both failed)"; exit 1; }
  wr_fetch "https://github.com/SagerNet/sing-box/releases/download/v${VER}/sing-box-${VER}-linux-${SB}.tar.gz" /tmp/sb.tgz || { log "failed to download sing-box ${VER}"; exit 1; }
  tar -xzf /tmp/sb.tgz -C /tmp || { log "failed to extract sing-box archive"; exit 1; }
  install -m755 "/tmp/sing-box-${VER}-linux-${SB}/sing-box" /usr/local/bin/sing-box
  rm -rf /tmp/sb.tgz "/tmp/sing-box-${VER}-linux-${SB}" 2>/dev/null || true
fi
mkdir -p /etc/sing-box
`

// scriptSelfSignedTLS generates (once, then reuses) a self-signed certificate for
// the TLS-bearing sing-box inbounds (VMess-WS-TLS, Trojan, Hysteria2, TUIC). The
// SNI baked into the cert is wayhop.local; because it is self-signed the client
// share-links emitted below carry insecure=1 (skip-cert-verify), which the importer
// honours (insecure / allowInsecure / allow_insecure). openssl is installed if
// absent. The key/cert are persisted so a re-run reuses them (no client churn).
const scriptSelfSignedTLS = `
command -v openssl >/dev/null 2>&1 || apt-get install -y openssl >/dev/null 2>&1 || true
SBD=/etc/sing-box
WR_TLS_SNI=wayhop.local
if [ ! -f "$SBD/wr-tls.crt" ] || [ ! -f "$SBD/wr-tls.key" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$SBD/wr-tls.key" -out "$SBD/wr-tls.crt" \
    -subj "/CN=$WR_TLS_SNI" -addext "subjectAltName=DNS:$WR_TLS_SNI" >/dev/null 2>&1 \
  || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$SBD/wr-tls.key" -out "$SBD/wr-tls.crt" -subj "/CN=$WR_TLS_SNI" >/dev/null 2>&1 \
  || { log "openssl TLS certificate generation failed; install openssl and re-run"; exit 1; }
  chmod 600 "$SBD/wr-tls.key" 2>/dev/null || true
fi
`

// singboxServiceUnit installs/refreshes the sing-box systemd unit and (re)starts it.
// Each fragment writes its own config drop-in into /etc/sing-box/conf.d and the unit
// runs sing-box with -C (config directory) so multiple protocols coexist in one
// process. It ALSO passes scriptReality's standalone /etc/sing-box/config.json via
// -c when that file exists, so a mixed Reality + (VMess/Trojan/…) provision keeps
// both inbounds live (Reality is untouched and still writes config.json + its own
// unit; whichever fragment runs last installs this superset unit). Mirrors
// scriptReality's unit, generalised to the conf.d directory.
const singboxServiceUnit = `
mkdir -p /etc/sing-box/conf.d
if [ -f /etc/sing-box/config.json ]; then
  SB_EXEC="/usr/local/bin/sing-box run -c /etc/sing-box/config.json -C /etc/sing-box/conf.d"
else
  SB_EXEC="/usr/local/bin/sing-box run -C /etc/sing-box/conf.d"
fi
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box
After=network.target
[Service]
ExecStart=$SB_EXEC
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload 2>/dev/null || true
systemctl enable --now sing-box 2>/dev/null || true
systemctl restart sing-box 2>/dev/null || true
`

// scriptVMess provisions a sing-box VMess inbound over WebSocket+TLS (self-signed).
// VMess identity (uuid) is generated once and persisted. The client link is the
// standard vmess://base64(json) form the importer's parseVMess reads (add/port/id/
// net=ws/path/tls=tls/sni/allowInsecure).
const scriptVMess = `
# ---- sing-box VMess (WebSocket + TLS) ----
log "installing sing-box (VMess)..."
` + scriptSingboxInstall + scriptSelfSignedTLS + `
[ -f "$SBD/wr-vmess-uuid" ] || sing-box generate uuid > "$SBD/wr-vmess-uuid"
chmod 600 "$SBD/wr-vmess-uuid" 2>/dev/null || true
VMUUID=$(cat "$SBD/wr-vmess-uuid")
VMPATH=/wayhop
mkdir -p /etc/sing-box/conf.d
cat > /etc/sing-box/conf.d/wr-vmess.json <<EOF
{"inbounds":[{"type":"vmess","tag":"wr-vmess-in","listen":"::","listen_port":8443,"users":[{"uuid":"$VMUUID","alterId":0}],"transport":{"type":"ws","path":"$VMPATH"},"tls":{"enabled":true,"server_name":"$WR_TLS_SNI","certificate_path":"$SBD/wr-tls.crt","key_path":"$SBD/wr-tls.key"}}],"outbounds":[{"type":"direct","tag":"wr-vmess-direct"}]}
EOF
` + singboxServiceUnit + `
# vmess client config = base64(json). add/port/id/net/path/tls/sni/allowInsecure
# are exactly the keys parseVMess reads. allowInsecure=1 because the cert is self-signed.
VMJSON=$(printf '{"v":"2","ps":"wayhop-vmess","add":"%s","port":"8443","id":"%s","aid":"0","scy":"auto","net":"ws","type":"none","host":"%s","path":"%s","tls":"tls","sni":"%s","allowInsecure":"1"}' "$PUBLIC_IP" "$VMUUID" "$WR_TLS_SNI" "$VMPATH" "$WR_TLS_SNI")
echo "WR_PROTO=vmess"
echo "WR_CLIENT_CONFIG=vmess://$(printf '%s' "$VMJSON" | base64 -w0 2>/dev/null || printf '%s' "$VMJSON" | base64 | tr -d '\n')"
`

// scriptTrojan provisions a sing-box Trojan inbound over TLS (self-signed). The
// password is generated once and persisted. The client link is the standard
// trojan://password@host:port?sni=...&insecure=1#name form parseTrojan reads.
const scriptTrojan = `
# ---- sing-box Trojan (TLS) ----
log "installing sing-box (Trojan)..."
` + scriptSingboxInstall + scriptSelfSignedTLS + `
[ -f "$SBD/wr-trojan-pass" ] || sing-box generate rand --base64 18 > "$SBD/wr-trojan-pass"
chmod 600 "$SBD/wr-trojan-pass" 2>/dev/null || true
TJPASS=$(cat "$SBD/wr-trojan-pass")
mkdir -p /etc/sing-box/conf.d
cat > /etc/sing-box/conf.d/wr-trojan.json <<EOF
{"inbounds":[{"type":"trojan","tag":"wr-trojan-in","listen":"::","listen_port":8444,"users":[{"password":"$TJPASS"}],"tls":{"enabled":true,"server_name":"$WR_TLS_SNI","certificate_path":"$SBD/wr-tls.crt","key_path":"$SBD/wr-tls.key"}}],"outbounds":[{"type":"direct","tag":"wr-trojan-direct"}]}
EOF
` + singboxServiceUnit + `
# trojan://<urlencoded-password>@host:port?security=tls&sni=...&insecure=1#name.
# insecure=1 (skip-cert-verify) because the cert is self-signed; parseTrojan reads it.
TJENC=$(printf '%s' "$TJPASS" | sed 's/+/%2B/g;s/\//%2F/g;s/=/%3D/g')
echo "WR_PROTO=trojan"
echo "WR_CLIENT_CONFIG=trojan://$TJENC@$PUBLIC_IP:8444?security=tls&sni=$WR_TLS_SNI&insecure=1&type=tcp#wayhop-trojan"
`

// scriptShadowsocks provisions a sing-box Shadowsocks inbound (2022-blake3-
// aes-256-gcm). The PSK is generated once (32 random bytes, base64) and persisted.
// The client link is the SIP002 ss://base64(method:password)@host:port#name form
// parseShadowsocks reads. No TLS (Shadowsocks is its own AEAD layer).
const scriptShadowsocks = `
# ---- sing-box Shadowsocks (2022-blake3-aes-256-gcm) ----
log "installing sing-box (Shadowsocks)..."
` + scriptSingboxInstall + `
SBD=/etc/sing-box
SSMETHOD=2022-blake3-aes-256-gcm
# SS-2022 requires a 32-byte base64 PSK for aes-256-gcm; generate once + persist.
[ -f "$SBD/wr-ss-psk" ] || sing-box generate rand --base64 32 > "$SBD/wr-ss-psk"
chmod 600 "$SBD/wr-ss-psk" 2>/dev/null || true
SSPSK=$(cat "$SBD/wr-ss-psk")
mkdir -p /etc/sing-box/conf.d
cat > /etc/sing-box/conf.d/wr-shadowsocks.json <<EOF
{"inbounds":[{"type":"shadowsocks","tag":"wr-ss-in","listen":"::","listen_port":8388,"method":"$SSMETHOD","password":"$SSPSK"}],"outbounds":[{"type":"direct","tag":"wr-ss-direct"}]}
EOF
` + singboxServiceUnit + `
# SIP002: ss://base64(method:password)@host:port#name. parseShadowsocks splits on the
# last '@' (it does NOT url.Parse ss://), so std-base64 '+/=' in the userinfo survive;
# it then base64-decodes method:password (decodeB64 accepts std AND url alphabets).
SSUI=$(printf '%s:%s' "$SSMETHOD" "$SSPSK" | base64 -w0 2>/dev/null || printf '%s:%s' "$SSMETHOD" "$SSPSK" | base64 | tr -d '\n')
echo "WR_PROTO=shadowsocks"
echo "WR_CLIENT_CONFIG=ss://$SSUI@$PUBLIC_IP:8388#wayhop-ss"
`

// scriptHysteria2 provisions a sing-box Hysteria2 inbound (QUIC + TLS, self-signed) with
// Salamander obfuscation ON by default — the QUIC handshake is camouflaged as random UDP so
// DPI can't fingerprint Hysteria2, the camouflage that matters in a censored region. The
// password and the obfs password are each generated once and persisted. The client link is
// hysteria2://password@host:port?sni=...&insecure=1&obfs=salamander&obfs-password=...#name,
// which parseHysteria2 + the generator already round-trip (model obfs / obfs_password).
const scriptHysteria2 = `
# ---- sing-box Hysteria2 (QUIC + TLS) ----
log "installing sing-box (Hysteria2)..."
` + scriptSingboxInstall + scriptSelfSignedTLS + `
[ -f "$SBD/wr-hy2-pass" ] || sing-box generate rand --base64 18 > "$SBD/wr-hy2-pass"
# Salamander obfs password (persisted, like the auth password) — both ends share it; WR bakes
# it into the client link below so an imported endpoint matches the server automatically.
[ -f "$SBD/wr-hy2-obfs" ] || sing-box generate rand --base64 18 > "$SBD/wr-hy2-obfs"
chmod 600 "$SBD/wr-hy2-pass" "$SBD/wr-hy2-obfs" 2>/dev/null || true
HY2PASS=$(cat "$SBD/wr-hy2-pass")
HY2OBFS=$(cat "$SBD/wr-hy2-obfs")
mkdir -p /etc/sing-box/conf.d
cat > /etc/sing-box/conf.d/wr-hysteria2.json <<EOF
{"inbounds":[{"type":"hysteria2","tag":"wr-hy2-in","listen":"::","listen_port":8445,"users":[{"password":"$HY2PASS"}],"obfs":{"type":"salamander","password":"$HY2OBFS"},"tls":{"enabled":true,"server_name":"$WR_TLS_SNI","alpn":["h3"],"certificate_path":"$SBD/wr-tls.crt","key_path":"$SBD/wr-tls.key"}}],"outbounds":[{"type":"direct","tag":"wr-hy2-direct"}]}
EOF
# Hysteria2 is UDP/QUIC — open the port if a firewall is active (best-effort).
iptables -C INPUT -p udp --dport 8445 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 8445 -j ACCEPT 2>/dev/null || true
` + singboxServiceUnit + `
# hysteria2://<urlencoded-password>@host:port?sni=...&insecure=1#name (parseHysteria2).
HY2ENC=$(printf '%s' "$HY2PASS" | sed 's/+/%2B/g;s/\//%2F/g;s/=/%3D/g')
HY2OBFSENC=$(printf '%s' "$HY2OBFS" | sed 's/+/%2B/g;s/\//%2F/g;s/=/%3D/g')
echo "WR_PROTO=hysteria2"
echo "WR_CLIENT_CONFIG=hysteria2://$HY2ENC@$PUBLIC_IP:8445?sni=$WR_TLS_SNI&insecure=1&obfs=salamander&obfs-password=$HY2OBFSENC#wayhop-hy2"
`

// scriptTUIC provisions a sing-box TUIC v5 inbound (QUIC + TLS, self-signed). A uuid
// and password are generated once and persisted. The client link is the standard
// tuic://uuid:password@host:port?sni=...&insecure=1&congestion_control=bbr#name form
// parseTUIC reads.
const scriptTUIC = `
# ---- sing-box TUIC v5 (QUIC + TLS) ----
log "installing sing-box (TUIC)..."
` + scriptSingboxInstall + scriptSelfSignedTLS + `
[ -f "$SBD/wr-tuic-uuid" ] || sing-box generate uuid > "$SBD/wr-tuic-uuid"
[ -f "$SBD/wr-tuic-pass" ] || sing-box generate rand --base64 18 > "$SBD/wr-tuic-pass"
chmod 600 "$SBD/wr-tuic-uuid" "$SBD/wr-tuic-pass" 2>/dev/null || true
TUUUID=$(cat "$SBD/wr-tuic-uuid")
TUPASS=$(cat "$SBD/wr-tuic-pass")
mkdir -p /etc/sing-box/conf.d
cat > /etc/sing-box/conf.d/wr-tuic.json <<EOF
{"inbounds":[{"type":"tuic","tag":"wr-tuic-in","listen":"::","listen_port":8446,"users":[{"uuid":"$TUUUID","password":"$TUPASS"}],"congestion_control":"bbr","tls":{"enabled":true,"server_name":"$WR_TLS_SNI","alpn":["h3"],"certificate_path":"$SBD/wr-tls.crt","key_path":"$SBD/wr-tls.key"}}],"outbounds":[{"type":"direct","tag":"wr-tuic-direct"}]}
EOF
# TUIC is UDP/QUIC — open the port if a firewall is active (best-effort).
iptables -C INPUT -p udp --dport 8446 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 8446 -j ACCEPT 2>/dev/null || true
` + singboxServiceUnit + `
# tuic://uuid:<urlencoded-password>@host:port?sni=...&insecure=1&congestion_control=bbr#name (parseTUIC).
TUENC=$(printf '%s' "$TUPASS" | sed 's/+/%2B/g;s/\//%2F/g;s/=/%3D/g')
echo "WR_PROTO=tuic"
echo "WR_CLIENT_CONFIG=tuic://$TUUUID:$TUENC@$PUBLIC_IP:8446?sni=$WR_TLS_SNI&insecure=1&congestion_control=bbr&alpn=h3#wayhop-tuic"
`

// BuildScript assembles the installer for the chosen protocols. publicHost (the
// server's reachable address) overrides the script's auto-detected public IP.
//
// SECURITY PRECONDITION: publicHost MUST already be validated to a bare host/IP
// (callers use netdiag.ValidTarget, which rejects shell metacharacters, spaces, and a
// leading '-'). The %q below is Go-quoting, NOT shell-quoting — inside the emitted
// double-quoted `PUBLIC_IP="…"`, a `$(…)`/backtick in publicHost would still be expanded
// by the remote shell. ValidTarget's charset (alnum . _ : - [ ]) contains no such
// characters, so %q is safe here; do NOT call BuildScript with unvalidated input, or
// shell-quote publicHost first.
func BuildScript(protocols []string, publicHost string, mirrors ...string) string {
	var b strings.Builder
	b.WriteString(scriptHeader)
	b.WriteString(mirrorFetchShell(mirrors)) // defines wr_fetch before any fragment uses it
	if publicHost != "" {
		// prepend an override (placed after header sets the default; re-set it).
		b.WriteString(fmt.Sprintf("PUBLIC_IP=%q\n", publicHost))
	}
	for _, p := range protocols {
		if o := optionByID(p); o != nil && o.Script != "" {
			b.WriteString(o.Script)
		}
	}
	b.WriteString("\nlog \"done\"\n")
	return b.String()
}

// mirrorFetchShell renders the wr_fetch shell helper the install fragments use to download
// from GitHub through a mirror chain — the same prefix list the self-updater uses
// (config.Updater.Mirrors), so provisioning a server from a censored region works the way
// updating the router does. Each prefix is tried in order ("" = direct); wr_fetch writes to
// its optional second arg (a file) or to stdout, and fails only if every mirror fails. A
// direct attempt is always included first, and any mirror that isn't a plain http(s) URL free
// of shell metacharacters is dropped — so a nil/empty/garbage list degrades safely to a
// direct-only fetch (the historical behaviour) and a hostile config value can't inject.
func mirrorFetchShell(mirrors []string) string {
	prefixes := []string{""} // always try direct first
	for _, m := range mirrors {
		if m == "" || !safeMirrorPrefix(m) {
			continue
		}
		prefixes = append(prefixes, m)
	}
	quoted := make([]string, len(prefixes))
	for i, p := range prefixes {
		quoted[i] = "'" + p + "'"
	}
	// curl is the if-CONDITION (never the left of &&) so a failed attempt is exempt from
	// `set -e` on every shell (ash/dash/bash) — the loop simply tries the next mirror.
	return "\n# wr_fetch URL [OUTFILE]: download via the GitHub mirror chain (each prefix tried\n" +
		"# in order; '' = direct). Writes to OUTFILE, else stdout. Fails only if all mirrors fail.\n" +
		"wr_fetch() {\n" +
		"  for __pre in " + strings.Join(quoted, " ") + "; do\n" +
		"    if [ -n \"$2\" ]; then\n" +
		"      if curl -fsSL \"${__pre}$1\" -o \"$2\"; then return 0; fi\n" +
		"    else\n" +
		"      if curl -fsSL \"${__pre}$1\"; then return 0; fi\n" +
		"    fi\n" +
		"  done\n" +
		"  return 1\n" +
		"}\n"
}

// safeMirrorPrefix reports whether m is a plain http(s) URL prefix with no shell
// metacharacters, so it can be single-quoted into the generated wr_fetch list verbatim.
func safeMirrorPrefix(m string) bool {
	if !strings.HasPrefix(m, "http://") && !strings.HasPrefix(m, "https://") {
		return false
	}
	return !strings.ContainsAny(m, " \t\r\n'\"`$;|&<>(){}\\")
}

// Creds are per-request SSH credentials. They are never stored or logged.
type Creds struct {
	Host     string
	Port     int
	User     string
	Password string
	Key      string
	// KnownHostsFile is an optional persistent, WayHop-owned known_hosts path. When
	// set, ssh records the host key there (instead of the ambiguous default known_hosts —
	// which on a router may be non-persistent, re-TOFUing each reboot, or unreadable) so
	// the pin survives across connects, and Provision can fingerprint the recorded key for
	// out-of-band verification. When empty, behaviour is byte-identical to before: the
	// default known_hosts and accept-new TOFU are used, with no fingerprint reporting.
	KnownHostsFile string
}

// provisionSSHArgs builds the ssh option/positional argument vector shared by every
// auth path (key, password-via-sshpass). It is a pure helper so the exact argv can be
// unit-tested. When c.KnownHostsFile is set, two extra options pin the key to that
// persistent file (HashKnownHosts=no keeps the recorded entry greppable so Provision can
// fingerprint it).
//
// A "--" end-of-options marker precedes the user@host destination as defense-in-depth: ssh
// (OpenSSH and dropbear, both getopt-based) then treats the destination as a positional even
// if c.User/c.Host begins with '-', so a hostile value can never be reparsed as an option
// (argument injection, CWE-88). Callers MUST still validate user+host with netdiag.ValidTarget
// (the primary guard); this only ensures the arg-builder is self-safe if a future caller forgets.
func provisionSSHArgs(c Creds) []string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	args := []string{
		"-p", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=15",
	}
	if c.KnownHostsFile != "" {
		args = append(args,
			"-o", "UserKnownHostsFile="+c.KnownHostsFile,
			"-o", "HashKnownHosts=no",
		)
	}
	args = append(args, "--", c.User+"@"+c.Host, "sh -s")
	return args
}

// sshFingerprintSHA256 computes the OpenSSH SHA256 fingerprint of a base64-encoded host
// key blob (the second field of a known_hosts entry). On a base64 decode error it
// returns ("", false) — never panics — so a malformed entry can be skipped silently.
func sshFingerprintSHA256(b64blob string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64blob))
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), true
}

// hostKeyFingerprint reads knownHostsPath, finds the entry for host (host token =
// host when port==22, else "[host]:port") by matching the comma-separated first field
// of each non-comment line, and returns the key type plus its OpenSSH SHA256
// fingerprint. ok=false (never an error/panic) if the file is unreadable, the host is
// absent, or the matched entry is unparseable.
func hostKeyFingerprint(knownHostsPath, host string, port int) (keytype, fp string, ok bool) {
	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
		return "", "", false
	}
	token := host
	if port != 22 {
		token = "[" + host + "]:" + strconv.Itoa(port)
	}
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		fields := strings.Fields(ln)
		if len(fields) < 3 {
			continue // need: hosts keytype keyblob
		}
		matched := false
		for _, h := range strings.Split(fields[0], ",") {
			if h == token {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if f, fpOk := sshFingerprintSHA256(fields[2]); fpOk {
			return fields[1], f, true
		}
		return "", "", false // matched host, but key blob is unparseable
	}
	return "", "", false
}

// Provision tries to run the script on the server over SSH. ran=false means the
// auto path isn't available (no ssh/sshpass, or no creds) — the caller should
// fall back to manual instructions. Output is the captured stdout/stderr.
func Provision(ctx context.Context, c Creds, script string) (output string, ran bool, err error) {
	sshPath, e := exec.LookPath("ssh")
	if e != nil {
		return "", false, nil
	}
	if c.Port == 0 {
		c.Port = 22
	}
	base := provisionSSHArgs(c)
	// When pinning to a WayHop-owned known_hosts, ensure its directory exists (0700)
	// so ssh can create the file on the first connect. Best-effort: a failure here is not
	// fatal — ssh will still attempt the connection and simply may not record the key.
	if c.KnownHostsFile != "" {
		_ = os.MkdirAll(filepath.Dir(c.KnownHostsFile), 0o700)
	}

	var cmd *exec.Cmd
	switch {
	case c.Key != "":
		kf, e := os.CreateTemp("", "wrkey-*")
		if e != nil {
			return "", false, e
		}
		defer os.Remove(kf.Name())
		_ = os.Chmod(kf.Name(), 0o600)
		_, _ = kf.WriteString(c.Key)
		_ = kf.Close()
		cmd = exec.CommandContext(ctx, sshPath, append([]string{"-i", kf.Name()}, base...)...)
	case c.Password != "":
		sp, e := exec.LookPath("sshpass")
		if e != nil {
			return "", false, nil // no sshpass -> manual fallback
		}
		// Pass the password via the SSHPASS env (sshpass -e), NOT "-p <pw>" on argv: a
		// process's argv is world-readable (/proc/<pid>/cmdline), so -p would briefly leak
		// the credential to any local process; a process's environment is not.
		cmd = exec.CommandContext(ctx, sp, append([]string{"-e", sshPath}, base...)...)
		cmd.Env = append(os.Environ(), "SSHPASS="+c.Password)
	default:
		return "", false, nil
	}

	cmd.Stdin = strings.NewReader(script)
	// Bounded combined-output capture (CombinedOutput is unbounded → OOM risk on a router).
	cw := &capWriter{max: provisionOutputCap}
	cmd.Stdout = cw
	cmd.Stderr = cw
	err = cmd.Run()
	out := cw.String()
	// Host-key transparency: after ssh has (TOFU-)recorded the key in our persistent
	// known_hosts, surface its SHA256 fingerprint so the user can verify it out-of-band
	// against the server's console (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`),
	// catching a first-connect MITM that accept-new would otherwise hide. Best-effort:
	// a missing/unparseable entry is skipped silently and NEVER fails the provision.
	if c.KnownHostsFile != "" {
		if keytype, fp, ok := hostKeyFingerprint(c.KnownHostsFile, c.Host, c.Port); ok {
			out = fmt.Sprintf("# host key (verify out-of-band against your server's console): %s %s for %s\n", keytype, fp, c.Host) + out
		}
	}
	return out, true, err
}

// ExtractConfig pulls the first client config the script printed (a vless:// link,
// or a base64-encoded AmneziaWG .conf).
func ExtractConfig(output string) string {
	if cs := ExtractConfigs(output); len(cs) > 0 {
		return cs[0]
	}
	return ""
}

// ExtractConfigs pulls every client config the script printed, in order — one per
// installed protocol (multi-protocol provisioning prints several).
func ExtractConfigs(output string) []string {
	out := make([]string, 0)
	for _, tc := range ExtractTagged(output) {
		out = append(out, tc.Config)
	}
	return out
}

// TaggedConfig is a client config paired with the protocol that produced it, so
// the orchestration never has to guess by position.
type TaggedConfig struct {
	Proto  string
	Config string
}

// ExtractTagged pulls every client config the installer printed, each attributed
// to its protocol via the WR_PROTO marker the script prints just above it. If a
// marker is missing it falls back to detecting the protocol from the payload.
func ExtractTagged(output string) []TaggedConfig {
	var out []TaggedConfig
	proto := ""
	add := func(cfg string) {
		p := proto
		if p == "" {
			p = DetectProto(cfg)
		}
		out = append(out, TaggedConfig{Proto: p, Config: cfg})
		proto = "" // consume the marker
	}
	for _, ln := range strings.Split(output, "\n") {
		ln = strings.TrimSpace(ln)
		if v, ok := strings.CutPrefix(ln, "WR_PROTO="); ok {
			proto = strings.TrimSpace(v)
			continue
		}
		if v, ok := strings.CutPrefix(ln, "WR_CLIENT_CONFIG_B64="); ok {
			if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v)); err == nil {
				add(string(b))
			} else {
				proto = "" // discard the preceding WR_PROTO so it can't mis-tag the next config
			}
			continue
		}
		if v, ok := strings.CutPrefix(ln, "WR_CLIENT_CONFIG="); ok {
			add(v)
		}
	}
	return out
}

// OneLiner is the manual command the user can run themselves (creds inline are
// theirs; wayhop doesn't keep them).
func OneLiner(c Creds) string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	if c.Key != "" {
		return fmt.Sprintf("ssh -i <your-key> -p %d %s@%s 'sh -s' < wayhop-install.sh", port, c.User, c.Host)
	}
	return fmt.Sprintf("ssh -p %d %s@%s 'sh -s' < wayhop-install.sh   # (or: sshpass -p '<pass>' ssh ...)", port, c.User, c.Host)
}
