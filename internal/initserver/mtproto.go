package initserver

import "strings"

// MTProto proxy for Telegram (competitor gap 7: b4 and the nfqws2 Keenetic selector ship one). It
// runs on the server, not the router: LAN devices already reach Telegram through the routing lists,
// while a tg://proxy link works on a phone's mobile data with no VPN app - the job telemt already
// does on the NL VPS.
//
// telemt (github.com/telemt/telemt, Rust) is installed at a pinned version from its static musl
// builds, each checked against the sha256 GitHub publishes for the asset, embedded here rather than
// fetched: the download may come through a mirror (wr_fetch), and a checksum from the same mirror
// would prove nothing.

// TelemtVersion is the telemt release Set up Server installs.
const TelemtVersion = "3.5.15"

// telemtSHA256 is the published digest of each telemt-<arch>-linux-musl.tar.gz at TelemtVersion
// (gh api repos/telemt/telemt/releases/tags/3.5.15, .assets[].digest; both also checked by a local
// sha256sum of the downloaded asset and against the release's own .sha256 files).
var telemtSHA256 = map[string]string{
	"x86_64":  "3b9b9869f9b77342622fa817c8f4864f3dd4826f38946c403dd8983835724970",
	"aarch64": "629564125cd788edae53f44e93098e5a21024230622bc00330edf5fbb6c0207e",
}

// mtprotoPort is the proxy's TCP port; 8446-8448 are the other Set up Server protocols.
const mtprotoPort = "8449"

// mtprotoCover is the site the fake-TLS handshake imitates (and, with mask on, forwards a stranger
// to). The NL VPS runs telemt with this cover.
const mtprotoCover = "www.bing.com"

// ShareLinkMarker introduces a link the installer hands back for people to use, not for this router
// to import: a tg://proxy link is a Telegram setting, not a connection.
const ShareLinkMarker = "WR_SHARE_LINK="

var scriptMTProto = `
# ---- MTProto proxy (telemt ` + TelemtVersion + `) ----
log "installing telemt (MTProto proxy for Telegram)..."
# A telemt someone installed by hand uses the same unit, user and /etc/telemt as upstream's guide, so
# installing over it would stop that proxy and break every link already handed out. Ours is the unit
# whose Description names WayHop, or no telemt at all.
if { systemctl cat telemt >/dev/null 2>&1 && ! systemctl cat telemt 2>/dev/null | grep -q 'proxy (WayHop)'; } || { [ -e /etc/telemt ] && [ ! -f /etc/telemt/wr-secret ]; }; then
  log "a telemt not installed by WayHop is already on this server - leaving it alone (remove it to install WayHop's)"; exit 1
fi
command -v curl >/dev/null 2>&1 || { apt-get update >/dev/null 2>&1; apt-get install -y curl tar >/dev/null 2>&1 || true; }
case "$(uname -m)" in
  x86_64|amd64) TMA=x86_64; TMSUM=` + telemtSHA256["x86_64"] + `;;
  aarch64|arm64) TMA=aarch64; TMSUM=` + telemtSHA256["aarch64"] + `;;
  *) log "telemt has no build for $(uname -m)"; exit 1;;
esac
wr_fetch "https://github.com/telemt/telemt/releases/download/` + TelemtVersion + `/telemt-${TMA}-linux-musl.tar.gz" /tmp/telemt.tgz || { log "failed to download telemt ` + TelemtVersion + `"; exit 1; }
echo "${TMSUM}  /tmp/telemt.tgz" | sha256sum -c - >/dev/null 2>&1 || { log "the telemt download does not match its pinned checksum - refusing it"; rm -f /tmp/telemt.tgz; exit 1; }
rm -rf /tmp/telemt-x && mkdir -p /tmp/telemt-x && tar -xzf /tmp/telemt.tgz -C /tmp/telemt-x telemt || { log "failed to extract telemt"; exit 1; }
id telemt >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /opt/telemt telemt 2>/dev/null || true
systemctl stop telemt >/dev/null 2>&1 || true
install -m 755 /tmp/telemt-x/telemt /usr/local/bin/telemt
rm -rf /tmp/telemt-x /tmp/telemt.tgz
mkdir -p /etc/telemt /opt/telemt/tlsfront
[ -f /etc/telemt/wr-secret ] || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/telemt/wr-secret
chmod 600 /etc/telemt/wr-secret
TMSEC=$(cat /etc/telemt/wr-secret)
cat > /etc/telemt/telemt.toml <<EOF
[general]
use_middle_proxy = true
log_level = "normal"
[general.modes]
classic = false
secure = false
tls = true
[server]
port = ` + mtprotoPort + `
[server.api]
enabled = false
[[server.listeners]]
ip = "0.0.0.0"
[censorship]
tls_domain = "` + mtprotoCover + `"
mask = true
tls_emulation = true
tls_front_dir = "/opt/telemt/tlsfront"
[access.users]
wayhop = "$TMSEC"
EOF
chown -R telemt:telemt /etc/telemt /opt/telemt 2>/dev/null || true
chmod 600 /etc/telemt/telemt.toml
cat > /etc/systemd/system/telemt.service <<EOF
[Unit]
Description=telemt MTProto proxy (WayHop)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=/opt/telemt
ExecStart=/usr/local/bin/telemt /etc/telemt/telemt.toml
Restart=on-failure
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable telemt >/dev/null 2>&1 || true
systemctl restart telemt
iptables -C INPUT -p tcp --dport ` + mtprotoPort + ` -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport ` + mtprotoPort + ` -j ACCEPT 2>/dev/null || true
sleep 2
systemctl is-active --quiet telemt || { log "telemt did not start: $(journalctl -u telemt -n 3 --no-pager 2>/dev/null | tail -n 3)"; exit 1; }
TMHEX=$(printf '%s' "` + mtprotoCover + `" | od -An -tx1 | tr -d ' \n')
echo "WR_PROTO=mtproto"
echo "` + ShareLinkMarker + `tg://proxy?server=$PUBLIC_IP&port=` + mtprotoPort + `&secret=ee${TMSEC}${TMHEX}"
`

// ShareLink is a link the installer handed back for people to use.
type ShareLink struct {
	Proto string
	Link  string
}

// ExtractShareLinks reads the WR_SHARE_LINK lines, each attributed by the WR_PROTO marker before it.
func ExtractShareLinks(output string) []ShareLink {
	var out []ShareLink
	proto := ""
	for _, ln := range strings.Split(output, "\n") {
		ln = strings.TrimSpace(ln)
		if v, ok := strings.CutPrefix(ln, "WR_PROTO="); ok {
			proto = strings.TrimSpace(v)
			continue
		}
		if v, ok := strings.CutPrefix(ln, ShareLinkMarker); ok {
			if v = strings.TrimSpace(v); strings.HasPrefix(v, "tg://") {
				out = append(out, ShareLink{Proto: proto, Link: v})
			}
			proto = ""
			continue
		}
		if strings.HasPrefix(ln, "WR_CLIENT_CONFIG") {
			proto = "" // a client config consumed the marker
		}
	}
	return out
}
