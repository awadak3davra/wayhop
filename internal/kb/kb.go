// Package kb is a curated knowledgebase of common VPN/proxy engine errors. Each
// entry maps a log-line signature (regexp) to a plain-language explanation, a
// fix, and source links (GitHub issues / forums / official docs) the entry was
// distilled from. Match() annotates a log line with any entries that apply.
//
// Entries were researched from real reports; see each Sources list.
package kb

import "regexp"

// Entry is one known error and its explanation.
type Entry struct {
	ID          string   `json:"id"`
	Engine      string   `json:"engine"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Fix         string   `json:"fix"`
	Sources     []string `json:"sources"`
	Pattern     string   `json:"-"` // regexp source (case-insensitive)
	re          *regexp.Regexp
}

var entries = []Entry{
	// --- sing-box ---
	{
		ID: "sb-tun-file-exists", Engine: "sing-box", Pattern: `configure tun interface:.*file exists`,
		Title:       "TUN interface already exists",
		Explanation: "sing-box could not create its TUN device because one with the same name already exists — usually a previous instance is still running or left a stale interface behind.",
		Fix:         "Stop any other sing-box/velinx instance, delete the stale TUN (e.g. `ip link del tun0`), or reboot. Make sure only one router owns the TUN.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3411"},
	},
	{
		ID: "sb-tun-invalid-arg", Engine: "sing-box", Pattern: `configure tun interface:.*invalid argument`,
		Title:       "TUN interface rejected (invalid argument)",
		Explanation: "The kernel rejected the TUN configuration — typically the tun module isn't loaded or an option is unsupported on this kernel/platform.",
		Fix:         "Ensure `/dev/net/tun` exists and `modprobe tun` succeeds. On Entware routers where TUN may be limited, use TPROXY/redirect mode instead of TUN.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3734"},
	},
	{
		ID: "sb-wg-route-exists", Engine: "sing-box", Pattern: `start outbound/wireguard.*add route.*file exists`,
		Title:       "WireGuard outbound route conflict",
		Explanation: "sing-box failed to add a route for the WireGuard outbound because that route already exists — often seen after an upgrade or when another tool owns the route.",
		Fix:         "Remove the conflicting route (`ip route`), or disable the duplicate WireGuard interface, then restart sing-box.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3738"},
	},
	{
		ID: "sb-fatal-start", Engine: "sing-box", Pattern: `FATAL.*start service`,
		Title:       "sing-box failed to start",
		Explanation: "sing-box aborted at startup; the rest of the line names the failing inbound/outbound. Usually a config error or a port/interface already in use.",
		Fix:         "Validate with `sing-box check -c config.json` (velinx's Apply does this automatically), then fix the named section or free the busy port.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues"},
	},

	// --- vmess / trojan / shadowsocks (sing-box outbounds) ---
	{
		ID: "ss-bad-auth", Engine: "shadowsocks", Pattern: `bad header|salt not unique|invalid GCM tag|stream-aead.*decrypt|read response key`,
		Title:       "Shadowsocks password/cipher mismatch",
		Explanation: "The Shadowsocks AEAD stream could not be decrypted — the password or the cipher (method) doesn't match the server, so every packet fails its authentication tag.",
		Fix:         "Make sure the password AND the cipher (e.g. aes-128-gcm, 2022-blake3-aes-128-gcm) are byte-for-byte identical to the server. 2022 ciphers also require a base64 key of the exact length for the method.",
		Sources:     []string{"https://github.com/shadowsocks/shadowsocks-rust/issues/1022", "https://github.com/SagerNet/sing-box/issues/1056"},
	},
	{
		ID: "vmess-auth", Engine: "vmess", Pattern: `VMess: failed to (decode|read) (request|header)|invalid user|failed to match.*auth`,
		Title:       "VMess UUID / authentication rejected",
		Explanation: "The server could not authenticate the VMess request — almost always a wrong UUID (id), or alterId/security that the server no longer accepts (modern servers expect alterId 0 with auto/aes-128-gcm security).",
		Fix:         "Verify the UUID matches a user on the server exactly. Use alterId 0 and security auto (or aes-128-gcm); re-import the vmess:// link so no field is dropped.",
		Sources:     []string{"https://github.com/v2fly/v2ray-core/issues/1281", "https://github.com/SagerNet/sing-box/issues/1056"},
	},
	{
		ID: "trojan-auth", Engine: "trojan", Pattern: `trojan.*(invalid password|authentication failed|password mismatch|invalid request)`,
		Title:       "Trojan password rejected",
		Explanation: "Trojan authenticates by a SHA-224 of the password sent inside the TLS tunnel; if it doesn't match a server password the server silently falls back to its fallback site, so the proxy never connects.",
		Fix:         "Check the Trojan password matches the server exactly, and that the TLS server_name/SNI is the server's real domain (a wrong SNI also looks like an auth failure).",
		Sources:     []string{"https://github.com/trojan-gfw/trojan/issues/393", "https://github.com/SagerNet/sing-box/issues/1056"},
	},

	// --- self-signed / insecure TLS (any TLS-based sing-box protocol) ---
	{
		ID: "gen-self-signed", Engine: "any", Pattern: `x509: certificate signed by unknown authority|certificate is not trusted|self.?signed certificate|x509: certificate is valid for .* not`,
		Title:       "Server TLS certificate is not trusted",
		Explanation: "The server presented a self-signed certificate (or one whose name doesn't match) and the client refused it. Common when a server uses a self-signed cert instead of a real domain certificate.",
		Fix:         "If you control the server and it's self-signed, enable 'Allow insecure' on this connection (skips verification), or import the server's certificate / point server_name at the cert's real domain (e.g. via a Let's Encrypt cert).",
		Sources:     []string{"https://sing-box.sagernet.org/configuration/shared/tls/", "https://github.com/SagerNet/sing-box/issues/1844"},
	},

	// --- tuic ---
	{
		ID: "tuic-auth", Engine: "tuic", Pattern: `tuic:.*authentication (timeout|failed)|TUIC.*(invalid|wrong) (uuid|password)|authentication failed.*tuic`,
		Title:       "TUIC UUID/password rejected",
		Explanation: "The TUIC server rejected the credentials (or the auth packet never arrived because UDP/QUIC is blocked). TUIC needs the UUID and password to match, and the right congestion control / udp_relay_mode.",
		Fix:         "Verify the TUIC UUID and password match the server. Confirm the QUIC (UDP) port is reachable and not blocked; check udp_relay_mode (native/quic) and ALPN match the server.",
		Sources:     []string{"https://github.com/EAimTY/tuic/issues/204", "https://github.com/SagerNet/sing-box/issues/1844"},
	},
	{
		ID: "quic-udp-blocked", Engine: "any", Pattern: `quic:.*(no recent network activity|handshake did not complete|timeout: no recent)|INTERNAL_ERROR.*quic|connect: no route to host`,
		Title:       "QUIC/UDP path blocked (Hysteria2 / TUIC)",
		Explanation: "Hysteria2 and TUIC ride on QUIC over UDP. 'no recent network activity', a QUIC handshake timeout or 'no route to host' means UDP to the server port never gets through — a firewall/CGNAT dropping UDP, or DPI throttling QUIC.",
		Fix:         "Confirm the UDP port is open end-to-end (test from another network). If the network blocks/throttles UDP, switch to a TCP-based protocol (Reality/VLESS-TCP or WebSocket-over-CDN).",
		Sources:     []string{"https://v2.hysteria.network/docs/advanced/Troubleshooting/", "https://github.com/apernet/hysteria/issues/1207"},
	},

	// --- xray / reality ---
	{
		ID: "xr-reality-invalid", Engine: "xray", Pattern: `REALITY:.*invalid connection|failed to read client hello`,
		Title:       "Reality rejected the connection",
		Explanation: "The Reality handshake failed verification. Top causes: client/server clocks differ by more than ~90s (Reality embeds a timestamp), a wrong public key (pbk) / short id (sid) / SNI, or a UUID that isn't registered on the server.",
		Fix:         "Sync the router clock (NTP). Re-check that the Reality public key, short id and SNI match the server, and that the UUID exists server-side.",
		Sources:     []string{"https://github.com/XTLS/Xray-core/issues/2728", "https://github.com/XTLS/Xray-core/issues/6048"},
	},
	{
		ID: "xr-reality-verify", Engine: "xray", Pattern: `reality verification failed|REALITY: failed to verify|reality: processed invalid`,
		Title:       "Reality key / SNI verification failed",
		Explanation: "The Reality handshake passed TLS but failed Reality's own verification — a wrong public key (pbk), a short id (sid) the server doesn't know, or an SNI/server_name that isn't on the server's Reality dest list.",
		Fix:         "Re-check the Reality public key (pbk), short id (sid) and SNI all match the server exactly. Reality also embeds a timestamp, so sync the router clock (NTP) if everything else looks right.",
		Sources:     []string{"https://github.com/XTLS/Xray-core/issues/2728", "https://github.com/XTLS/Xray-core/discussions/1697"},
	},
	{
		ID: "xr-deadline", Engine: "xray", Pattern: `context deadline exceeded`,
		Title:       "Connection / latency test timed out",
		Explanation: "A dial or URL-test exceeded its timeout — the endpoint is slow/unreachable, or the configured test timeout is too tight.",
		Fix:         "Increase the test timeout (e.g. 3000 → 6000 ms), confirm the server is reachable, and check for packet loss or DPI blocking on the path.",
		Sources:     []string{"https://github.com/throneproj/Throne/issues/1237", "https://proxypoland.com/blog/vless-connection-errors-troubleshooting"},
	},
	{
		ID: "xr-invalid-user", Engine: "xray", Pattern: `invalid user|not match any user`,
		Title:       "User / UUID not recognized",
		Explanation: "The server could not find the client's UUID/password in its user list — the credentials don't match.",
		Fix:         "Verify the UUID/password exactly matches a server-side user (watch for trailing spaces); re-import the share link to be sure.",
		Sources:     []string{"https://github.com/XTLS/Xray-core/issues/2359"},
	},

	// --- wireguard ---
	{
		ID: "wg-handshake-timeout", Engine: "wireguard", Pattern: `handshake did not complete`,
		Title:       "WireGuard handshake never completed",
		Explanation: "The client sent handshake initiations but got no reply. This is almost always an unreachable UDP port: a blocked/filtered network, wrong endpoint host:port, NAT, or a firewall dropping UDP. (A wrong peer public key is also silent.)",
		Fix:         "Confirm UDP reaches the server port (tcpdump on server / nc on client), verify endpoint+port+AllowedIPs and the peer public key. On censored networks WireGuard/UDP is often throttled — switch to AmneziaWG or a TCP/QUIC-camouflaged protocol.",
		Sources:     []string{"https://forum.opnsense.org/index.php?topic=30540.0", "https://discourse.nixos.org/t/wireguard-problems-handshake-did-not-complete/26237", "https://github.com/pivpn/pivpn/discussions/1532"},
	},
	{
		ID: "wg-unknown-peer", Engine: "wireguard", Pattern: `handshake initiation from unknown peer|invalid handshake initiation`,
		Title:       "Handshake from an unknown peer",
		Explanation: "The server received a handshake it couldn't match to any configured peer — the client's public key isn't on the server, or (AmneziaWG) the junk-packet params differ so the packet can't be parsed.",
		Fix:         "Add the client's public key to the server's peers. For AmneziaWG, make sure Jc/Jmin/Jmax/S1/S2/H1–H4 match the server exactly.",
		Sources:     []string{"https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/issues/132"},
	},

	// --- amneziawg ---
	{
		ID: "awg-junk-mismatch", Engine: "amneziawg", Pattern: `sending dummy junk|only \d+ bytes received`,
		Title:       "AmneziaWG junk-packet parameters mismatch",
		Explanation: "AmneziaWG's obfuscation params (Jc, Jmin, Jmax, S1, S2, H1–H4) must be IDENTICAL on both ends. When they differ the server can't parse the obfuscated handshake, so you see partial reads ('only 92 bytes received') or it never completes.",
		Fix:         "Copy the exact Jc/Jmin/Jmax/S1/S2/H1–H4 from the server. (A plain WireGuard server also works if only Jc/Jmin/Jmax are set and the rest are 0.) Re-import the .conf so velinx captures every param.",
		Sources:     []string{"https://github.com/amnezia-vpn/amnezia-client/issues/1823", "https://github.com/amnezia-vpn/amnezia-client/issues/1041", "https://github.com/shtorm-7/sing-box-extended/issues/18"},
	},

	{
		ID: "awg-bad-header", Engine: "amneziawg", Pattern: `received message with (unknown|invalid) type|unexpected packet type|message type \d+ not`,
		Title:       "AmneziaWG packet-type / header mismatch",
		Explanation: "AmneziaWG remaps WireGuard's message-type magic via H1–H4. If H1–H4 differ between client and server, each side tags packets with a type the other doesn't recognise, so handshakes are dropped as 'unknown/invalid message type'.",
		Fix:         "Copy H1, H2, H3 and H4 from the server verbatim (along with Jc/Jmin/Jmax/S1/S2). All eight obfuscation values must be identical on both ends; re-import the .conf so none are lost.",
		Sources:     []string{"https://github.com/amnezia-vpn/amneziawg-go/issues/13", "https://github.com/amnezia-vpn/amnezia-client/issues/1041"},
	},

	// --- hysteria2 ---
	{
		ID: "hy-tls-verify", Engine: "hysteria2", Pattern: `tls: failed to verify certificate|x509: certificate signed by unknown|certificate is not (trusted|valid)`,
		Title:       "TLS certificate verification failed",
		Explanation: "The client rejected the server's TLS certificate — usually a self-signed cert that isn't trusted, an incomplete certificate chain, or an SNI/server_name that doesn't match the certificate.",
		Fix:         "If self-signed, enable 'insecure' or add the CA. Ensure the cert file contains the full chain (multiple BEGIN CERTIFICATE blocks). Set SNI/server_name to the certificate's domain.",
		Sources:     []string{"https://v2.hysteria.network/docs/advanced/Troubleshooting/"},
	},
	{
		ID: "hy-auth", Engine: "hysteria2", Pattern: `authentication failed|auth error|HTTP/\S+ 401`,
		Title:       "Hysteria2 authentication failed",
		Explanation: "The server rejected the client. Beyond a wrong password, Hysteria2 is picky: the ALPN must match the server and the server_name must match the certificate.",
		Fix:         "Check the password; ensure ALPN matches the server and server_name matches the certificate domain.",
		Sources:     []string{"https://v2.hysteria.network/docs/advanced/Troubleshooting/", "https://github.com/SagerNet/sing-box/issues/1844"},
	},

	// --- provisioned inbound: port conflicts (any inbound on 8443/8444/8388/8445/8446) ---
	{
		ID: "inbound-port-in-use", Engine: "sing-box", Pattern: `listen.*:(8443|8444|8388|8445|8446).*address already in use|bind.*:(8443|8444|8388|8445|8446).*address already in use|start inbound.*(8443|8444|8388|8445|8446).*address already in use`,
		Title:       "Provisioned inbound port already in use",
		Explanation: "sing-box could not bind to one of the provisioned inbound ports (8443/8444/8388/8445/8446) because another process already holds it — a stale sing-box instance, a system service (e.g. Apache on 8443), or a previous crash that left the socket open.",
		Fix:         "Run `ss -tlunp | grep -E '8443|8444|8388|8445|8446'` to find the owner, stop it, then restart sing-box (or choose a different port in the Velinx Init-Server settings).",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3411", "https://sing-box.sagernet.org/configuration/inbound/"},
	},

	// --- provisioned inbound: VMess (sing-box inbound, port 8443, WS+TLS) ---
	{
		ID: "inbound-vmess-auth", Engine: "sing-box", Pattern: `inbound/vmess.*failed to handle|vmess.*invalid user|vmess.*failed to (decode|read) (request|header)|inbound.*vmess.*authentication`,
		Title:       "VMess inbound: client UUID rejected",
		Explanation: "The provisioned VMess inbound (port 8443) could not authenticate the client — the UUID in the client config does not match the server, or the client is not using WebSocket transport / the correct path.",
		Fix:         "Re-import the share link from Init-Server to ensure the UUID, WS path and SNI are exact. Set allow_insecure=true on the client (self-signed cert); verify the client uses WebSocket transport.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/1056", "https://sing-box.sagernet.org/configuration/inbound/vmess/"},
	},

	// --- provisioned inbound: Trojan (sing-box inbound, port 8444, TLS) ---
	{
		ID: "inbound-trojan-auth", Engine: "sing-box", Pattern: `inbound/trojan.*failed to handle|trojan.*inbound.*(invalid password|password mismatch|authentication failed)|inbound.*trojan.*fallback`,
		Title:       "Trojan inbound: client password rejected",
		Explanation: "The provisioned Trojan inbound (port 8444) rejected the client — the password doesn't match, or the client connected without TLS / with the wrong SNI, causing Trojan to fall back to the fallback handler instead of proxying.",
		Fix:         "Re-import the trojan:// link from Init-Server to get the exact password and SNI. Ensure the client uses TLS with SNI matching the server cert; set insecure=1 for the self-signed cert.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/1056", "https://sing-box.sagernet.org/configuration/inbound/trojan/"},
	},

	// --- provisioned inbound: Shadowsocks (sing-box inbound, port 8388, 2022-blake3-aes-256-gcm) ---
	{
		ID: "inbound-ss-psk", Engine: "sing-box", Pattern: `inbound/shadowsocks.*failed to handle|shadowsocks.*inbound.*(bad header|salt not unique|invalid GCM tag|psk|pre-shared key)|inbound.*shadowsocks.*(decrypt|authentication)`,
		Title:       "Shadowsocks inbound: PSK/password mismatch",
		Explanation: "The provisioned Shadowsocks inbound (port 8388, 2022-blake3-aes-256-gcm) could not decrypt the client's stream — the pre-shared key (PSK) or cipher doesn't match. The 2022 cipher requires a base64 key of exactly 32 bytes.",
		Fix:         "Re-import the ss:// link from Init-Server — the base64 PSK must match the server exactly. Ensure the client also uses 2022-blake3-aes-256-gcm; mixing with older ciphers silently fails.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/1056", "https://sing-box.sagernet.org/configuration/inbound/shadowsocks/"},
	},

	// --- provisioned inbound: Hysteria2 (sing-box inbound, port 8445, QUIC+TLS) ---
	{
		ID: "inbound-hy2-auth", Engine: "sing-box", Pattern: `inbound/hysteria2.*failed to handle|hysteria2.*inbound.*(authentication failed|invalid password|auth error)|inbound.*hy2.*(auth|password)`,
		Title:       "Hysteria2 inbound: client authentication failed",
		Explanation: "The provisioned Hysteria2 inbound (port 8445) rejected the client — wrong password, wrong ALPN (must be h3), or the UDP/QUIC port is blocked so the handshake never completes.",
		Fix:         "Re-import the hysteria2:// link from Init-Server. Confirm UDP port 8445 is open (check iptables on the server). The client must set insecure=1 for the self-signed cert and ALPN h3.",
		Sources:     []string{"https://v2.hysteria.network/docs/advanced/Troubleshooting/", "https://sing-box.sagernet.org/configuration/inbound/hysteria2/"},
	},

	// --- provisioned inbound: TUIC v5 (sing-box inbound, port 8446, QUIC+TLS) ---
	{
		ID: "inbound-tuic-auth", Engine: "sing-box", Pattern: `inbound/tuic.*failed to handle|tuic.*inbound.*(authentication failed|authentication timeout|invalid uuid|invalid password|auth timeout)|inbound.*tuic.*(auth|uuid|password)`,
		Title:       "TUIC v5 inbound: UUID/password rejected",
		Explanation: "The provisioned TUIC inbound (port 8446) rejected the client — wrong UUID or password, wrong ALPN (must be h3), or the UDP/QUIC port is firewalled so the QUIC handshake never arrives.",
		Fix:         "Re-import the tuic:// link from Init-Server (both UUID and password must match). Confirm UDP port 8446 is open; set insecure=1 for the self-signed cert. ALPN must be h3 and congestion_control bbr.",
		Sources:     []string{"https://github.com/EAimTY/tuic/issues/204", "https://sing-box.sagernet.org/configuration/inbound/tuic/"},
	},

	// --- provisioned inbound: TLS — client rejects self-signed cert ---
	{
		ID: "inbound-tls-bad-cert", Engine: "sing-box", Pattern: `tls: bad certificate|tls: unknown certificate authority|remote error: tls:.*certificate|inbound.*tls.*(bad cert|unknown ca|certificate unknown)`,
		Title:       "Client rejected the server's self-signed TLS certificate",
		Explanation: "A client connected to a provisioned TLS inbound (VMess :8443, Trojan :8444, Hysteria2 :8445, TUIC :8446) but refused the self-signed certificate. The TLS alert 'bad certificate' or 'unknown certificate authority' is sent back to the server.",
		Fix:         "Enable 'allow_insecure' / 'insecure=1' on the client (velinx's Init-Server share links include this flag). Alternatively, replace the self-signed cert with a Let's Encrypt cert matching the SNI domain.",
		Sources:     []string{"https://sing-box.sagernet.org/configuration/shared/tls/", "https://github.com/SagerNet/sing-box/issues/1844"},
	},

	// --- provisioned inbound: QUIC UDP blocked (Hysteria2 / TUIC inbounds) ---
	{
		ID: "inbound-quic-blocked", Engine: "sing-box", Pattern: `inbound/(hysteria2|tuic).*udp.*(unreachable|blocked|refused)|listen udp.*:(8445|8446).*(unreachable|blocked)|quic.*inbound.*handshake.*timeout|inbound.*(hy2|tuic).*no recent network`,
		Title:       "QUIC/UDP inbound unreachable (Hysteria2/TUIC)",
		Explanation: "The Hysteria2 (UDP :8445) or TUIC (UDP :8446) inbound is not receiving QUIC handshakes — the UDP port is likely blocked by iptables, a cloud-provider firewall rule, or CGNAT. sing-box starts but no client can reach it.",
		Fix:         "On the server run `iptables -I INPUT -p udp --dport 8445 -j ACCEPT` and `iptables -I INPUT -p udp --dport 8446 -j ACCEPT`. Check the cloud provider's security group/firewall also allows these UDP ports inbound.",
		Sources:     []string{"https://v2.hysteria.network/docs/advanced/Troubleshooting/", "https://github.com/apernet/hysteria/issues/1207"},
	},

	// --- general (any engine) ---
	{
		ID: "gen-no-host", Engine: "any", Pattern: `no such host|name resolution failed|server misbehaving`,
		Title:       "DNS resolution failed",
		Explanation: "The engine couldn't resolve the server's hostname to an IP — DNS is failing, blocked, or hijacked.",
		Fix:         "Use an IP instead of a hostname, point velinx's DNS at a working DoH/DoT resolver, or check that DNS isn't being intercepted upstream.",
		Sources:     []string{"https://sing-box.sagernet.org/configuration/dns/"},
	},
	{
		ID: "gen-conn-refused", Engine: "any", Pattern: `connection refused`,
		Title:       "Connection refused",
		Explanation: "The server actively refused the connection — nothing is listening on that port, the port is wrong, or a firewall is sending RST.",
		Fix:         "Verify the server is running and the port is correct and open. For UDP/QUIC protocols, 'refused' can also mean the path is filtered.",
		Sources:     []string{"https://github.com/apernet/hysteria/issues/1207"},
	},
	{
		ID: "urltest-target-unreachable", Engine: "sing-box", Pattern: `outbound/urltest\[[^\]]*\].*(timeout|no route to host|connection refused|network unreachable)`,
		Title:       "Failover group can't reach its test target",
		Explanation: "A failover group's URL-test could not reach its test target through any member, so the whole tier is reported DOWN. Either every member tunnel is actually down, or the test URL is unreachable/blocked through them (e.g. the test host blocks the server IP, or DPI drops the path) even though the tunnels themselves work.",
		Fix:         "Confirm the member servers are up and reachable. If the tunnels work but the test still fails, point the group at a more-reliable, less-likely-blocked test URL, or raise the group's test timeout.",
		Sources:     []string{"https://sing-box.sagernet.org/configuration/outbound/urltest/"},
	},
	{
		ID: "gen-io-timeout", Engine: "any", Pattern: `i/o timeout|dial tcp.*timeout`,
		Title:       "Connection timed out",
		Explanation: "The connection attempt timed out with no response — the server is unreachable or the path is being silently dropped (common with DPI blocking).",
		Fix:         "Check reachability and firewall. On censored networks try a camouflaged transport (Reality, WebSocket-over-CDN) or AmneziaWG.",
		Sources:     []string{"https://github.com/XTLS/Xray-core/issues/5332"},
	},
	{
		ID: "gen-clock", Engine: "any", Pattern: `certificate has expired|not valid before|tls: failed to verify certificate because of clock`,
		Title:       "System clock is wrong",
		Explanation: "TLS and Reality handshakes fail when the router clock is off (common after a power loss on devices without an RTC). Certificates look 'expired' or 'not yet valid'.",
		Fix:         "Sync the clock via NTP. velinx warns on large clock skew at startup.",
		Sources:     []string{"https://github.com/XTLS/Xray-core/issues/2728"},
	},
	{
		ID: "gen-permission", Engine: "any", Pattern: `permission denied|operation not permitted`,
		Title:       "Permission denied",
		Explanation: "The engine lacks privileges for the operation — creating a TUN device, binding a low port, or setting routes.",
		Fix:         "Run as root with CAP_NET_ADMIN and ensure `/dev/net/tun` is accessible. On Entware the service runs as root by default.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3411"},
	},
	{
		ID: "sb-decode-config", Engine: "sing-box", Pattern: `(decode|read) config at .+:`,
		Title:       "sing-box rejected the config (parse error)",
		Explanation: "sing-box could not load its config: either invalid JSON, or a field/value this sing-box version doesn't accept (a key removed/renamed across versions, or a typo). It aborts before any inbound/outbound starts.",
		Fix:         "Run `sing-box check -c <config>` to see the exact bad key/line. An 'unknown field' means the JSON uses a key the installed core (target 1.12.x) doesn't support — re-Apply from Velinx so the JSON matches the core, or update the core.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/620"},
	},
	{
		ID: "sb-decode-key", Engine: "sing-box", Pattern: `decode (private|public|peer.?public)[ _]?key\b|decode short_id\b|invalid public_key`,
		Title:       "A protocol key or short-id is malformed",
		Explanation: "sing-box could not decode a key while loading the config — a WireGuard private/peer key, a Reality public key, or a Reality short-id is not valid. WireGuard keys are standard base64; a Reality public key is url-safe base64; a short-id is even-length hex (≤16 chars). The usual cause is a truncated or wrongly-encoded copy-paste, or a hand-edited profile.",
		Fix:         "Re-copy the key / short-id from its source (the server config or the share link) and re-import — Velinx normalizes key encodings on import, so importing the link or .conf is more reliable than hand-editing the profile JSON. A short-id must be hex, e.g. `0123abcd`.",
		Sources:     []string{"https://sing-box.sagernet.org/configuration/shared/tls/", "https://sing-box.sagernet.org/configuration/endpoint/wireguard/"},
	},
	{
		ID: "sb-conn-reset", Engine: "sing-box", Pattern: `open outbound connection:.*\b(connection )?reset by peer\b`,
		Title:       "Connection reset by peer (likely DPI / blocking)",
		Explanation: "A proxied connection was forcibly reset mid-stream. On censored networks this is the classic DPI signature — the firewall injects an RST once it fingerprints the proxy (especially Reality/VLESS on :443). It can also be the upstream server or an overloaded CDN dropping the connection.",
		Fix:         "If intermittent under censorship: move the endpoint off :443 to a random high port, use a different/empty SNI, or switch to a more camouflaged transport (Reality+uTLS, WS-over-CDN, AmneziaWG). If constant, the server may be down or rate-limiting — verify it.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/539"},
	},
	{
		ID: "gen-net-unreachable", Engine: "any", Pattern: `(connect:|dial (tcp|udp).*:) network (is )?unreachable`,
		Title:       "Network is unreachable (often IPv6 with no IPv6 route)",
		Explanation: "The OS has no route to the destination address family. The common case: the server resolves to an IPv6 (AAAA) address while the router has no working IPv6 route, so every dial to the [....] address fails instantly.",
		Fix:         "Force IPv4 for the endpoint (domain strategy ipv4_only, or use the server's IPv4 literal). If IPv6 is intended, fix the upstream IPv6 route/gateway. The Diagnostics IPv6-leak check flags a broken IPv6 path.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/2802"},
	},
	{
		ID: "sb-tls-handshake-fail", Engine: "sing-box", Pattern: `TLS handshake:.*(context deadline exceeded|timeout|EOF|reset by peer)`,
		Title:       "TLS handshake timed out or was dropped",
		Explanation: "The TLS/Reality handshake started but never finished — the peer stopped responding or the connection was cut during negotiation. This is a transport/blocking problem (DPI dropping the ClientHello, packet loss, or a filtered SNI), NOT a certificate-trust problem.",
		Fix:         "Check reachability + packet loss to the server port; verify the SNI/server_name is one the server (or its front) serves. On censored paths try a different SNI or move off :443.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/2620"},
	},
	{
		ID: "awg-resolvconf-missing", Engine: "amneziawg", Pattern: `(resolvconf|resolvectl): (command )?not found|wg-quick:.*resolvconf`,
		Title:       "awg-quick can't apply DNS (resolvconf missing)",
		Explanation: "The AmneziaWG .conf has a 'DNS =' line, so awg-quick tries to set DNS via resolvconf/resolvectl, but that tool isn't installed on this router — so DNS handling fails or the bring-up aborts.",
		Fix:         "Install resolvconf/openresolv (`opkg install resolvconf` on Entware), OR remove the 'DNS =' line from the AmneziaWG profile and let Velinx handle DNS, OR set 'Table = off' and point DNS manually via PostUp.",
		Sources:     []string{"https://github.com/amnezia-vpn/amneziawg-tools"},
	},
	{
		ID: "awg-route-exists", Engine: "amneziawg", Pattern: `RTNETLINK answers: (File exists|Address already in use)`,
		Title:       "AmneziaWG route/address already exists",
		Explanation: "awg-quick tried to add a route or IP the kernel already has — usually a previous tunnel instance wasn't torn down, two tunnels share the same AllowedIPs/subnet, or another VPN owns the same route table, so bring-up fails.",
		Fix:         "Tear down the stale interface (`awg-quick down <iface>` / `ip link del <iface>`) and retry. If two tunnels overlap, give them distinct subnets or set 'Table = off' so awg-quick doesn't manage the route, then re-Apply.",
		Sources:     []string{"https://github.com/amnezia-vpn/amneziawg-tools"},
	},

	// --- Velinx's own local ports + host resource limits ---
	{
		ID: "local-port-in-use", Engine: "sing-box", Pattern: `(inbound/mixed|clash.?api|external_controller).*address already in use|listen.*:(7890|9090)\b.*address already in use`,
		Title:       "Velinx's local proxy / Clash-API port is already in use",
		Explanation: "sing-box couldn't bind Velinx's own local mixed-proxy (default :7890) or Clash-API (default :9090) port — distinct from the provisioned server inbounds (8443/8444/…). Almost always a previous sing-box/Velinx instance that didn't exit cleanly still holds the socket, or another proxy is listening on the same port.",
		Fix:         "Find the holder with `ss -tlnp | grep -E ':(7890|9090)'`. If it's a stale `sing-box`, `killall sing-box` and let Velinx's watchdog restart it cleanly; or change Velinx's mixed/Clash port in Settings if another app needs that port.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3411", "https://sing-box.sagernet.org/configuration/inbound/"},
	},
	{
		ID: "gen-too-many-files", Engine: "any", Pattern: `too many open files`,
		Title:       "Out of file descriptors (open-files limit)",
		Explanation: "The engine hit the per-process open-files limit (`ulimit -n`) — common on routers with a low default (often 1024) under many concurrent connections. New connections then fail until descriptors free up, so traffic stalls intermittently.",
		Fix:         "Raise the limit for the service and restart it — on OpenWrt add a procd `limits { nofile = '16384 16384'; }` block to the init script (or `ulimit -n 16384` before launch on Entware). If it keeps recurring, something is leaking connections — look for a flapping endpoint reconnecting in a loop.",
		Sources:     []string{"https://openwrt.org/docs/guide-developer/procd-init-scripts"},
	},
}

var errLine = regexp.MustCompile(`(?i)\b(fatal|error|panic|failed|denied|refused|invalid|timeout|reject)\b`)

func init() {
	for i := range entries {
		entries[i].re = regexp.MustCompile(`(?i)` + entries[i].Pattern)
	}
}

// Entries returns the whole knowledgebase (for browsing in the UI).
func Entries() []Entry { return entries }

// Match returns every knowledgebase entry whose signature appears in the line.
func Match(line string) []Entry {
	var out []Entry
	for i := range entries {
		if entries[i].re.MatchString(line) {
			out = append(out, entries[i])
		}
	}
	return out
}

// IsErrorLine reports whether a log line looks like an error/warning.
func IsErrorLine(line string) bool { return errLine.MatchString(line) }
