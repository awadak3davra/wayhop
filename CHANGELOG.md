# Changelog

All notable changes to WayHop are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.5.9] — 2026-10-31

### Added
- **Certificate pinning on TLS connections.** A connection can now accept its server only when the
  server's certificate matches a pin, instead of checking the certificate's chain and name: the way
  to reach a server with a self-signed certificate without turning certificate checks off. The
  connection form takes the pins of VLESS, VMess, Trojan, AnyTLS, Hysteria2 and TUIC connections
  (the SHA-256 of the server's whole certificate: 64 hex digits, colons allowed, or padded base64;
  several separated by commas or spaces), and saving refuses one that is not a SHA-256 hash; the
  field is hidden under Reality, which uses no pin. Share links bring them in and sharing writes them
  back: Hysteria2's `pinSHA256`, and `pcs=` on VLESS, VMess, Trojan, AnyTLS, TUIC and Hysteria2 links
  as Xray and v2rayN write them; so do the `fingerprint` of a Clash or mihomo proxy (a pin, not a
  browser fingerprint, which is `client-fingerprint`) and the `certificate_sha256` and
  `certificate_public_key_sha256` of a sing-box config. sing-box checks a whole-certificate pin from
  1.15 and a public-key pin from 1.13; an older core would refuse the whole configuration over them,
  so there they are left out and nothing else changes: a connection that checks certificates still
  does, and refuses a self-signed server, while one whose link turned checks off still accepts any
  certificate. The Apply review and the connection check say so. Where the pin is applied it takes
  the place of "insecure", and of the chain check: with Hysteria's `pinSHA256` and certificate checks
  on, Hysteria checks both, while sing-box accepts a certificate that matches the pin even once it
  has expired, which the Apply review says. sing-box compares a pin with the server's own
  certificate only, while Xray's `pcs=` and mihomo's `fingerprint` also accept a CA's, and it checks
  the certificate against the SNI, while a link's `vcn=` names another name to check; the Apply
  review says when either can make a connection fail, and when a Reality connection carries pins it
  does not use. A public-key pin has no share-link form, so a connection whose only pin is one, with
  certificate checks off, is not shared: the link would accept any certificate, and the export says
  so instead. A Hysteria2 pin imported before this release is applied too; one that is not a
  SHA-256 hash is ignored, and the Apply review asks for it to be entered again.
- **DNS through an OpenVPN or OpenConnect connection's own resolvers.** A company VPN usually tells
  its clients which DNS servers answer its private names (intranet hosts, internal domains), and
  those servers can only be reached through the VPN. The DNS page now has two resolver types for
  that, one per protocol: pick the connection, then send the VPN's domains to it with a DNS rule.
  The lookup goes through that connection's tunnel to whatever its server pushes. Two switches
  decide the rest: whether names outside the VPN's own domains are answered too (a VPN that pushes
  servers but no domains needs it, or every lookup sent there comes back "no such name"), and
  whether a short name such as `intranet` is completed with the VPN's search domains. While the
  connection is down these lookups get "no such name"; they do not fall back to another resolver.
  Such a resolver cannot answer the names no rule matches (as the default resolver, or as the first
  one when the default is left out), cannot bootstrap another one, and a connection takes one of
  them; saving refuses each of these, because the proxy core accepts them at its check and then
  refuses to start or answers every lookup with "no such name". Deleting or switching off the
  connection offers to switch the resolver and its rules off with it, and changing the
  connection's protocol is refused while the resolver uses it. They need sing-box 1.14 or newer,
  like the OpenVPN and OpenConnect connections they use.
- **QUIC packet size on Hysteria2 and TUIC connections.** On PPPoE, LTE or a VPN inside a VPN,
  large UDP packets can vanish without any error. QUIC raises its packet size by probing the path,
  and on such a link it can settle on a size the path then drops, so the connection starts and
  then stalls. The connection form now has two settings for these two protocols: the size QUIC
  starts at and never goes below (1200 to 1452 bytes; unset, it starts at 1280), and a switch that
  turns probing off so packets stay at that size. Saving refuses a size outside that range. They
  need sing-box 1.14 or newer. An older core would refuse the whole configuration over them, so
  there they are left out, the connection comes up as before, and the Apply review and the
  connection check say so. On Hysteria2 the starting size applies only with "No Chrome QUIC
  fingerprint" on, because the Chrome handshake brings its own size; the form and the Apply review
  say so, and turning probing off works either way. sing-box configs bring both settings with them;
  a size there outside the range comes in as the size the proxy core actually used. Clash and
  mihomo configs bring a TUIC connection's `disable-mtu-discovery`. Share links have no such
  parameters, so they neither bring nor carry them.
- **Multiplex on VLESS, VMess, Trojan and Shadowsocks connections.** A connection can now carry
  many connections over a few to its server (sing-box's multiplex, the sing-mux protocol), which
  saves a handshake per connection and can hide how many there are. The connection form has a
  Multiplex section on these four protocols: the protocol (h2mux, smux or yamux), how many
  connections and streams, padding, and TCP Brutal with its upload and download rates. It starts
  at 4 connections of at least 4 streams; without that, only an idle connection is reused. The
  server needs multiplex switched on in its sing-box inbound, or mihomo, which always takes it;
  Xray, 3x-ui and Marzban servers drop every connection, and the form says so. TCP Brutal holds
  one connection, so the form hides the pool while it is on, and it needs Linux, the tcp-brutal
  kernel module and Brutal switched on at the server. Clash and mihomo configs bring their `smux:`
  settings with them and sing-box configs their `multiplex` block; what sing-box cannot carry
  (`only-tcp`, multiplex on Hysteria2 and the other protocols without it) is listed when the
  subscription is previewed. Share links neither bring nor carry multiplex: Hiddify adds its
  `muxtype` parameters to a link only for an Xray server, which would drop every connection.
  Saving refuses a setting the proxy core would fail on. One that arrives another way (a restored
  backup) is left out of the configuration and named in the Apply review, as is multiplex on
  Shadowsocks with UDP over TCP, where sing-box never uses it. Servers made with Set up Server now
  accept multiplexed connections, and still accept connections without it.
- **A device ID (HWID) for subscriptions with a device limit.** Provider panels such as Remnawave
  can limit how many devices use one subscription; with that limit on, a download that carries no
  device ID gets "404 Not Found", so WayHop could not fetch such a subscription at all. The
  Subscription tab now has an HWID choice: off (as before), generated, or your own. A generated ID
  is 16 random hex digits, made once and kept: it is not taken from the router's serial number or
  MAC address, and it never changes on its own, because a new ID would take another device slot.
  Switching to off or to your own ID and back to generated brings the same ID back. Your own ID
  must be 10 to 64 letters, digits, `=` or `-`; anything else is refused, since the provider would
  ignore it. The import and the scheduled refresh both send it as `x-hwid`, with the router
  platform (KeeneticOS, OpenWrt or Linux) as `x-device-os`; the firmware version and the router
  model are not sent, and neither header follows a redirect to another host. A new choice takes
  effect only with a download that succeeds, so a failed one leaves the refresh asking as before.
  A "404 Not Found" to a download without an ID now says that a device limit may be the reason.
  The settings export masks the IDs unless "Include secrets" is ticked. The full backup always
  carries them, so restoring it on a reflashed router brings them back and the router is still
  the same device to the provider; a backup without them leaves the current ones as they are.
- **Telegram bridge on the router: Telegram without a tunnel.** The router can run
  tg-ws-proxy-rs (MIT), a local MTProto proxy on its LAN address. A phone or desktop on the LAN
  adds it as a Telegram proxy (a `tg://proxy` link with the LAN address, the port and the
  secret). The bridge reads the data center from each client's obfuscated handshake and carries
  the connection over WebSocket and TLS to Telegram's own web domains, or through a Cloudflare
  domain or Worker of your own, so Telegram works where its servers are blocked. Its connections
  leave the router like the router's own: by the main table unless your routing sends them
  elsewhere. Install it on the Components page ("Telegram bridge (tg-ws-proxy-rs)": the static
  musl build for the router's CPU, the soft-float one on ARMv7, never the UPX one, checked against
  GitHub's digest and the release's own SHA256SUMS). It listens only on the LAN bridge's address
  (`br-lan` on OpenWrt, `br0` on KeeneticOS), never on all interfaces, refuses to start where
  that address is public, and runs as uid/gid 65531, not root, with no supplementary groups; the
  secret reaches it through its environment, not its command line. It dies with the daemon however
  the daemon ends, and a daemon that starts ends any bridge an earlier one left running (on or off),
  so turning it off or making a new secret always reaches the process that serves the old one. Turning it on generates a 32-hex secret, kept in the config
  and masked in a shared export; the default port is 1443, and WayHop's own ports and ports below
  1024 are refused (a reset to defaults whose ports land on the bridge's turns the bridge off). A save takes effect at once, not through Apply: the bridge routes nothing, so
  there is nothing for the fail-safe window to roll back. It starts with the daemon, is restarted
  with backoff when it exits, and the review says when it is on but not installed, keeps exiting
  (with the reason it printed, e.g. a port another program holds), or listens on a network the
  router's default route also leaves by. Settings → Telegram bridge, next to the Telegram bot,
  says whether it runs (or is not installed, with a link to Components, or why it stopped, or that
  it keeps exiting, with how it last ended) and
  opens a dialog with the switch, the port, the optional Cloudflare domain and Worker, and New
  secret, which asks first because every device then needs the new link. While it runs, the
  dialog shows the `tg://proxy` link with Copy and a QR code; the secret appears only inside that
  link, never as a field of its own. The bridge's row on the Components page is shown whatever
  the router runs, with one-click Install. (API: `GET`/`PUT /api/telegram-bridge`, which return
  the link, its QR code, the listen address, the last error and `crash_loop`.)
- **Override the sing-box config WayHop generates.** A core override is JSON saved with the
  settings: a merge patch (RFC 7396 - objects merge, `null` deletes a key, anything else, a list
  included, replaces) plus a `prepend` object whose lists go in front of the generated
  `outbounds`, `route.rules`, `dns.rules` and `dns.servers`, e.g.
  `{"log":{"level":"info"},"prepend":{"route.rules":[{"domain_suffix":["example.org"],"outbound":"direct"}]}}`.
  Prepended route rules go ahead of the profile's rules and lists but after WayHop's own guards
  (the service check's probe rules, the TUN's sniff, and the bypass that keeps each tunnel's own
  server traffic out of the tunnels), so a domain rule needs no sniff of its own.
  It is applied last, to every core config WayHop writes, the preview included; a malformed
  override (not an object, over 64 KiB, an unknown prepend path, a prepend the patch would
  discard) is refused at save. On KeeneticOS the devices NDM routes into are not the override's
  to change: each connection's wrtunN TUN, its local SOCKS inbound and its route rule are put
  back after it, and an override that cannot keep them (a TUN of its own that routes, say) is
  refused at Apply. Apply checks the result with `sing-box check` inside the fail-safe window, and
  the review says the override is active and which keys it touches, names any listener it opens
  beyond loopback (inbounds and services), and warns when it takes what WayHop runs the core
  through - the Clash API, the probe inbound, the generated inbounds or route rules - naming
  what stops working. A shared config export masks it, since a prepended outbound carries a
  server's credentials. Edited in Settings -> Proxy core -> Core override (JSON); an override the
  daemon cannot read is refused on save with the reason. (API: `core_override` in `PUT /api/config`.)
- **Send a routing list to one of the Keenetic's own access policies.** The Routing page's exit
  picker lists them by their description ("⌂ VPN · Keenetic access policy"); saved, the exit is
  `ndm-policy:<name>`, e.g. `ndm-policy:Policy1`: the kernel
  plane marks the list's destinations with that policy's own mark, so KeeneticOS routes them by the
  policy - its connection failover, fail-back and its drop when nothing the policy allows is up - and
  WayHop installs no routing table of its own for it. With the proxy core in the path, the core's
  connections for the list carry the same mark. Only the policy's name is saved; its mark is read
  from the router at every Apply, and a list sent to a policy the router no longer has, or on a
  router that is not KeeneticOS, blocks Apply with the list named. A connection keeps its policy
  when its destination later leaves the list (a domain's address expiring), and should the policy
  disappear from the router between Applies its traffic is dropped, not sent to the internet
  connection. Rules cannot use a policy yet.
  (API: `GET /api/keenetic/policies`.)
- **Import routing lists you already keep.** Routing -> Import shows this Keenetic's own
  `object-group fqdn` lists (names and prefixes, and the interface the router routed each by), or
  reads a pasted HydraRoute Neo `domain.conf` or `ip.list`, one list per target; tick the ones to
  bring over, pick the exit, and each becomes an ordinary routing list. Reading changes nothing on
  the router. What cannot be carried is counted with the reason: geosite and geoip tags, `.domain`
  names, disabled blocks, and prefixes no list should hold - the default route or a large share of
  the internet, private and CGNAT ranges, loopback, link-local and multicast. (API:
  `GET /api/routing/import/keenetic`, `POST /api/routing/import/hydraroute`.)
- **Routing presets that keep RU services on your own ISP.** For a router that sends everything
  through a tunnel, "RU services (keep on your ISP)" lists the banks, Mir and SBP, Gosuslugi, FNS,
  VK, MAX and Rutube (lite, ~480 names) or also Ozon, Wildberries, Yandex, Avito and the operators
  (standard, ~1.6k names), plus the standard tier's networks for apps that connect by address. They
  come from kyoresuas/ru-direct, rebuilt daily, need no proxy core and suggest Direct; on a router
  abroad, point them at the RU exit instead.
- **A routing preset for a router in Ukraine.** "UA inside (itdoginfo)" lists the domains blocked
  inside Ukraine, mostly Russian services (1555 names when added), refreshed weekly; its category is
  "UA-blocked (route abroad)".
- **Routing presets for Roblox and Google Meet calls by address.** "Roblox networks" is what
  Roblox's own ASN announces (IPv4 and IPv6; the file list it replaces missed three networks), and
  "Google Meet media" is Google's published Meet media ranges. Both are plain CIDR lists the
  router routes without a core, and both catch what the domain presets cannot: game and call
  traffic goes to raw UDP addresses, not to a name.
- **Set up Server can add an MTProto proxy for Telegram** (TCP 8449): telemt 3.5.15 from its static
  build, checked against the sha256 GitHub publishes before it is installed, fake-TLS imitating
  www.bing.com (a stranger is shown Bing's real certificate), its own user under systemd, the secret
  kept across re-runs. The result is a `tg://proxy` link for phones - Telegram on mobile data with no
  VPN app - handed back in the setup result and never imported as a connection. A telemt already
  on the server that WayHop did not install is left alone (the step stops and says so).
- **Restart the proxy core on a schedule.** Settings -> Reliability -> Scheduled core restart: a
  daily time in router time (`04:30`) or every N hours (`6h`); empty, the default, never. For a core
  that keeps running but degrades over days - the watchdog already restarts one that crashes. A
  restart drops every live connection, so it is opt-in; it is skipped while an Apply runs or with
  routing switched off, and a failed one is alerted.
- **ByeDPI as an exit.** Add connection -> ByeDPI runs ByeDPI's `ciadpi` on the router as a local
  proxy that reshapes the start of each connection so DPI cannot read the site name; send a routing
  list to it like to any other exit. Its strategy is ciadpi's own flags (three upstream presets in
  the form), checked on save. Install the ByeDPI component from Components (static builds for
  aarch64, ARMv7, MIPS and x86-64 from hufrea/byedpi). In tun and hybrid mode it runs as its own
  uid, which the TUN skips - without that its own connections came straight back into sing-box -
  and with none of the daemon's supplementary groups.
  OpenWrt only for now: on KeeneticOS WayHop does not start `ciadpi`, so a ByeDPI connection there
  can be saved only disabled, and the review blocks Apply on one stored enabled.
- **See which services work through which exit.** Diagnostics -> Run all checks has a row "Services
  through each exit": for the WAN and every tunnel and group, the country the internet places it in
  and whether ChatGPT, Claude and YouTube Premium work there. "Blocked" is only ever the service's
  own refusal; an exit that cannot be asked says why (not Applied since, core not running, interface
  not up). Tunnels sing-box carries are asked through a loopback-only port (17890 by default) that
  appears after the next Apply.
- **Connections follow a route change.** The kernel plane keeps each connection on the exit it
  started on, so after moving a list to another tunnel (or removing one) a call or a QUIC session
  stayed on the old route, or on none, until it ended. Apply, Roll back, the fail-safe and switching
  routing off or on now drop the connections the new plan would route elsewhere, so they reconnect on
  the new route. Only what the plan can prove moved is touched: devices outside a list's scope,
  addresses added by the resolver, private destinations, tunnel servers and the router's own
  connections are left alone, and one change touches at most 4096. Needs the kernel's conntrack
  netlink: built into KeeneticOS; on OpenWrt the installer offers `kmod-nf-conntrack-netlink`, and
  without it connections keep their old route until they end, as before.
- **Choose the User-Agent a subscription is downloaded with.** Some provider panels pick the format
  by it (sing-box JSON for "sing-box", Clash YAML for "clash.meta") or refuse a client they do not know.
  It is set on the Subscription tab, kept with the subscription, and used by the scheduled refresh too.
- **Split the TLS handshake for a list routed direct.** A routing list going straight out can have
  the router fragment its TLS handshake, as TLS records or as TCP segments, against DPI that reads
  the site name there - for a blocked site that is still reachable directly, without a VPN. It works
  where the traffic passes through sing-box (tun or hybrid mode); the review says so when a list's
  traffic would not.
- **Set up Server can install AnyTLS** (TCP 8447, self-signed TLS, like Trojan) **and Snell v6**
  (TCP 8448, sing-box 1.14 on the server and the router), and imports the client each prints. AnyTLS
  pads the record pattern that shows a TLS connection carried inside another. A server whose
  existing sing-box is too old for the chosen one (1.12 for AnyTLS, 1.14 for Snell) is refused before
  anything is written, since an inbound type it does not know would stop every protocol on it.
- **OpenConnect (needs sing-box 1.14 or newer):** Cisco AnyConnect and ocserv, GlobalProtect,
  Fortinet, F5, Pulse and NC servers, set up in the connection form - user name and password, group,
  a TOTP secret, a pin for a server certificate no public CA signs, TLS only. A router cannot answer an
  interactive sign-in prompt, and the form says so.
- **An SSH server as an exit:** any VPS that takes an SSH login becomes an exit with nothing
  installed on it (sing-box's ssh outbound, 1.12 or newer). It carries TCP only: UDP sent to it -
  calls, games, DNS over UDP, QUIC (browsers fall back to TCP) - does not pass. The form says so, and
  the Apply review notes it, without holding Apply, when a rule, a routing list or a DNS server over
  UDP sends traffic to the exit. Set up in the connection form - the user
  (root when empty), a password or a pasted private key with its passphrase, the server's host keys
  one per line as `ssh-keyscan` prints them, an optional client version - or pasted as
  `ssh://user[:password]@host[:port]`, or read from a sing-box config. Without a host key sing-box
  accepts any server, so whoever can intercept the way to it can read the tunnel: the form says so,
  and the Apply review lists it as a privacy finding that holds nothing back. Only the pinned key
  types are offered in the handshake, since a server with both an ECDSA and an Ed25519 key otherwise
  answers with the one nobody pinned. What sing-box would refuse to load - a key that is not PEM, an
  encrypted PKCS#8 key, a passphrase missing or set for a key without one, a host key line that is
  malformed or cut short - is refused when saved, since it would stop every exit at Apply; so is a
  user name with a line break, which no server has. The algorithm limits sing-box 1.14
  added (`cipher`, `mac`, `kex_algorithm`, from an import or the API) are written only for a 1.14+
  core; on an older one they are left out and the review says so. Nothing is exported as a link: an
  `ssh://` URI cannot carry the key or the pinned host keys. The password, key and passphrase are
  masked in the change review like every other secret, and Diagnostics explains a host key that does
  not match, a refused login, and a server that does not allow port forwarding.
- **Encrypted Client Hello (ECH) on TLS connections.** ECH hides the real server name in the TLS
  handshake, so a firewall that reads it sees only the server's public cover name. VLESS, VMess,
  Trojan and AnyTLS can take the server's ECH config pasted into the connection form (base64, or the
  PEM block sing-box prints) or look it up in DNS (kept for the record's TTL); Hysteria 2 and TUIC
  take a pasted config only, since sing-box never runs the lookup over QUIC, and a link that asks
  them for the lookup is imported switched off with a request for the server's config. Share links
  bring it in (`ech=`, as Xray, v2rayN and Hysteria write it), and so do Clash / mihomo `ech-opts`
  and sing-box `tls.ech`; sharing a connection writes `ech=` back. A config that is not a real ECH
  config is refused when saved, because sing-box would load it and then fail every connection. Of
  the uTLS fingerprints only chrome and firefox can carry ECH (with the others every handshake
  fails), so a connection with ECH and another fingerprint is applied with chrome, and the Apply
  review says so. ECH cannot be combined with Reality: a Reality link that also carries `ech=` keeps
  it switched off, which the import and the connection form say. With a DNS lookup, the router's
  own DNS rules answer it, and a connection whose name has no ECH record fails instead of going out
  unencrypted; the Apply review warns about this, asks for an acknowledgement when the DNS server
  that answers is reached through the connection itself or a group holding it (as WayHop's secure
  DNS default is through the main exit), and says when that server is plain DNS, which sends the
  name ECH hides in the clear. A query server name needs sing-box 1.13 or newer, and a sing-box 1.12
  built with Go older than 1.24 has no ECH at all, so it is left out there; the Apply review and the
  connection's Check say which applies.
- **Snell v4 and v6 (needs sing-box 1.14 or newer)**, from the connection form, a Clash / mihomo
  subscription, or Surge `[Proxy]` lines (pasted, or a whole Surge profile, which also brings its
  Shadowsocks, Trojan, Hysteria 2, TUIC v5 and AnyTLS entries). v5 runs as v4, which it is on the
  wire; v1-v3, TLS obfuscation and Shadow TLS are refused by name, since sing-box does not carry them.
- **Hysteria 2 servers with no public address, through a Hysteria realm (needs sing-box 1.14 or
  newer).** Paste a `hysteria2+realm://` link, Hysteria's realm-mode share link (`hy2+realm://` and
  the plain-HTTP `+http` forms too): the router asks the rendezvous in the link where the server is
  and punches a UDP hole to it, so a server behind NAT with no port forwarding works as an exit. The
  link's `stun=` servers are used, or Hysteria's three defaults; `lport=` is not carried. On an older
  core the connection is applied without a server and the Apply review says it will not come up;
  every other connection keeps working. Sharing it gives the same kind of link back. The Hysteria2
  form has the realm address and its STUN servers (server and port are not needed then), and the
  connection's card shows the rendezvous host - never the realm name, which reveals the server. A Hysteria 2 link that pins
  the server certificate (`pinSHA256`) keeps the pin and exports it again; the proxy core cannot
  enforce it, so with certificate checks off the Apply review says the connection accepts any
  certificate.
- **OpenVPN client connections (needs sing-box 1.14 or newer).** Paste an `.ovpn` profile under
  Paste link: UDP or TCP, several servers, `tls-auth` / `tls-crypt` / `tls-crypt-v2`, a user name and
  password or a client certificate, or a static key, with the certificates inline. The connection form
  edits the transport and the sign-in. A profile that needs what the core cannot do - a certificate in
  a separate file, TAP, PKCS#12, a proxy to reach the server - is refused with the reason, and on an
  older sing-box the protocol reads unavailable with the version it needs.
- **Simplified Chinese (简体中文, zh-CN).** The panel ships a tenth translation, every key translated
  with the terms mainland router UIs use (路由, 故障转移, 订阅, 隧道, 出口); protocol and product names
  stay as they are. A browser set to any Chinese variant (zh, zh-CN, zh-Hans, zh-SG, and zh-TW/zh-HK,
  for which no Traditional dictionary exists) opens in it; the Settings picker switches back. The
  language resolver now matches the exact code before the language alone, so a region-tagged code
  can be shipped at all, and a browser language with no dictionary no longer requests a missing file.
- **Switch WayHop's routing off, and back on.** A Routing switch in the panel's header (and
  `/routing` in the Telegram bot, for owners) takes WayHop's routing off the router: sing-box and its
  TUN stop, the kernel routing plane is removed, and on KeeneticOS the native routes and the
  default-route priorities WayHop raised go back below the router's own connections. Every device
  then goes straight out through the WAN. The tunnels WayHop owns stay up, carrying nothing, and the
  panel, the bot and the health checks keep running. Switching back on restores the last applied
  configuration; saved changes that were not applied stay pending, and Apply is refused while routing
  is off. Each step asks first, a banner says routing is off on every page, and the switch survives a
  restart or a reboot. Nothing in the background (boot, the fail-safe, the kernel-plane reconcile,
  the routing lists' failover) puts routing back while it is off.
- **Routing presets re-checked against their sources.** Telegram's networks come from what
  Telegram's five ASNs announce (IPv4 and IPv6): the list Telegram publishes, and the mirror the
  preset used, both omit a /20 that Telegram's main ASN announces. Two
  RKN feeds that stopped updating early in 2026 (antizapret-sing-box, vernette's rkn) are replaced by
  runetfreedom's RU-blocked rule-sets, rebuilt every six hours. New presets that need no proxy core:
  the Cloudflare, CloudFront, Hetzner, DigitalOcean and OVH networks for sites that stall on throttled
  hosting, the matching per-site list, and itdoginfo's news, anime, geo-block, Roblox, Google Meet
  and Google Play lists. Presets refresh at the pace their sources change: twice a day for
  antifilter and runetfreedom, once a day for Re:filter, the RU bundle and itdoginfo's lists,
  which change every few weeks. Lists already added keep their source and their refresh interval.

### Removed
- **olcRTC.** Its project ended (the upstream repository was archived on 2026-09-30, its author
  calling it end of life), and WayHop could not run it in 0.5.8 either. The engine is gone from
  Components, the importer, the connection form and the build. A connection saved by an older build
  still loads and is shown with a note; while it is enabled, Apply asks to delete or disable it. An
  `olcrtc` binary a panel install left beside sing-box stays on the router until you delete it
  (`rm /usr/bin/olcrtc` on OpenWrt, or the same name in the directory sing-box runs from).

### Security
- **Set up Server's TLS connections check the server's certificate.** VMess, Trojan,
  Hysteria2, TUIC and AnyTLS run on a self-signed certificate, and the connection Set up Server added
  carried only `insecure=1`, so it accepted any certificate: anyone on the path could stand in for the
  server. The installer now hashes the certificate after making it and prints its pins with each
  client config: the whole certificate's SHA-256 inside the link (`pinSHA256=` on Hysteria2, `pcs=` on
  Trojan, TUIC and AnyTLS, `"pcs"` in the VMess JSON) and the public key's SHA-256 on a
  `WR_PUBKEY_SHA256=` line of its own, which the panel puts on the imported connection. The router
  then checks the server by its public key from sing-box 1.13 and by the whole certificate from 1.15,
  and leaves `insecure` out there; on 1.12 nothing changes. The links keep `insecure=1` for clients
  that cannot pin. The pins come from the certificate on disk every run, so a server whose
  certificate was regenerated gets new pins, never the old ones. The installer reads the certificate
  once and writes no file of its own, so two setups of one server at once cannot hand each other's
  half-written input to openssl. A pin openssl cannot compute exactly is not printed (the hash of
  empty input, which a failed step would produce, is refused by value), and one that is not a
  SHA-256 hash is left out with a line in the console instead of failing the setup. The connection
  form shows the public-key pin read-only, under "Server public-key pin", with Remove: a pin is
  checked whatever "Allow insecure TLS" says, so after the server's certificate changes outside Set up
  Server, clear the pins there or run Set up Server again. Run Set up Server again on an existing
  server to pin its connections; the certificate and passwords stay the same, so other clients keep
  working.

### Fixed
- **A failed manual Roll back stays reported as failed.** After pressing Roll back in the safety
  window and having it fail, the next connectivity checks relabelled the window "armed" (or
  "degraded"), and it could close as "live, not saved" while the test configuration was still
  partly on the router. The window now keeps reporting the failed rollback until it closes.
- **Importing a link again no longer undoes your changes to its connection.** Importing the
  same subscription or link a second time put the connection back as the link had it: the name you gave
  it, its on/off switch, its health target and multiplex were lost, and the panel said "Imported 1".
  Now what the link's format can say comes from the link, including what it no longer carries (a
  dropped Vision flow, allowInsecure, fingerprint or certificate pin is removed, not kept), and
  everything that format cannot say stays as you set it: name, switch, health target, group membership,
  the amneziawg-go choice, an SSH host key or private key, Hysteria2's QUIC tuning, and the pins you
  added (a pin from a sing-box JSON config cannot be told from one you added and is kept too). Each
  format (share links per scheme, Clash, sing-box, Surge, .conf, .ovpn) has its own list, checked
  against its parser's code, so a Clash or sing-box config also brings its multiplex setting. A
  WireGuard MTU or keepalive the format can carry is always the link's, also after the connection was
  saved in the form, so a provider's new MTU takes effect. An import that does not say which format it
  came from, as a script's may not, never keeps "accept any certificate", a fingerprint or an imported
  pin the link no longer has. The panel says how many were added, updated and unchanged, and says when
  a server public-key pin from Set up Server was kept, so a server whose key changed is not a mystery.
- **Editing a failover group keeps its nested groups and Direct.** A group whose members
  included another group or Direct lost them on any save, even one with no change, because the edit
  dialog listed only connections. They are now listed in their place, checked, and say what they are.
- **Changing a routing preset's URL no longer stops the proxy core.** A preset's list kept its
  "binary" format when you pointed it at a .json list, so sing-box read the JSON as binary, and a list
  that fails to load stops the whole core. On a new URL, in the panel and in the daemon alike, the
  format stays when the new file name has no extension (a mirror or a query-string feed, which would
  otherwise vanish from the core's rule sets) or names the same format, and is dropped and read from the
  URL again when it names the other format or is a plain-text list such as .lst; a different format
  sent with the new URL is kept.
- **An OpenVPN profile with several servers takes the server you type.** The form said its
  Server, Port and Transport fields edit the profile's first server, but the router kept dialling the
  old one. They now change that first server; the others stay as the profile gave them.
- **A page left open no longer saves over newer changes.** A connection's on/off switch, a
  connection, group or routing list edit, and Settings each sent back the copy the page had loaded, so
  they quietly put back what another tab, device or script had saved since (a switch restored an old
  server; a Settings save undid the download route chosen on Components). A switch now changes only
  its on/off state, and an edit of a connection, group or routing list that was saved by someone else
  after you opened it, or a Settings save after another settings save, is refused with nothing saved:
  the panel says so and shows the current version to edit again. Only that object counts: saving
  anything else, a new device group made from inside the form, or the automatic feed refresh does not
  stop your save. Scripts that do not send a revision keep working as before; the new switch requests
  refuse any field but `enabled`.
- **A full restore says when it did not restore the routing mode.** A backup whose routing
  mode this router cannot run is restored without it, and the daemon said why, but the panel showed
  only "Restored". It now shows that the mode was kept and why.
- **A routing list with both a URL and its own entries keeps the entries.** Editing such a
  list, which the API and backups can create, saved it without its manual entries. Both are now shown
  and saved.
- **A DNS rule that matches by domain or geosite can be saved again.** The panel refused it as
  having no match condition although the daemon accepts it; it now counts every condition the daemon
  counts.
- **A boot retry no longer undoes what you changed while it waited.** When the router came up
  before its network, WayHop tried again 30 seconds later to bring back the applied configuration, the
  one it had read before the first try. Switching routing off, or applying and saving a change, during
  those 30 seconds was undone: routing came back on while the switch said off, or the old
  configuration ran while the panel said the new one was applied. The retry now looks again and stands
  down when either changed.
- **An Apply whose rollback also failed is no longer forgotten.** When an Apply failed part
  way and putting the previous configuration back failed too, WayHop went on saying the saved
  configuration was running: Roll back answered that there was nothing to roll back, the background
  check put the saved routing back under the failed Apply's sing-box, and with a test window open, Keep
  saved a test that no longer ran as tested. The failed Apply, or the open test, now stays on record
  as a rollback that failed part way, as after a failed Roll back: the panel and the Telegram bot say
  so, Keep is refused, the background check leaves the routing as the rollback left it, and Roll back
  finishes the job. The next Apply also removes what either of them left on the router that it no
  longer uses: before, a saved tunnel the failed Apply had not yet removed stayed behind for good.
- **Keep no longer deletes a test's tunnels on Keenetic that were changed in KeeneticOS.**
  When a tunnel the test created was changed during the window (switched off in KeeneticOS, for
  example), Keep or Apply & Save rightly refused to save it, but also deleted the tunnel and its
  routes while still saying the configuration ran: sing-box and the routing pointed at an interface
  that was gone, and Keep could never succeed. The save is now refused with everything left as it is:
  the window goes on checking the connection, Roll back still undoes the test, and Keep works once the
  change is undone.
- **Installing sing-box during a test window no longer runs the saved configuration.**
  Installing or updating sing-box while an unsaved test ran started the saved configuration's sing-box
  and routing under a panel that still showed the test, and Keep would then have saved the test. The
  install now brings back what is applied, the test; a test that does not use sing-box is left alone,
  and so is one whose rollback failed part way.
- **The fail-safe window no longer reboots a router that recovered on its rollback.** When a
  test whose sing-box crashed was rolled back to a saved configuration that runs without sing-box (fast
  mode, or router-native tunnels only), the window went on taking the stopped sing-box for an outage:
  it never closed as recovered and, with auto-reboot on, rebooted the router with "no connectivity
  even after rollback". The window now judges what actually runs: the saved configuration after a
  rollback, and the test while a Roll back that failed early left it in place.
- **A rollback that could not remove a test's router-native tunnels says so.** Rolling a
  test back to a saved configuration without router-native tunnels removes the test's tunnels, routes
  and connection priorities. When that failed (a KeeneticOS command timing out, say), Roll back still
  answered "rolled back" and WayHop forgot them. It is now a failed rollback, with the saved
  configuration's sing-box and routing back in place, and Roll back tries the removal again. A retry
  on Keenetic asks only for what is still on the router and sends each removal on its own, so one
  refused removal, or a tunnel already deleted in KeeneticOS, no longer stops the rest. Switching
  routing back on with such a test left from before still switches it on, with the leftover shown as
  a rollback to finish.
- **Links with an Xray finalmask no longer import as connections that cannot work.** v2rayN
  and 3x-ui put Xray's finalmask in a share link as `fm=` (VLESS, VMess, Trojan, Shadowsocks, AnyTLS;
  v2rayN reads it on TUIC and Hysteria2 links too). The import dropped it without a word, so a link
  whose server undoes a mask (salamander, sudoku, xdns, xicmp, xmc, realm, header-custom, mkcp-legacy)
  became a connection that failed every handshake with nothing to say why. Such a link is now refused,
  naming the mask, and so is `fm=` that Xray itself would refuse (not JSON, a mask type it does not
  know, or a value of the wrong type in `quicParams` or a mask's settings). `fm=` is read as v2rayN
  reads it, so a raw `;`, a stray `%`, a raw `+` or the key in capitals does not lose or change it.
  Masks that change only what the client sends (fragment, noise, udphop) or do nothing on a
  client (filter) import: sing-box has no masks, so they are not applied, the connection works without
  that evasion, and the Apply review names them. `fm=` is kept as it came and shared back with the
  link, and an edit of the connection keeps it. Hysteria2's own `obfs=salamander` is unchanged.
- **Certificate pin field, three fixes.** The field is hidden on an AnyTLS connection with
  Reality, as on the other Reality connections. A pin typed beside imported `pcs=` or `fingerprint`
  pins no longer drops the Apply review's warning that those may name a CA certificate: it stays while
  one of the imported pins remains. And a connection holding a Hysteria2 pin an older WayHop kept as
  its link held it, one that is not a SHA-256 hash (such as `deadbeef`), can be edited again without
  clearing the pin first: left as it was, the field keeps it as stored, and the Apply review still
  reports it; an edited field is checked as before.
- **VMess links read v2rayN's `insecure`.** v2rayN writes a VMess link with certificate checks off as
  `"insecure": "1"` in its JSON and reads only that key; WayHop read only `allowInsecure`, so such a
  connection checked the certificate and failed against a self-signed server. Both are read now, and a
  shared VMess link carries both.
- **Surge `server-cert-fingerprint-sha256` imports as a certificate pin.** A Surge `[Proxy]` line with
  it was refused. Surge's manual gives it as the SHA-256 fingerprint (64 hex digits) of the server's
  certificate, checked instead of the certificate chain, which is how sing-box checks a
  whole-certificate pin; it is now read like the other formats' pins, refusing one that is not a
  SHA-256 hash on any line (on Shadowsocks and Snell, which have no TLS, a valid one is not kept).
- **Xray links to a self-signed server import with their pin.** Xray dropped
  `allowInsecure`, so a current Xray panel's link to a server with a self-signed certificate carries
  only the certificate's hash, `pcs=` (with, sometimes, `vcn=`, the name to check it against). The
  import ignored both: the connection checked the certificate against public authorities and failed
  every handshake, with nothing to say why. Both are now read and written back, the pin as above.
  Since sing-box checks the pin from 1.15, on an older core such a connection still fails, and the
  Apply review names the version it needs. A link whose pin is not a SHA-256 hash (Hysteria's
  documentation example carries `pinSHA256=deadbeef`) is refused with that reason instead of being
  imported with a pin nothing could match.
- **A backup too large to upload says so.** A backup over the 16 MiB upload limit, which large
  address-list caches can produce, was refused as "invalid JSON", as if the file were damaged. Both
  restore routes now answer that it is larger than the 16 MiB limit.
- **Hysteria2 speeds from Clash and mihomo configs are read in the right unit.** `up` and `down`
  were read up to the first non-digit, so "1 Gbps" became 1 Mbps and "10 MBps" (megabytes) 10 Mbps.
  They are now read as mihomo reads them: a bare number is Mbps, "1 Gbps" is 1000 Mbps and
  "10 MBps" is 80 Mbps.
- **A redirected subscription download no longer passes the subscription link on.** When a
  provider answered the import or the scheduled refresh with a redirect, WayHop sent the full
  subscription URL, with the account token in it, as `Referer` to wherever it was redirected (a
  CDN, for example). No `Referer` is sent on a redirect now; the same goes for the other downloads
  from addresses you give (routing-list sources and the watchdog webhook).
- **Keenetic: WayHop can create the router's own WireGuard and AmneziaWG tunnels.** In 0.5.7 every
  Apply that needed a new native tunnel on KeeneticOS failed at the "router-native tunnels" step
  before anything was sent: the check on the commands WayHop sends to the router refused the
  indented peer settings (`endpoint`, `allow-ips`, `connect`) that every such tunnel has. They are
  now accepted, and each one is sent under its own peer, as `interface WireguardN wireguard peer
  <key> endpoint …`. KeeneticOS does not print private or pre-shared keys in its configuration, so
  WayHop no longer looks for them there (that would have deleted every tunnel right after creating
  it); it checks the private key against the public key the router reports for the interface
  instead. Not yet tried on a router: that KeeneticOS takes the one-line form for `endpoint`,
  `keepalive-interval` and `connect` (a Keenetic developer has confirmed it for `allow-ips`), and
  that a created tunnel still reads back unchanged after the router reboots. Tunnels that were
  already on the router and that WayHop only uses are not affected.
- **Keenetic: a tunnel WayHop created stays where it is.** An Apply that does not change a native
  tunnel's own settings leaves it on the same `WireguardN` interface, connected, with whatever you
  attached to it in the Keenetic web UI (an access rule, for example): WayHop neither moves it nor
  sends its settings again. A tunnel whose own settings changed, or whose position among the native
  tunnels did, is created on a new interface and the old one is removed. When an Apply fails, and
  when WayHop re-applies its configuration at boot or after a failed Apply, it removes only what
  that run created, never a tunnel that was already on the router. Pointing the default route away
  from such a tunnel puts its priority back to the one it was created with, so traffic really
  leaves it.
- **Keenetic: a tunnel changed in the Keenetic web UI is never overwritten.** If the settings or the
  key of a tunnel WayHop created were changed in the Keenetic web UI, an Apply stops before
  changing anything, names the interface and says that nothing was changed (no rollback, no "could
  not be fully restored"). At boot and after a failed Apply, WayHop leaves that tunnel as it is and
  starts everything else, where it used to stop at the first step and leave sing-box down. The
  notification webhook, if one is set, is told, and Diagnostics has a row, "WayHop's KeeneticOS
  tunnels are as it created them", that reads the router each time it runs, so it clears as soon as
  the change is undone. Undo the change in the Keenetic web UI, or delete the interface there and
  Apply again to have it created anew. If the router's configuration or interface list cannot be
  read, an Apply stops the same way, having changed nothing and without a rollback; at boot and
  after a failed Apply an unreadable interface list only leaves the keys unchecked, which the log
  and that Diagnostics row say.
- **Keenetic: a native tunnel's IPv6 address is sent as an IPv6 address.** It went out as
  `ip address <address> 128`; it is now `ipv6 address <address>/<length>`, the form and the place
  in the interface's settings in which KeeneticOS prints the IPv6 address of its own WireGuard
  interfaces (all of them `/128` on the router read). Not yet tried on a router: creating a tunnel
  with an IPv6 address from WayHop, and how the router takes and prints a prefix other than `/128`,
  such as `/64`.
- **Keenetic: AmneziaWG 2.0 settings I1-I5 are sent the way the router keeps them.** Unset ones went
  out as `0` and now go out as empty values, `""`, which is how KeeneticOS prints them on its own
  AmneziaWG 2.0 interfaces. Set ones that contain spaces, such as `<b 0x…>`, went out bare, so the
  router split them and every later value landed in the wrong place; they are now quoted, as the
  router prints any value with spaces. Not yet tried on a router: creating such a tunnel from
  WayHop, the router accepting `""` and a quoted I1-I5 as input, and how it prints S3/S4 when they
  are not set (WayHop sends `0`).
- **The routing catalog no longer promises "no proxy core needed" where it is needed.** Off
  KeeneticOS a domain-list preset runs in the proxy core and is badged "needs sing-box", yet twelve
  of them still said they were carried by the router's resolver without it. Their text now says that
  on this router they run in the proxy core.
- **A sing-box left behind by a crashed daemon is stopped at start.** After an out-of-memory kill or
  a forced kill of WayHop, the old sing-box kept running on the old configuration and held its
  ports, so the new one failed at every start and the watchdog restarted it in a loop, alerting on
  each attempt. sing-box now stops together with the daemon however the daemon ends, and a new
  daemon also ends any leftover sing-box (for example one left by an older version) before it
  starts its own.
- **A plugin that crashes a few seconds after each start is slowed down.** The crash-loop backoff for
  nfqws2, ByeDPI, amneziawg-go and the Telegram bridge was reset whenever the process was seen alive
  once, so one that lived 3 to 6 seconds was restarted every 6 seconds forever. It is now reset only
  after the process has stayed up for 30 seconds.
- **No reinstall of the routing rules on top of a Keenetic firewall rebuild.** KeeneticOS rebuilds
  its firewall every two and a half minutes and WayHop's hook puts the rules back within a second. A
  check that landed inside that second took the rules for missing and reinstalled them while the hook
  was doing the same; the router logged reinstalls in bursts (five in twenty minutes) with the hook
  failing beside them. WayHop now looks again a few seconds later and reinstalls only rules that are really gone.
- **Leak protection and the Apply check now see the resolver that answers when no default is
  chosen.** Deleting the default resolver (or picking "(first resolver)") leaves the first resolver
  in the list answering every name no rule covers, routing lists sent to a tunnel included. When that
  was the router's own plain resolver, leak protection and the Apply check both let it through; the
  same setup with that resolver chosen by name was refused. Both now judge the resolver that will
  really answer, and the DNS page shows that resolver as the catch-all: the first switched-on one,
  skipping a FakeIP resolver in fast and mixed mode, where it is not used.
- **FakeIP DNS rules no longer block Apply as a plaintext leak.** A FakeIP resolver sends no query
  anywhere (the name is looked up at the tunnel exit), but the Apply check read it as a plain, direct
  lookup, so the catalog's "FakeIP (domain routing, TUN only)" setup could not be applied. In tun and
  hybrid mode, and on KeeneticOS in every mode, it now raises nothing; in fast and mixed mode
  elsewhere, where FakeIP is not used, the list is judged by the resolver it falls back to, and the
  finding says the FakeIP rule is left out instead of claiming no rule covers the list. A DNS rule
  that blocks a list is likewise no longer treated as letting its lookups through, also when it
  names extra domains, which add to the list rather than narrow it.
- **The DNS page no longer says clients cannot get around the router's DNS when IPv6 is open.**
  WayHop's DNS redirect and its DoT/DoH refusals are IPv4 only. On a LAN with a routable IPv6 address
  a device can still reach its own resolver over IPv6, yet the page reported every bypass as closed.
  It now reads the IPv6 firewall too, flags the leak risk and says which IPv6 routes are open.
  KeeneticOS's own IPv6 DNS rules, which apply only to some devices, do not count as the redirect.
  IPv6 forwarding refused outright for the LAN counts as every route shut, and an uplink whose IPv6
  default route sits in a routing table of its own is no longer taken for the LAN.
  Where IPv4 is all there is, the page now says what the DoH refusal really does: the well-known
  resolvers are refused, any other DoH resolver still gets through.
- **A routing list's IP feed can no longer send all traffic through the list's exit.** A fetched
  feed (an address or `asn:`) that carried the default route (`0.0.0.0/0`, `::/0`, or
  `::ffff:0.0.0.0/96`, the same route written as IPv6), two `/1` halves, or any other prefix
  shorter than an IPv4 /4 or an IPv6 /8 (an eighth or more of the IPv4 space, a sixteenth or more
  of the IPv6 internet) went into the list as it came. After Apply every destination went through
  the list's exit, or past every tunnel when the list goes direct; on Keenetic, where the kernel
  refuses a /0, every Apply failed until the list was switched off. A refresh now leaves such lines
  out and loads the rest of the feed. Its answer names them by list under `refused`, apart from its
  `errors`, and the panel's toasts name the list and the lines instead of counting a failure; the
  log names them too. A feed with nothing else keeps what it last loaded. A country feed's
  aggregates (ipdeny's US list carries /6 and /7 prefixes) are not such lines and still load. The
  routing-list import holds pasted prefixes to the same lengths, where it refused anything shorter
  than an IPv4 /8 or an IPv6 /16 and so dropped those aggregates, and it now judges an `::ffff:`
  prefix as the IPv4 prefix it stands for. A refresh that changed a list while reporting an error
  for it now says the list changed, where the panel said "No changes" over a list that needed Apply.
- **The panel's speed test says which way it went.** On a split-tunnel profile (no default rule, or
  a list sending Cloudflare straight out) the test's site leaves by the provider's line, and the
  result was still marked "(proxy)", as if it were the tunnel's speed. The result is now marked by
  where the rules send the test's site, and when the router chooses, a test whose site goes direct
  is measured past the proxy core, as a direct test is. When the rules send the site to a kernel
  tunnel (in hybrid mode, a list routed to an adopted `awg1`, which the core does not carry), the
  test runs bound to that tunnel, as the Telegram bot's does, and is marked with the exit's name.
  Pinning one exit of a selector for a test (the API's `id`) switches the selector only when the
  test's site is routed through it, and otherwise answers `pinned: false`.
- **The Routing page's Matched column no longer counts packets as connections.** Where the kernel
  routes a list, its counters are packets since the rules were installed; the column showed them as
  connections ("52341 conns"). The API now returns them on their own (`kernel: {packets, bytes}` for
  each list), and the column shows them as packets ("52341 pkts") until the proxy core counts a
  connection for the list, then the core's connections, each under its own unit. Diagnostics' "Lists
  matching traffic" shows each list's kernel packets where it has some, else the core's
  connections, so a hybrid router's idle kernel lists no longer hide a rule-set list's traffic
  behind "none yet".
- **Telegram tells a fail-safe rollback as the alarm it is, and its buttons act on the Test they
  show.** An automatic rollback after lost connectivity used to end as a quiet "Rolled back" edit;
  it is now the critical alert, and the message loses its Keep / Roll back buttons as soon as the
  rollback starts. Keep or Roll back pressed on an older Test's message no longer acts on a newer
  Test (the router answers WINDOW_CHANGED and the message shows the present one); a second Test
  inside the first one's window gets its own message; a double tap counts once; an outcome edit that
  fails on a network error is retried. A channel stays alerts-only whatever role it was given (its
  subscribers could press its buttons), and replies to strangers or to members of an alerts-only
  group never wait out Telegram's flood control, which could delay the owner's Keep past the window.
- **Keenetic: turning DNS interception off takes it off at once.** Switching off "Intercept clients' DNS"
  or "Break hardcoded encrypted resolvers", moving to the tun or mixed mode, or turning routing off left the rules in
  place until the router next rebuilt its firewall: clients' DNS was still answered by the router
  whatever server they asked, and DoT and DoH to the well-known public resolvers were still refused.
  They are now removed with the rest of WayHop's rules, every copy of them, including on a router
  whose rules an earlier version installed.
- **Keenetic: refused DoT and DoH stay refused after a firewall rebuild.** With "Break hardcoded
  encrypted resolvers" on, KeeneticOS rebuilding its firewall dropped the refusals, and nothing put them back until a
  later rebuild of another table, so devices could reach DoT and the public DoH resolvers and walk
  past the DNS redirect. WayHop now restores them on that rebuild (without redoing its routing
  rules), and the background check that watches WayHop's rules now also looks for the DNS redirect
  and the refusals and reinstalls them when they are gone.
- **Undo in the change review undoes what it shows.** Rules, device groups, the DNS settings and
  many field rows (keepalive, transport, kill switch, feeds, ...) could not be undone, and Discard
  all reported success while keeping them. A restored routing list or rule now returns between the
  neighbours it had, instead of at its old index (which reordered rule evaluation), and Undo on a
  Position row no longer gets refused. An Undo no longer overwrites a Settings save or a list
  refresh made meanwhile, and a restored list keeps its refresh times instead of re-fetching.
- **Keenetic: a group's routing table no longer stays on a dead member.** BusyBox `ip` lists IPv6
  routes together with IPv4 ones unless asked for one family, so after an outage moved a group's
  IPv4 table to its second member, the failover loop read the untouched IPv6 route, took the table
  for already fine, and never moved it back; IPv6 tables are now re-pointed too. The loop also
  reads the applied plan instead of the saved profile, so an unapplied edit that renumbers the
  tables can no longer make it write into another exit's table, and the Failover card no longer says
  a group "does not switch" exactly while all its members are down. With the kill switch on and
  IPv6 in use, IPv6 was dropped while the tunnel was up; it now passes.
- **Editing connections and groups.** Disabling a group member no longer offers to move it into a
  group that contains itself, and an edit refused by validation can no longer change the DNS
  settings in use. The DNS page's conflict check no longer repeats its numbers after a restart.
- **The fail-safe Test window keeps its word.** A Roll back clicked while a new Test Apply was
  starting reported success and cancelled the new window's timer, leaving an untested configuration
  live with no automatic rollback; it now leaves the new window armed. On OpenWrt, a power cut
  during a Test window left the tested settings on flash and the core stopped after boot; boot now
  rolls the Test back first. A rollback that fails no longer forgets the Test it was undoing: the
  router keeps following whichever routing it actually runs, Keep is refused until the rollback is
  finished (the panel and Telegram offer Roll back only, and Telegram alerts once), and a later
  Apply that fails restores the saved configuration rather than that Test. The window no longer
  reports "rebooting" when auto-reboot is off, a check that cannot run no longer hides a failed
  rollback, and the webhook alert names the rollback's real outcome.
- **Auto-update no longer reinstalls a release that was just rolled back.** A build that crashed on
  start was rolled back by the supervisor and then installed again every 15 minutes, each time
  stopping the proxy core for over a minute and rewriting the binary on flash. Releases the
  installers rolled back are recognised too. A second update can no longer start while the
  supervisor is still finishing the last one's rollback or clean-up, which could lose the copy a
  rollback restores; the refusal shows the router's local time. Companion and core binary installs,
  the update record and the installers' update marker are now flushed to disk in an order a power
  cut cannot break, and an install no longer leaves its copy in RAM.
- **Apply refuses a proxy core config that would not fit on the router's flash**, before writing
  anything, and says how much it needs and how much is free. Large downloaded lists sent to a proxy
  can make a config of megabytes; an Apply holds about three copies of it at its peak.
- **Files survive a power cut mid-write.** The Keenetic routing hook and its dnsmasq file, and the
  live sing-box config, were rewritten in place: KeeneticOS could run half a script, and a power cut
  could leave an empty or cut-off file. They are now written aside and swapped in by rename. Temp
  files a killed write left behind are cleaned up at the next start. A corrupt `servers.json` no
  longer stops the daemon from starting (it is set aside and logged), and two simultaneous first
  server set-ups can no longer lose one protocol.
- **Lists fed by a downloaded list now route on OpenWrt.** A list filled from a domain feed (every
  itdoginfo preset such as "RU outside" or "Google AI"), and a list filled from an IP feed when it
  went to a proxy connection or the router ran in tun mode, applied cleanly and matched nothing: the
  proxy core read only typed entries. The core now carries the downloaded entries too; in hybrid and
  fast an IP feed at a WireGuard or AmneziaWG connection stays with the kernel, as before. On a
  router without the proxy core the domain presets are now marked as needing it. The review warns
  when the core would hold more than 20,000 entries (memory, flash and check time).
- **Keenetic: duplicate firewall rules from a lock race.** The routing plane's iptables commands
  did not wait for the firewall lock, so one that met KeeneticOS's own rebuild took "busy" for
  "missing" and added the jump again (four IPv6 copies after ten hours on a test router). They now
  wait, and switching routing off removes every copy.
- **"LAN clients use the router's DNS" no longer passes on the setting alone.** It counted DNS
  interception as enforced whenever the profile asked for it, though WayHop installs the redirect
  only on KeeneticOS in hybrid and fast; it now checks that the applied plane carries it (or, on
  OpenWrt, that the firewall itself redirects port 53).
- **The review names a block list that hybrid mode can bypass.** A list that blocks by name is
  matched only in the proxy core, and in hybrid the kernel routes the address ranges of the IP lists
  before the core sees the connection, so a blocked service hosted in one of those ranges was routed
  through the tunnel while the review said "No action needed". The remedy: add the service's IP
  ranges to the block list, since a block the kernel carries wins any overlap.
- **A DNS rule naming only switched-off lists no longer applies to every query** of its type, and
  one naming a plain-text list no longer stops the proxy core's config check.
- **A rule-set compiled for a newer sing-box** is now named as such when the core stops, instead
  of advice to clear the cache, which downloads the same file again.
- **KeeneticOS in tun or mixed mode with Entware's ipset installed routed no list at all.** WayHop
  took the tools' presence for its kernel plane, which only hybrid and fast build, so neither the
  router's own routes nor the proxy core carried the lists and they left by the internet
  connection with a clean review. The plane is now counted on only in hybrid and fast.
- **sing-box no longer logs every connection's destination** on KeeneticOS's fallback core or on
  servers made by Set up Server. With no log level set, sing-box logs at trace, and its info lines
  alone name where each client connects; both now log warnings only, like the router's main core.
- **Ready for sing-box 1.16:** the TUN `stack` option, deprecated in 1.15 (sing-tun has its own
  stack now) and refused by 1.16, is left out for a 1.16+ core. Every core that still accepts it
  keeps the stack WayHop has measured (system on OpenWrt, gvisor on KeeneticOS); 1.15 only warns.
- **The per-exit reachability check names a missing tunnel interface** before it dials, instead of
  relying on the bind to fail: where the bind is ignored (the panel's demo off Linux) a missing
  interface answered through the WAN and read as reachable.
- **Editing a connection no longer drops settings the form does not show.** Saving an imported
  connection from the editor, even unchanged, turned an HTTPS proxy into plain HTTP, removed Reality
  from an AnyTLS connection, and dropped TLS fragmentation imported from a sing-box config. They are
  now kept, while a field the form does show still clears when emptied.
- **Keenetic: a WireGuard or AmneziaWG tunnel keeps its MTU and keepalive after an edit.** The
  editor stores them as the connection's own settings, which the Keenetic tunnel setup did not read.
- **A sing-box built without a protocol is caught before Apply.** OpenWrt can build sing-box without
  QUIC, WireGuard, OpenVPN or OpenConnect support; a connection needing one was accepted and then the
  whole configuration failed to load. The check now reads the core's build options, keeps such a
  connection off with the reason, and Diagnostics names it too.
- **The Telegram bot no longer hands out a pairing code before it has a token.** The code came with
  "send it to your bot" on a router that had no bot yet; the button now waits for the token, and the
  daemon refuses the request the same way.
- **Adding a preset list fetches that list only, and says when it cannot.** It used to refetch every
  feed (tens of seconds with the large RKN lists, Apply blocked meanwhile) and ignored the fetch
  errors, so a list whose feed failed was found empty only at Apply.
- **Components installs the right build on ARM and MIPS routers.** mihomo on ARM picked its `.deb`
  package, which was written out as the binary and could not run; Xray on 32-bit ARM picked the
  ARMv5 build over ARMv7; and on MIPS a hardfloat build could win over softfloat, which FPU-less
  router chips need. Distro packages are no longer candidates, the ARM level is read correctly, and
  softfloat is preferred.
- **A subscription entry that cannot load no longer blocks every Apply.** An imported connection
  missing what its protocol requires (an OpenVPN client from a sing-box config with no certificate)
  was stored enabled, and the next Apply refused the whole configuration. It is now stored disabled,
  like a protocol this router cannot carry, and the import says which entries were disabled and why.
  The scheduled subscription refresh does the same, and saving one connection by hand (a TUIC with no
  UUID, say) is refused with the missing field named instead of being accepted.
  The Subscription tab also lists why each skipped line was skipped instead of only counting them.
- **An update that does not come up is rolled back by itself.** The panel's update, the bot's,
  auto-update, an installer re-run and the panel's package-manager update are judged by a supervisor
  that outlives the daemon it replaces (`update-verify.sh` beside the config): a new build that crashes,
  hangs or does not answer with its own commit within 90 s is replaced by the previous one, once, and
  the Components page and the bot say why. A power cut inside that window is finished by the init at
  boot. After a good update on a nearly full flash the rollback copy is kept compressed.
- **A feed-installed WayHop updates from the panel.** "Update now" (and the bot's Install) runs
  `apk upgrade wayhop` / `opkg update && opkg upgrade wayhop` outside the service, with the space
  check first, a log, and on apk the same automatic rollback; demo mode changes nothing.
- **The Entware installer** keeps its rollback copy as a hard link (or `wayhop.bak.gz`), reclaims its
  own leftovers before measuring, refuses with the MiB to free, and has `--cleanup [--dry-run]`.
- **Updating on a nearly full OpenWrt overlay.** Re-running the installer (or the bootstrap) needed
  room for two more binaries and, when it ran out, left WayHop stopped with a partial `wayhop.new`
  holding the room. It now decides before stopping anything: WayHop's own leftovers are removed first,
  the rollback copy is a hard link (no extra space) or, below that, a verified `wayhop.bak.gz`, and a
  refusal says how many MiB to free and leaves the running WayHop untouched. The init restores the
  binary from the rollback copy if power is lost mid-swap. The panel's self-update needs room for the
  new binary alone (it used to ask ~31 MiB on the test router) and measures it exactly in RAM first. The
  apk package keeps one copy of the binary instead of two, and an opkg upgrade measures the file
  system the binary lands on (opkg's own check measures the root, so with /usr elsewhere it wrote a
  truncated binary and reported success).
- **A feed-installed WayHop on apk is recognised as the package's.** The panel no longer self-updates
  a binary the package database still describes as the old version; update it with
  `apk upgrade wayhop` (a targeted `apk add` keeps the installed build).
- **`install.sh --cleanup [--dry-run]`** (OpenWrt) reclaims what earlier installs and updates left
  behind without updating, keeping one rollback copy compressed.
- **The Components page no longer says a generation-2 router carries AmneziaWG with nothing to
  install.** "This router's kernel carries AmneziaWG itself" appeared over a module that cannot carry
  a single 3.x setting. The page now names the generation the router's own AmneziaWG carries next to
  the one amneziawg-go runs, and where the router's is older it offers amneziawg-go as optional,
  with what it is for and what it costs. Only a router whose own AmneziaWG is already the newest
  generation gets "nothing to install".
- **OpenWrt: the native DNS write-back preview no longer throws away settings WayHop does not
  manage.** The commands shown under "Preview write-back" deleted dnsmasq's whole server list and
  every https-dns-proxy instance and rebuilt them from what WayHop reads, which leaves out split-DNS
  entries (`/domain/address`) and every instance setting except the resolver address and port. Anyone
  who ran those commands lost their split-DNS entries, each instance's `bootstrap_dns` and the rest,
  and the preview did not say so. The commands now change each https-dns-proxy instance in place and
  leave its address and port alone, point dnsmasq at that address and port, and remove from dnsmasq's
  lists only the entries WayHop itself writes, one by one; everything else stays. Only the first
  dnsmasq instance is read and written: a second one keeps its own servers and switches instead of
  having them copied onto the first. A server bound to an interface (`address#53@wan`) keeps its
  binding. WayHop never runs these commands itself.
- **OpenWrt: the DNS loop check no longer reports a loop on every router.** It read the router's
  `/etc/resolv.conf` as the upstreams dnsmasq forwards to, but on OpenWrt that file points the
  router's own programs at the local dnsmasq (`127.0.0.1` and `::1`), so every OpenWrt router showed
  two confirmed loops. The check now reads where dnsmasq really forwards (its `server` list and,
  unless `noresolv` is on, the WAN's resolv file; on KeeneticOS the `server=` lines of the Entware
  dnsmasq), and still reports dnsmasq told to forward to the router itself. Each dnsmasq instance is
  judged on its own port, and only an address dnsmasq itself listens on counts: a local service on
  another port, such as `127.0.0.1#5053` for https-dns-proxy, another resolver on `127.0.0.1:53`
  while dnsmasq is bound to the LAN address, or a second instance on 5353 forwarding to the first, is
  not a loop. The
  result appears only in `GET /api/dns/native` for now; nothing else reads it.
- **Keenetic: AmneziaWG on older KeeneticOS runs on WayHop's own engine instead of failing every
  Apply.** WayHop treated any Keenetic with the WireGuard component as able to run AmneziaWG itself,
  but KeeneticOS before 4.2 has WireGuard and no `wireguard asc` command, so the router refused the
  tunnel and every Apply rolled back. WayHop now reads the firmware release (`firmware_release` in
  `/api/native/capabilities`): before 4.2 an AmneziaWG connection runs on WayHop's AmneziaWG engine,
  and the review says why and that updating KeeneticOS to 4.2 would let the router run it. A new one
  can be added there too: the panel offers AmneziaWG for a new connection and a pasted config, saying
  it will run on WayHop's engine and why, a subscription stores its AmneziaWG entries switched on,
  and switching one on is accepted - the save check asks the planner where the connection runs
  rather than only whether the router's own AmneziaWG can create it. If amneziawg-go is not yet
  installed, the panel and the review say to install it from the Components page. Only where WayHop's
  engine cannot run either (no `/dev/net/tun`) is the connection refused, naming both reasons. The same
  holds one step up: KeeneticOS 4.2 to 5.0 takes only the AmneziaWG 1 settings, so a connection with
  AmneziaWG 2 settings (S3/S4, H ranges, I1-I5) runs on the engine there as well, with 5.1 named as
  the release that takes them. Such a connection, and one set to run on amneziawg-go by hand, is now
  refused when switched on where the engine cannot run it (no `/dev/net/tun`), saying why the engine
  would run it; it was accepted before, though the router's own never runs it, and every Apply then
  failed to bring it up. Where the router's own creates an AmneziaWG connection, the panel no longer
  says it will run there and can be rolled back: it says that newer settings or amneziawg-go move it
  to WayHop's engine, and that the review says which. Not yet tried on such a router: the 4.2
  threshold is from Amnezia's instructions for older KeeneticOS, and the 5.1 one from reports about
  the 5.1 test releases. Routers on 5.1 or newer, and any whose release WayHop cannot read, run
  AmneziaWG where they did before.
- **OpenWrt: a WAN that is down during Apply no longer moves the router's own tunnels to sing-box.**
  With offload set to auto, software or hardware and no offload devices listed, Apply looks for the
  WAN and LAN devices to attach the flowtable to. When the WAN had no default route, that failure
  marked every router capability as unknown, so Apply dropped the reviewed plan, ran the tunnels
  through sing-box and the engine plugins instead, and left the previous router-native interfaces in
  place under the names the plugins then wanted. The failure now only turns flow offload off for that
  Apply, and the Apply says so in its warnings; the tunnels stay as reviewed.
- **Fast and hybrid routing are offered again after installing what the review asked for.** Whether
  the router can run the kernel routing plane (nftables, or ipset and iptables on KeeneticOS) and
  which flow-offload accelerator it has were checked once, when WayHop started. After running the
  install command the review prints, the review kept refusing fast and hybrid until WayHop was
  restarted, even with a refresh, while the panel's routing mode list already offered them; a
  flow-offload module installed later was never used either. Both are now checked again
  with the rest of the router capabilities, at most five minutes apart and on every refresh.
- **A wrong router clock is no longer reported as an untrusted certificate.** After a power cut a
  router without a battery-backed clock starts with the wrong time, and every secure exit fails with
  "certificate has expired or is not yet valid". The card for a down exit, the Test button and the
  bot's exits view named that "TLS certificate verification failed" and suggested turning on
  'insecure', which switches off certificate checking for a server that is fine. They now say the
  clock is wrong and to set it (NTP). For a router whose clock is right they tell the two cases
  apart by the end of the message: "is after" is a server certificate that has expired and is
  renewed on the server; "is before" is one that is not valid yet, usually because the server's
  clock was wrong when it was issued, so the server's clock is checked and the certificate issued
  again. A certificate the router does not trust is still reported as before.
- **Update times are shown in the router's time.** "The update was rolled back at …" (Updater page,
  the bot's /update and its start-up message) and "GitHub's request allowance is used up until …"
  were written in UTC on Keenetic and OpenWrt, three hours off on a router in UTC+3, with no zone
  shown. Both now use the router's time zone, like the bot's other times, and also name the zone
  (MSK, or an offset such as +03), which those other times do not.
- **The init scripts raise the open-files limit, and the advice for "too many open files" no longer
  breaks OpenWrt's start-up script.** It told owners to put a `limits { … }` block in the init
  script, which is not procd syntax: the script then fails to parse and WayHop does not start. The
  OpenWrt init script now sets the limit itself (`procd_set_param limits nofile="16384 16384"`, up
  from the usual 4096), the Entware one runs `ulimit -n 16384` before it starts the daemon, and the
  advice shows those lines. An init script reaches the router only with an install or a package
  upgrade (install.sh, opkg, apk): an update from the panel or the bot replaces only the binary, so
  a router updated that way keeps its old script until the owner adds the line or runs install.sh of
  this release again, and the advice says so. Other advice that named a command the routers do not
  have was corrected: `ss` (routers have BusyBox `netstat`), `modprobe` on Keenetic, a `resolvconf`
  package that neither Entware nor OpenWrt provides, `awg-quick` for a tunnel WayHop brings up with
  `ip link` and `awg setconf` (a leftover interface is removed with `ip link del`), and a TPROXY mode
  WayHop does not offer. The advice for a wrong clock no longer says WayHop warns about it at
  start-up; the Diagnostics clock check does.

## [0.5.8-r5] — 2026-10-26

A rebuild of 0.5.8-r4 with a newer Go. The product version stays 0.5.8.

### Security
- **Go 1.26.10** for every build. It fixes GO-2026-6809 in `crypto/x509` (compromised intermediate
  certificates were not distrusted), which govulncheck reports against 1.26.9 through every TLS dial
  WayHop makes.

## [0.5.8-r4] — 2026-10-26

A rebuild of 0.5.8-r3 with one fix. The product version stays 0.5.8.

### Fixed
- **A kernel exit is pinged at the address its health-check target names.** The connection editor
  offers "or 1.1.1.1 / gateway IP" as the target and calls it what the tunnel pings, but an exit the
  router carries in its kernel (an adopted or native WireGuard/AmneziaWG tunnel) was always pinged at
  1.1.1.1. An exit that does not reach 1.1.1.1 (a VPS that forwards only some networks) read Down at
  0% while it carried its traffic. A target that is an address, or a URL whose host is one, is now
  what the probe pings; a hostname or an empty target still means 1.1.1.1.

## [0.5.8-r3] — 2026-10-25

A rebuild of 0.5.8-r2 with two fixes. The product version stays 0.5.8; routers on 0.5.8-r2 see `-r3`
as the newer build.

### Fixed
- **A Keenetic can route through a tunnel it runs outside KeeneticOS.** An Entware AmneziaWG tunnel
  (such as `awg1` from 0.5.8's AmneziaWG 3.1 install) could be added as an exit, and then every
  Apply was refused with "Native Keenetic tunnel needs re-adoption", a repair that did not exist for
  it: such a tunnel has no NDM interface at all. Apply now proves instead that its live link is the
  one the connection names and that it lies outside NDM's own tunnels, and routes lists into it on
  the kernel policy plane by its device. What would need NDM to name the device (a default route on
  the connection ladder, a failover group, static routes without the kernel plane) goes to the
  compatibility core instead, as for WayHop's own userspace AmneziaWG. A Keenetic tunnel that only
  lacks its captured NDM name still asks for re-adoption.
- **The Google AI preset no longer needs the proxy core.** It shipped as a sing-box `.srs` rule-set,
  which a router in routing mode "fast" dropped with nothing routed. It is now itdoginfo's plain-text
  `google_ai.lst`, the file that rule-set is compiled from, carried by the router's own resolver.
  A Google AI list added before this keeps its old source: remove it and add the preset again.

## [0.5.8-r2] — 2026-10-19

A rebuild of 0.5.8 with one fix. The product version stays 0.5.8; routers on 0.5.8 see `-r2` as
the newer build.

### Fixed
- **The router's own VPN connections stay in step with the router.** On a Keenetic that also runs an
  Entware `awg` tunnel (as 0.5.8's AmneziaWG install allows), WayHop listed that one tunnel and none
  of the Keenetic's own: the NDM listing was read only when the `awg`/`wg` dumps found nothing, so
  connections added or deleted in the Keenetic web UI never reached the panel. Every source is now
  read every time (the dumps, `ndmc show interface`, and on OpenWrt `uci show network`, so a tunnel
  that is down is still listed). An adopted connection follows its tunnel: a new name, interface or
  peer address is picked up, and the router's label replaces a name WayHop made (never one you
  chose). A connection whose tunnel was deleted on the router is removed when it is off and nothing
  uses it; otherwise it is marked "deleted on the router" until you repoint what uses it. A new
  Keenetic tunnel that reuses a deleted one's `WireguardN` slot is told apart by its public key and
  offered as new. WayHop's own `wr_` devices are no longer offered for adoption, and a Keenetic
  tunnel that is switched on but has no handshake reads as idle rather than up.
- **The QEMU end-to-end test reads the `awg0` link from sysfs**, since `ip link show` failed on
  OpenWrt 24.10 while the tunnel carried traffic (test-only).

## [0.5.8] — 2026-10-17

### Added
- **AmneziaWG 3.1 from WayHop's own feed, kernel module included.** WayHop's CI now builds the
  newest AmneziaWG from pinned upstream commits (kernel module 3.1.20260906, tools 3.1.20260812,
  amneziawg-go 3.1.20260828) and the feed carries it: on OpenWrt `kmod-amneziawg`,
  `amneziawg-tools` with netifd's `amneziawg` protocol and `luci-proto-amneziawg`, built per release
  and target (24.10.8 and 25.12.5 on thirteen targets, listed in packaging/awg/targets.txt);
  for every other router `amneziawg-go`, and on Entware also a static `awg`. The kernel module is
  about 0.3 MB installed, which makes it the path for routers with little flash or RAM. Every build
  is tested on real OpenWrt in QEMU, a 64 MB mipsel router among them: install from the feed, an
  AmneziaWG 3.1 tunnel with every 3.1 setting, and an uninstall that leaves nothing behind.
- **`install-awg.sh`, one installer for all of it.** It picks the kernel module where the feed has
  one for the router's exact kernel and `amneziawg-go` otherwise, checks flash and RAM before
  anything is downloaded, verifies what it installed, rolls back on failure, and with `--uninstall`
  removes exactly what it added. `--dry-run` shows the plan, `--mode` forces a path,
  `--restart-network` restarts netifd so a new protocol takes effect at once. The WayHop installers
  take `--with-awg`, and the release carries the script next to `bootstrap.sh`, listed in the
  signed `SHA256SUMS.txt`.
- **Components installs AmneziaWG 3.1.** The AmneziaWG row says which path this router gets and
  why ("kernel module AmneziaWG 3.1 for OpenWrt 25.12.5 x86/64, about 0.3 MB", or userspace with
  its memory profile, or why it does not fit), installs and removes it, offers to restart the
  network service when the new protocol needs it, and says which connections still run on
  amneziawg-go and when they move to the kernel module. A running tunnel is never moved by force.
- **OpenWrt runs AmneziaWG 3 connections as its own interfaces** once its kernel module carries
  them: the header protection key, content padding, the timers, random trailers and disabling
  cookies are written to netifd only when both the module and the installed protocol handler carry
  them. Older modules keep such a connection on amneziawg-go, as before.
- **Choose the AmneziaWG engine per connection.** A connection's editor now has an AmneziaWG engine
  setting: Automatic runs it on the router's own AmneziaWG (the kernel module, or KeeneticOS's and
  OpenWrt's native tunnels) whenever that can carry its settings, as before; amneziawg-go runs it on
  the newest AmneziaWG WayHop ships (3.1) even where the router's own could carry it. The router's own
  AmneziaWG is often generation 1 or 2. The Apply review says which engine each connection runs on
  and why. A running connection moves on the next Apply, except on OpenWrt when it already runs on
  OpenWrt's own AmneziaWG: both use the same device name there, so the review asks for two Applies,
  one with the connection off and one with it back on.

### Changed
- **amneziawg-go uses a fraction of the memory.** WayHop's build caps its packet buffers and queues
  through a small patch, and WayHop sizes them by the router's RAM. Under sustained traffic on a
  test stand the peak went from over 1 GiB unpatched to about 28 MiB below 128 MB of RAM, 33-39 MiB
  below 256 MB and about 75 MiB above.
- **`awg` and amneziawg-go agree on where the userspace socket lives** through one variable,
  `AWG_SOCKET_DIR`, so netifd's fallback to amneziawg-go works with either build of `awg`.
- **Go 1.26.9** for every build, which closes the `net/http` advisories reported against 1.26.6.

### Fixed
- **The feed page's apk line works.** It lacked `/packages.adb`, so apk 3 read it as an old-style
  repository and fetched an index that does not exist. The Entware snippet no longer runs
  `opkg-key`, which writes under `/etc` and does nothing there: Entware does not check feed
  signatures.
- **Self-update and the amneziawg-go list read only `v` releases.** The AmneziaWG package releases
  (`awg-v…`, never marked latest) cannot be mistaken for a WayHop version.
- **The Components page no longer says a generation-2 router carries AmneziaWG with nothing to
  install.** "This router's kernel carries AmneziaWG itself" appeared over a module that cannot carry
  a single 3.x setting. The page now names the generation the router's own AmneziaWG carries next to
  the one amneziawg-go runs, and where the router's is older it offers amneziawg-go as optional,
  with what it is for and what it costs. Only a router whose own AmneziaWG is already the newest
  generation gets "nothing to install".

## [0.5.7] — 2026-09-29

### Added
- **A Telegram bot for the router** (Settings → Telegram bot). Status, exits and the failover log
  from the phone, and alerts that read as a story: a recovery replies to its outage, a burst of
  failures is one message, quiet hours hold what can wait and sum it up afterwards. `/route` says
  where a site goes and why, `/devices` who is using the line right now, `/diag` runs the
  Diagnostics. Owners can keep or roll back a test Apply while its countdown runs, apply saved
  changes as a test, refresh lists and the subscription, receive a backup, restart, update, and run
  `/speed`: the provider's line against the route through WayHop, or against one WireGuard or
  AmneziaWG tunnel, measured bound to it so nobody's traffic moves. Chats pair with a one-time code
  or its QR code as owner, viewer or alerts only; a daily summary is optional; English, Russian and
  Ukrainian. The router long-polls Telegram, so no port is opened, and the bot can reach Telegram
  through a tunnel where it is blocked. The token is write-only.
- **AmneziaWG 3.** A `.conf` carrying the 3.x settings (header protection key, random trailers,
  disabled cookies, content padding and the new timers) imports with them instead of losing them,
  and the connection runs. Where the router's own AmneziaWG cannot carry it (KeeneticOS and
  OpenWrt's native writers stop at 2.0, and a kernel module can be older than the config needs),
  WayHop runs it on `amneziawg-go` next to the tunnels the firmware keeps. The generation is read
  from the loaded kernel module itself, never from a package version, and the review says before
  Apply which path a connection takes. Upstream publishes no `amneziawg-go` binaries, so every
  WayHop release now carries a reproducible build for each router arch (v3.1.20260828, pinned by
  commit), installed and updated from Components; on a flash too small for it the compressed build
  is stored and unpacked into RAM at start. A relaunched `amneziawg-go` gets its routing-list routes
  back, and its device MTU is lowered when padding would push a full-size packet past the path to
  the server, where the kernel drops its batched sends outright.

### Fixed
- **Apply works on a Keenetic with Entware.** Every Apply stopped at "capture - the router state
  could not be read". Entware starts its services with its own libraries first on the library path,
  and the daemon passed that on to the firmware's `ndmc`, which then failed to start
  (`system failed [0xcffd0062]`); the configuration writer, interface discovery and the capability
  probe broke the same way. The daemon is statically linked and never used the variable, so it now
  drops it before it starts anything; Entware's own tools were checked to run without it.
- **UDP and ICMP to a routed list leave through its tunnel.** sing-box's auto-redirect rewrites the
  packet mark on UDP and ICMP after WayHop has classified the packet, so on a kernel-routed list
  every UDP service, calls included, and every traceroute left by the WAN while TCP to the same
  address went through the tunnel. The classification is now applied again after the engine's chain
  for UDP and ICMP; TCP is untouched.
- **The dashboard no longer shows the router's own WAN address as a tunnel's exit.** On a gateway
  router the engine's transparent redirect caught the exit probe before it entered the tunnel and
  answered with the uplink's address, flag and provider included. The probe now carries the
  engine's bypass mark, an answer equal to the router's own exit is not believed, and the probe
  leads with an echo service that is not behind Cloudflare. A kernel tunnel that records no server
  address falls back to its live peer instead of vanishing from the grid.
- **Each tunnel's exit tile is measured through the device the router runs it on**, taken from the
  applied plan as the health monitor and the bot's speed test take it. An AmneziaWG tunnel imported
  from a `.conf` and a tunnel a native Apply created under its own name were never measured before,
  and an interface edited but not yet applied was probed in place of the tunnel's.
- **Update on a package-managed component updates it.** On apk routers the panel ran
  `apk add <package>`, which keeps the installed build and exits 0, and reported success. Each
  action now has its own command, the command shown is the one that runs, and afterwards the panel
  says so when the build did not move.
- **A component that does not fit twice can still be updated.** A package manager writes the new
  build beside the old one, so on a small overlay an upgrade could never succeed. When the new build
  fits only in the room the installed one holds, the panel plans removal then install, shows the
  arithmetic, asks before taking the core down and restarts it afterwards; when not even that fits,
  it says how much must be freed.
- **Remove and Roll back are offered for a package-managed component**; no control led to them, so
  an engine owned by opkg or apk could only be removed over SSH.
- **A component that matches its feed no longer reports that no repository offers it.**
- **A routing list given a new feed is fetched within the hour.** The refresh loop kept the list's
  old schedule, so the new feed waited up to its interval (a day by default) while the list held
  nothing and Apply refused it. A feed that has never loaded is now asked on every hourly pass
  until it does, and after a restart a list with a name feed only is scheduled from that feed's
  last load instead of being fetched again at every boot.
- **A feed's credentials stay out of the log and the panel's errors.** A failed list refresh wrote
  the feed's full address, user, password and tokens included, to the log, the refresh answer and
  the lists' status; the address is now cut to its host there.
- **Speed tests run one at a time.** Two started together shared the line and each reported about
  half of it; the second is now refused with "a speed test is already running". A test that asks for
  the direct path is no longer carried into sing-box by the engine's transparent redirect on a
  gateway router; it leaves by the router's own routes, over IPv4.
- **An SSH port outside 1-65535 is refused when a server is saved**, naming the field. Any value an
  integer could hold was stored before, and the first symptom was a dial failing much later, during
  provisioning, with an error that named neither the field nor the value.
- **A share link carrying a bare IPv6 address is refused, and the message says what to do**
  (`[2001:db8::1]:443`). It used to import "successfully" as a server that cannot exist — `::1`
  became host `:` on port 1 — and the generated config carried that into both server and SNI.
- **Engine log lines reach `logread` and the Diagnostics page without colour codes.** sing-box
  colours its output unconditionally and has no switch for it; the escape sequences are stripped on
  the way through, including one split across two writes.
- **"Depended on by" names each routing list once**, listing every role it plays — routes through
  this exit, downloads its list through it — instead of printing the same list twice.

### Removed
- `POST /api/qr`, a server-side QR renderer no screen ever called, and with it the only dependency
  outside `golang.org/x` (`go-qrcode`). The Clash-Meta config renderer, complete but never wired to
  a route, is set aside the same way. Both are parked, not deleted, and can return with a caller.
- Code the daemon could not reach: the functions named by the reachability analyzer, the unused
  Keenetic `kernel.go` plane with its tests, and five panel functions left behind by the page-chunk
  split (about 1.7 KB less initial payload).

## [0.5.6] — 2026-08-22

### Added
- **Full UI translation.** 321 strings that had been left in English while their wording settled are
  now translated into all nine languages (Russian, Ukrainian, Belarusian, German, Spanish, French,
  Portuguese, Turkish, Persian). Plural forms follow each language's own rules rather than a
  singular/plural guess.
- **"IPv6 works where it is routed"** — a diagnostics row that answers the question the IPv6-leak row
  deliberately left open. A router whose IPv6 default route egresses a tunnel that does not actually
  carry IPv6 will fail its own outbound requests — routing-list refreshes, update checks, engine
  downloads — intermittently, depending on which address a resolver hands back first. The row says so
  and names the two ways out.
- **"Latency limits one connection"** — the arithmetic behind a download that looks stalled but is
  not. A single TCP connection cannot exceed its receive window divided by the round trip, and when
  the far end answers without window scaling that window is pinned at 64 KB. On a distant exit this
  caps one connection well below the link's capacity; the row states the ceiling for the fastest
  exit currently answering, and says to use several connections for large files.
- **Routing lists report when they were last CHECKED**, not only when they last changed. A list whose
  upstream is stable is fetched every cycle and written to disk by none of them (rewriting identical
  bytes costs router flash), which made a working refresh read as one that had not run in days.

### Changed
- **One number decides "is there room to install"**, shared by the Components page and the
  diagnostics battery. They previously judged the same disk by two different thresholds, so the same
  free space could read as "enough" on one page and "little room" on the other.
- The storage row now says which question it answered: above the space needed to replace WayHop but
  below what a component install needs, it passes and says so rather than reporting a bare
  "enough free space".
- Counters are pluralised properly. "1 pending changes" is gone; languages with three plural forms
  get three.

### Fixed
- **The OpenWrt installer finishes.** It called two command-line flags the daemon no longer has, so
  every OpenWrt install exited 2 with the binary and config already written and the service never
  started — and the retry diagnosed it as a datapath mismatch, sending the user to verify a problem
  that did not exist. The flags were removed from the Entware installer and the package scripts a
  while ago; the tarball installer, which is what the one-line command runs, was missed. The check
  that should have caught it listed the flags we remembered to delete, in the files we remembered to
  look at; it now derives the permitted set from the daemon's own flag definitions and checks every
  script that runs the binary.
- **One command now installs a working router, not a panel with a to-do list.** Piped from `curl`
  there is no terminal to answer prompts, so every prompt took its default — and the default for
  "install the missing routing packages" was no. The router ended up without `ip`/`nft`/`ipset` and
  the kernel plane had nothing to write with. Those packages, and sing-box, are now installed by
  default. On OpenWrt sing-box is skipped when the overlay has less than 25 MB free, because filling
  a 16 MB flash is how an installer takes a router down.

- **The diagnostics filter filters.** Typing a check's name marked the non-matching rows hidden and
  left every one of them on screen: the `hidden` attribute lost to an explicit `display` rule, so the
  field looked dead. A global rule now makes the attribute win everywhere, which also retires two
  earlier one-selector patches for the same defeat.
- **The router is no longer reported as a client bypassing its own DNS.** Connection tracking writes
  IPv6 expanded while the interface list reports it compressed, so one address in two spellings never
  matched and the router's own encrypted resolver was flagged as a LAN device evading the panel.
- **Domain-based routing lists say when nothing is enforcing them.** Those lists work by the router
  answering the client's DNS; where interception is not in force, a client that asks another resolver
  gets a different address for the same name and its traffic leaves the ordinary way, silently.
- Deleting a failover group now lists every object still pointing at it instead of refusing with one
  reason at a time, and deleting a connection mentions group removal only when a group actually holds
  it.
- Saving a broken profile reports every reference problem at once, so a review cycle no longer fixes
  them one per pass.
- A router refusing to start against a foreign configuration directory now names the directory it
  requires.

## [0.5.5] — 2026-07-25

### Added
- **Per-interface throughput graph** — the dashboard's Internet graph now draws one colour-keyed line
  per tunnel from live `/proc/net/dev` counters, with a hover crosshair + readout of every interface's
  rate at the pointed moment, over a fixed 5-minute scrolling window with a nice-stepped Y axis and
  gently smoothed lines.
- **Per-egress exit tiles** — one tile per enabled exit showing its name, the real WAN exit IP (a live
  per-egress probe on the router, else the connection's server address), country flag, provider, a
  green/red health ring, and its live throughput. Proxy exits (VLESS/SOCKS, no kernel interface) get
  their rate from the sing-box Clash API.
- **Check config** on each connection — validates that one connection's config compiles + passes
  `sing-box check`, replacing the per-row Share/QR export.
- **RAM-only traffic history** — a fresh dashboard seeds the graph with the last few minutes from an
  in-memory ring (`GET /api/system/recent`); nothing is written to flash.
- **Ukrainian + Belarusian** UI translations.

### Changed
- The on-demand **Speedtest** moved from the dashboard to Diagnostics (the graph already shows live
  throughput continuously).
- Quieter 1px exit-tile health rings, uniform tile heights, and the graph/exit-tile palette trimmed to
  eight distinct hues.

### Fixed
- Eight dashboard bugs from an adversarial bug-hunt: stale per-outbound rates on a Clash outage, the
  graph Y-axis/lines not clipped to the visible window, stale series lingering, a first-sample
  over-report, exit-tile dot-colour collisions, an exit bound to a non-tunnel interface stuck on "—",
  and a redundant 1 Hz poll — plus a stray graph-hover crosshair on keyboard navigation.

### Removed
- Per-row throughput sparklines under the failover/connection rows (the exit tiles carry the live rate now).
- **The Plugins catalog and the IPTV module are deferred and no longer ship.** They were already absent
  from the panel — no navigation entry, no route, no mounted `/api/features` or `/api/iptv/*` — while
  ~5.9k lines of backend still compiled into every binary behind a setter nothing called. The code is
  preserved in the development repository, out of the build and out of this one, and the translations
  for those screens are gone from the shipped dictionaries. This retracts the **IPTV plugin** entry
  under 0.5.0 below: that feature is not available in 0.5.5. `internal/plugin` — the AmneziaWG and
  olcRTC engine manager, and `/api/plugins` — is a different subsystem and is unaffected.

## [0.5.4] — 2026-07-23

### Fixed
- Correctness fixes and IPv6 teardown hardening; built on Go 1.26.5; CHANGELOG + release-CI hardening.

## [0.5.3] — 2026-07-22

### Added
- **Signed releases** — the release manifest (`SHA256SUMS.txt`) is signed with usign (openssl-free) and
  verified on-router by the installer; applied-state v2.

### Fixed
- Security + reliability hardening from an external review + bug hunt: injection-safe endpoint
  interface/ID validation, updater install serialization, atomic backup restore, atomicfile/config/demo
  hardening, full UI i18n coverage, and a CI secret scan; installer / kernel-PBR / accessibility fixes.

## [0.5.2] — 2026-07-19

### Added
- Routing + streaming **presets**, **scheduled auto-backup**, a **redacted support bundle**, a
  Reality-destination picker, diagnostics **domain-trace** + **per-device views**, and a per-OS
  subscription page.

### Fixed
- Assorted routing/diagnostics correctness fixes.

## [0.5.1] — 2026-07-14

### Added
- **Device-group routing scope** — apply/block a routing list for only a named set of LAN devices.
- **Kernel-PBR self-heal** — the nft policy-routing plane reinstalls itself if flushed out-of-band
  (fw4 reload / adblock / https-dns-proxy).

## [0.5.0] — 2026-07-06

### Changed
- **Renamed WayHop → WayHop.** Same project, new name. The Go module, binary, service, config paths
  (`/opt/etc/wayhop`, `/etc/wayhop`, …), and self-update repository are all `wayhop` now. The installer
  **migrates an existing WayHop (or older WakeRoute) install in place** — it moves your saved config and
  runtime state to the new paths, removes the old service, and treats a running `wayhop` on the UI port
  as an upgrade — so your connections, groups, and routing rules carry over untouched. (One-time note:
  because the self-update download source is renamed too, a device on the old name needs a single manual
  reinstall to pick up the new update channel; after that, self-update tracks WayHop releases as usual.)

### Added
- **IPTV plugin** — assemble a filtered, de-duplicated M3U playlist from public country / language /
  category catalogs, your own list URLs, or Xtream Codes accounts, and serve it at a private token URL.
  A catalog picker (the same browse-and-add UX as the routing-list catalog) makes public sources one
  click; pin and keep categories, optionally probe streams for liveness, and merge EPG guide data.
  Credentials embedded in Xtream / list URLs never reach logs, error messages, or the UI.
- **Complete translations for all 13 languages** — the panel *and* the new IPTV plugin are fully
  localized (ru, zh, fa, ar, tr, vi, es, fr, de, pt, hi, ja, ko), and a CI guard now blocks a missing
  key or a dropped `{0}`/`{1}` placeholder from ever shipping.
- **Memory ceiling** — the daemon caps its own heap so it stays light on RAM-constrained routers.

## [0.4.0] — 2026-06-29

### Changed
- **Renamed WakeRoute → WayHop.** Same project, new name. The Go module, binary, service, config
  paths (`/opt/etc/wayhop`, `/etc/wayhop`, …), and self-update repository are all `wayhop` now. The
  installer **migrates an existing WakeRoute install in place** — it moves your saved config and runtime
  state to the new paths, removes the old service, and treats a running `wakeroute` on the UI port as an
  upgrade — so your connections, groups, and routing rules carry over untouched.

### Added
- **Low-memory guard for self-update** — a pre-download RAM check refuses an engine or self update that
  wouldn't fit in available memory, instead of risking an out-of-memory kill mid-install on tight routers.
- **Engine uninstall** — installed engines can be removed from the Updater (the running core and
  source-only engines are guarded).

## [0.3.7] — 2026-06-28

### Added
- **Source-based routing** — route by *who's asking*, not just where to. A routing rule can now
  match the **source**: a device IP or subnet, a MAC address, a LAN interface, or a source port —
  so you can send one device (or your whole guest network) out a specific tunnel while everything
  else routes normally, and combine it with the usual destination match. Enforced natively in the
  kernel (nftables on OpenWrt, iptables + ipset on Keenetic / Entware) and by sing-box in TUN mode,
  with the anti-loop and kill-switch carve-outs preserved.
- **Network pickers for routing rules** — two read-only endpoints (`/api/interfaces`,
  `/api/devices`) list the router's network interfaces and DHCP-leased devices, so a rule editor
  can offer dropdowns instead of hand-typed IPs / MACs / interface names.
- **Device-discovery view** — see what each LAN device has actually been reaching (per-client
  external destinations from the live connection table, with the egress each took and the sniffed
  domain where known), so you can spot a service and turn it into a routing rule instead of
  guessing its IPs.
- **DNS-bypass diagnostics** — the "Run all checks" battery now flags two silent
  rule-won't-fire causes: a source-routing rule whose interface doesn't exist, and a LAN client
  resolving names through its own public DoH/DoT resolver (which bypasses the router so
  domain-based rules never apply to it). A curated public-resolver list is available to build a
  one-click block.
- **Per-domain trace** — type a domain and see where its traffic actually goes: the resolved IPs,
  the live connections to them and the exit each took (the observed truth, from the connection
  table), plus the configured rules / lists / kernel carve-outs that reference it. Answers "why
  isn't *this* site going through the VPN" without nslookup + manual CIDR tests.
- **Correct install commands in recommendations** — when WayHop suggests installing a package
  for native routing, it now shows the command for *your* router's package manager (`apk add …` on
  newer OpenWrt, `opkg install …` elsewhere) instead of a hardcoded one.
- **Restore a routing-profile backup** — the whole routing config (endpoints, groups, rules, lists)
  can now be restored from a backup, so you can roll back a bad change or migrate a complete setup to
  another router. The download side already existed; this adds the upload/restore side, validated
  before it lands (a bad backup is rejected, your current config untouched).
- **Optional drop-on-failover for groups** — a failover or selector group can now be set to drop its
  existing connections when it switches exits, so in-flight connections move off a just-failed exit
  onto the healthy one immediately instead of hanging until they time out. Off by default, which
  keeps long-lived transfers alive across a switch.
- **Kill switch for kernel-routed groups** — a group can now be set to fail closed: if its tunnel
  goes down, traffic that was using it is dropped rather than falling back to your normal internet
  connection. Off by default; turn it on for a group whose traffic must never leave unprotected.
- **TLS handshake fragmentation (anti-DPI)** — a TLS-based connection can now split its handshake so
  a firewall that blocks by inspecting the server name in the first packet can't see it. Off by
  default; enable it on a TLS endpoint that a network is blocking by SNI. (Not used with Reality,
  which already hides the server name.)
- **AnyTLS protocol** — import an `anytls://` link (or add one by hand) and route through AnyTLS, a
  newer TLS-based protocol designed to resist traffic-analysis fingerprinting of proxied TLS.
- **Detects your router's native VPN support** — WayHop now checks which protocols your router can
  run directly in its kernel (WireGuard, AmneziaWG) versus which need sing-box, and tailors its
  install recommendations to that.
- **Route through a VPN tunnel your router already has** — if WireGuard / AmneziaWG tunnels are
  already configured on the router, WayHop can detect them and route through one directly without
  re-entering its keys. It never modifies or tears down a tunnel the system owns.
- **Runs without sing-box when your setup is fully native** — a fast-mode profile that uses only
  kernel-native tunnels now runs entirely on the router's own routing, and WayHop stops sing-box
  instead of leaving it running as a redundant path — less memory and CPU for the same result.

### Fixed
- **Kill switch enforced on the iptables routing plane too** — a fail-closed group on a Keenetic / Entware
  (iptables) router could still leak to the WAN when its tunnel dropped; the fail-closed drop is now
  rendered on that plane as well, matching the nftables path.
- **Fail-safe rollback no longer double-starts sing-box** — on a fully kernel-routed (native) profile, an
  automatic rollback no longer brings a redundant sing-box core up over the kernel datapath.
- **TCP MSS clamped on tunnel egresses** — SYN packets leaving any tunnel get their MSS clamped to the path
  MTU, fixing stalls / hangs from oversized packets over WireGuard/AmneziaWG.
- **Established flows keep their tunnel** — a connection re-adopts its chosen exit from the connmark, so it
  no longer falls back to the WAN mid-connection when its destination later leaves an auto-refreshing list.
- **No routing loop for a peer IP inside a routed range** — the anti-loop bypass is now applied first and is
  terminating, so a tunnel's own server IP can't be marked back into the tunnel.
- **SSRF guards cover NAT64 / 6to4** — the subscription-fetch and reachability-probe guards now decode the
  IPv4 embedded in NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) addresses and refuse internal targets.
- **Share links import despite odd node names** — a link whose name contains `[Interface]` or olcRTC-like
  text is no longer misclassified as a `.conf` / olcRTC config and dropped.
- **Source-routed IPv6 no longer leaks to the WAN (OpenWrt)** — a rule matched only by source (a LAN
  interface, MAC address, or source port) or by a source IPv6 range marked IPv6 packets for the tunnel,
  but the OpenWrt nftables path didn't install the matching IPv6 policy rule — so those packets fell
  through to your normal internet connection instead of the tunnel. The IPv6 datapath is now emitted
  whenever the rules mark IPv6 (matching the Keenetic path), closing the leak.
- **A group's chosen exit now survives a reboot** — when a profile had failover/selector groups but
  no list-based routing, the selected member reset to the first one on every restart or config apply.
  The selection is now remembered across reboots.
- **Health and throughput now shown for kernel-routed tunnels** — a WireGuard / AmneziaWG tunnel
  routed entirely in the kernel (fast mode) previously showed Unknown health and zero traffic on the
  dashboard, because both readings came only from the proxy engine, which such a tunnel bypasses. Its
  health is now probed directly through the interface and its throughput read from the interface's own
  counters, so the dashboard and metrics reflect the real state — for the tunnels and for the failover
  groups built on them.
- **The share-safe config backup no longer leaks the subscription URL** — the default (redacted) config
  export masked the subscription token but not the subscription URL, which often embeds a per-account
  token in its path. The URL is now masked too; the full value is still included with the explicit
  "include secrets" option.
- **A configuration edit that fails to save no longer appears applied** — if writing the profile failed
  (e.g. a full router overlay), the edit stayed in memory and the panel showed it as applied while it
  silently vanished on the next reboot. A failed save now leaves the configuration exactly as it was.
- **A second Apply in quick succession can no longer trigger a stale rollback of the previous one** — if
  a new "Apply (until reboot)" landed while an earlier apply's fail-safe window was deciding to roll
  back, the old window could roll back (or even reboot) on top of the just-applied config. Each Apply
  now cleanly supersedes the previous fail-safe window.
- **Clash/mihomo subscriptions with HTTP/2 endpoints or nested failover groups now load** — two export
  defects could make a strict mihomo client reject the WHOLE subscription: an HTTP/2 endpoint's host
  was emitted as a quoted string instead of a list, and a failover group that nested an unexportable
  group left a dangling reference. Both are fixed.

### Security
- **Remote-server provisioning now rejects a malformed SSH username** — the "set up a server" form
  validated the host but not the SSH user, so a crafted username could be misread by the ssh client as
  a command-line option and run a command on the router. The user is now validated (matching every other
  SSH action), with an extra end-of-options guard on the ssh invocation as a second layer.
- **The Reality dest/SNI checker can no longer be steered at internal addresses** — its block on
  internal targets was applied at name-resolution time and could be sidestepped by a hostname that
  re-resolved to an internal IP at connect time. The check now also runs on the address actually dialed,
  matching the subscription fetcher.

## [0.3.3]

### Added
- **Subscription auto-refresh** — keep an imported subscription current automatically. Turn it
  on in Settings (pick an interval, or hit *Refresh now*) and WayHop periodically re-fetches
  the URL and adds any servers the provider has rotated in, with no manual re-import. The card
  shows when it last ran and how many connections it added.
- **Failover groups in the Clash subscription** — a Clash / Clash-Meta client subscribed to
  WayHop now receives your failover groups as real `url-test` / `fallback` / `select` groups,
  so it keeps the same automatic best-server selection the panel does instead of a flat list.
- **SSH host-key pinning for the server provisioner** — provisioning a remote VPS now pins its
  SSH host key to a persistent file (so a later changed key is caught) and prints the key's
  SHA-256 fingerprint, so you can verify it out-of-band against your provider's console.
- **A larger error knowledgebase** — Diagnostics now explains more common sing-box / AmneziaWG
  failures in plain language with a fix: config parse errors, connection-reset (DPI) drops,
  IPv6 *network unreachable*, TLS-handshake timeouts, AmneziaWG `awg-quick` DNS/route conflicts,
  and a failover tier whose health check can't reach its target.

### Changed
- **Diagnostics show how often each problem occurred** — a recurring error now carries a ×N
  count and rises to the top, so a persistent failure stands out from a one-off blip.

### Fixed
- **The Clash subscription now imports cleanly into real Clash / Clash-Meta clients** — boolean
  fields (`tls`, `skip-cert-verify`, `udp-over-tcp`) and the WARP `reserved` list are emitted in
  the exact YAML shapes the client expects; before, they were quoted in a way a strict parser
  rejected, which could fail the whole config.
- **Importing two variants of the same server no longer drops one** — e.g. a WebSocket entry and
  a Reality entry on the same host:port are kept as distinct connections (and auto-refresh
  likewise picks up a server that switched transport or TLS).
- **A corrupt or empty config no longer blocks start-up** — a zero-length `config` / `profile` /
  `servers` file (the typical result of a power loss) is recreated with defaults instead of
  bricking the panel; a failed config save no longer leaves memory and disk out of sync.
- **OpenWrt routers with AmneziaWG are no longer told to install plain WireGuard** they already
  have — the AmneziaWG kernel module carries vanilla WireGuard too.
- **Share links escape special characters** in passwords and connection names correctly.
- **A Reality connection imported with a standard-base64 public key now generates a valid config** —
  the key is normalized to the url-safe base64 the proxy core requires, so a `+/=`-style key (rather
  than the url-safe form) no longer produces a config that fails to load on apply.
- **Sturdier failover & supervision** — the Apply rollback can no longer fire twice, and the
  sing-box watchdog won't restart a core you deliberately stopped; a boot-time config-generation
  error is logged instead of silently leaving routing down.
- More accurate per-interface ping latency and per-connection speed tests.

### Security
- **Self-update is checksum-verified** — the WayHop binary is replaced only when its release
  asset's SHA-256 digest is present and matches; the update tag and release metadata are now
  validated and size-capped.
- The subscription-fetch and reachability-probe guards also block carrier-grade-NAT
  (`100.64.0.0/10`) targets, closing an SSRF gap.

## [0.3.2]

### Added
- **Flow-offload controls in Settings** — turn on the kernel/hardware fast path for general
  (non-tunnel) traffic from the Routing-mode card: Off / Software / Hardware, with optional
  device pinning (blank auto-detects the WAN uplink + LAN bridge). Your tunnel carve-outs
  (calls, VoWiFi, blocked sites) are mark-routed and automatically excluded from the
  flowtable, so they keep working while everything else gets the line-rate forwarding path.
- **Flow-offload status check** in the Diagnostics health battery — shows whether the fast
  path is active and flags the throughput left on the table when it is off.

### Changed
- **Design system** — spacing, typography and headings are now a documented token scale (a
  4px spacing grid and a six-step type scale replacing ~14 ad-hoc font sizes), for a cleaner,
  more consistent look across every page in both themes.
- **Richer empty states** — first-run placeholders show a clear title plus a short how-to
  hint instead of a single long sentence.

### Fixed
- The sidebar no longer shifts a few pixels between pages when the scrollbar appears or
  disappears (the scrollbar gutter is now reserved).
- The Add/Edit-connection form's Server/Port row no longer overflows on narrow phones.
- Mobile polish — modals use dynamic viewport height (no clipping on landscape phones),
  respect the safe-area inset, and meet the 44px touch-target minimum.
- A boot-time config-generation failure is now logged instead of silently leaving routing
  down with no trace after a reboot.

### Accessibility
- The reachability-matrix latency column conveys its quality with a non-color cue and a
  screen-reader label, not color alone.

## [0.3.1]

### Added
- **Settings backup & restore** — download the whole configuration as a file (secrets
  redacted by default, included only on request), restore it from a backup, or reset to
  defaults. Reset keeps your panel address, UI port, host allow-list and subscription
  token, so it can never lock you out.

### Changed
- **Settings page** — secret fields (Clash secret, watchdog webhook) are masked with a
  reveal toggle; client-side validation catches a bad listen/port/URL before saving; an
  unsaved-changes guard; and a clearer split between **Save** (store config) and **Apply**
  (regenerate routing), with a prompt to Apply after a routing-mode change.
- **Accurate "restart needed"** — saving reports a restart only when a startup-time field
  actually changed (bind / ports / proxy core / demo); hot fields apply without one.
- **Host allow-list is now hot** — a saved allow-list takes effect on the next request (no
  restart), and a too-narrow one is recoverable straight from the UI instead of via SSH.

### Fixed
- Config validation (`listen`/`clash` host:port, port range + uniqueness, routing-mode and
  offload enums, webhook URL) is enforced fail-closed by the API and warned-only at load.
- Persist the `offload` / `offload_devices` fast-mode settings the config API used to drop.

### Security
- Config export redacts the Clash secret, subscription token and watchdog webhook by default.

## [0.3.0]

### Added
- **Keenetic kernel-PBR backend** *(built and tested, **not wired into the apply path** — see the
  platform matrix in the README; `fast`/`hybrid` are refused on Keenetic and `tun`/`mixed` are used
  instead)* — native iptables + ipset policy routing for KeeneticOS
  routers (which ship no nftables), compiled from the same routing model as the OpenWrt path:
  `hash:net` ipsets, mangle fwmark marking, per-list `ip rule`/`ip route` tables, a 1-minute
  **load-independent failover cron** (RX-counter → WireGuard-handshake → ICMP liveness, with
  miss-hysteresis so a transient probe miss can't flap a list onto the WAN), a `netfilter.d`
  re-assert hook, and a scripted cutover/rollback that leaves the default path untouched.
- **Summarise live connections by destination IP** — each remote IP groups the ports it used,
  with per-port byte counts on hover.
- **DPI-desync engine (nfqws2)** — supervised as a long-running plugin (groundwork for a
  direct-path desync routing target).

### Fixed
- **Per-exit reachability test** now probes native kernel tunnels iface-bound
  (`curl --interface`) instead of only through the proxy core, so AmneziaWG/WireGuard exits
  report reachability correctly — with an **SSRF guard** (internal/metadata targets refused,
  the resolved public IP pinned to defeat DNS-rebind) and IPv4 preference so a v6-first host
  isn't a false negative.
- **Monitor mode** — detect an independently-running proxy core via the Clash API, so the UI
  no longer shows "core not running" while live traffic is flowing.
- **Kernel-plane forwarding correctness** — NAT forwarded LAN traffic on every failover-member
  tunnel; keep LAN/private-destination replies on the main routing table (so a re-marked reply
  can't loop back out the tunnel); and wire a symmetric IPv6 datapath so a marked v6 packet
  routes through the tunnel instead of leaking to the WAN.

## [0.2.0]

### Added
- **Diagnostics health battery** — a one-click *"Run all checks"* that fans out across the
  core, internet, tunnels, exit IP, clock, IPv6, DNS and system resources, then shows a
  verdict-first banner with expandable per-check rows (cause, fix and deep links) and a
  copyable Markdown report.
  - **Exit-IP geolocation** — the active exit's country (flag), ISP and AS number.
  - **Blocked-sites reachability** — probes representative censored hosts through every exit
    so you can see at a glance whether a tunnel still carries them.
  - **DNS-over-HTTPS health** — confirms encrypted DNS resolvers actually answer
    (DNS rcode checked, not just HTTP 200), plus **IPv6-leak** and **router clock-skew**
    checks the browser can't run itself.
  - **Per-row re-check** and a **support-grade report** with default-on redaction of public
    IPs, keys and tokens.
  - **Sortable reachability matrix** (Exit · Status · Latency) with a mobile card layout.
- **Redesigned Dashboard** — status hero, live RAM/CPU/uptime strip, per-tunnel latency
  sparklines, grouped health with severity, a live connections table with top talkers, and
  the public exit IP.
- **Kernel-native policy routing** — an optional `hybrid` mode that programs per-destination
  carve-outs directly with `nft` + `ip rule` fwmark tables, alongside the sing-box TUN gateway.
- **Self-update** — WayHop can check for and install its own releases, with opt-in auto-update.
- **Mobile-responsive panel** and additional UI translations.

### Changed
- Import/validation hardening across transports (ws/gRPC/httpupgrade), TLS/Reality/uTLS,
  TUIC ALPN, IPv6 hosts and WireGuard keys.
- Backend health probes now run concurrently.

### Fixed
- Numerous generator and config round-trip fixes.

### Security
- **Same-origin (CSRF) guard** — state-changing requests carrying a cross-origin
  `Origin`/`Referer` are rejected, so another site open in a LAN browser can't drive
  Apply / Rollback / Restart through the panel.
- **Anti-clickjacking + hardening headers** on every response — `X-Frame-Options: DENY`
  and a `frame-ancestors 'none'` CSP, plus `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer`.
- **Content-Security-Policy `script-src 'self'`** — neutralises injected/reflected scripts
  (the bundled UI loads only same-origin scripts).
- **Request-body size cap** — bounds memory so one oversized request can't OOM a low-RAM
  router and take the proxy core down with it.
- **SSRF guard** on subscription fetches — a user-supplied URL can't be turned into a
  request against the router's own control API, other LAN hosts or cloud metadata.
- **Optional Host allow-list** (`allowed_hosts`, Settings → Security) — pin which Host
  headers the panel serves, as a DNS-rebinding defense; empty (default) allows any.
- See the **Security** section of the README for the trust model. The panel is
  unauthenticated and LAN-trust by design — do not expose `:8088` to the internet without
  fronting it with authentication + TLS.

## [0.1.0] — Initial public release

First public release of WayHop: a self-hosted web panel for configuring any VPN/proxy
protocol on Entware/OpenWrt routers, with failover, health checks and live traffic graphs.

### Added
- Go daemon with the dark/light web UI embedded in a single static binary.
- **Connections** — paste-link / subscription / `.conf` import for VLESS-Reality, Hysteria2,
  TUIC, AmneziaWG, WireGuard, Shadowsocks, Trojan, VMess and more, including olcRTC.
- **Failover groups** built on sing-box `urltest`, with a watchdog that autostarts and
  crash-restarts the core with backoff.
- **Selective routing** — list-based, per-destination routing through any tunnel, namespaced
  away from an existing policy-routing setup via a dedicated fwmark + table.
- **Dashboard** with a live traffic graph and per-tunnel health, **Diagnostics** (per-tunnel
  speedtests), **Updater**, **Init Server** (SSH-provision a VPS into an endpoint) and **Settings**.
- Per-Apply fail-safe rollback and a researched error knowledgebase.
- CI: `go vet` + `go test -race`, cross-builds for `mipsle`, `mips`, `arm` v7, `arm64`, `amd64`,
  and tagged GitHub Releases with per-arch Entware + OpenWrt tarballs and `SHA256SUMS.txt`.
