# Changelog

All notable changes to WakeRoute are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- **Correct install commands in recommendations** — when WakeRoute suggests installing a package
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
- **Detects your router's native VPN support** — WakeRoute now checks which protocols your router can
  run directly in its kernel (WireGuard, AmneziaWG) versus which need sing-box, and tailors its
  install recommendations to that.
- **Route through a VPN tunnel your router already has** — if WireGuard / AmneziaWG tunnels are
  already configured on the router, WakeRoute can detect them and route through one directly without
  re-entering its keys. It never modifies or tears down a tunnel the system owns.
- **Runs without sing-box when your setup is fully native** — a fast-mode profile that uses only
  kernel-native tunnels now runs entirely on the router's own routing, and WakeRoute stops sing-box
  instead of leaving it running as a redundant path — less memory and CPU for the same result.

### Fixed
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
  on in Settings (pick an interval, or hit *Refresh now*) and WakeRoute periodically re-fetches
  the URL and adds any servers the provider has rotated in, with no manual re-import. The card
  shows when it last ran and how many connections it added.
- **Failover groups in the Clash subscription** — a Clash / Clash-Meta client subscribed to
  WakeRoute now receives your failover groups as real `url-test` / `fallback` / `select` groups,
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
- **Self-update is checksum-verified** — the WakeRoute binary is replaced only when its release
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
- **Keenetic kernel-PBR backend** — native iptables + ipset policy routing for KeeneticOS
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
- **Self-update** — WakeRoute can check for and install its own releases, with opt-in auto-update.
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

First public release of WakeRoute: a self-hosted web panel for configuring any VPN/proxy
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
