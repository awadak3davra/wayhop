# Changelog

All notable changes to WayHop are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
