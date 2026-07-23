<div align="center">

<img src=".github/assets/banner.png" alt="WayHop" width="760">

**Run any modern VPN/proxy protocol on your router — from one clean web panel, with automatic failover.**

[![License: MIT](https://img.shields.io/badge/license-MIT-22a06b?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.5.4-0097dc?style=flat-square)](../../releases/latest)
[![Go](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)](go.mod)
[![Platforms](https://img.shields.io/badge/router-OpenWrt%20%C2%B7%20Keenetic%20%C2%B7%20Entware-151c28?style=flat-square)](#install)
[![Arches](https://img.shields.io/badge/arch-mipsle%20%C2%B7%20mips%20%C2%B7%20arm%20%C2%B7%20arm64%20%C2%B7%20amd64-555?style=flat-square)](#install)

</div>

<div align="center">

<img src=".github/assets/wayhop-demo.gif" alt="WayHop web UI walkthrough" width="820">

</div>

WayHop is a **single static Go binary** (the web UI is embedded) that turns [sing-box](https://github.com/SagerNet/sing-box) into a router admin panel. Stock firmware gives you WireGuard and OpenVPN — WayHop adds the modern censorship-resistant stack (**VLESS-Reality, Hysteria2, TUIC, AmneziaWG**), one-click **failover groups**, list-based **selective routing**, live **traffic graphs**, and a one-click **diagnostics battery** — all on its own port, without touching your router's native VPN config.

> **No more hand-edited sing-box JSON, policy-routing scripts, and SSH.** Paste a share link, pick a failover order, hit Apply — and if anything breaks connectivity, it rolls back on its own.

---

## ✨ Highlights

| | |
|---|---|
| 🔌 **Any protocol, one panel** | Import VLESS-Reality, Hysteria2, TUIC, Trojan, VMess, Shadowsocks, WireGuard, AmneziaWG, and olcRTC from a share link, a `.conf` file, or a subscription URL. |
| 🔁 **Smart failover & health** | Auto-select the fastest working endpoint (`urltest`), manual selector, or strict ordered fallback — with live latency, success-rate, uptime, and **probable failure cause** read from the engine logs. |
| 🧭 **Selective routing, 20+ presets** | Route per destination by domain / IP / geo / port. One-click curated rule-sets (unblock RU sites, route Discord/Telegram/YouTube, block ads), or your own lists — with **auto-refreshing IP carve-outs** from CIDR/ASN feeds. |
| ⚡ **Native-first kernel routing** | Let the kernel route WireGuard/AmneziaWG and IP carve-outs at full speed; sing-box handles only the obfuscation protocols. *(new in 0.3.0: a kernel-PBR backend for **Keenetic**, which ships no nftables.)* |
| 🛟 **Fail-safe Apply** | Changes go live **until reboot** unless you Save. Lose connectivity and WayHop auto-reverts the previous config; optional guarded auto-reboot as a last resort. |
| 🩺 **One-click diagnostics** | Ping, traceroute, DNS-leak, IPv6-leak, DoH reachability, clock-skew, config validation, and live engine-log tailing — with fixes suggested from a built-in knowledgebase. |
| 📈 **Live dashboard** | Real-time traffic graph, per-tunnel latency sparklines, top-talkers, grouped connections by destination IP, RAM/CPU/uptime, and your public exit IP. |
| 🔒 **Hardened by default** | SSRF-guarded subscription fetches, same-origin (CSRF) guard, CSP `script-src 'self'`, clickjacking/`nosniff`/referrer headers, a 16 MiB body cap, and an optional Host allow-list. |

<div align="center">
<img src=".github/assets/dashboard.png" alt="WayHop dashboard" width="820">
</div>

<details align="center">
<summary><b>📸 More screenshots</b></summary>

| Connections | Failover |
|:---:|:---:|
| <img src=".github/assets/connections.png" width="400"> | <img src=".github/assets/failover.png" width="400"> |
| **Routing** | **Diagnostics** |
| <img src=".github/assets/routing.png" width="400"> | <img src=".github/assets/diagnostics.png" width="400"> |

</details>

---

## 📡 Protocol support

| Protocol | Transport / mode | Import from | Engine |
|---|---|---|---|
| **VLESS** (+ Reality) | TCP · WebSocket · gRPC · HTTP/2, Reality or TLS, uTLS | link · subscription · form | sing-box |
| **VMess** | WebSocket · gRPC · mKCP · h2 | link · subscription · form | sing-box |
| **Trojan** | TLS (+ WebSocket / gRPC) | link · subscription · form | sing-box |
| **Shadowsocks** | AEAD ciphers · SS-2022 | link · subscription · form | sing-box |
| **Hysteria2** | QUIC, Salamander obfs, port-hopping | link · subscription · form | sing-box |
| **TUIC v5** | QUIC, BBR/cubic, UDP relay | link · subscription · form | sing-box |
| **WireGuard** | UDP (kernel-native routing) | `.conf` · link · form | sing-box / kernel |
| **AmneziaWG** | WireGuard + junk-packet obfuscation | `.conf` · form | `amneziawg-go` plugin |
| **olcRTC** | TCP-over-WebRTC (anti-whitelist) | YAML · form | olcRTC plugin |
| **nfqws** | DPI-desync on the **direct** path (not a tunnel) | — | nfqws plugin |

Subscriptions auto-detect base64 vs. plain text, import each link independently (one bad link doesn't sink the batch), and de-duplicate by name.

---

## 🚀 Install

WayHop runs on **OpenWrt** (`opkg` ≤24.10, `apk` 25.12+, native `procd`) and on **Keenetic / generic Entware** (busybox `/opt`). CPUs: `mipsle` · `mips` · `arm` (ARMv7) · `arm64` · `amd64`. *(ARMv6/ARMv5 are refused rather than handed an ARMv7 build that would crash.)*

### One command

SSH into the router (you're usually `root`) and run:

```sh
curl -fsSL https://github.com/awadak3davra/wayhop/releases/latest/download/bootstrap.sh | sh
```

The bootstrap auto-detects your arch + platform, downloads the matching build from the latest release, **verifies its SHA-256 (mandatory — it refuses to install anything it can't verify)**, and runs the installer, which moves WayHop to a free port if `:8088` is taken and starts the service. Nothing to fill in — no `<version>`, `<arch>`, or `<package>`.

No `curl`? `wget -qO- <same-url> | sh` works too. It ends with roughly:

```
  == Done ==
  + version:  wayhop 0.5.x
  + UI is up (HTTP 200 on :8088)
  open  ->  http://192.168.1.1:8088
```

Open that URL. Options (env vars, or flags after a literal `--` on the download-then-run form):
- `WAYHOP_VERSION=v0.5.3 curl … | sh` — pin a specific version · `WAYHOP_PRERELEASE=1 …` — allow a pre-release.
- Custom UI port / other installer flags: download first, then pass them — `curl -fsSLO <url>/bootstrap.sh && sh bootstrap.sh -- --port 8089`.
- `--arch mipsle` · `--openwrt` · `--entware` — override auto-detect if it guesses wrong.

### Update

Re-run the same one command. On an upgrade the installer **keeps your existing config and UI port**, backs up the current binary, atomically swaps in the new one, and health-checks it — and if the new version doesn't come up, it **automatically rolls back** to the previous binary, restarts it, and exits non-zero. A foreign `sing-box` is never touched; only WayHop's own instance is stopped.

### Uninstall

The installer saves the uninstaller next to your config (path printed at the end). Run:

```sh
sh /opt/etc/wayhop/uninstall.sh            # OpenWrt: sh /etc/wayhop/uninstall.sh
```

It stops **only** WayHop, tears down **only** WayHop's own kernel routing (its `nft` table + fwmark `ip` rules — never a foreign one), and removes the binary + service. Your config + saved connections are **kept** by default; add `--purge` to delete them too. It reports what it kept.

### Offline / air-gapped

On a machine with internet, grab two files for your arch from the [**Releases**](../../releases/latest) page — `wayhop-<ver>-<arch>[-openwrt].tar.gz` and `SHA256SUMS.txt` — copy both to the router, then verify and install:

```sh
grep " wayhop-" SHA256SUMS.txt | sha256sum -c -            # MUST print "OK"
mkdir -p wr && tar -xzf wayhop-*.tar.gz -C wr && cd wr && sh ./install.sh
```

<details>
<summary><b>Manual tarball / package feed</b></summary>

Each CPU arch ships in two flavours on the [Releases](../../releases/latest) page:

| `uname -m` | Arch | Entware / Keenetic | OpenWrt |
|---|---|---|---|
| `mipsel` (little-endian, most MT7621) | `mipsle` | `wayhop-<ver>-mipsle.tar.gz` | `…-mipsle-openwrt.tar.gz` |
| `mips` (big-endian) | `mips` | `wayhop-<ver>-mips.tar.gz` | `…-mips-openwrt.tar.gz` |
| `armv7l` | `arm` | `wayhop-<ver>-arm.tar.gz` | `…-arm-openwrt.tar.gz` |
| `aarch64` | `arm64` | `wayhop-<ver>-arm64.tar.gz` | `…-arm64-openwrt.tar.gz` |
| `x86_64` | `amd64` | `wayhop-<ver>-amd64.tar.gz` | `…-amd64-openwrt.tar.gz` |

Download the tarball for your arch into `/tmp`, then `mkdir -p wr && tar -xzf wayhop-*.tar.gz -C wr && cd wr && sh ./install.sh`.

**Native packages.** There is a signed **opkg/apk feed** (`opkg install wayhop` / `apk add wayhop`) — see the [feed page](https://awadak3davra.github.io/wayhop-feed/). For **offline package install**, every release also attaches the packages directly: the OpenWrt/Entware `.ipk` (`opkg install ./wayhop_<ver>-1_<arch>.ipk`) and, best-effort, the OpenWrt-24.10+ `.apk` (`apk add --allow-untrusted ./wayhop-*.apk`).
</details>

### Troubleshooting

| Message you see | What to do |
|---|---|
| `ARMv6/ARMv5 … not supported` | Your CPU predates the ARMv7 build and no armv6 build is shipped — nothing was changed. |
| `SHA-256 MISMATCH` / `refusing to install` | The download was corrupt or tampered; re-run. If it persists, your network/proxy may be altering downloads. |
| `:8088` in use | The installer auto-moves WayHop to a free port (it never disables a foreign web server unless you confirm). Or set one: `sh bootstrap.sh -- --port 8089`. |
| `could not resolve … no internet` | Check connectivity/DNS, or pin `WAYHOP_VERSION=vX.Y.Z`. |
| `UI not answering on :PORT` | Give it a few seconds, then `logread 2>/dev/null \| grep wayhop`. |
| An upgrade failed | It auto-rolls-back to the previous binary and exits non-zero; the old version keeps running — check logs and retry. |

<details>
<summary><b>Build from source</b></summary>

Requires Go 1.22+. The UI is embedded in the binary, so a UI change needs a rebuild.

```powershell
./build.ps1            # Windows: cross-compile + package every arch into dist\
```
```sh
make package           # the same, on a Unix build host
```

Single-arch, by hand:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags "-s -w -X wayhop/internal/version.Version=0.5.4" \
  -o wayhop-arm64 ./cmd/wayhop
```

Run the demo UI locally (synthetic data, no sing-box needed):

```sh
go run ./cmd/wayhop --demo --listen 127.0.0.1:8088
```
</details>

---

## 🆕 What's new in 0.5.0

- **New name: WayHop** — the project formerly known as Velinx is now **WayHop**. Same tool, clearer brand. On upgrade the installer migrates your existing config and runtime state automatically (older WakeRoute installs migrate too).
- **IPTV plugin** — build a filtered, de-duplicated M3U playlist from public country / language / category catalogs, your own list URLs, or Xtream Codes accounts, served at a private token URL. A catalog picker — the same browse-and-add UX as the routing-list catalog — makes public sources one click; pin and keep categories, optionally probe streams for liveness, and merge EPG guide data. Credentials in Xtream / list URLs never reach logs or the UI.
- **Every language, fully translated** — the panel *and* the new IPTV plugin ship complete translations across all 13 supported languages, with a CI guard that blocks a missing key or a dropped placeholder from ever shipping.
- **Lighter on RAM** — the daemon caps its own heap so it stays small on tight routers.

See the [changelog](CHANGELOG.md) for the full 0.4.x / 0.3.x release history.

---

## 🧱 Architecture

```
                       ┌─────────────────────────────────────────────┐
   browser ──:8088──▶  │  wayhop daemon  (one Go binary, UI baked in) │
                       │   • model → config   • health probes            │
                       │   • fail-safe Apply   • REST + Clash API client │
                       └───────┬───────────────────────┬─────────────────┘
                               │ writes config          │ live traffic / latency
                               ▼                         │ (Clash API :9090)
                         ┌──────────────┐                │
                         │   sing-box   │◀───────────────┘
                         │  (universal  │   VLESS-Reality · Hy2 · TUIC · VMess · …
                         │    core)     │
                         └──────┬───────┘
              kernel plane      │ engine plugins (gaps only)
        ┌─────────────────┐     ├──▶ amneziawg-go   (AmneziaWG)
   LAN ─┤ fwmark + ip rule│     └──▶ olcrtc         (WebRTC tunnel)
        │  WG/AWG · WAN   │
        │  IP carve-outs  │   One core handles ~90% of protocols; dedicated binaries
        └─────────────────┘   fill the gaps. In hybrid mode the kernel routes
                              WireGuard/AmneziaWG + IP carve-outs at native speed,
                              and only obfuscation flows enter sing-box.
```

**Failover** is a first-class object built on sing-box `urltest`, watched by a daemon watchdog that autostarts the core and crash-restarts it with backoff. **Routing** coexists with an existing policy-routing setup via a dedicated fwmark + table — it only steers the traffic it marks.

---

## 🔒 Security model

**WayHop is a router LAN admin panel.** It binds `:8088` without a login, treating any LAN-connected user as a trusted operator — the same assumption stock router UIs (LuCI, the Keenetic UI) make.

> [!IMPORTANT]
> **Do not expose `:8088` to the internet.** It has no auth and returns secrets (keys, credentials) to its own UI for editing. For remote access, reach the router over a VPN, or front the panel with TLS + authentication (e.g. a reverse proxy).

Within that LAN-trust boundary the daemon still hardens against realistic LAN-adjacent attacks (a malicious page open in a LAN browser, request forgery, resource exhaustion):

- **SSRF guard** — subscription URLs can't be turned into requests against the router's own API, other LAN hosts, or cloud metadata (`169.254.169.254`).
- **Same-origin (CSRF) guard** — cross-origin `POST`/`PUT`/`DELETE` are rejected, so another tab can't drive Apply / Rollback / Restart through your browser.
- **CSP + security headers** — `script-src 'self'` (anti-XSS), `X-Frame-Options: DENY` + `frame-ancestors 'none'` (anti-clickjacking), `nosniff`, `Referrer-Policy: no-referrer`.
- **Request-body cap** — 16 MiB, so one oversized request can't OOM a low-RAM router.
- **Optional Host allow-list** — pin `allowed_hosts` in `config.json` as a DNS-rebinding defense (empty by default = allow any).

The panel is unauthenticated and LAN-trust by design: treat anyone who can reach `:8088` as an operator.

---

## ❓ FAQ

<details>
<summary><b>Which routers does it run on?</b></summary>

Anything that runs **OpenWrt** (22.x–25.x, `procd`/`fw4`) or has **Entware** under `/opt` — that includes most **Keenetic** routers running stock firmware with the Entware/OPKG add-on. CPU: MIPS (little/big-endian), ARMv7, ARM64, or x86-64. The installer auto-detects yours.
</details>

<details>
<summary><b>Will it break my stock VPN / firewall config?</b></summary>

No. WayHop runs as its own service on `:8088` and routes only the traffic it explicitly marks (its own fwmark + routing table). It coexists with the stock firewall and with other selective-routing systems — the installer detects those and asks before changing anything.
</details>

<details>
<summary><b>Do I need sing-box?</b></summary>

The UI runs without it, but you need `sing-box` present to **Apply** a proxy config. Install it via `opkg install sing-box` or drop the matching build from the [sing-box releases](https://github.com/SagerNet/sing-box/releases). WireGuard/AmneziaWG can route in the kernel without it.
</details>

<details>
<summary><b>What if an Apply breaks my connection?</b></summary>

Apply is **live-until-reboot** unless you explicitly Save. If connectivity drops, WayHop automatically rolls back to the previous config. As a last resort it can auto-reboot — but only if you opt in.
</details>

---

## 🤝 Contributing & license

Issues and PRs welcome. The codebase is protocol-agnostic at its core: adding a protocol touches `model` → `importer` → `generator` → `exporter`, and validation stays generic. CI runs `go vet` + `go test -race` and cross-builds every router arch on each push.

Licensed under the [MIT License](LICENSE). Built on the work of the MIT/Apache-licensed cores it orchestrates — sing-box, mihomo, xray, and amneziawg.
