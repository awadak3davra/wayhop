// Package plugin runs the non-sing-box "engine" binaries wakeroute orchestrates
// (AmneziaWG, olcRTC). It renders each engine's native config from the wakeroute model
// and supervises the process. sing-box reaches these via a chained SOCKS (olcRTC)
// or the awg interface (AmneziaWG — full routing is M7). Off-device (no binary)
// it degrades to needs_binary instead of failing.
package plugin

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"wakeroute/internal/model"
	"wakeroute/internal/util"
)

// Spec is one plugin to run: the endpoint + the local SOCKS port sing-box chains.
type Spec struct {
	ID        string
	Endpoint  model.Endpoint
	SOCKSPort int
}

// Status is the JSON-facing plugin state.
type Status struct {
	ID          string `json:"id"`
	Engine      string `json:"engine"`
	Running     bool   `json:"running"`
	NeedsBinary bool   `json:"needs_binary"`
	SOCKSPort   int    `json:"socks_port"`
	Reason      string `json:"reason,omitempty"` // why it isn't running, if it failed to start
}

// mtuStr / keepaliveStr prefer the typed Endpoint field (the UI's canonical home — it writes
// these there and drops the legacy Params copy on edit) and fall back to Params for not-yet-
// migrated configs, so a UI-edited AmneziaWG tunnel still has its MTU/keepalive applied at
// bring-up AND exported. Empty string = unset (omit the line).
func mtuStr(e model.Endpoint) string {
	if e.MTU > 0 {
		return strconv.Itoa(e.MTU)
	}
	return numStr(e.Params["mtu"])
}

// awgMTU is the MTU to set on an AmneziaWG kernel iface at bring-up (QW2): the configured
// value, or a safe 1280 floor when the config omits one. The kernel default (1500) fragments
// or PMTU-blackholes large packets once AmneziaWG's junk + WG encap overhead is added — a
// dominant slow-site / setup-latency cause. 1280 (the IPv6 minimum) always fits and is only
// ever locally conservative (never too large for any path); an explicit MTU still wins. The
// importer deliberately leaves the model MTU unset when the .conf omits it, so this consumer-
// side default is where the floor is applied.
func awgMTU(e model.Endpoint) string {
	if m := mtuStr(e); m != "" {
		return m
	}
	return "1280"
}

func keepaliveStr(e model.Endpoint) string {
	if e.PersistentKeepalive > 0 {
		return strconv.Itoa(e.PersistentKeepalive)
	}
	return numStr(e.Params["persistent_keepalive"])
}

// awgKeepalive is the PersistentKeepalive to set on an AmneziaWG peer (L4): the configured value,
// or a 20s default when the config omits one. An idle WG/AmneziaWG tunnel with no keepalive lets
// its NAT/firewall UDP mapping expire, so the link silently dies until new traffic forces a
// re-handshake — a dropped call/flow. 20s is the wireguard-tools convention. The importer
// deliberately leaves the model keepalive unset when the .conf omits it (conf.go), so this
// consumer-side default is where the floor is applied — mirroring awgMTU.
func awgKeepalive(e model.Endpoint) string {
	if ka := keepaliveStr(e); ka != "" {
		return ka
	}
	return "20"
}

// NativeConfig renders the engine-native config text + filename for an endpoint.
func NativeConfig(e model.Endpoint, socksPort int) (string, string, error) {
	switch e.Engine {
	case model.EngineAmneziaWG:
		return awgConfig(e), e.ID + ".conf", nil
	case model.EngineOlcRTC:
		return olcConfig(e, socksPort), e.ID + ".yaml", nil
	case model.EngineNfqws:
		// nfqws2 is argv-driven (no config file); the joined args are the "config" used for
		// change detection, and start() spawns the process from nfqwsArgs(e) directly.
		return strings.Join(nfqwsArgs(e), " "), e.ID + ".nfqws", nil
	default:
		return "", "", fmt.Errorf("no native config for engine %q", e.Engine)
	}
}

// awgOrder is the .conf line order for AmneziaWG's obfuscation params. Jc/Jmin/Jmax,
// S1/S2 and H1-H4 are AWG 1.x; S3/S4 and I1-I5 (hex "magic" packets) are the 2.0
// additions. H1-H4 may be a single value (1.x) or a "min-max" range (2.0) — numStr
// passes strings through unchanged, so both render correctly. All are optional:
// absent params emit nothing, so 1.x endpoints are unaffected.
var awgOrder = []struct{ key, name string }{
	{"jc", "Jc"}, {"jmin", "Jmin"}, {"jmax", "Jmax"},
	{"s1", "S1"}, {"s2", "S2"}, {"s3", "S3"}, {"s4", "S4"},
	{"h1", "H1"}, {"h2", "H2"}, {"h3", "H3"}, {"h4", "H4"},
	{"i1", "I1"}, {"i2", "I2"}, {"i3", "I3"}, {"i4", "I4"}, {"i5", "I5"},
}

// isIKey reports whether an awg param key is one of the I1-I5 magic-packet headers,
// which must be hex strings (never bare numbers) for `awg setconf`.
func isIKey(key string) bool {
	return len(key) == 2 && key[0] == 'i' && key[1] >= '1' && key[1] <= '5'
}

// confLine returns s truncated at the first ASCII control character (newline, CR, tab, …)
// so a crafted value can never inject extra lines into the line-based awg .conf that
// `awg setconf` parses. A key carrying "KEY\nPublicKey = <attacker>" thus collapses to the
// malformed single-line "KEY" — the tunnel fails to come up (drop-don't-brick) rather than
// smuggling in attacker-controlled cryptokey-routing directives. Validation only checks the
// key is non-empty, and a raw POST/hand-edited profile.json bypasses the importer, so this
// is the render-time guard.
func confLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return s[:i]
		}
	}
	return s
}

// normalizeWGKey re-encodes a WireGuard/AmneziaWG key (any base64 variant) as standard
// base64 WITH padding — the only form `awg`/`wg` accept. amneziawg-tools' key_from_base64
// requires exactly a 44-char std-base64 key ending in '=' (it rejects url-safe `-`/`_` AND
// unpadded keys via a std-alphabet decode), so a non-std key rendered verbatim makes the
// interface fail to come up ("awg setconf" / key parse error) while its bind_interface
// outbound still routes to the dead tunnel. A string that does not decode to a 32-byte key
// (a placeholder, or a confLine-guarded injection attempt) is returned unchanged for
// confLine to sanitize. Mirrors the generator's sing-box-side normalizeWGKey — both cores'
// WireGuard key decoders share the std-base64-with-padding rule.
func normalizeWGKey(s string) string {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return base64.StdEncoding.EncodeToString(b)
		}
	}
	return s
}

func awgConfig(e model.Endpoint) string {
	p := e.Params
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + confLine(normalizeWGKey(str(p, "private_key"))) + "\n")
	if a := util.LocalAddr(p); a != "" {
		b.WriteString("Address = " + a + "\n")
	}
	if mtu := mtuStr(e); mtu != "" {
		b.WriteString("MTU = " + mtu + "\n")
	}
	for _, j := range awgOrder {
		// I1-I5 are hex "magic-packet" strings (e.g. 0xa1b2c3d4…) with their own grammar;
		// a NUMERIC value (a raw POST /api/endpoints or a hand-edited profile.json — the
		// importer always stores I as a string) renders as a bare decimal that `awg
		// setconf` rejects, so the interface never comes up while its bind_interface
		// outbound still routes to it → silent dead tunnel. Emit I only when it is a
		// string; drop a numeric one (the iface comes up without that junk param rather
		// than failing). Jc/Jmin/Jmax/S1-S4/H1-H4 stay number-or-string (numStr).
		if isIKey(j.key) {
			if _, ok := p[j.key].(string); !ok {
				continue
			}
		}
		if v := numStr(p[j.key]); v != "" {
			b.WriteString(j.name + " = " + v + "\n")
		}
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = " + confLine(normalizeWGKey(str(p, "peer_public_key"))) + "\n")
	if psk := confLine(normalizeWGKey(str(p, "pre_shared_key"))); psk != "" {
		b.WriteString("PresharedKey = " + psk + "\n")
	}
	b.WriteString("Endpoint = " + e.Server + ":" + strconv.Itoa(e.Port) + "\n")
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	// PersistentKeepalive survives awgStrip (it is a peer cryptokey-routing field `awg setconf`
	// honors) and keeps an idle tunnel's NAT mapping from expiring. This .conf (fed to setconf) is
	// keepalive's live consumer, so awgKeepalive applies a 20s default when the config omits one (L4)
	// — without it an idle AmneziaWG tunnel silently drops behind NAT until new traffic forces a
	// re-handshake. The importer/model stays faithful (unset); an explicit value still wins.
	b.WriteString("PersistentKeepalive = " + awgKeepalive(e) + "\n")
	return b.String()
}

func olcConfig(e model.Endpoint, socksPort int) string {
	p := e.Params
	transport := str(p, "transport")
	if transport == "" {
		transport = "datachannel"
	}
	dns := str(p, "dns")
	if dns == "" {
		dns = "8.8.8.8:53"
	}
	if socksPort <= 0 {
		socksPort = 8808
	}
	return fmt.Sprintf("mode: cnc\nauth:\n  provider: %s\nroom:\n  id: %s\ncrypto:\n  key: %s\nnet:\n  transport: %s\n  dns: %s\nsocks:\n  host: \"127.0.0.1\"\n  port: %d\ndata: data\n",
		yamlDQ(str(p, "provider")), yamlDQ(str(p, "room")), yamlDQ(str(p, "key")), yamlDQ(transport), yamlDQ(dns), socksPort)
}

// yamlDQ renders s as a YAML double-quoted scalar, escaping the characters that would
// otherwise break the document or inject extra keys. A room id / crypto key / provider
// comes from an imported config or the API — untrusted free text — and the old render
// interpolated it raw (provider/transport unquoted; id/key/dns quoted but UNESCAPED), so
// a value containing a quote (e.g. `id: "a"b"`) produced invalid YAML, and an unquoted
// provider with a space/colon mis-parsed, breaking olcRTC bring-up. Backslash and
// double-quote are escaped; control chars (the API can carry them even though the
// single-line YAML importer can't) become their YAML escapes.
func yamlDQ(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}

func str(p map[string]any, k string) string {
	if v, ok := p[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func numStr(v any) string {
	switch t := v.(type) {
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		// AmneziaWG H1-H4 are 32-bit magic values that routinely exceed 2^31. When such a
		// value reaches numStr as a JSON number (an AWG endpoint created/edited via the
		// API/UI rather than .conf-imported — the importer keeps H as a STRING, see the
		// conf.go fix), `int(t)` OVERFLOWS on a 32-bit build (mipsle/mips OpenWrt +
		// Keenetic): int is int32, and int32(float64(3e9)) saturates to -2147483648, so the
		// rendered `awg setconf` header is corrupted and the handshake fails. FormatInt on
		// int64 is correct on every arch; 64-bit output is unchanged.
		return strconv.FormatInt(int64(t), 10)
	case string:
		return t
	}
	return ""
}

// --- process manager ---

type proc struct {
	engine   model.Engine
	socks    int
	config   string // last rendered config (to detect changes)
	cfgPath  string
	iface    string        // AmneziaWG: the kernel interface we created (for teardown)
	binName  string        // engine binary to (re)resolve for a supervised long-running proc (olcRTC/nfqws2)
	runArgs  []string      // argv after the binary, for (re)launch
	cmd      *exec.Cmd     // long-running (olcRTC/nfqws2)
	done     chan struct{} // closed when cmd exits (nil for one-shot awg-quick)
	running  bool
	needsBin bool
	reason   string // why it isn't running (config/exec error), surfaced in Status
	managed  bool   // a launched long-running olcRTC proc under Supervise crash-restart control
	restarts int    // consecutive crash-restarts since the last healthy tick (drives backoff)
	cooldown int    // Supervise ticks to wait before the next relaunch (crash-loop throttle)
}

// Manager supervises the running engine plugins.
type Manager struct {
	mu        sync.Mutex
	dir       string // where plugin configs are written
	binDir    string // where engine binaries live (e.g. /opt/sbin)
	procs     map[string]*proc
	lastSpecs []Spec // the most recent desired set passed to Sync (for fail-safe baseline snapshot)
}

// New builds a Manager. dir is created on first Sync.
func New(dir, binDir string) *Manager {
	return &Manager{dir: dir, binDir: binDir, procs: map[string]*proc{}}
}

// Sync reconciles running plugins to the desired set: it stops removed/changed
// plugins and (re)starts new/changed ones. Idempotent for unchanged specs.
func (m *Manager) Sync(specs []Spec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = os.MkdirAll(m.dir, 0o755)

	m.lastSpecs = append([]Spec(nil), specs...) // snapshot the desired set for Specs()

	desired := map[string]Spec{}
	for _, s := range specs {
		desired[s.ID] = s
	}

	// stop removed or changed
	for id, p := range m.procs {
		s, ok := desired[id]
		if !ok {
			m.stop(id, p)
			delete(m.procs, id)
			continue
		}
		if cfg, _, err := NativeConfig(s.Endpoint, s.SOCKSPort); err == nil && cfg != p.config {
			m.stop(id, p)
			delete(m.procs, id)
			continue
		}
		// Kept unchanged. A NOT-running proc (crashed past supervision, throttled, or
		// needs_binary because its binary was absent at start / has since been
		// installed) is re-created so a deliberate re-Apply actually re-resolves the
		// binary and restarts it — the old code left it stale until a config change or
		// daemon restart. A running proc is untouched (don't kill a healthy plugin):
		// just clear its crash-loop throttle so a re-Apply retries a backed-off one promptly.
		if !p.running {
			m.stop(id, p)
			delete(m.procs, id)
			continue
		}
		p.restarts, p.cooldown = 0, 0
	}
	// start new/changed
	for id, s := range desired {
		if _, ok := m.procs[id]; !ok {
			m.procs[id] = m.start(id, s)
		}
	}
}

func (m *Manager) start(id string, s Spec) *proc {
	cfg, fname, err := NativeConfig(s.Endpoint, s.SOCKSPort)
	p := &proc{engine: s.Endpoint.Engine, socks: s.SOCKSPort, config: cfg}
	if err != nil {
		p.reason = "native config: " + err.Error()
		return p
	}
	p.cfgPath = filepath.Join(m.dir, fname)
	if err := os.WriteFile(p.cfgPath, []byte(cfg), 0o600); err != nil {
		p.reason = "write config: " + err.Error()
		return p
	}

	switch s.Endpoint.Engine {
	case model.EngineOlcRTC:
		bin, ok := m.resolve("olcrtc")
		if !ok {
			p.needsBin = true
			return p
		}
		p.binName, p.runArgs = "olcrtc", []string{"-config", p.cfgPath} // exact flag confirmed on-device
		if err := launchProc(p, bin); err != nil {
			p.reason = "start olcrtc: " + err.Error()
			return p
		}
	case model.EngineNfqws:
		bin, ok := m.resolve("nfqws2")
		if !ok {
			p.needsBin = true
			return p
		}
		// nfqws2 listens on the NFQUEUE; the iptables divert that feeds it is the `desync` routing
		// target (kernel-PBR), applied separately. Supervised long-running, like olcRTC.
		p.binName, p.runArgs = "nfqws2", nfqwsArgs(s.Endpoint)
		if err := launchProc(p, bin); err != nil {
			p.reason = "start nfqws2: " + err.Error()
			return p
		}
	case model.EngineAmneziaWG:
		iface, err := m.awgUp(s.Endpoint, cfg)
		if err != nil {
			p.reason = "awg up: " + err.Error()
			if errors.Is(err, errNoBinary) {
				p.needsBin = true
			}
			return p
		}
		p.iface, p.running = iface, true
	}
	return p
}

var errNoBinary = errors.New("required binary not found")

// awgUp brings up an AmneziaWG interface natively — `ip link add type amneziawg`
// + `awg setconf` + address + up — instead of `awg-quick`, which OpenWrt does not
// ship (it manages AmneziaWG via ip/netifd). We deliberately do NOT install the
// peer's AllowedIPs as routes: sing-box egresses through this interface via
// bind_interface, so a default-route here would hijack the whole host. Returns the
// created interface name for teardown.
func (m *Manager) awgUp(e model.Endpoint, cfgText string) (string, error) {
	ipBin, ok := m.resolve("ip")
	if !ok {
		return "", fmt.Errorf("%w: ip", errNoBinary)
	}
	awgBin, ok := m.resolve("awg")
	if !ok {
		return "", fmt.Errorf("%w: awg", errNoBinary)
	}
	iface := util.AWGIface(e.ID)
	// `awg setconf` only understands the WireGuard/AmneziaWG crypto + peer + junk
	// fields — strip the ip-layer lines (Address/DNS/MTU) awg-quick would consume.
	sf := filepath.Join(m.dir, iface+".setconf")
	if err := os.WriteFile(sf, []byte(awgStrip(cfgText)), 0o600); err != nil {
		return "", err
	}
	defer os.Remove(sf)

	_ = exec.Command(ipBin, "link", "del", iface).Run() // clear any stale interface
	if out, err := exec.Command(ipBin, "link", "add", "dev", iface, "type", "amneziawg").CombinedOutput(); err != nil {
		return "", fmt.Errorf("ip link add %s: %v: %s", iface, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command(awgBin, "setconf", iface, sf).CombinedOutput(); err != nil {
		_ = exec.Command(ipBin, "link", "del", iface).Run()
		return "", fmt.Errorf("awg setconf: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// Add each interface address with its own `ip addr add` — a single call rejects
	// a comma-joined argument ("inet prefix is expected"), so a dual-stack config
	// (10.x/32 + fd00::x/128) would otherwise come up with NO address (broken).
	for _, addr := range util.LocalAddrs(e.Params) {
		// The iface was just re-created (link del+add above), so a failure here is real —
		// a missing address means a dead tunnel. Log it instead of swallowing it silently;
		// don't abort, since a dual-stack config may legitimately add only one family.
		if out, err := exec.Command(ipBin, "addr", "add", addr, "dev", iface).CombinedOutput(); err != nil {
			log.Printf("wakeroute: awg %s: ip addr add %s failed: %v: %s", iface, addr, err, strings.TrimSpace(string(out)))
		}
	}
	// MTU is stripped from the setconf input (awg setconf rejects it) but is a real
	// ip-layer setting; apply it here like the address, or the tunnel uses the kernel
	// default and over a constrained path large packets fragment/blackhole.
	// MTU is stripped from the setconf input (awg setconf rejects it) but is a real ip-layer
	// setting; apply it here (QW2). awgMTU returns a safe 1280 floor when the config omits one
	// so the tunnel never falls back to the kernel 1500 (which fragments/blackholes over the
	// AmneziaWG encap+junk overhead); an explicit MTU still wins.
	mtu := awgMTU(e)
	if out, err := exec.Command(ipBin, "link", "set", iface, "mtu", mtu).CombinedOutput(); err != nil {
		log.Printf("wakeroute: awg %s: set mtu %s failed: %v: %s", iface, mtu, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command(ipBin, "link", "set", iface, "up").CombinedOutput(); err != nil {
		_ = exec.Command(ipBin, "link", "del", iface).Run()
		return "", fmt.Errorf("ip link set up: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return iface, nil
}

// awgStrip removes the ip-layer lines (Address/DNS/MTU) from an awg-quick .conf so
// the remainder is valid input for `awg setconf`.
func awgStrip(conf string) string {
	var b strings.Builder
	for _, ln := range strings.Split(conf, "\n") {
		k := strings.ToLower(strings.TrimSpace(ln))
		if strings.HasPrefix(k, "address") || strings.HasPrefix(k, "dns") || strings.HasPrefix(k, "mtu") {
			continue
		}
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return b.String()
}

func (m *Manager) stop(_ string, p *proc) {
	if p.cmd != nil && p.cmd.Process != nil {
		// os.ErrProcessDone means the process already exited (e.g. crashed or was
		// reaped by the supervise goroutine) — that's the benign expected case, not
		// a failure worth logging.
		if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			log.Printf("wakeroute: plugin kill (engine=%s iface=%s): %v", p.engine, p.iface, err)
		}
		if p.done != nil {
			<-p.done // the exit-tracking goroutine owns Wait()
		}
	}
	if p.engine == model.EngineAmneziaWG && p.running && p.iface != "" {
		if ipBin, ok := m.resolve("ip"); ok {
			_ = exec.Command(ipBin, "link", "del", p.iface).Run()
		}
	}
	// Remove the rendered config — it holds secrets (WireGuard PrivateKey/PresharedKey,
	// olcRTC crypto.key) and would otherwise linger 0600 on the router overlay across
	// add/remove cycles. Best-effort; ENOENT (one-shot already cleaned, or never written) is fine.
	if p.cfgPath != "" {
		if err := os.Remove(p.cfgPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("wakeroute: plugin cfg cleanup (engine=%s iface=%s): %v", p.engine, p.iface, err)
		}
	}
	p.running = false
}

// procDied reports whether a tracked long-running plugin process has exited.
func procDied(p *proc) bool {
	if p.done == nil {
		return false
	}
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// Crash-restart throttle for the supervised olcRTC process. The watchdog calls
// Supervise once per tick (3s), so these are expressed in ticks. The first
// pluginRestartGrace crash-restarts are immediate (transient-crash resilience);
// past that the wait between relaunches doubles each crash up to pluginMaxCooldown
// (~60s, mirroring the watchdog's maxBackoff). It never permanently gives up —
// a true crash loop is merely slowed so it stops spamming the router log.
const (
	pluginRestartGrace = 3
	pluginMaxCooldown  = 20
)

// pluginBackoffTicks maps a consecutive crash-restart count to the number of
// Supervise ticks to wait before the next relaunch.
func pluginBackoffTicks(restarts int) int {
	if restarts <= pluginRestartGrace {
		return 0
	}
	shift := restarts - pluginRestartGrace - 1
	if shift >= 31 { // guard the shift against a pathological counter
		return pluginMaxCooldown
	}
	if n := 1 << uint(shift); n < pluginMaxCooldown {
		return n
	}
	return pluginMaxCooldown
}

// Supervise restarts any long-running plugin process (olcRTC, nfqws2) that has crashed,
// re-launching it from its stored binName + runArgs, with crash-loop backoff
// (see pluginBackoffTicks) so a plugin that dies every tick is throttled rather
// than relaunched ~20x/min (each relaunch would spam the router log). AmneziaWG
// uses a one-shot `awg-quick up` (interface, not a process), so it is left to M7
// routing health. Best-effort and on-device only (no-op when binaries are absent).
func (m *Manager) Supervise() {
	// Non-blocking: Sync() holds m.mu across blocking external commands (ip/awg setconf)
	// and the process reap (<-p.done), which can take seconds during an Apply/rollback.
	// The watchdog drives this on the SAME tick that crash-restarts sing-box, so blocking
	// here would delay the core's crash recovery. If a Sync is in flight, skip this tick;
	// the next (~3s) one supervises. A skipped plugin relaunch waits one tick — harmless.
	if !m.mu.TryLock() {
		return
	}
	defer m.mu.Unlock()
	for _, p := range m.procs {
		// Only launched long-running procs (olcRTC/nfqws2) are supervised here (AmneziaWG is
		// one-shot; needs_binary / failed-initial-start procs were never managed).
		if !p.managed {
			continue
		}
		if p.running {
			if !procDied(p) {
				// Alive across a full tick -> healthy -> clear the crash-loop throttle.
				p.restarts, p.cooldown = 0, 0
				continue
			}
			// Exited: retire the dead handle, then fall through to a throttled relaunch.
			p.running = false
			p.cmd, p.done = nil, nil
		}
		// Crash-loop throttle: wait out the backoff window before relaunching, and
		// surface the throttled state so the UI doesn't read it as merely idle.
		if p.cooldown > 0 {
			p.cooldown--
			p.reason = fmt.Sprintf("%s crash-looping; backing off (restart #%d)", p.binName, p.restarts)
			continue
		}
		m.relaunchProc(p)
	}
}

// launchProc spawns a supervised long-running engine process (bin + p.runArgs), wires the
// exit-tracking goroutine, and marks the proc running+managed. Shared by olcRTC and nfqws2. On a
// Start error it leaves the proc not-running (the caller sets reason) — never running on failure.
func launchProc(p *proc, bin string) error {
	cmd := exec.Command(bin, p.runArgs...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	p.cmd, p.running, p.managed = cmd, true, true
	p.done = make(chan struct{})
	go func(c *exec.Cmd, done chan struct{}) { _ = c.Wait(); close(done) }(cmd, p.done)
	return nil
}

// relaunchProc re-spawns a managed long-running proc (olcRTC/nfqws2) from its stored binName +
// runArgs and arms the next backoff window. A binary that has vanished degrades the proc to
// needs_binary and drops it from supervision (a later re-Apply re-creates and re-resolves it); a
// failed Start is throttled like a crash so it keeps retrying without log spam.
func (m *Manager) relaunchProc(p *proc) {
	bin, ok := m.resolve(p.binName)
	if !ok {
		p.needsBin = true
		p.managed = false
		return
	}
	p.restarts++
	p.cooldown = pluginBackoffTicks(p.restarts)
	if err := launchProc(p, bin); err != nil {
		p.reason = "restart " + p.binName + ": " + err.Error()
		return
	}
	p.reason = ""
}

// resolve finds an engine binary in binDir, then on PATH.
func (m *Manager) resolve(name string) (string, bool) {
	if m.binDir != "" {
		pth := filepath.Join(m.binDir, name)
		if fi, err := os.Stat(pth); err == nil && !fi.IsDir() {
			return pth, true
		}
	}
	if pth, err := exec.LookPath(name); err == nil {
		return pth, true
	}
	return "", false
}

// Status returns the current plugin states.
func (m *Manager) Status() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.procs))
	for id, p := range m.procs {
		out = append(out, Status{ID: id, Engine: string(p.engine), Running: p.running, NeedsBinary: p.needsBin, SOCKSPort: p.socks, Reason: p.reason})
	}
	return out
}

// Specs returns a copy of the most recent desired set passed to Sync. The daemon
// snapshots this at the start of a fail-safe window so a rollback can re-Sync the
// plugins that matched the pre-apply (restored) config — otherwise a rollback restores
// the sing-box config but leaves the plugins at the failed apply's set, so a restored
// outbound bind_interface'd to an awg device that the failed apply tore down runs dead.
func (m *Manager) Specs() []Spec {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Spec(nil), m.lastSpecs...)
}

// StopAll stops every plugin (daemon shutdown).
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, p := range m.procs {
		m.stop(id, p)
	}
	m.procs = map[string]*proc{}
}
