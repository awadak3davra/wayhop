package plugin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/awg"
	"wayhop/internal/model"
	"wayhop/internal/util"
)

// The userspace AmneziaWG path: amneziawg-go on /dev/net/tun, configured over its UAPI socket. It is
// what runs a tunnel the loaded kernel module is too old for - every KeeneticOS, whose NDM has no
// generation 3, and every OpenWrt whose kmod predates the config - and it needs no awg-tools at all.

const (
	// awgStartTimeout bounds the wait for a fresh amneziawg-go to serve its socket; it does so within
	// milliseconds of creating the TUN device, even on a mips router.
	awgStartTimeout = 5 * time.Second
	// awgResolveTimeout bounds resolving the peer's name, which UAPI cannot take.
	awgResolveTimeout = 5 * time.Second
	// awgStaleWait bounds the wait for an orphaned amneziawg-go to let go of its socket.
	awgStaleWait = 2 * time.Second
	// awgAssumedPathMTU is the path MTU taken when the route to the server cannot be read: Ethernet's.
	awgAssumedPathMTU = 1500
	// awgMinMTU is the smallest device MTU worth running, IPv4's minimum datagram: paddings that
	// leave less of the path than that are refused rather than run at an MTU nothing fits through.
	awgMinMTU = 576
)

// awgGOGC is the collector target amneziawg-go runs with. Its memory is its packet buffers - 64 KiB
// each, one per packet in flight whatever the packet's size - which the Go runtime pools and, at the
// default GOGC=100, lets grow to twice what is live before it collects. Measured on the pinned build
// carrying an AmneziaWG 3.1 tunnel, 1 GiB each way with the router side held to one CPU: GOGC=25 took
// a download's peak from about 100 to 64 MiB, and what stayed resident after an upload from 105-179
// to about 70 MiB, at the same throughput, for 4x the collections and 20% more allocation. Collecting
// is cheap here: the buffers hold no pointers to scan.
//
// GOMEMLIMIT is deliberately not set. Most of that memory is live - packets queued between the reader
// and the crypto workers - and no collector can free it: a 26 MiB limit made the collector run without
// pause (22,791 cycles against 12), cut the throughput to between a fifth and a half, and still let an
// upload peak at 194 MiB. Only a bound on the buffers themselves holds the peak down.
const awgGOGC = "25"

// awgRuntimeEnv is what amneziawg-go's environment adds to the daemon's: GOGC, unless the daemon was
// started with one - amneziawg-go inherits that, as the operator's choice.
func awgRuntimeEnv(environ []string) []string {
	for _, kv := range environ {
		if v, ok := strings.CutPrefix(kv, "GOGC="); ok && v != "" {
			return nil
		}
	}
	return []string{"GOGC=" + awgGOGC}
}

// awgSocket is the part of *awg.UAPI bring-up uses; a field of Manager, so tests can stand in a fake.
type awgSocket interface {
	Set(ctx context.Context, lines []awg.KV) error
	Get(ctx context.Context) (awg.Snapshot, error)
}

// dialAWG opens the socket of the amneziawg-go serving p's interface. It takes the proc rather than
// the name so a test's fake can answer the way the real socket does - only while p's process lives.
func dialAWG(p *proc) (awgSocket, error) {
	u, err := awg.NewUAPI(p.iface)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// awgDecide picks the path for an endpoint from what the router can do and what the config needs.
func (m *Manager) awgDecide(e model.Endpoint) awg.Decision {
	return AWGDecision(m.awgProbe(), m.awgFirmwareKernel, e)
}

// AWGDecision is the path the plugin takes for an AmneziaWG endpoint on a router probed as probe, as a
// pure function so the Components page shows the answer the plugin acts on rather than a second
// opinion about it. firmwareOwned is FirmwareOwnsAWGKernel: the module is the firmware's and never
// used. The probe's netlink query also loads an installed but unloaded module: the module declares
// MODULE_ALIAS_GENL_FAMILY, and the controller request_module()s an unknown family before it answers,
// so "no module" here means none is installed. When the probe itself fails (the Windows demo build, a
// kernel without generic netlink) the kernel path is kept - what ran before this path existed.
func AWGDecision(probe awg.Probe, firmwareOwned bool, e model.Endpoint) awg.Decision {
	if firmwareOwned {
		if !probe.TUN {
			return awg.Decision{Path: awg.PathUnavailable, Reason: "this router's firmware owns the AmneziaWG kernel module, and /dev/net/tun is missing, so amneziawg-go cannot run either"}
		}
		return awg.Decision{Path: awg.PathUserspace, Reason: "this router's firmware owns the AmneziaWG kernel module; using amneziawg-go on /dev/net/tun"}
	}
	if probe.Err != "" {
		return awg.Decision{Path: awg.PathKernel, Reason: "the AmneziaWG probe failed (" + probe.Err + "); using the kernel path as before"}
	}
	return awg.Decide(probe.Kernel, probe.TUN, awg.Need(e.Params))
}

// UserspaceAWGProcesses lists, sorted, the pids of the amneziawg-go processes running now - the
// resident memory the Components page reports as the component's cost. A process that has exited is
// left out at once, not at the supervisor's next tick: its pid may already belong to something else.
func (m *Manager) UserspaceAWGProcesses() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []int
	for _, p := range m.procs {
		if p.binName == "amneziawg-go" && p.running && p.cmd != nil && p.cmd.Process != nil && !procDied(p) {
			out = append(out, p.cmd.Process.Pid)
		}
	}
	sort.Ints(out)
	return out
}

// awgUserspaceUp brings an endpoint up on a fresh amneziawg-go and leaves the process supervised.
//
// Fresh, because a UAPI set keeps every key it does not mention (measured against the pinned build):
// Sync restarts a proc whose config changed, so one process only ever carries one config. The config
// is translated and the peer resolved before anything starts, so a config that cannot run leaves no
// process behind. setup is kept on the proc because a crash takes the TUN device and every setting
// with it: Supervise's relaunch runs it again.
func (m *Manager) awgUserspaceUp(p *proc, e model.Endpoint) error {
	bin, ok := m.resolve("amneziawg-go")
	if !ok {
		return fmt.Errorf("%w: amneziawg-go", errNoBinary)
	}
	ipBin, ok := m.resolve("ip")
	if !ok {
		return fmt.Errorf("%w: ip", errNoBinary)
	}
	iface := util.AWGIface(e.ID)

	ctx, cancel := context.WithTimeout(context.Background(), awgResolveTimeout)
	peer, err := awgEndpoint(ctx, m.awgLookup, e.Server, e.Port)
	cancel()
	if err != nil {
		return err
	}
	lines, warnings, err := awgUAPI(e, peer)
	if err != nil {
		return err
	}
	mtu, note, err := awgUserspaceMTU(e, lines, peer.Addr(), m.awgPathMTU(ipBin, peer.Addr()))
	if err != nil {
		return err
	}
	for _, w := range warnings {
		log.Printf("wayhop: awg %s: %s", iface, w)
	}
	if note != "" {
		log.Printf("wayhop: awg %s: %s", iface, note)
	}

	p.iface, p.note = iface, note
	m.awgClearStale(ipBin, p)
	p.binName, p.runArgs, p.runEnv = "amneziawg-go", []string{"-f", iface}, awgRuntimeEnv(os.Environ())
	p.setup = func(p *proc) error { return m.awgUserspaceSetup(p, ipBin, e, lines, strconv.Itoa(mtu)) }
	if err := launchProc(p, bin); err != nil {
		return fmt.Errorf("start amneziawg-go: %w", err)
	}
	if err := p.setup(p); err != nil {
		killProc(p)
		return err
	}
	return nil
}

// awgUserspaceSetup configures a just-started amneziawg-go: wait for its socket, send the whole
// config, then the ip-layer half the kernel path shares. A process that dies before it serves the
// socket - no access to /dev/net/tun, the name taken - is reported as that rather than as a timeout.
func (m *Manager) awgUserspaceSetup(p *proc, ipBin string, e model.Endpoint, lines []awg.KV, mtu string) error {
	sock, err := m.awgDial(p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), awgStartTimeout)
	defer cancel()
	for {
		if _, err := sock.Get(ctx); err == nil {
			break
		}
		if procDied(p) {
			return errors.New("amneziawg-go exited before it served its socket")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("amneziawg-go did not serve its socket within %v", awgStartTimeout)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := sock.Set(ctx, lines); err != nil {
		return fmt.Errorf("configure: %w", err)
	}
	return awgLinkUp(ipBin, p.iface, e, mtu)
}

// awgUserspaceMTU is the MTU amneziawg-go's device is given: the configured one (awgMTU's 1280 when
// the config has none), lowered when a packet that size would not fit the path to the server once
// amneziawg-go has wrapped it. The kernel module fragments such a packet and it still arrives.
// amneziawg-go sends in UDP GSO batches, and the kernel refuses a batch whose segments exceed the
// path - with EMSGSIZE since the patch "udp: gso: do not drop small packets when PMTU reduces", which
// amneziawg-go does not take as its cue to stop batching (it does for EIO and EINVAL) - so every such
// batch is lost. Measured on the pinned build, MTU 1420 and S4 50 over a 1500-byte veth: 3 Mbit/s and
// 13,750 retransmits; at MTU 1370, 5.5 Gbit/s and none.
//
// A packet grows by S4 (the padding in front of it), WireGuard's 32 (header and tag) and the path's
// IP and UDP headers (28, or 48 to an IPv6 server). pathMTU is the route's MTU, 0 when it could not be
// read - an Ethernet 1500 is assumed then, and the note says so. The note is for the operator: what
// runs differently from the config, and why.
func awgUserspaceMTU(e model.Endpoint, lines []awg.KV, peer netip.Addr, pathMTU int) (int, string, error) {
	s4, padsToReceived := 0, false
	for _, kv := range lines {
		switch kv.Key {
		case "s4":
			s4, _ = strconv.Atoi(kv.Value)
		case "random_trailers":
			padsToReceived = padsToReceived || kv.Value == "1"
		case "content_padding_addition":
			padsToReceived = padsToReceived || kv.Value != "0"
		}
	}
	path, assumed := pathMTU, ""
	if path <= 0 {
		path, assumed = awgAssumedPathMTU, " (assumed: the route to the server could not be read)"
	}
	ipudp := 20 + 8
	if !peer.Unmap().Is4() {
		ipudp = 40 + 8
	}
	overhead := ipudp + 32 + s4
	limit := path - overhead
	if limit < awgMinMTU {
		return 0, "", fmt.Errorf("S4 %d leaves %d bytes of a %d-byte path to the server%s for a packet; at least %d are needed", s4, max(limit, 0), path, assumed, awgMinMTU)
	}
	mtu, err := strconv.Atoi(awgMTU(e))
	if err != nil || mtu <= 0 {
		mtu = awgDefaultMTU
	}
	var notes []string
	if mtu > limit {
		notes = append(notes, fmt.Sprintf("MTU %d lowered to %d: amneziawg-go adds %d bytes to a packet (S4 %d, WireGuard's 32, IP and UDP %d), a %d-byte path%s carries no more, and the kernel drops its batched sends of anything larger", mtu, limit, overhead, s4, ipudp, path, assumed))
		mtu = limit
		if mtu < 1280 && slices.ContainsFunc(util.LocalAddrs(e.Params), func(a string) bool { return strings.Contains(a, ":") }) {
			notes = append(notes, "IPv6 inside the tunnel needs an MTU of 1280 and will not pass")
		}
	}
	// Both pad a packet up to the largest one received from the server (the peer's udpWindow, which
	// counts a received packet without its 16-byte tag), so the server's MTU bounds them too.
	if padsToReceived {
		notes = append(notes, fmt.Sprintf("RandomTrailers and ContentPaddingAddition pad packets up to the largest received, so the server's MTU must be at most %d as well", limit+16))
	}
	return mtu, strings.Join(notes, "; "), nil
}

// awgRoutePathMTU is the MTU of the route the kernel picks to peer for amneziawg-go's socket, which
// carries no mark: the route's own mtu - a PMTU exception, or one set on the route - when it has one,
// else its outgoing device's. 0 when it cannot be read.
func awgRoutePathMTU(ipBin string, peer netip.Addr) int {
	out, err := exec.Command(ipBin, "route", "get", peer.String()).Output()
	if err != nil {
		return 0
	}
	return routeGetMTU(string(out), func(dev string) int {
		// net.InterfaceByName asks the kernel over netlink in this process's own network namespace;
		// /sys/class/net would answer for the namespace sysfs was mounted in.
		ifi, err := net.InterfaceByName(dev)
		if err != nil {
			return 0
		}
		return ifi.MTU
	})
}

// routeGetMTU reads an `ip route get` answer - iproute2's or busybox's, "203.0.113.5 via 192.0.2.1
// dev wan src 192.0.2.2 uid 0" and maybe "cache expires 580sec mtu 1400" or "mtu lock 1400" - as
// the mtu it names, else devMTU of the device it names; 0 when it names neither.
func routeGetMTU(out string, devMTU func(dev string) int) int {
	f := strings.Fields(out)
	dev := ""
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "dev":
			dev = f[i+1]
		case "mtu":
			v := f[i+1]
			if v == "lock" && i+2 < len(f) {
				v = f[i+2]
			}
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return n
			}
		}
	}
	if dev == "" {
		return 0
	}
	return devMTU(dev)
}

// awgClearStale ends an amneziawg-go a previous daemon left behind on this interface. Such an orphan
// holds the socket, and a new amneziawg-go refuses to start on a socket in use. Deleting its TUN
// device ends it - the kernel path clears a stale interface the same way - and the wait lets it
// release the socket before the new process asks for it.
func (m *Manager) awgClearStale(ipBin string, p *proc) {
	_ = exec.Command(ipBin, "link", "del", p.iface).Run()
	sock, err := m.awgDial(p)
	if err != nil {
		return
	}
	deadline := time.Now().Add(awgStaleWait)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		_, err := sock.Get(ctx)
		cancel()
		if err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	log.Printf("wayhop: awg %s: an earlier amneziawg-go still holds the socket; starting anyway", p.iface)
}

// awgEndpoint resolves the peer for UAPI, which takes an address only. The kernel path hands the name
// to `awg setconf`, which resolves it itself; here IPv4 is preferred, which is what a router without
// IPv6 transit can reach, and IPv6 is used when the name has nothing else.
func awgEndpoint(ctx context.Context, lookup func(context.Context, string) ([]netip.Addr, error), host string, port int) (netip.AddrPort, error) {
	if port <= 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("peer port %d is out of range", port)
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %v", host, err)
	}
	var v6 netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() {
			return netip.AddrPortFrom(a, uint16(port)), nil
		}
		if !v6.IsValid() {
			v6 = a
		}
	}
	if v6.IsValid() {
		return netip.AddrPortFrom(v6, uint16(port)), nil
	}
	return netip.AddrPort{}, fmt.Errorf("resolve %s: no address", host)
}

// killProc ends a proc's process and waits for its exit, leaving it not running. The TUN device of an
// amneziawg-go goes with it.
func killProc(p *proc) {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		if p.done != nil {
			<-p.done
		}
	}
	p.cmd, p.done, p.running = nil, nil, false
}
