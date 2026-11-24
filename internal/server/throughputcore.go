package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
	"wayhop/internal/platform"
	"wayhop/internal/ramdir"
	"wayhop/internal/speedtest"
)

// throughputcore.go measures a connection that exists only inside the proxy core (OpenWrt, stage 3).
//
// Such a connection has no device a socket could be bound to, so the interface-bound download cannot
// reach it, and until now the panel said "no interface" and offered nothing. The core already has a
// way to send one request out one chosen exit without moving anybody's traffic: the probe inbound
// (generator/probe.go), a mixed inbound on loopback with one user per exit and a route rule per user
// ahead of every other rule. The per-exit service check uses it; the download does now.
//
// The download is the same one: speedtest.MeasureDownload with its fixed 64 KB buffer, the same
// sources, bounds, budget and classification. Only the dial differs: a TCP connection to the probe
// port, one HTTP CONNECT for the source's (already resolved, public) address as that exit's user,
// and from there the TLS of the download runs end to end through the tunnel the core opened. Nothing
// is buffered on the way: the daemon reads the body into the one buffer and drops it, the core
// relays a stream with its own fixed copy buffers, and the 4 KB reader of the CONNECT answer is
// released as soon as the answer has been read.
//
// What the figure is: the speed through that outbound as the core carries it, the core's own
// userspace cost included, which is what a client of that connection gets. It is shown on the
// connection; it does not enter an election (the kernel elector does not elect a connection without
// a link, NOTES "members that exist only inside sing-box"), so the schedule never spends budget on it:
// only the button does.
//
// OpenWrt only. On KeeneticOS the feature was tested as it is and stays as it is.

var (
	errThroughputCoreDown  = errors.New("the proxy core is not running")
	errThroughputNeedApply = errors.New("the running core has no probe user for this connection: Apply once")
	errThroughputLowMemory = errors.New("the router has too little free memory for a measurement through the proxy core")
)

// throughputCoreMemoryGate refuses a measurement through the core while MemAvailable is under the
// configured floor. What the core holds during it follows the rate, not the volume:
// relay buffers, the outbound's windows and the collector's slack, all on the router, on a button.
// Where meminfo cannot be read (not Linux) the gate does not apply; the volume cap still does.
func (s *Server) throughputCoreMemoryGate(t config.Throughput) error {
	floor := t.CoreMinFreeMB
	if floor <= 0 {
		floor = defaultCoreMinFreeMB
	}
	read := s.throughputMemAvailableOf
	if read == nil {
		read = ramdir.MemAvailable
	}
	avail, ok := read()
	if !ok || avail >= floor<<20 {
		return nil
	}
	return fmt.Errorf("%w: %d MB available, %d MB needed", errThroughputLowMemory, avail>>20, floor)
}

const (
	reasonCoreDown  = "core_down"
	reasonNeedApply = "needs_apply"

	// throughputVia values of the API.
	throughputViaInterface = "interface"
	throughputViaCore      = "core"

	coreConnectTimeout = 10 * time.Second
	// coreConnectAnswerMax bounds the proxy's answer to CONNECT: a status line and a few headers.
	coreConnectAnswerMax = 4 << 10
)

// coreExit is how to reach one exit through the core's probe inbound.
type coreExit struct {
	port           int
	user, password string
}

// throughputCoreExit says how a connection without a kernel link can be measured through the core,
// or why it cannot: errThroughputNoInterface where the path does not exist at all (not OpenWrt),
// errThroughputCoreDown, errThroughputNeedApply.
func (s *Server) throughputCoreExit(e model.Endpoint) (coreExit, error) {
	conf := s.config()
	if conf.Demo || s.detectedPlatform() != platform.OpenWrt {
		return coreExit{}, errThroughputNoInterface
	}
	if e.Engine != model.EngineSingBox && e.Engine != "" {
		return coreExit{}, errThroughputNoInterface // an engine of its own without a link: nothing carries it
	}
	running := s.throughputCoreRunningOf
	if running == nil {
		running = func() bool { return s.singbox != nil && s.singbox.Running() }
	}
	if !running() {
		return coreExit{}, errThroughputCoreDown
	}
	probe, have := runningProbeInbound(conf.SingBox.Config)
	if !have {
		return coreExit{}, errThroughputNeedApply
	}
	user := generator.ProbeUser(e.ID)
	pw, ok := probe.users[user]
	if !ok {
		return coreExit{}, errThroughputNeedApply
	}
	return coreExit{port: probe.port, user: user, password: pw}, nil
}

// coreProxyDial dials addr through the core's probe inbound as one exit's user: a connection to the
// loopback port and one CONNECT. The returned connection is the tunnel itself.
func coreProxyDial(exit coreExit) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		// Loopback: nothing to bind to, and the core's redirect does not take local destinations.
		d := net.Dialer{Timeout: coreConnectTimeout}
		conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(exit.port)))
		if err != nil {
			return nil, fmt.Errorf("proxy core's probe port: %w", err)
		}
		deadline := time.Now().Add(coreConnectTimeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = conn.SetDeadline(deadline)
		auth := base64.StdEncoding.EncodeToString([]byte(exit.user + ":" + exit.password))
		req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\nProxy-Authorization: Basic " + auth + "\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy core: %w", err)
		}
		br := bufio.NewReaderSize(&limitedConnReader{conn: conn, left: coreConnectAnswerMax}, coreConnectAnswerMax)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy core answered CONNECT badly: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("proxy core refused the connection through %s: %s", exit.user, resp.Status)
		}
		_ = conn.SetDeadline(time.Time{})
		if br.Buffered() > 0 {
			// Bytes of the tunnel that arrived with the answer (a server that speaks first): keep them.
			return &prefacedConn{Conn: conn, pre: br}, nil
		}
		return conn, nil
	}
}

// limitedConnReader reads at most left bytes from conn: the CONNECT answer cannot grow the reader.
type limitedConnReader struct {
	conn net.Conn
	left int
}

func (l *limitedConnReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errors.New("the answer to CONNECT is too long")
	}
	if len(p) > l.left {
		p = p[:l.left]
	}
	n, err := l.conn.Read(p)
	l.left -= n
	return n, err
}

// prefacedConn hands out what the handshake's reader already holds, then the connection itself.
type prefacedConn struct {
	net.Conn
	pre *bufio.Reader
}

func (c *prefacedConn) Read(p []byte) (int, error) {
	if c.pre != nil {
		if n := c.pre.Buffered(); n > 0 {
			if len(p) > n {
				p = p[:n]
			}
			return c.pre.Read(p)
		}
		c.pre = nil // released: the rest is read straight from the connection
	}
	return c.Conn.Read(p)
}

// runCoreThroughput is runBoundThroughput for a connection the core carries: the same download, dialed
// through the core's probe inbound. The source's address is resolved and checked to be public here,
// on the router, as for a bound download, so every exit is measured against the same address and a
// custom URL cannot become a probe of the LAN through the core.
func (s *Server) runCoreThroughput(ctx context.Context, exit coreExit, opts speedtest.DownloadOptions) (speedtest.DownloadResult, error) {
	dial := coreProxyDial(exit)
	resolve := throughputResolve
	opts.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		resolved, err := resolve(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("resolve public download source: %w", err)
		}
		return dial(ctx, network, resolved)
	}
	return speedtest.MeasureDownload(ctx, opts)
}

// throughputResolve turns a source's host:port into the public address to dial; tests replace it.
var throughputResolve = netdiag.ResolveProbeTarget

// throughputPathOf says how one enabled connection would be measured now: via is "interface" or
// "core", or "" with the reason it cannot be.
func (s *Server) throughputPathOf(e model.Endpoint, native map[string]string, known bool) (via, reason string) {
	if s.config().Demo || tunnelLink(e, native, known) != "" {
		return throughputViaInterface, ""
	}
	switch _, err := s.throughputCoreExit(e); {
	case err == nil:
		return throughputViaCore, ""
	case errors.Is(err, errThroughputCoreDown):
		return "", reasonCoreDown
	case errors.Is(err, errThroughputNeedApply):
		return "", reasonNeedApply
	}
	return "", reasonNoInterface
}
