package awg

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Keys are built from 16-character runs so no key-shaped hex literal sits in the source.
var (
	testKey  = strings.Repeat("0123456789abcdef", 4)
	peerKey  = strings.Repeat("fedcba9876543210", 4)
	otherKey = strings.Repeat("89abcdef01234567", 4)
	zeroKey  = strings.Repeat("0", 64)
)

// pipeUAPI is a UAPI whose every connection reaches serve over an in-memory pipe, so the protocol
// is checked byte for byte without a socket. serve gets the request as upstream would frame it.
func pipeUAPI(serve func(req string, conn net.Conn)) *UAPI {
	u := &UAPI{iface: "wr_1a2b3c4d", path: "(pipe)"}
	u.dial = func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			serve(readRequest(server), server)
		}()
		return client, nil
	}
	return u
}

// readRequest reads one request the way upstream's IpcHandle does: lines up to an empty one.
func readRequest(c net.Conn) string {
	r := bufio.NewReader(c)
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		b.WriteString(line)
		if err != nil || line == "\n" {
			return b.String()
		}
	}
}

func answer(reply string) func(string, net.Conn) {
	return func(_ string, c net.Conn) { _, _ = io.WriteString(c, reply) }
}

func TestSet_WireFormat(t *testing.T) {
	got := make(chan string, 1)
	u := pipeUAPI(func(req string, c net.Conn) {
		got <- req
		_, _ = io.WriteString(c, "errno=0\n\n")
	})
	err := u.Set(context.Background(), []KV{
		{"jc", "4"}, {"i1", "<b 0xc0ff00><r 16>"},
		{"public_key", peerKey}, {"allowed_ip", "0.0.0.0/0"},
	})
	if err != nil {
		t.Fatalf("set failed: %v", err)
	}
	want := "set=1\njc=4\ni1=<b 0xc0ff00><r 16>\npublic_key=" + peerKey + "\nallowed_ip=0.0.0.0/0\n\n"
	if req := <-got; req != want {
		t.Fatalf("request on the wire:\n%q\nwant\n%q", req, want)
	}
}

// A refusal carries amneziawg-go's errno, and it must stay reachable with errors.As through the
// wrapping: the caller decides on it (a refused set means "recreate the device").
func TestSet_RefusalIsATypedErrno(t *testing.T) {
	u := pipeUAPI(answer("errno=-22\n\n"))
	err := u.Set(context.Background(), []KV{{"i1", "<c>"}})
	var refused *UAPIError
	if !errors.As(err, &refused) || refused.Errno != -22 || refused.Op != "set" {
		t.Fatalf("got %v (%T), want *UAPIError{set, -22}", err, err)
	}
	if !strings.Contains(err.Error(), "-22") {
		t.Errorf("the message drops the errno: %q", err)
	}
}

// Everything that would break the line framing is refused before the socket is even dialled - a
// smuggled key, an early end of the operation, a value upstream would store changed.
func TestSet_RefusesLinesThatBreakTheFraming(t *testing.T) {
	dialled := false
	u := &UAPI{iface: "wr_1a2b3c4d", path: "(none)", dial: func(context.Context) (net.Conn, error) {
		dialled = true
		return nil, errors.New("must not dial")
	}}
	bad := []KV{
		{"i1", "<b 0x01>\nprivate_key=" + testKey}, // a key smuggled through a value
		{"i1", "<b 0x01>\n\nset=1"},                // ends the operation early
		{"i1", "<b 0x01>\r"},                       // upstream strips the \r: stored != sent
		{"i1", "a\x00b"},
		{"i1", "a\x7fb"},
		{"", "4"},
		{"JC", "4"},
		{"j c", "4"},
		{"jc=4\nx", "4"},
		{"i1", strings.Repeat("a", uapiMaxLine-4+1)}, // one byte over upstream's line limit
	}
	for _, kv := range bad {
		if err := u.Set(context.Background(), []KV{{"jc", "4"}, kv}); err == nil {
			t.Errorf("accepted %q=%q", kv.Key, kv.Value)
		}
	}
	if err := u.Set(context.Background(), nil); err == nil {
		t.Error("an empty set was accepted")
	}
	if dialled {
		t.Fatal("a refused line still reached the socket")
	}
}

// The line limit is exact: "i1=" + value + "\n" may fill upstream's scanner and no more. A tab is
// allowed, because upstream splits I-packet tags on any whitespace.
func TestSet_LimitAndTabAreAccepted(t *testing.T) {
	u := pipeUAPI(answer("errno=0\n\n"))
	for _, v := range []string{strings.Repeat("a", uapiMaxLine-4), "<r\t16>"} {
		if err := u.Set(context.Background(), []KV{{"i1", v}}); err != nil {
			t.Errorf("a %d-byte value was refused: %v", len(v), err)
		}
	}
}

// A set reply is the status alone; anything before it means the socket is not what we think.
func TestSet_UnexpectedLinesBeforeTheStatus(t *testing.T) {
	u := pipeUAPI(answer("jc=4\nerrno=0\n\n"))
	if err := u.Set(context.Background(), []KV{{"jc", "4"}}); err == nil {
		t.Fatal("a set reply carrying lines was accepted")
	}
}

// The reply shape upstream's IpcGetOperation writes: device keys, then peers, each opening with
// public_key; random_trailers and disable_cookies are printed even at 0.
func TestGet_SplitsDeviceAndPeers(t *testing.T) {
	reply := "private_key=" + testKey + "\nlisten_port=51820\njc=4\njmin=40\njmax=70\ns1=40\n" +
		"h1=100000-200000\ni1=<b 0xc0ff00><r 16>\nrandom_trailers=0\ndisable_cookies=0\n" +
		"public_key=" + peerKey + "\npreshared_key=" + zeroKey + "\nprotocol_version=1\n" +
		"endpoint=192.0.2.1:51820\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n" +
		"tx_bytes=0\nrx_bytes=0\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\n" +
		"public_key=" + otherKey + "\npreshared_key=" + zeroKey + "\nprotocol_version=1\n" +
		"allowed_ip=198.51.100.0/24\n" +
		"errno=0\n\n"
	got := make(chan string, 1)
	u := pipeUAPI(func(req string, c net.Conn) {
		got <- req
		_, _ = io.WriteString(c, reply)
	})
	snap, err := u.Get(context.Background())
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if req := <-got; req != "get=1\n\n" {
		t.Errorf("get request %q", req)
	}
	if len(snap.Device) != 10 || len(snap.Peers) != 2 {
		t.Fatalf("split into %d device keys and %d peers, want 10 and 2", len(snap.Device), len(snap.Peers))
	}
	if p := snap.Peers[0]; p[0] != (KV{"public_key", peerKey}) || p[len(p)-1] != (KV{"allowed_ip", "0.0.0.0/0"}) {
		t.Errorf("first peer block %v", p)
	}
	if p := snap.Peers[1]; p[0] != (KV{"public_key", otherKey}) || len(p) != 4 {
		t.Errorf("second peer block %v", p)
	}
	if v, ok := snap.Value("random_trailers"); !ok || v != "0" {
		t.Errorf("random_trailers = %q, %v", v, ok)
	}
	if v, ok := snap.Value("h1"); v != "100000-200000" || !ok {
		t.Errorf("h1 = %q, %v", v, ok)
	}
	if _, ok := snap.Value("fwmark"); ok {
		t.Error("fwmark was not in the reply but reads as present")
	}
	if _, ok := snap.Value("allowed_ip"); ok {
		t.Error("a peer key reads as a device key")
	}
}

// Replies that are not the protocol are errors of the exchange - never a success, and never
// reported as amneziawg-go refusing something it did not refuse.
func TestReply_MalformedIsAnError(t *testing.T) {
	cases := map[string]string{
		"closed before the status":        "jc=4\n",
		"nothing at all":                  "",
		"status without the empty line":   "errno=0\n",
		"status followed by more data":    "errno=0\nx=1\n",
		"status that is not a number":     "errno=zero\n\n",
		"line that is not key=value":      "garbage\nerrno=0\n\n",
		"empty line before the status":    "jc=4\n\nerrno=0\n\n",
		"line longer than upstream sends": "i1=" + strings.Repeat("a", uapiMaxLine) + "\nerrno=0\n\n",
	}
	for name, reply := range cases {
		u := pipeUAPI(answer(reply))
		_, err := u.Get(context.Background())
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		var refused *UAPIError
		if errors.As(err, &refused) {
			t.Errorf("%s: reported as a refusal: %v", name, err)
		}
	}
}

func TestReply_OverTheCapIsRefused(t *testing.T) {
	u := pipeUAPI(answer(strings.Repeat("tx_bytes=0\n", uapiMaxReply/11+1)))
	if _, err := u.Get(context.Background()); err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("an endless reply came back as %v", err)
	}
}

// A process that accepts the connection and never answers must not hold the caller past its
// deadline.
func TestExchange_StalledPeerHitsTheDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	u := pipeUAPI(func(string, net.Conn) { <-release })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := u.Get(ctx)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a stalled peer came back as %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the deadline took %v", d)
	}
}

// Cancelling the caller's context (no deadline of its own) must end the exchange at once, not when
// uapiTimeout runs out: that is what the AfterFunc in exchange is for.
func TestExchange_CancelEndsItAtOnce(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	u := pipeUAPI(func(string, net.Conn) { <-release })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	if _, err := u.Get(ctx); err == nil {
		t.Fatal("a cancelled exchange succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("cancellation took %v; uapiTimeout is %v", d, uapiTimeout)
	}
}

// The name becomes the socket path, so anything that is not a device name is refused, and a device
// name maps to the socket location WayHop's build of amneziawg-go serves.
func TestNewUAPI_Names(t *testing.T) {
	for _, bad := range []string{"", "../etc", "a/b", ".", "..", ".x", "-x", "_x", "wr 1", "wr\n1", "wr:1", "wr_0123456789abc"} {
		if _, err := NewUAPI(bad); err == nil {
			t.Errorf("%q was accepted as an interface name", bad)
		}
	}
	u, err := NewUAPI("wr_1a2b3c4d")
	if err != nil {
		t.Fatalf("the plugin's own device name was refused: %v", err)
	}
	if u.path != "/tmp/wayhop/amneziawg/wr_1a2b3c4d.sock" {
		t.Fatalf("socket path %q is not where amneziawg-go serves it", u.path)
	}
}

// The directory is set at build time - a linker flag on upstream's ipc.socketDirectory in
// scripts/build-amneziawg-go.sh - and a client looking anywhere else finds no socket at all.
func TestUAPISocketDirIsTheBuilds(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-amneziawg-go.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^AWG_GO_SOCKET_DIR="([^"]+)"`).FindSubmatch(script)
	if m == nil || string(m[1]) != uapiSocketDir {
		t.Fatalf("the build sets the socket directory to %q, the client looks in %q", m, uapiSocketDir)
	}
	if !bytes.Contains(script, []byte("-X github.com/amnezia-vpn/amneziawg-go/v3/ipc.socketDirectory=$AWG_GO_SOCKET_DIR")) {
		t.Fatal("the build no longer passes the socket directory to the linker")
	}
}

// The dial path itself, over a real unix socket (AF_UNIX works on Linux and on the Windows the
// verify runner uses).
func TestUAPI_OverARealUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wr.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on a unix socket: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if strings.HasPrefix(readRequest(c), "get=1") {
					_, _ = io.WriteString(c, "random_trailers=0\ndisable_cookies=0\nerrno=0\n\n")
					return
				}
				_, _ = io.WriteString(c, "errno=0\n\n")
			}()
		}
	}()
	u := uapiAt("wr_1a2b3c4d", path)
	if err := u.Set(context.Background(), []KV{{"jc", "4"}}); err != nil {
		t.Fatalf("set over the socket: %v", err)
	}
	snap, err := u.Get(context.Background())
	if err != nil {
		t.Fatalf("get over the socket: %v", err)
	}
	if v, ok := snap.Value("disable_cookies"); !ok || v != "0" {
		t.Fatalf("disable_cookies = %q, %v", v, ok)
	}
}

func TestUAPI_NothingListening(t *testing.T) {
	u := uapiAt("wr_1a2b3c4d", filepath.Join(t.TempDir(), "absent.sock"))
	err := u.Set(context.Background(), []KV{{"jc", "4"}})
	if err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Fatalf("a missing socket came back as %v", err)
	}
}

// The reply parser reads what a local process wrote, but a malformed reply must still be an error,
// never a panic.
func FuzzReadReply(f *testing.F) {
	f.Add([]byte("jc=4\nerrno=0\n\n"))
	f.Add([]byte("errno=-22\n\n"))
	f.Add([]byte("public_key=x\nallowed_ip=0.0.0.0/0\npublic_key=y\nerrno=0\n\n"))
	f.Add([]byte("errno=0\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		body, err := readReply(bufio.NewReaderSize(bytes.NewReader(b), uapiMaxLine), "get")
		if err == nil {
			_ = splitSnapshot(body)
		}
	})
}
