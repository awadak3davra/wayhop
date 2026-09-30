package awg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// amneziawg-go is configured over one unix socket per device, in WireGuard's cross-platform text
// configuration protocol with the AmneziaWG keys added. Talking to it directly is what
// lets the userspace path ship no awg-tools at all: one binary to install, and no tools build whose
// generation has to match it. Every rule below is read from the pinned upstream source,
// device/uapi.go and ipc/uapi_unix.go at v3.1.20260828.

// uapiSocketDir is where WayHop's build of amneziawg-go serves its sockets, one "<dir>/<iface>.sock"
// per device. It is not upstream's default /var/run/amneziawg: amneziawg-go stops at startup when it
// cannot create its socket directory, and /tmp is the one directory measured writable tmpfs on both
// platforms (OpenWrt's /var/run is a symlink into it). scripts/build-amneziawg-go.sh sets upstream's
// ipc.socketDirectory to this path with a linker flag; a test holds the two equal.
const uapiSocketDir = "/tmp/wayhop/amneziawg"

const (
	// uapiTimeout bounds one operation, the connect included. A set that applies a whole config
	// returns in milliseconds even on a mips router; a socket that has not answered in 5 s belongs to
	// a process that is stuck, and the caller should hear that instead of hanging with it.
	uapiTimeout = 5 * time.Second

	// uapiMaxLine is upstream's line limit: IpcSetOperation reads the request with a default
	// bufio.Scanner, whose token limit is bufio.MaxScanTokenSize with the newline included. A longer
	// line fails the set with -EIO and leaves the rest of the request to be read as further
	// operations, which closes the connection - so it is refused here instead, naming the key.
	uapiMaxLine = bufio.MaxScanTokenSize

	// uapiMaxReply bounds a get reply. A device with a peer and a few allowed IPs answers in a few
	// hundred bytes; the cap only keeps a wrong socket from growing the daemon without limit.
	uapiMaxReply = 4 << 20
)

// KV is one protocol line, key=value.
type KV struct {
	Key, Value string
}

// UAPIError is amneziawg-go refusing an operation, with the status it answered: a negative errno.
// -EINVAL is a key or a value it rejects (an unknown I-packet tag, overlapping H ranges),
// -EADDRINUSE a listen_port already taken, -EIO or -EPROTO a request it could not read.
//
// A refused set may have been applied in part. Upstream stages S1-S4, H1-H4 and the header
// protection key and applies them together once the request ends, but applies every other key the
// moment it reads the line - so after an error the device holds some new values and some old ones.
// Measured against the pinned build: a listen_port refused as taken leaves the device listening on
// no port at all. Recreate the device; do not trust it.
type UAPIError struct {
	Op    string // "set" or "get"
	Errno int64
}

func (e *UAPIError) Error() string {
	msg := fmt.Sprintf("amneziawg-go refused the %s (errno %d", e.Op, e.Errno)
	if name := errnoText(e.Errno); name != "" {
		msg += ", " + name
	}
	return msg + ")"
}

// UAPI is the configuration socket of one amneziawg-go device.
type UAPI struct {
	iface string
	path  string
	dial  func(ctx context.Context) (net.Conn, error)
}

// NewUAPI addresses the amneziawg-go instance that serves iface.
//
// The name becomes a path, so it is held to the rule internal/config applies to device names: a
// letter or digit, then letters, digits, '.', '_' or '-', at most 15 bytes (IFNAMSIZ-1). That rules
// out '/' and a leading '.', so no name can address a socket outside amneziawg-go's directory.
func NewUAPI(iface string) (*UAPI, error) {
	if !validIface(iface) {
		return nil, fmt.Errorf("%q is not a usable interface name for amneziawg-go", iface)
	}
	return uapiAt(iface, uapiSocketDir+"/"+iface+".sock"), nil
}

// uapiAt addresses a socket at an explicit path, which is how the tests reach their own listeners.
func uapiAt(iface, path string) *UAPI {
	return &UAPI{iface: iface, path: path, dial: func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}
}

func validIface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || c != '.' && c != '_' && c != '-') {
			return false
		}
	}
	return true
}

// Set sends one set operation and returns amneziawg-go's verdict on it.
//
// Every line is checked before anything is sent. The protocol is framed by newlines, so a newline
// inside a value would end the line there and have the rest read as further keys - a private key or
// a peer smuggled in through, say, an I-packet string - and an empty line would end the operation
// early and leave what follows to be parsed as a new one.
func (u *UAPI) Set(ctx context.Context, lines []KV) error {
	if len(lines) == 0 {
		return errors.New("a UAPI set needs at least one line")
	}
	var req strings.Builder
	req.WriteString("set=1\n")
	for _, kv := range lines {
		if err := checkLine(kv); err != nil {
			return err
		}
		req.WriteString(kv.Key)
		req.WriteByte('=')
		req.WriteString(kv.Value)
		req.WriteByte('\n')
	}
	req.WriteByte('\n')
	body, err := u.exchange(ctx, "set", req.String())
	if err != nil {
		return err
	}
	if len(body) != 0 {
		return fmt.Errorf("amneziawg-go answered a set on %s with %d line(s) before its status", u.iface, len(body))
	}
	return nil
}

// checkLine holds a line to what upstream will store exactly as sent: a key of lower-case letters,
// digits and '_', the shape of every key it knows, and a value without control characters. The
// newline is the framing, and a trailing '\r' is stripped by upstream's scanner, so the value it kept
// would not be the value that was sent. A tab is the one exception: upstream splits I-packet tags
// with strings.Fields, so a tab inside a tag is ordinary whitespace.
func checkLine(kv KV) error {
	if kv.Key == "" {
		return errors.New("a UAPI line needs a key")
	}
	for i := 0; i < len(kv.Key); i++ {
		c := kv.Key[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return fmt.Errorf("UAPI key %q: keys are made of a-z, 0-9 and _", kv.Key)
		}
	}
	for i := 0; i < len(kv.Value); i++ {
		if c := kv.Value[i]; c < 0x20 && c != '\t' || c == 0x7f {
			return fmt.Errorf("the UAPI value for %s carries control character 0x%02x", kv.Key, c)
		}
	}
	if n := len(kv.Key) + 1 + len(kv.Value) + 1; n > uapiMaxLine {
		return fmt.Errorf("the UAPI line for %s is %d bytes; amneziawg-go reads lines of at most %d", kv.Key, n, uapiMaxLine)
	}
	return nil
}

// Get reads the device's current configuration and state.
func (u *UAPI) Get(ctx context.Context) (Snapshot, error) {
	body, err := u.exchange(ctx, "get", "get=1\n\n")
	if err != nil {
		return Snapshot{}, err
	}
	return splitSnapshot(body), nil
}

// Snapshot is a get reply as the protocol nests it: the device's keys, then one block per peer,
// each opening with public_key.
type Snapshot struct {
	Device []KV
	Peers  [][]KV
}

// Value returns a device key's value. amneziawg-go leaves out a key whose value is zero or unset
// (jc, s1, fwmark, ...), so a missing key means exactly that. random_trailers and disable_cookies are
// the exceptions: it always prints them, as 0 or 1, which makes their presence the cheap check that
// the socket belongs to a 3.1 build.
func (s Snapshot) Value(key string) (string, bool) {
	for _, kv := range s.Device {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

func splitSnapshot(body []KV) Snapshot {
	var s Snapshot
	for _, kv := range body {
		if kv.Key == "public_key" {
			s.Peers = append(s.Peers, nil)
		}
		if n := len(s.Peers); n > 0 {
			s.Peers[n-1] = append(s.Peers[n-1], kv)
		} else {
			s.Device = append(s.Device, kv)
		}
	}
	return s
}

// exchange sends one request on a fresh connection and reads the reply up to its status: the
// key=value lines before "errno=N", and N as a *UAPIError when it is not 0. Upstream serves many
// operations per connection; one per connection costs a local connect and keeps an operation that
// went wrong from leaving the next one to read its leftovers.
func (u *UAPI) exchange(ctx context.Context, op, req string) ([]KV, error) {
	ctx, cancel := context.WithTimeout(ctx, uapiTimeout)
	defer cancel()
	conn, err := u.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("amneziawg-go for %s is not answering on %s: %w", u.iface, u.path, err)
	}
	defer conn.Close()
	// The deadline stops a peer that stalls; AfterFunc stops the exchange when the caller gives up
	// before the deadline, which a deadline set once cannot see.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("amneziawg-go %s on %s: sending the request: %w", op, u.iface, err)
	}
	body, err := readReply(bufio.NewReaderSize(conn, uapiMaxLine), op)
	var refused *UAPIError
	if err != nil && !errors.As(err, &refused) {
		return nil, fmt.Errorf("amneziawg-go %s on %s: %w", op, u.iface, err)
	}
	return body, err
}

// readReply reads a reply up to and including its status: "errno=N" and the empty line after it.
func readReply(r *bufio.Reader, op string) ([]KV, error) {
	var body []KV
	read := 0
	for {
		raw, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("a reply line is longer than %d bytes", uapiMaxLine)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("the reply ended before its status: %w", err)
		}
		if read += len(raw); read > uapiMaxReply {
			return nil, fmt.Errorf("the reply is over %d bytes", uapiMaxReply)
		}
		line := string(raw[:len(raw)-1])
		if line == "" {
			return nil, errors.New("the reply has an empty line before its status")
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("the reply has a line that is not key=value: %q", line)
		}
		if key != "errno" {
			body = append(body, KV{key, value})
			continue
		}
		code, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("the reply's status %q is not a number", value)
		}
		if end, err := r.ReadSlice('\n'); err != nil || len(end) != 1 {
			return nil, errors.New("the reply's status is not followed by the empty line that ends it")
		}
		if code != 0 {
			return nil, &UAPIError{Op: op, Errno: code}
		}
		return body, nil
	}
}
