package nativedns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// probeName is what the chain's checks ask for. Only the shape of the answer is read, so a name that
// exists everywhere and says nothing about this household is enough.
const probeName = "www.example.com"

// ProbeResolver asks the DNS server at addr for an answer, resending as a client would, until ctx ends.
// NOERROR and NXDOMAIN both prove a working path. A SERVFAIL or REFUSED is what dnsmasq says when no
// upstream answered, so it is kept for the error and asked again rather than taken as a result.
func ProbeResolver(ctx context.Context, addr string) error {
	query := buildQuery(probeName)
	var last error
	for ctx.Err() == nil {
		if err := probeOnce(ctx, addr, query); err == nil {
			return nil
		} else {
			last = err
		}
		// A refused socket returns at once: dnsmasq is still coming up, so give it a moment.
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	if last == nil {
		last = ctx.Err()
	}
	return last
}

func probeOnce(ctx context.Context, addr string, query []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(1500 * time.Millisecond)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := conn.Write(query); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return errors.New("no answer")
		}
		return err
	}
	if n < 12 || !bytes.Equal(buf[:2], query[:2]) {
		return errors.New("an answer that is not DNS")
	}
	switch rcode := buf[3] & 0x0f; rcode {
	case 0, 3:
		return nil
	case 2, 5: // SERVFAIL, REFUSED: what dnsmasq says when it has no upstream left to ask
		return errors.New("no upstream answered")
	default:
		return fmt.Errorf("the resolver answered with code %d", rcode)
	}
}

// buildQuery is one A question with recursion desired.
func buildQuery(name string) []byte {
	var id [2]byte
	now := time.Now().UnixNano()
	id[0], id[1] = byte(now>>8), byte(now)
	q := []byte{id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

// TrialDnsmasq proves one row the way the real service would use it: a throwaway dnsmasq from the same
// binary, under the same user, with this row as its only upstream, on a free loopback port. On 2.90 the
// service drops to nobody and keeps CAP_NET_RAW for the binding (measured); on another build this is
// what would show it cannot.
func TrialDnsmasq(ctx context.Context, bin, stateDir, mainConf string, row ChainRow) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	port, err := freeUDPPort()
	if err != nil {
		return err
	}
	main, _ := os.ReadFile(mainConf)
	conf, pid := filepath.Join(stateDir, "trial.conf"), filepath.Join(stateDir, "trial.pid")
	if err := os.WriteFile(conf, []byte(renderTrialConf(row, port, pid, string(main))), 0o600); err != nil {
		return err
	}
	defer os.Remove(conf)
	defer os.Remove(pid)
	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tctx, bin, "-k", "-C", conf)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	if err := ProbeResolver(tctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err != nil {
		if said := trialComplaints(logs.String()); said != "" {
			return fmt.Errorf("%w (%s)", err, said)
		}
		return err
	}
	return nil
}

// trialComplaints keeps what dnsmasq said about the row out of its start-up banner.
func trialComplaints(log string) string {
	var out []string
	for _, ln := range strings.Split(log, "\n") {
		low := strings.ToLower(ln)
		for _, word := range []string{"ignoring", "cannot", "failed", "bad ", "illegal"} {
			if strings.Contains(low, word) {
				out = append(out, strings.TrimSpace(ln))
				break
			}
		}
	}
	return strings.Join(out, " / ")
}

// renderTrialConf is the throwaway configuration. It takes the user and group from the main config, so
// the binding is tried with the privileges the service will really have.
func renderTrialConf(row ChainRow, port int, pidFile, main string) string {
	var b strings.Builder
	for _, ln := range []string{
		"no-resolv", "no-hosts", "cache-size=0", "bind-interfaces", "listen-address=127.0.0.1",
		"port=" + strconv.Itoa(port), "pid-file=" + pidFile, "log-facility=-", row.Line(),
	} {
		b.WriteString(ln + "\n")
	}
	for _, ln := range strings.Split(main, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "user=") || strings.HasPrefix(ln, "group=") {
			b.WriteString(ln + "\n")
		}
	}
	return b.String()
}

func freeUDPPort() (int, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port, nil
}

func fileRev(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:", len(p))
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
