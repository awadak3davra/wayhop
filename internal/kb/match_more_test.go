package kb

import (
	"strings"
	"testing"
)

// kbinitserver_matchHasID reports whether Match(line) returns an entry with id.
func kbinitserver_matchHasID(line, id string) bool {
	for _, e := range Match(line) {
		if e.ID == id {
			return true
		}
	}
	return false
}

// kbinitserver_matchIDs returns the ids Match produced for line (for diagnostics).
func kbinitserver_matchIDs(line string) []string {
	var ids []string
	for _, e := range Match(line) {
		ids = append(ids, e.ID)
	}
	return ids
}

// TestMatchEverySourcedEntry feeds one representative real-world error line per
// sourced entry and asserts the expected entry is among the matches. Every entry
// in the curated knowledgebase is exercised exactly once here.
func TestMatchEverySourcedEntry(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		wantID string
	}{
		// sing-box
		{"sb-tun-file-exists", `FATAL[0000] start service: configure tun interface: ioctl: file exists`, "sb-tun-file-exists"},
		{"sb-tun-invalid-arg", `FATAL[0000] start service: configure tun interface: netlink: invalid argument`, "sb-tun-invalid-arg"},
		{"sb-wg-route-exists", `start outbound/wireguard[wg-out]: initialize: add route 0.0.0.0/0: file exists`, "sb-wg-route-exists"},
		{"sb-fatal-start", `FATAL[0000] start service: bad json`, "sb-fatal-start"},
		// xray / reality
		{"xr-reality-invalid", `REALITY: processed invalid connection from 1.2.3.4`, "xr-reality-invalid"},
		{"xr-reality-hello", `REALITY: failed to read client hello`, "xr-reality-invalid"},
		{"xr-deadline", `app/dispatcher: dial outbound: context deadline exceeded`, "xr-deadline"},
		{"xr-invalid-user", `VLESS: invalid user, please check your config`, "xr-invalid-user"},
		{"xr-invalid-user-nomatch", `VMess: not match any user in the list`, "xr-invalid-user"},
		// wireguard
		{"wg-handshake-timeout", `peer(ABC): Handshake did not complete after 5 seconds`, "wg-handshake-timeout"},
		{"wg-unknown-peer", `Receiving handshake initiation from unknown peer 4.5.6.7`, "wg-unknown-peer"},
		{"wg-invalid-handshake", `Received invalid handshake initiation`, "wg-unknown-peer"},
		// amneziawg
		{"awg-junk", `peer: Sending dummy junk packets to disguise`, "awg-junk-mismatch"},
		{"awg-bytes", `handshake parse: only 92 bytes received, expected more`, "awg-junk-mismatch"},
		// hysteria2
		{"hy-tls-verify-x509", `tls: failed to verify certificate: x509: certificate signed by unknown authority`, "hy-tls-verify"},
		{"hy-tls-verify-nottrusted", `error: server certificate is not trusted`, "hy-tls-verify"},
		{"hy-auth", `connect: authentication failed (wrong password?)`, "hy-auth"},
		{"hy-auth-401", `received HTTP/3 401 from server`, "hy-auth"},
		// general
		{"gen-no-host", `dial tcp: lookup vpn.example.com: no such host`, "gen-no-host"},
		{"gen-no-host-misbehaving", `lookup foo on 1.1.1.1:53: server misbehaving`, "gen-no-host"},
		{"gen-conn-refused", `dial tcp 1.2.3.4:443: connect: connection refused`, "gen-conn-refused"},
		{"gen-io-timeout", `read tcp 10.0.0.2->1.2.3.4:443: i/o timeout`, "gen-io-timeout"},
		{"gen-io-timeout-dial", `dial tcp 1.2.3.4:443: timeout while connecting`, "gen-io-timeout"},
		{"gen-clock-expired", `x509: certificate has expired or is not yet valid`, "gen-clock"},
		{"gen-clock-notbefore", `x509: certificate is not valid before 2026-01-01`, "gen-clock"},
		{"gen-permission-denied", `open /dev/net/tun: permission denied`, "gen-permission"},
		{"gen-permission-notpermitted", `tun: operation not permitted`, "gen-permission"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !kbinitserver_matchHasID(c.line, c.wantID) {
				t.Errorf("line %q did not match entry %q (got %v)", c.line, c.wantID, kbinitserver_matchIDs(c.line))
			}
		})
	}
}

// TestMatchEntryFields verifies the matched entry carries the descriptive fields
// the UI shows (title/explanation/fix), not just an ID.
func TestMatchEntryFields(t *testing.T) {
	m := Match(`FATAL[0000] start service: configure tun interface: file exists`)
	if len(m) == 0 {
		t.Fatal("expected at least one match")
	}
	var got *Entry
	for i := range m {
		if m[i].ID == "sb-tun-file-exists" {
			got = &m[i]
		}
	}
	if got == nil {
		t.Fatalf("sb-tun-file-exists not in matches %v", kbinitserver_matchIDs(`configure tun interface: file exists`))
	}
	if got.Title == "" || got.Explanation == "" || got.Fix == "" {
		t.Errorf("matched entry missing text: %+v", got)
	}
	if got.Engine != "sing-box" {
		t.Errorf("engine = %q, want sing-box", got.Engine)
	}
}

// TestMatchBenignLinesNoMatch confirms ordinary, non-error log lines do not match
// any knowledgebase entry (avoids noisy false positives in the UI).
func TestMatchBenignLinesNoMatch(t *testing.T) {
	benign := []string{
		"INFO router started, 5 outbounds loaded",
		"INFO[0001] inbound/tun[tun-in]: started at 198.18.0.1/30",
		"sing-box version 1.9.0",
		"DEBUG sniffed domain example.com",
		"applied config successfully",
		"",
		"   ",
		"connected to peer, handshake complete",
	}
	for _, ln := range benign {
		if m := Match(ln); len(m) != 0 {
			t.Errorf("benign line %q matched %d entries (%v), want 0", ln, len(m), kbinitserver_matchIDs(ln))
		}
	}
}

// TestMatchIsCaseInsensitive verifies patterns compiled with the (?i) flag match
// regardless of the casing engines emit.
func TestMatchIsCaseInsensitive(t *testing.T) {
	lower := `configure tun interface: file exists`
	upper := strings.ToUpper(lower)
	if !kbinitserver_matchHasID(lower, "sb-tun-file-exists") {
		t.Fatal("lowercase line should match sb-tun-file-exists")
	}
	if !kbinitserver_matchHasID(upper, "sb-tun-file-exists") {
		t.Fatal("uppercase line should match sb-tun-file-exists (patterns are case-insensitive)")
	}
}

// TestMatchReturnsAllApplicable confirms Match returns every applicable entry, not
// just the first — a clock-related TLS failure matches both hy-tls-verify and
// gen-clock.
func TestMatchReturnsAllApplicable(t *testing.T) {
	line := `tls: failed to verify certificate because of clock skew`
	if !kbinitserver_matchHasID(line, "hy-tls-verify") {
		t.Error("expected hy-tls-verify match")
	}
	if !kbinitserver_matchHasID(line, "gen-clock") {
		t.Error("expected gen-clock match")
	}
}

// TestIsErrorLineCases exercises both the keyword hits and the benign passes of
// IsErrorLine across the whole keyword set the regexp recognises.
func TestIsErrorLineCases(t *testing.T) {
	errLines := []string{
		"FATAL boom",
		"some ERROR happened",
		"runtime panic: nil map",
		"connection FAILED",
		"permission denied",
		"connection refused",
		"invalid argument",
		"i/o timeout",
		"handshake reject",
	}
	for _, l := range errLines {
		if !IsErrorLine(l) {
			t.Errorf("IsErrorLine(%q) = false, want true", l)
		}
	}
	okLines := []string{
		"INFO all good",
		"router started",
		"applied config",
		"handshake complete", // 'complete' is not a flagged keyword
		"",
	}
	for _, l := range okLines {
		if IsErrorLine(l) {
			t.Errorf("IsErrorLine(%q) = true, want false", l)
		}
	}
}

// TestIsErrorLineWordBoundary checks that the keyword match is anchored on word
// boundaries — a keyword as a substring of a longer word does NOT flag the line.
// "errors" embeds "error" but the trailing "s" is a word char, so \berror\b does
// not match; only the keyword delimited by non-word chars on both sides matches.
func TestIsErrorLineWordBoundary(t *testing.T) {
	notFlagged := []string{
		"processing 3 errorsxyz tokens", // 'error' followed by word chars
		"3 errors found",                // 'error' followed by 's'
		"a terror in the night",         // 'error' preceded by a word char
	}
	for _, l := range notFlagged {
		if IsErrorLine(l) {
			t.Errorf("IsErrorLine(%q) = true, want false (no standalone keyword)", l)
		}
	}
	// Keyword delimited by non-word chars on both sides does flag.
	flagged := []string{
		"an error here",   // 'error' between spaces
		"3 errors. found", // wait: 'errors' still has trailing s -> stays unflagged below
	}
	if !IsErrorLine(flagged[0]) {
		t.Errorf("IsErrorLine(%q) = false, want true", flagged[0])
	}
	// '3 errors. found' is still 'errors' (trailing 's'), so it is NOT flagged.
	if IsErrorLine(flagged[1]) {
		t.Errorf("IsErrorLine(%q) = true, want false ('errors' still has trailing 's')", flagged[1])
	}
}

// TestEntriesNonEmptyFixAndSource asserts every catalog entry carries a concrete
// fix and at least one source link (the kb's reason to exist).
func TestEntriesNonEmptyFixAndSource(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range Entries() {
		if e.ID == "" {
			t.Errorf("entry with empty ID: %+v", e)
		}
		if seen[e.ID] {
			t.Errorf("duplicate entry ID %q", e.ID)
		}
		seen[e.ID] = true
		if strings.TrimSpace(e.Fix) == "" {
			t.Errorf("entry %s has empty Fix", e.ID)
		}
		if len(e.Sources) == 0 {
			t.Errorf("entry %s has no Sources", e.ID)
		}
		for _, s := range e.Sources {
			if strings.TrimSpace(s) == "" {
				t.Errorf("entry %s has an empty source link", e.ID)
			}
		}
		if strings.TrimSpace(e.Pattern) == "" {
			t.Errorf("entry %s has empty Pattern", e.ID)
		}
	}
}
