// Package keenetic drives a KeeneticOS router via RCI (the REST mirror of the NDM command
// tree) — the foundation of WayHop's native-first Keenetic backend. The backend uses
// native AmneziaWG/WireGuard interfaces + NDM metric-ordered routing instead of userspace
// tunnels; RCI is how it reads state and applies config over HTTP. See memory
// keenetic-backend.md + docs/ARCHITECTURE_NATIVE_FIRST.md (Phase 3).
package keenetic

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

// maxRCIBody caps an RCI response read (the running-config show can be large).
const maxRCIBody = 8 << 20

// RCIClient talks to a Keenetic router's RCI over HTTP. It authenticates with KeeneticOS's
// "x-ndw2-interactive" challenge flow and keeps the session cookie, then Show() reads JSON
// state (GET /rci/show/<path>) and Parse() executes an NDM CLI command (POST /rci/parse).
// All methods auto-(re)authenticate on a 401, so a caller just calls Show/Parse.
type RCIClient struct {
	base string // e.g. "http://192.168.1.1" (no trailing slash)
	user string
	pass string
	hc   *http.Client // carries the session cookie via its jar
}

// NewRCIClient builds a client for base (host URL) with admin credentials.
func NewRCIClient(base, user, pass string) (*RCIClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &RCIClient{
		base: strings.TrimRight(base, "/"),
		user: user, pass: pass,
		hc: &http.Client{Timeout: 25 * time.Second, Jar: jar},
	}, nil
}

// Auth performs the KeeneticOS challenge handshake and stores the authenticated session
// cookie in the client's jar. Flow (verified on KeeneticOS 5.0.11 Hopper SE):
//
//	GET /auth → 401 + X-NDM-Realm + X-NDM-Challenge + Set-Cookie (the challenge is bound to
//	  the session cookie, which the jar now holds);
//	POST /auth {"login":user,"password":SHA256(challenge + MD5(user:realm:pass))} → 200.
//
// A subsequent GET /auth that already returns 200 means the session is still valid (no-op).
func (c *RCIClient) Auth(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/auth", nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("rci auth challenge: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil // already authenticated
	}
	realm := resp.Header.Get("X-NDM-Realm")
	challenge := resp.Header.Get("X-NDM-Challenge")
	if realm == "" || challenge == "" {
		return fmt.Errorf("rci auth: missing realm/challenge headers (status %d)", resp.StatusCode)
	}
	md := md5.Sum([]byte(c.user + ":" + realm + ":" + c.pass))
	sh := sha256.Sum256([]byte(challenge + hex.EncodeToString(md[:])))
	body, _ := json.Marshal(map[string]string{"login": c.user, "password": hex.EncodeToString(sh[:])})

	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/auth", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := c.hc.Do(req2)
	if err != nil {
		return fmt.Errorf("rci auth post: %w", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		return fmt.Errorf("rci auth failed (bad credentials?): status %d", resp2.StatusCode)
	}
	return nil
}

// Show GETs /rci/show/<path> and returns the raw JSON body (e.g. "interface",
// "ip/route", "version", "system"). Read-only.
func (c *RCIClient) Show(ctx context.Context, path string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, "/rci/show/"+strings.TrimLeft(path, "/"), nil)
}

// Parse executes an NDM CLI command via POST /rci/parse — this is how the backend APPLIES
// native config (e.g. `interface Wireguard0`, `wireguard asc …`, `ip route …`, `up`).
// CALLER OWNS SAFETY: only WayHop-managed config should be passed; never run with the
// live family router without the user's explicit OK (the loop is read-only by default).
func (c *RCIClient) Parse(ctx context.Context, command string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"parse": command})
	return c.do(ctx, http.MethodPost, "/rci/parse", body)
}

// ParseBatch executes a SEQUENCE of NDM commands in one /rci/parse request (the JSON-array
// form the RCI accepts — validated: `[{"parse":"…"}, …]` → array of results). Commands run
// in order within the single request, so a config block (interface … / sub-commands / up)
// applies as a unit and the NDM editing context is preserved across the block. Returns the
// raw result-array JSON. ⚠️ DEVICE-WRITING when the commands are config commands — only call
// with the user's explicit OK (the research loop never calls Apply).
func (c *RCIClient) ParseBatch(ctx context.Context, cmds []string) ([]byte, error) {
	items := make([]map[string]string, len(cmds))
	for i, cmd := range cmds {
		items[i] = map[string]string{"parse": cmd}
	}
	body, _ := json.Marshal(items)
	b, err := c.do(ctx, http.MethodPost, "/rci/parse", body)
	if err != nil {
		return b, err
	}
	// NDM returns HTTP 200 even when a command is REJECTED — the failure is an
	// {"status":[{"status":"error",…}]} object in the (per-command) result. Surface it so an
	// Apply/Teardown can't silently report success on a half-applied config.
	if errs := rciErrors(b); len(errs) > 0 {
		return b, fmt.Errorf("rci command error(s): %s", strings.Join(errs, "; "))
	}
	return b, nil
}

// rciErrors extracts NDM command-error messages from a /rci/parse response (validated live):
// a single command → an object {"prompt":…,"status":[{"status":"error","code","ident",
// "message"},…]}; a batch → an array of such per-command results. A successful command
// returns its data (no error-status). Only status=="error" entries are reported (warnings /
// ok / message are ignored).
func rciErrors(raw []byte) []string {
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil { // batch: one result per command
		var out []string
		for _, el := range arr {
			out = append(out, statusErrors(el)...)
		}
		return out
	}
	return statusErrors(raw) // single result
}

func statusErrors(raw json.RawMessage) []string {
	var obj struct {
		Status []struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Ident   string `json:"ident"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	var out []string
	for _, s := range obj.Status {
		if s.Status == "error" {
			msg := s.Message
			if msg == "" {
				msg = s.Ident
			}
			out = append(out, msg)
		}
	}
	return out
}

// do performs an authenticated request, transparently (re)authenticating once on a 401.
func (c *RCIClient) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	attempt := func() (*http.Response, error) {
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return c.hc.Do(req)
	}
	resp, err := attempt()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if err := c.Auth(ctx); err != nil {
			return nil, err
		}
		if resp, err = attempt(); err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxRCIBody))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rci %s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}
