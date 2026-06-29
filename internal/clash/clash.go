// Package clash bridges sing-box's Clash API: it streams traffic samples for
// the live graph and reverse-proxies the REST API (proxies, delay, logs) to the UI.
package clash

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"velinx/internal/traffic"
)

const (
	// streamIdleTimeout bounds how long StreamTraffic waits for the next /traffic sample
	// before forcing a reconnect. The stream emits at ~1 Hz, so a long silence means a
	// half-open socket (sing-box restarted, firewall dropped the flow with no RST) that a
	// plain blocking read would never notice. Reset on every sample.
	streamIdleTimeout = 20 * time.Second
	// maxClashBody caps one-shot REST reads (/connections, /proxies) so an abnormally large
	// payload can't spike memory on the ~60MB-overlay router. The /traffic STREAM stays
	// uncapped (it is incremental). Generous: a busy table is well under this.
	maxClashBody = 8 << 20
)

// ErrProxyDown means a Clash delay test ran but the proxy could not reach the
// test URL — distinct from the Clash API itself being unreachable.
var ErrProxyDown = errors.New("proxy delay test failed")

// Client talks to a sing-box / Clash-compatible controller.
type Client struct {
	base   *url.URL
	secret string
	hc     *http.Client
}

// New builds a Client for controller "host:port" with an optional bearer secret.
func New(controller, secret string) (*Client, error) {
	u, err := url.Parse("http://" + controller)
	if err != nil {
		return nil, fmt.Errorf("bad controller %q: %w", controller, err)
	}
	return &Client{
		base:   u,
		secret: secret,
		// No global timeout: /traffic is a long-lived streaming response;
		// per-call timeouts are set via context.WithTimeout by callers.
		hc: &http.Client{Transport: &http.Transport{
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 8, // default 2 is too low for 8-parallel health probes
			IdleConnTimeout:     30 * time.Second,
		}},
	}, nil
}

func (c *Client) auth(r *http.Request) {
	if c.secret != "" {
		r.Header.Set("Authorization", "Bearer "+c.secret)
	}
}

// StreamTraffic connects to /traffic and invokes onSample once per emitted
// object until ctx is cancelled or the stream ends.
func (c *Client) StreamTraffic(ctx context.Context, onSample func(traffic.Sample)) error {
	// Idle watchdog: a half-open socket leaves dec.Decode blocked forever, and the caller
	// only reconnects when this returns — so the live graph would freeze until a daemon
	// restart. Cancel the request ctx if no sample arrives within streamIdleTimeout (each
	// sample resets it), which unblocks the read and triggers a reconnect.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(streamIdleTimeout, cancel)
	defer idle.Stop()

	u := *c.base
	u.Path = "/traffic"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	c.auth(req)

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("clash /traffic: status %d", resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)
	for {
		var m struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		}
		if err := dec.Decode(&m); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		idle.Reset(streamIdleTimeout)
		onSample(traffic.Sample{T: time.Now().UnixMilli(), Up: m.Up, Down: m.Down})
	}
}

// Proxy returns a reverse proxy that forwards requests under stripPrefix to the
// controller, injecting the bearer secret. Mount it at e.g. /api/clash/.
func (c *Client) Proxy(stripPrefix string) http.Handler {
	rp := httputil.NewSingleHostReverseProxy(c.base)
	director := rp.Director
	rp.Director = func(r *http.Request) {
		director(r)
		r.URL.Path = strings.TrimPrefix(r.URL.Path, stripPrefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		if c.secret != "" {
			r.Header.Set("Authorization", "Bearer "+c.secret)
		}
	}
	return rp
}

// Proxy is one entry from the Clash API /proxies map.
type Proxy struct {
	Name    string         `json:"name"`
	Type    string         `json:"type"`
	Now     string         `json:"now"`     // selected member (selector/urltest)
	All     []string       `json:"all"`     // member names
	History []DelayHistory `json:"history"` // recent latency samples
}

// DelayHistory is a past latency sample reported by the Clash API.
type DelayHistory struct {
	Time  string `json:"time"`
	Delay int    `json:"delay"`
}

// Proxies returns the Clash proxy map keyed by name.
func (c *Client) Proxies(ctx context.Context) (map[string]Proxy, error) {
	u := *c.base
	u.Path = "/proxies"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clash /proxies: status %d", resp.StatusCode)
	}
	var out struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxClashBody)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Proxies, nil
}

// Delay measures latency (ms) for a named proxy via the Clash API. A nil error
// means alive (returns the delay). A wrapped ErrProxyDown means the test ran but
// failed; any other error means the Clash API was unreachable.
func (c *Client) Delay(ctx context.Context, name, testURL string, timeoutMS int) (int, error) {
	u := *c.base
	// Set the decoded Path + the escaped RawPath so URL.String() encodes the name
	// exactly once (assigning a pre-escaped value to Path alone would re-escape the
	// '%', double-encoding names that contain '/', spaces, etc.).
	u.Path = "/proxies/" + name + "/delay"
	u.RawPath = "/proxies/" + url.PathEscape(name) + "/delay"
	q := u.Query()
	q.Set("url", testURL)
	q.Set("timeout", strconv.Itoa(timeoutMS))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	c.auth(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var m struct {
		Delay     int    `json:"delay"`
		MeanDelay int    `json:"meanDelay"`
		Message   string `json:"message"`
	}
	decErr := json.NewDecoder(io.LimitReader(resp.Body, maxClashBody)).Decode(&m)
	if resp.StatusCode != http.StatusOK {
		msg := m.Message
		if msg == "" {
			msg = resp.Status
		}
		return 0, fmt.Errorf("%w: %s", ErrProxyDown, msg)
	}
	if decErr != nil {
		// A 200 whose body didn't parse is not a valid measurement: report it as
		// unreachable (probe → Unknown) rather than silently Alive(0), which would mask a
		// real failure and could suppress a failover decision.
		return 0, fmt.Errorf("clash delay: malformed response: %w", decErr)
	}
	if m.Delay == 0 {
		return m.MeanDelay, nil
	}
	return m.Delay, nil
}

// Conn is one active connection reported by the Clash API.
type Conn struct {
	Upload   int64    `json:"upload"`
	Download int64    `json:"download"`
	Chains   []string `json:"chains"` // outbound + group tags this connection used
	// Routing-observability fields (the Dashboard live-connections table): which host
	// the connection is to, which routing rule matched it, and when it started.
	Rule        string   `json:"rule"`
	RulePayload string   `json:"rulePayload"`
	Start       string   `json:"start"` // RFC3339; UI derives the connection age
	Metadata    ConnMeta `json:"metadata"`
}

// ConnMeta is the per-connection target metadata from Clash /connections.
type ConnMeta struct {
	Host            string `json:"host"`
	DestinationIP   string `json:"destinationIP"`
	DestinationPort string `json:"destinationPort"`
	Network         string `json:"network"`
}

// Connections is the Clash /connections payload.
type Connections struct {
	DownloadTotal int64  `json:"downloadTotal"`
	UploadTotal   int64  `json:"uploadTotal"`
	Connections   []Conn `json:"connections"`
}

// Connections returns the current active connections (with per-connection bytes).
func (c *Client) Connections(ctx context.Context) (Connections, error) {
	u := *c.base
	u.Path = "/connections"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Connections{}, err
	}
	c.auth(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return Connections{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Connections{}, fmt.Errorf("clash /connections: status %d", resp.StatusCode)
	}
	var out Connections
	err = json.NewDecoder(io.LimitReader(resp.Body, maxClashBody)).Decode(&out)
	return out, err
}

// Select sets the chosen member of a selector group (PUT /proxies/{group}).
func (c *Client) Select(ctx context.Context, group, name string) error {
	u := *c.base
	u.Path = "/proxies/" + group
	u.RawPath = "/proxies/" + url.PathEscape(group) // single-encode (see Delay)
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("clash select %s=%s: status %d", group, name, resp.StatusCode)
	}
	return nil
}
