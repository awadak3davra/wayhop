package netdiag

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Per-exit service check (competitor gap 3: OpenClash's streaming check, built on
// lmc999/RegionRestrictionCheck). A reachability probe cannot answer "does ChatGPT work through this
// exit": a region-locked service answers from every country and says no in the body. So each check
// below reads the answer, and says "blocked" only on the service's own explicit refusal - a marker
// that went stale (Gemini's page marker did, #77) must degrade to "reachable", never to a false
// "blocked" or "available".

// Service states.
const (
	ServiceAvailable   = "available"   // the service's own answer says it works here
	ServiceBlocked     = "blocked"     // the service's own answer refuses this exit's region
	ServiceReachable   = "reachable"   // it answered, but nothing in the answer tells which
	ServiceUnreachable = "unreachable" // no answer through this exit
)

// ExitIdentity is how the internet sees an exit, from Cloudflare's trace endpoint: the address,
// the country Cloudflare places it in, the Cloudflare site that answered, and whether it arrived
// through WARP. It is what Cloudflare-fronted services see; another CDN may place the address
// elsewhere.
type ExitIdentity struct {
	IP      string `json:"ip,omitempty"`
	Country string `json:"country,omitempty"`
	Colo    string `json:"colo,omitempty"`
	Warp    bool   `json:"warp,omitempty"`
	Err     string `json:"err,omitempty"`
}

// ServiceVerdict is one service's answer through one exit.
type ServiceVerdict struct {
	Service string `json:"service"`
	State   string `json:"state"`
	Region  string `json:"region,omitempty"`
	Err     string `json:"err,omitempty"`
}

// ExitServices is everything checked through one exit.
type ExitServices struct {
	Identity ExitIdentity     `json:"identity"`
	Services []ServiceVerdict `json:"services"`
}

// browserUA is what the services expect from a person; several refuse or reshape an answer for a
// bare client.
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36"

// serviceBodyLimit bounds what one answer may cost: YouTube's page is about 1 MB.
const serviceBodyLimit = 2 << 20

// answer is what a check reads: the final URL after redirects, the status and the start of the body.
type answer struct {
	finalURL string
	status   int
	body     []byte
}

type serviceCheck struct {
	id      string
	url     string
	verdict func(a answer) (state, region string)
}

var (
	ytRegion = regexp.MustCompile(`"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"`)
)

// services is the list checked through every exit, in display order. The markers are
// RegionRestrictionCheck's (check.sh), confirmed against live answers on 2026-10-29.
var services = []serviceCheck{
	{id: "chatgpt", url: "https://api.openai.com/compliance/cookie_requirements", verdict: verdictChatGPT},
	{id: "claude", url: "https://claude.ai/", verdict: verdictClaude},
	{id: "youtube_premium", url: "https://www.youtube.com/premium", verdict: verdictYouTubePremium},
}

// ServiceIDs lists the checked services in display order.
func ServiceIDs() []string {
	out := make([]string, len(services))
	for i, s := range services {
		out[i] = s.id
	}
	return out
}

// verdictChatGPT: OpenAI's compliance endpoint answers JSON everywhere; outside the supported
// countries it carries "unsupported_country".
func verdictChatGPT(a answer) (string, string) {
	switch {
	case bytes.Contains(a.body, []byte("unsupported_country")):
		return ServiceBlocked, ""
	case a.status == http.StatusOK && bytes.Contains(a.body, []byte("cookie_consent_required")):
		return ServiceAvailable, ""
	}
	return ServiceReachable, ""
}

// verdictClaude: claude.ai sends an unsupported region to anthropic.com/app-unavailable-in-region.
// Otherwise a bot challenge usually answers a non-browser, so all that is proven is the answer.
func verdictClaude(a answer) (string, string) {
	if strings.Contains(a.finalURL, "/app-unavailable-in-region") {
		return ServiceBlocked, ""
	}
	return ServiceReachable, ""
}

// verdictYouTubePremium: the Premium page says outright where it is not offered, and names the
// country it served (INNERTUBE_CONTEXT_GL).
func verdictYouTubePremium(a answer) (string, string) {
	region := ""
	if m := ytRegion.FindSubmatch(a.body); m != nil {
		region = string(m[1])
	}
	switch {
	case bytes.Contains(a.body, []byte("www.google.cn")):
		return ServiceBlocked, "CN"
	case bytes.Contains(bytes.ToLower(a.body), []byte("premium is not available in your country")):
		return ServiceBlocked, region
	case bytes.Contains(bytes.ToLower(a.body), []byte("ad-free")):
		return ServiceAvailable, region
	}
	return ServiceReachable, region
}

// parseTrace reads Cloudflare's /cdn-cgi/trace (key=value lines).
func parseTrace(body []byte) ExitIdentity {
	var id ExitIdentity
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			if net.ParseIP(v) != nil {
				id.IP = v
			}
		case "loc":
			if len(v) == 2 {
				id.Country = strings.ToUpper(v)
			}
		case "colo":
			id.Colo = v
		case "warp":
			id.Warp = v == "on" || v == "plus"
		}
	}
	if id.IP == "" && id.Country == "" {
		id.Err = "unexpected answer from the trace endpoint"
	}
	return id
}

// traceURL is Cloudflare's trace endpoint; tests point it elsewhere.
var traceURL = "https://www.cloudflare.com/cdn-cgi/trace"

// get fetches one URL through c, following redirects, reading at most serviceBodyLimit.
func get(ctx context.Context, c *http.Client, url string) (answer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := c.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, serviceBodyLimit))
	if err != nil && len(body) == 0 {
		return answer{}, err
	}
	return answer{finalURL: resp.Request.URL.String(), status: resp.StatusCode, body: body}, nil
}

// CheckServices asks Cloudflare who this exit is and every service whether it works through it,
// all through c, which must send its connections out the exit under test.
func CheckServices(ctx context.Context, c *http.Client) ExitServices {
	out := ExitServices{Services: make([]ServiceVerdict, len(services))}
	var wg sync.WaitGroup
	wg.Add(1 + len(services))
	go func() {
		defer wg.Done()
		a, err := get(ctx, c, traceURL)
		if err != nil {
			out.Identity = ExitIdentity{Err: shortFetchErr(err)}
			return
		}
		out.Identity = parseTrace(a.body)
	}()
	for i, s := range services {
		go func(i int, s serviceCheck) {
			defer wg.Done()
			v := ServiceVerdict{Service: s.id}
			a, err := get(ctx, c, s.url)
			if err != nil {
				v.State, v.Err = ServiceUnreachable, shortFetchErr(err)
			} else {
				v.State, v.Region = s.verdict(a)
			}
			out.Services[i] = v
		}(i, s)
	}
	wg.Wait()
	return out
}

// shortFetchErr names a failed fetch without the URL and the client's wrapping.
func shortFetchErr(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case strings.Contains(err.Error(), "certificate"):
		return "TLS certificate rejected (an interception or block page?)"
	case strings.Contains(err.Error(), "connection refused"):
		return "connection refused"
	case strings.Contains(err.Error(), "connection reset"):
		return "connection reset"
	}
	return "no answer"
}

// IfaceClient is an HTTP client whose every connection - redirects included - is bound to iface
// ("" = the WAN, unbound). Each host is resolved here and dialled by the public address it resolved
// to, the same SSRF pin ReachViaIface uses. Certificates are verified: a verdict read from an
// interception page would be a lie.
func IfaceClient(iface string, timeout time.Duration) (*http.Client, error) {
	if iface != "" && !ValidIface(iface) {
		return nil, errors.New("invalid interface")
	}
	dialer := &net.Dialer{Timeout: timeout, Control: bindToDevice(iface)}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := resolvePublic(ctx, host)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}, nil
}
