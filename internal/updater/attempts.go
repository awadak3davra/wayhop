package updater

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Structured fetch attempts.
//
// The updater used to return only the last error, and Go puts the full URL into a *url.Error's
// message — so the single line the UI had to show was `Get "https://…": dial tcp: …`, truncated into
// a `title` attribute. That is wrong twice over: a mirror prefix can carry userinfo or a token in
// its path or query, so the one thing shown was the one thing that must not be, and on touch there
// was no way to read it at all.
//
// An Attempt records what happened against each source, with the host redacted to scheme+host and
// the cause reduced to a category. The full list is what the UI renders; nothing in it carries a
// credential.

// Attempt is one try against one source.
type Attempt struct {
	Source   string `json:"source"`           // "direct" | "mirror"
	Host     string `json:"host"`             // scheme://host only — never userinfo, path or query
	MS       int64  `json:"ms"`               // how long this attempt took
	Status   int    `json:"status,omitempty"` // HTTP status, when one was received
	Category string `json:"category"`         // ok | dns | connect | tls | timeout | http | body | invalid
	Detail   string `json:"detail,omitempty"` // the cause, with every URL removed
}

// Attempt categories. Strings rather than an enum because they cross the API boundary into the UI,
// where they choose the short label an operator reads instead of an exception.
const (
	CatOK      = "ok"
	CatDNS     = "dns"
	CatConnect = "connect"
	CatTLS     = "tls"
	CatTimeout = "timeout"
	CatHTTP    = "http"
	CatBody    = "body"
	CatInvalid = "invalid"
)

// FetchError is what a caller gets when every source failed. Its message states how many attempts
// were made and what mostly went wrong, because "it failed" and "all three sources failed DNS" send
// an operator to different places.
type FetchError struct {
	What     string    // what was being fetched, e.g. "release list"
	Attempts []Attempt // every attempt, in order
}

func (e *FetchError) Error() string {
	if len(e.Attempts) == 0 {
		// The wording is the pre-existing one: with no entry in the list there is nothing to try, and
		// a caller (and a test) that already recognises this condition should keep recognising it.
		return e.What + ": no mirrors configured"
	}
	// The dominant category, and the last one, are both worth naming: three DNS failures mean the
	// router cannot resolve, while two DNS and one 403 means the last mirror answered and refused.
	counts := map[string]int{}
	for _, a := range e.Attempts {
		counts[a.Category]++
	}
	main, n := "", 0
	for c, k := range counts {
		if k > n || (k == n && c < main) {
			main, n = c, k
		}
	}
	last := e.Attempts[len(e.Attempts)-1]
	msg := fmt.Sprintf("%s: %d source(s) tried, all failed; %d of them with %s",
		e.What, len(e.Attempts), n, describe(main))
	if last.Category != main {
		msg += fmt.Sprintf(", the last with %s", describe(last.Category))
	}
	return msg
}

// Summary is the short label the UI puts on a chip, so it never renders a raw exception.
func (e *FetchError) Summary() string {
	if len(e.Attempts) == 0 {
		return "No update source configured"
	}
	counts := map[string]int{}
	for _, a := range e.Attempts {
		counts[a.Category]++
	}
	main, n := "", 0
	for c, k := range counts {
		if k > n || (k == n && c < main) {
			main, n = c, k
		}
	}
	switch main {
	case CatDNS:
		return "Update check failed: name not resolved"
	case CatTimeout:
		return "Update check timed out"
	case CatConnect:
		return "Update check failed: cannot connect"
	case CatTLS:
		return "Update check failed: TLS error"
	case CatHTTP:
		return "Update check refused by the server"
	default:
		return "Update check failed"
	}
}

func describe(cat string) string {
	switch cat {
	case CatDNS:
		return "a name that did not resolve"
	case CatConnect:
		return "a connection that could not be made"
	case CatTLS:
		return "a TLS failure"
	case CatTimeout:
		return "a timeout"
	case CatHTTP:
		return "an HTTP error status"
	case CatBody:
		return "an unreadable response"
	case CatInvalid:
		return "an unusable source"
	default:
		return "an error"
	}
}

// redactHost reduces a URL to scheme://host. Userinfo, path and query are dropped rather than
// filtered: a mirror prefix is operator-supplied and can carry a token anywhere in them, so keeping
// any part would mean deciding which secrets are safe to show.
func redactHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "(unparseable source)"
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + u.Hostname()
}

// scrubErr renders an error without any URL in it.
//
// Go's *url.Error carries the request URL in its message, so err.Error() on a failed fetch prints
// whatever the operator put in the mirror prefix — the exact string that must not reach a UI or a
// log. Unwrapping to the cause removes it at the source instead of trying to pattern-match it out
// afterwards, which would leave every form nobody thought of.
func scrubErr(err error) string {
	if err == nil {
		return ""
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		err = ue.Err
	}
	s := err.Error()
	// A *net.DNSError names the host it failed to resolve, and that name is the most useful thing in
	// a DNS failure. It is safe as it stands: the resolver is only ever handed a hostname, so it
	// cannot carry userinfo, a path or a query — the URL parser strips those long before a lookup.
	var de *net.DNSError
	if errors.As(err, &de) && de.Name != "" {
		return "cannot resolve " + de.Name
	}
	// Belt and braces for a cause that embedded a URL of its own.
	for _, scheme := range []string{"https://", "http://"} {
		for {
			i := strings.Index(s, scheme)
			if i < 0 {
				break
			}
			j := i + len(scheme)
			for j < len(s) && !isURLEnd(s[j]) {
				j++
			}
			s = s[:i] + "(url)" + s[j:]
		}
	}
	return s
}

func isURLEnd(c byte) bool {
	return c == ' ' || c == '"' || c == '\'' || c == '\n' || c == '\t' || c == ',' || c == ')'
}

// categorize turns a transport error into one of the categories above.
func categorize(err error) string {
	if err == nil {
		return CatOK
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return CatTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return CatTimeout
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return CatDNS
	}
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) {
		return CatTLS
	}
	var re *tls.RecordHeaderError
	if errors.As(err, &re) {
		return CatTLS
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return CatConnect
	}
	return CatHTTP
}

// sourceKind names where an attempt went, without repeating the address.
func sourceKind(mirror string) string {
	if strings.TrimSpace(mirror) == "" {
		return "direct"
	}
	return "mirror"
}

// attemptTimeout bounds ONE source. Without it a wedged mirror consumes the caller's whole deadline
// and the sources after it are never tried, which is a fallback that does not fall back. Overall
// time stays bounded by the caller's context.
var attemptTimeout = 12 * time.Second

// withAttemptDeadline derives the per-attempt context, never extending the caller's own deadline.
func withAttemptDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, attemptTimeout)
}
