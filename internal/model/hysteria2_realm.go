package model

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Hysteria Realms let a Hysteria2 server with no public address (behind NAT, CGNAT, no port
// forwarding) take connections. The server registers a named slot - the realm - with a rendezvous
// service and advertises the UDP addresses STUN showed it; a client asks the rendezvous for them,
// both sides punch a UDP hole, and the ordinary Hysteria2 QUIC handshake (TLS, password) runs over
// it. The rendezvous carries no traffic.
//
// Such a connection has no server address of its own. It carries, instead of Server and Port:
//
//	realm       the rendezvous address in Hysteria's own client syntax:
//	            realm://<token>@<host>[:port]/<realm name> (HTTPS, port 443 by default), or
//	            realm+http:// for a rendezvous that speaks plain HTTP (port 80; Hysteria calls it
//	            development-only). The token may be empty for a rendezvous without one.
//	realm_stun  STUN servers, host or host:port (3478 by default), comma separated. Empty means the
//	            three Hysteria uses when none are given. Hysteria's own ?stun= on the realm address
//	            is read as well.
//
// sing-box carries a realm from 1.14 (the hysteria2 outbound's `realm` object).

// Hy2Realm is a parsed realm address.
type Hy2Realm struct {
	HTTP  bool     // realm+http://: the rendezvous is plain HTTP
	Token string   // bearer token for the rendezvous; "" when it has none
	Host  string   // rendezvous host (an IPv6 literal without brackets)
	Port  int      // rendezvous port; 0 = the scheme's default
	ID    string   // realm name: the slot the server registered
	STUN  []string // host or host:port; empty = the client's defaults
}

// The realm address schemes Hysteria defines.
const (
	hy2RealmScheme     = "realm"
	hy2RealmHTTPScheme = "realm+http"
)

// UsesRealm reports whether e is a Hysteria2 connection made through a realm, which then stands in
// for its server and port.
func (e Endpoint) UsesRealm() bool {
	if e.Protocol != ProtoHysteria2 {
		return false
	}
	s, _ := e.Params["realm"].(string)
	return strings.TrimSpace(s) != ""
}

// ServerAddress is the server this connection dials, "" when it dials none: a Realm connection reaches
// its server through the rendezvous, and a Server left over from before the realm (the panel's form,
// or an edit through the API) is not where its traffic goes. The health check dialled it, the bypass
// list routed it direct and the exit-IP view reported it; they read it through here.
func (e Endpoint) ServerAddress() string {
	if e.UsesRealm() {
		return ""
	}
	return e.Server
}

// Hy2RealmOf returns e's realm with its STUN servers (realm_stun, then any ?stun= on the address),
// nil when e has none, or an error naming what is wrong with it. The error never quotes the
// address: its userinfo is the rendezvous token.
func Hy2RealmOf(e *Endpoint) (*Hy2Realm, error) {
	if !e.UsesRealm() {
		return nil, nil
	}
	s, _ := e.Params["realm"].(string)
	r, err := ParseHy2Realm(s)
	if err != nil {
		return nil, err
	}
	extra, err := hy2RealmSTUNParam(e.Params["realm_stun"])
	if err != nil {
		return nil, err
	}
	r.STUN = appendUniqueSTUN(extra, r.STUN...)
	return r, nil
}

// ParseHy2Realm reads a realm address the way Hysteria's client does (extras/realm.ParseAddr), except
// that the token may be empty: sing-box's realm takes a rendezvous without one. ?stun= values are
// collected; ?lport= (a fixed local UDP port) is accepted and not carried, because sing-box has no
// such option, and other query parameters are ignored.
func ParseHy2Realm(s string) (*Hy2Realm, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("realm address is not a URL (want realm://token@host/name)")
	}
	r := &Hy2Realm{}
	switch strings.ToLower(u.Scheme) {
	case hy2RealmScheme:
	case hy2RealmHTTPScheme:
		r.HTTP = true
	default:
		return nil, errors.New("realm address must start with realm:// or realm+http://")
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return nil, errors.New("realm address has no rendezvous host (want realm://token@host/name)")
	}
	r.Host = u.Hostname()
	// A host that still holds a colon is an unbracketed IPv6 literal that url.Parse split at its last
	// colon (the importer's finalize meets the same remnant in share links).
	if strings.ContainsRune(r.Host, ':') && net.ParseIP(r.Host) == nil {
		return nil, errors.New("realm address: wrap an IPv6 rendezvous address in brackets, e.g. realm://token@[2001:db8::1]/name")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("realm address: rendezvous port %q out of range (1-65535)", p)
		}
		r.Port = n
	}
	if u.User != nil {
		tok, err := url.PathUnescape(u.User.String())
		if err != nil {
			return nil, errors.New("realm address: the token is not valid percent-encoding")
		}
		r.Token = tok
	}
	// One path segment, as Hysteria requires: the name is a single segment of the rendezvous API path.
	id := strings.TrimPrefix(u.EscapedPath(), "/")
	if id == "" || strings.Contains(id, "/") {
		return nil, errors.New("realm address needs the realm name as its only path segment (realm://token@host/name)")
	}
	if r.ID, err = url.PathUnescape(id); err != nil || r.ID == "" || strings.Contains(r.ID, "/") {
		return nil, errors.New("realm address needs the realm name as its only path segment (realm://token@host/name)")
	}
	if u.Fragment != "" {
		return nil, errors.New("realm address cannot carry a #fragment")
	}
	stun, err := hy2RealmSTUNList(u.Query()["stun"])
	if err != nil {
		return nil, err
	}
	r.STUN = stun
	return r, nil
}

// URI is the canonical realm address, without STUN servers (those live in realm_stun).
func (r *Hy2Realm) URI() string {
	scheme := hy2RealmScheme
	if r.HTTP {
		scheme = hy2RealmHTTPScheme
	}
	return r.Addr(scheme).String()
}

// Addr is the realm address under scheme, with no query: realm:// for the address itself, or the
// scheme of a share link that carries one (hysteria2+realm://).
func (r *Hy2Realm) Addr(scheme string) *url.URL {
	u := &url.URL{Scheme: scheme, Host: r.hostPort(), Path: "/" + r.ID}
	if r.Token != "" {
		u.User = url.User(r.Token)
	}
	return u
}

// ServerURL is the rendezvous base URL a client talks to: https://host[:port], or http:// for
// realm+http.
func (r *Hy2Realm) ServerURL() string {
	u := url.URL{Scheme: "https", Host: r.hostPort()}
	if r.HTTP {
		u.Scheme = "http"
	}
	return u.String()
}

func (r *Hy2Realm) hostPort() string {
	if r.Port != 0 {
		return net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	}
	if strings.ContainsRune(r.Host, ':') {
		return "[" + r.Host + "]"
	}
	return r.Host
}

// hy2RealmSTUNParam reads realm_stun: a comma (or space) separated string, or a list of strings.
func hy2RealmSTUNParam(v any) ([]string, error) {
	var raw []string
	switch t := v.(type) {
	case nil:
	case string:
		raw = strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	case []string:
		raw = t
	case []any:
		for _, x := range t {
			s, ok := x.(string)
			if !ok {
				return nil, errors.New("realm_stun must list STUN servers as host or host:port strings")
			}
			raw = append(raw, s)
		}
	default:
		return nil, errors.New("realm_stun must list STUN servers as host or host:port strings")
	}
	return hy2RealmSTUNList(raw)
}

// stunHostRe is a DNS name: dot-separated labels of letters, digits and inner hyphens.
var stunHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\.?$`)

// hy2RealmSTUNList checks STUN servers the way sing-box reads them (sing-quic realm.ResolveSTUNServers):
// host:port, or a bare host on port 3478.
func hy2RealmSTUNList(raw []string) ([]string, error) {
	var out []string
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			// A bare host or address, on 3478. A bracketed IPv6 literal loses its brackets, which only
			// mean something beside a port; anything else that did not split (a second colon, a
			// comma-joined pair) is refused below rather than reaching sing-box as a "host".
			host, port = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"), "-"
			s = host
		}
		switch {
		case port == "":
			return nil, fmt.Errorf("STUN server %q: the port after \":\" is empty", s)
		case port != "-":
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("STUN server %q: port out of range (1-65535)", s)
			}
		}
		if net.ParseIP(host) == nil && !stunHostRe.MatchString(host) {
			return nil, fmt.Errorf("STUN server %q is not host or host:port", s)
		}
		out = appendUniqueSTUN(out, s)
	}
	return out, nil
}

func appendUniqueSTUN(list []string, add ...string) []string {
	for _, s := range add {
		dup := false
		for _, have := range list {
			if have == s {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, s)
		}
	}
	return list
}
