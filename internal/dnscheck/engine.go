package dnscheck

import (
	"context"
	"time"
)

// Reply is one UDP datagram that answered a query.
type Reply struct {
	From string // the source address, without the port
	Msg  []byte
	Ms   int
}

// CertResult is the outcome of asking an address for a certificate valid for a name.
type CertResult string

const (
	CertOK     CertResult = "ok"      // the address holds a certificate for the name: the answer is real
	CertBad    CertResult = "bad"     // it connected and the certificate does not fit: the answer is forged
	CertNoConn CertResult = "no_conn" // no connection: the line may block it, nothing can be concluded
)

// Net is everything the probes need from the network, so every verdict can be tested without one.
type Net interface {
	// UDP sends q to server:53 from path and returns every reply whose id matches, until wait ends.
	UDP(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error)
	// DoT sends q over TLS to server:853 with sni, certificate verified, and returns the answer and the
	// certificate's common name.
	DoT(ctx context.Context, path Path, server, sni string, q []byte) (msg []byte, certName string, err error)
	// DoH posts q to url, certificate verified, over HTTP/2 when offered.
	DoH(ctx context.Context, path Path, url string, q []byte) (msg []byte, certName string, err error)
	// Cert dials ip:443 from path and verifies a certificate for name.
	Cert(ctx context.Context, path Path, ip, name string) CertResult
}

// Options tune one run.
type Options struct {
	Names         []string      // canary names on top of the defaults
	CanariesOnWAN bool          // send canary names in plaintext on PathWAN as well
	RouterHidden  bool          // the chain is measured to leave by tunnels, so canaries may go through :53
	ProofPath     *Path         // the path certificates are checked on: a tunnel when there is one
	Concurrency   int           // simultaneous probes; 0 means the default
	Wait          time.Duration // how long one query may wait for its first reply; 0 means the default
	Rand          func() string // random label source; nil means crypto/rand
	OnProgress    func(done, total int)
}

// Target is one resolver to check from one path.
type Target struct {
	Address string
	Path    Path
}

// Interceptions runs the decoy probe on each path.
func Interceptions(ctx context.Context, n Net, paths []Path, o Options) []Interception {
	return newAuthRun(n, o, countInterceptions(paths)).interceptions(ctx, paths)
}

// Authenticate runs the resolver probes on each target. The verdict for a target on a path whose decoy
// answered is forged whatever the other probes said, so interceptions is an input.
func Authenticate(ctx context.Context, n Net, targets []Target, interceptions []Interception, o Options) []ResolverResult {
	return newAuthRun(n, o, countTargetProbes(targets)).authenticate(ctx, targets, interceptions)
}

// Encrypted checks DoT and DoH for each target with a known operator.
func Encrypted(ctx context.Context, n Net, targets []Target, o Options) []EncryptedResult {
	return newAuthRun(n, o, countEncryptedProbes(targets)).encrypted(ctx, targets)
}
