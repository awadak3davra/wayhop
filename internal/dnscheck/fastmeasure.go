package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	fastDefaultConcurrency = 8
	fastDefaultTimeout     = 6 * time.Second
)

// FastOptions tune one quick-list run.
type FastOptions struct {
	Concurrency int           // simultaneous entries; 0 means eight
	Timeout     time.Duration // whole budget for one transport; 0 means six seconds
	OnProgress  func(done, total int)
}

// FastTransportCount is the number of individual protocol measurements in entries.
func FastTransportCount(entries []FastEntry) int {
	total := 0
	for _, e := range entries {
		if e.DoHPath != "" {
			total++
		}
		if e.DoT {
			total++
		}
	}
	return total
}

// MeasureFast measures every transport, eight entries at a time by default, then puts the usable
// resolvers in speed order. Each transport owns one connection for its timing and possible DNSSEC probe.
func MeasureFast(ctx context.Context, n FastNet, path Path, entries []FastEntry, o FastOptions) []FastResult {
	concurrency := o.Concurrency
	if concurrency <= 0 {
		concurrency = fastDefaultConcurrency
	}
	if concurrency > len(entries) {
		concurrency = len(entries)
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = fastDefaultTimeout
	}
	total := FastTransportCount(entries)
	results := make([]FastResult, len(entries))
	for i, e := range entries {
		results[i].ID = e.ID
	}

	var progressMu sync.Mutex
	done := 0
	progress := func() {
		if o.OnProgress == nil {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		done++
		o.OnProgress(done, total)
	}

	jobs := make(chan int)
	var workers sync.WaitGroup
	workers.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer workers.Done()
			for index := range jobs {
				results[index] = measureFastEntry(ctx, n, path, entries[index], timeout, progress)
			}
		}()
	}

send:
	for i := range entries {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	workers.Wait()
	SortFast(results)
	return results
}

func measureFastEntry(ctx context.Context, n FastNet, path Path, entry FastEntry, timeout time.Duration,
	progress func()) FastResult {
	protos := make([]string, 0, 2)
	if entry.DoHPath != "" {
		protos = append(protos, "doh")
	}
	if entry.DoT {
		protos = append(protos, "dot")
	}
	result := FastResult{ID: entry.ID, Transports: make([]FastTransport, len(protos))}
	var validated atomic.Bool
	var wg sync.WaitGroup
	wg.Add(len(protos))
	for i, proto := range protos {
		go func() {
			defer wg.Done()
			defer progress()
			transportCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			result.Transports[i] = measureFastTransport(transportCtx, n, path, entry, proto, &validated, &result.Validates)
		}()
	}
	wg.Wait()

	for _, transport := range result.Transports {
		if transport.Status != FastOK {
			continue
		}
		if !result.Alive || transport.Ms < result.Ms || (transport.Ms == result.Ms && transport.Proto == "doh") {
			result.Alive = true
			result.Best = transport.Proto
			result.Ms = transport.Ms
		}
	}
	return result
}

func measureFastTransport(ctx context.Context, n FastNet, path Path, entry FastEntry, proto string,
	validated *atomic.Bool, validates **bool) FastTransport {
	transport := FastTransport{Proto: proto}
	query, err := BuildQuery("www.example.com", dnsTypeA, dnsClassIN, false)
	if err != nil {
		transport.Status = FastOther
		return transport
	}
	if n == nil {
		transport.Status = FastOther
		return transport
	}

	started := time.Now()
	var conn FastConn
	if proto == "doh" {
		conn, err = n.DoH(ctx, path, entry)
	} else {
		conn, err = n.DoT(ctx, path, entry)
	}
	if err != nil {
		transport.Status = fastErrorStatus(err)
		return transport
	}
	defer conn.Close()

	msg, err := conn.Query(ctx, query)
	if err != nil {
		transport.Status = fastErrorStatus(err)
		return transport
	}
	connectMs := fastMilliseconds(started)
	reply, err := parseFastReply(query, msg)
	if err != nil || reply.Rcode != rcodeNoError || firstAddress(reply) == "" {
		transport.Status = FastBadAnswer
		return transport
	}
	transport.Status = FastOK
	transport.ConnectMs = connectMs
	cert := conn.Certificate()
	transport.CertName, transport.Issuer, transport.CertDays = cert.CertName, cert.Issuer, cert.CertDays

	var samples []int
	for i := 0; i < 2 && ctx.Err() == nil; i++ {
		q, buildErr := BuildQuery("www.example.com", dnsTypeA, dnsClassIN, false)
		if buildErr != nil {
			break
		}
		queryStarted := time.Now()
		msg, queryErr := conn.Query(ctx, q)
		if queryErr != nil {
			continue
		}
		ms := fastMilliseconds(queryStarted)
		if _, parseErr := parseFastReply(q, msg); parseErr == nil {
			samples = append(samples, ms)
		}
	}
	switch len(samples) {
	case 0:
		transport.Ms = connectMs
	case 1:
		transport.Ms = samples[0]
	default:
		transport.Ms = (samples[0] + samples[1]) / 2
	}

	// The first passing transport claims the entry's only DNSSEC probe and uses its existing connection.
	if validated.CompareAndSwap(false, true) {
		*validates = measureFastValidation(ctx, conn)
	}
	return transport
}

func measureFastValidation(ctx context.Context, conn FastConn) *bool {
	query, err := BuildQuery("dnssec-failed.org", dnsTypeA, dnsClassIN, false)
	if err != nil {
		return nil
	}
	msg, err := conn.Query(ctx, query)
	if err != nil {
		return nil
	}
	reply, err := parseFastReply(query, msg)
	if err != nil {
		return nil
	}
	if reply.Rcode == rcodeServFail {
		value := true
		return &value
	}
	if firstAddress(reply) != "" {
		value := false
		return &value
	}
	return nil
}

func parseFastReply(query, msg []byte) (DNSReply, error) {
	if len(query) < 2 || len(msg) < 4 || query[0] != msg[0] || query[1] != msg[1] || msg[2]&0x80 == 0 {
		return DNSReply{}, errors.New("fast DNS response does not match its query")
	}
	reply, err := ParseReply(msg)
	if err != nil {
		return DNSReply{}, fmt.Errorf("parse fast DNS response: %w", err)
	}
	return reply, nil
}

func fastMilliseconds(started time.Time) int {
	ms := int(time.Since(started) / time.Millisecond)
	if ms < 1 {
		return 1
	}
	return ms
}

func fastErrorStatus(err error) string {
	var httpStatus *fastHTTPStatusError
	var response *fastResponseError
	if errors.As(err, &httpStatus) || errors.As(err, &response) {
		return FastBadAnswer
	}
	if isCertificateError(err) {
		return FastBadCert
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return FastTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, io.EOF) || isSyscallRefused(err) {
		return FastRefused
	}
	return FastOther
}

func isSyscallRefused(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// 10061 = WSAECONNREFUSED, 10054 = WSAECONNRESET, 10058 = WSAESHUTDOWN on Windows.
		return errno == 10061 || errno == 10054 || errno == 10058
	}
	return false
}

// FastCertsUnreliable distinguishes a router-wide clock or root-store problem from resolvers that each
// failed in their own way. Most of what was tried must have failed on its certificate, at least three.
func FastCertsUnreliable(results []FastResult) bool {
	bad, attempted := 0, 0
	for _, result := range results {
		if result.Alive {
			return false
		}
		for _, transport := range result.Transports {
			attempted++
			switch transport.Status {
			case FastBadCert:
				bad++
			case FastBadAnswer:
				return false
			case FastOK:
				return false
			case FastTimeout, FastRefused, FastOther:
			}
		}
	}
	return bad >= 3 && bad*2 >= attempted
}
